using Microsoft.Extensions.Logging;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;

namespace WPShield.SecurityMonitor;

/// <summary>Why <see cref="EvidenceCollector.RunAsync"/> returned.</summary>
public enum EvidenceCollectorExit
{
    /// <summary>Cancelled: the service or the console is stopping. What was buffered was written.</summary>
    Stopped,

    /// <summary>
    /// The store's directory does not exist. Nothing was created; <c>wpshield install</c> creates it
    /// with replaced permissions.
    /// </summary>
    StoreMissing
}

/// <summary>
/// Records failed Windows logons into the evidence store (ADR 0007), continuously: a catch-up from the
/// event logs on start, then the live subscription, with coverage intervals that say what was and was
/// not read.
/// </summary>
/// <remarks>
/// <para>
/// <b>It never hands history to anything that decides.</b> No part of it reads <c>decisions</c> or
/// restores a block. The decision engine (ADR 0009) lives in this object for the life of the process and
/// sees only live records, after pairing: never the catch-up read at start, which includes the records
/// near the start that go through the pairing buffer with the live ones. ADR 0006's guarantee that a
/// block lives exactly as long as the process depends on that (ADR 0007, section 5). The engine runs in
/// Monitor: it records decisions and enforces nothing, and a failure in it is logged and never stops
/// collection.
/// </para>
/// <para>
/// <b>It never stops its host.</b> It runs inside the gateway, and a background service that throws
/// stops the whole host by default, which would take every protected site with it. Every failure is
/// logged, backed off and retried; a store directory that does not exist is the one condition that
/// makes it idle, because the fix is <c>wpshield install</c> and the install restarts the service.
/// </para>
/// <para>
/// <b>A quiet period and an unrecorded one never look alike.</b> The interval it vouches for is
/// <c>collected</c> only while the Security log is being read; otherwise it is <c>unavailable</c> with
/// the reason, and a bound that stopped the catch-up or a full buffer is recorded as <c>limited</c>.
/// </para>
/// <para>
/// Log lines carry counts, channel identifiers and reason codes only. Account names and addresses are
/// attacker-chosen text and stay in the store, where they are cleaned and bounded.
/// </para>
/// </remarks>
public sealed class EvidenceCollector
{
    public const string LoggerCategory = "WPShield.Evidence.Collector";
    public const string EventLogReadersSid = "S-1-5-32-573";
    public const string EventLogReadersRemedy = @"Add-LocalGroupMember -SID S-1-5-32-573 -Member 'NT SERVICE\WPShield'";

    /// <summary>How often live records are paired and written.</summary>
    public static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(2);

    /// <summary>How often the open coverage interval is extended.</summary>
    public static readonly TimeSpan CoverageInterval = TimeSpan.FromMinutes(1);

    public static readonly TimeSpan PruneInterval = TimeSpan.FromHours(1);

    /// <summary>How often decisions past their expiry are ended and recorded.</summary>
    public static readonly TimeSpan ExpireInterval = TimeSpan.FromMinutes(1);

    /// <summary>How often a session that cannot read the Security log tries again.</summary>
    public static readonly TimeSpan UnavailableRetryInterval = TimeSpan.FromMinutes(15);

    /// <summary>A session that lasted this long resets the back-off.</summary>
    internal static readonly TimeSpan StableAfter = TimeSpan.FromMinutes(5);

    private readonly ILogger logger;
    private string? lastUnavailableReason;

    public EvidenceCollector(string storePath, ILogger logger)
        : this(storePath, logger, TimeProvider.System, (end, window) => AuthFailureFeed.ReadRecent(end, window), AuthFailureFeed.Watch,
            HostProbes.Protection())
    {
    }

    internal EvidenceCollector(string storePath, ILogger logger, TimeProvider time,
        Func<DateTimeOffset, TimeSpan, AuthFailureSnapshot> readRecent,
        Func<Action<AuthFailure>, Action<string, string>, IDisposable> watch, AddressProtection protection,
        DecisionEngineLimits? limits = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(storePath);
        StorePath = storePath;
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        Time = time ?? throw new ArgumentNullException(nameof(time));
        ReadRecent = readRecent ?? throw new ArgumentNullException(nameof(readRecent));
        Watch = watch ?? throw new ArgumentNullException(nameof(watch));
        // One engine for the life of the process, not of a session: a session restarted after a failed
        // subscription must not forget the decisions in force or the repeat offenders.
        Engine = new DecisionEngine(protection ?? throw new ArgumentNullException(nameof(protection)), limits);
    }

    public string StorePath { get; }

    /// <summary>The directory the store lives in. The collector checks it; it never creates it.</summary>
    public string StoreDirectory => Path.GetDirectoryName(Path.GetFullPath(StorePath)) ?? StorePath;

    internal TimeProvider Time { get; }
    internal Func<DateTimeOffset, TimeSpan, AuthFailureSnapshot> ReadRecent { get; }
    internal Func<Action<AuthFailure>, Action<string, string>, IDisposable> Watch { get; }
    internal ILogger Logger => logger;

    /// <summary>The decision engine (ADR 0009). In-process only; nothing restores it.</summary>
    internal DecisionEngine Engine { get; }

    /// <summary>Whether this process has recorded its engine's start in the store yet.</summary>
    internal bool EngineAnnounced { get; set; }

    /// <summary>The pause between ticks. Tests shorten it; the service uses <see cref="FlushInterval"/>.</summary>
    internal TimeSpan TickInterval { get; init; } = FlushInterval;

    /// <summary>The pause after the n-th consecutive failure.</summary>
    internal Func<int, TimeSpan> Backoff { get; init; } = DefaultBackoff;

    internal static TimeSpan DefaultBackoff(int failures) => failures switch
    {
        <= 1 => TimeSpan.FromSeconds(5),
        2 => TimeSpan.FromSeconds(15),
        3 => TimeSpan.FromMinutes(1),
        4 => TimeSpan.FromMinutes(5),
        _ => TimeSpan.FromMinutes(15)
    };

    /// <summary>
    /// Collects until <paramref name="cancellationToken"/> is cancelled. Never throws for a collection
    /// failure: a broken store, an unreadable log or a failed subscription is logged and retried.
    /// </summary>
    public async Task<EvidenceCollectorExit> RunAsync(CancellationToken cancellationToken)
    {
        // The catch-up below blocks for up to the read budget; the host must not wait for it to start.
        await Task.Yield();

        if (!Directory.Exists(StoreDirectory))
        {
            logger.LogWarning(
                "The evidence directory {Directory} does not exist, so failed logons are not being recorded. " +
                "Run 'wpshield install', which creates it with replaced permissions. The collector never creates it: a " +
                "directory it created would inherit ProgramData's permissions, which let every local user read it. " +
                "It stays idle until the service restarts.",
                StoreDirectory);
            return EvidenceCollectorExit.StoreMissing;
        }

        var failures = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            CollectorSession? session = null;
            var started = Time.GetUtcNow();
            try
            {
                session = CollectorSession.Start(this, started);
                while (await DelayAsync(TickInterval, cancellationToken) && session.Tick(Time.GetUtcNow()))
                {
                }

                session.Stop(Time.GetUtcNow(), final: cancellationToken.IsCancellationRequested);
                session = null;
                if (cancellationToken.IsCancellationRequested) break;
                // Asked to restart (a subscription failed, or the Security log is retried). A session
                // that failed again soon after starting grows the pause; a long one resets it.
                failures = Time.GetUtcNow() - started >= StableAfter ? 1 : failures + 1;
            }
            catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                session?.Abandon();
                failures = Time.GetUtcNow() - started >= StableAfter ? 1 : failures + 1;
                logger.LogError(exception,
                    "Evidence collection failed ({ErrorType}). The gateway keeps serving; collection restarts in {DelaySeconds} s " +
                    "and catches up from the last stored record. Failures in a row: {Failures}.",
                    exception.GetType().Name, (int)Backoff(failures).TotalSeconds, failures);
            }
            catch (OperationCanceledException)
            {
                session?.Abandon();
                break;
            }

            if (!await DelayAsync(Backoff(failures), cancellationToken)) break;
        }

        return EvidenceCollectorExit.Stopped;
    }

    /// <summary>Logs an unreadable Security log once per reason, with the remedy, then quietly.</summary>
    internal void ReportSecurityUnavailable(string reason)
    {
        if (reason == lastUnavailableReason)
        {
            logger.LogDebug("The Security log is still unavailable ({Reason}).", reason);
            return;
        }

        lastUnavailableReason = reason;
        if (reason == "access-denied")
        {
            logger.LogWarning(
                "The Security log could not be read (access-denied), so failed logons are not being recorded and the " +
                "period is stored as unavailable. Add the service account to Event Log Readers ({Sid}) and restart the " +
                "service: {Remedy}",
                EventLogReadersSid, EventLogReadersRemedy);
        }
        else
        {
            logger.LogWarning(
                "The Security log could not be read ({Reason}), so failed logons are not being recorded and the period is " +
                "stored as unavailable. Retrying every {RetryMinutes} minutes.",
                reason, (int)UnavailableRetryInterval.TotalMinutes);
        }
    }

    internal void ReportSecurityReadable()
    {
        lastUnavailableReason = null;
        UnavailableInterval = null;
    }

    /// <summary>The open "Security log unavailable" interval, carried across retries with the same reason.</summary>
    internal (long Id, string Reason)? UnavailableInterval { get; set; }

    private async Task<bool> DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(delay, Time, cancellationToken);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }
}

/// <summary>
/// One run of the collector: an open store, a subscription, a catch-up and the coverage intervals it
/// keeps extending. A failed subscription ends the session; the next one catches up from the last
/// stored record, so what the subscription missed is read back from the log.
/// </summary>
/// <remarks>
/// Only the collector's own loop touches SQLite. The subscription's callbacks arrive on event-log
/// threads and touch only the <see cref="PairingBuffer"/> and the fields behind <c>gate</c>.
/// </remarks>
internal sealed class CollectorSession
{
    private readonly EvidenceCollector owner;
    private readonly EvidenceStore store;
    private readonly EvidenceWriter writer;
    private readonly EvidenceSettings settings;
    private readonly PairingBuffer buffer = new();
    private readonly object gate = new();
    private readonly HashSet<(string Channel, long RecordId)> boundary = [];

    /// <summary>
    /// The catch-up records that went through the pairing buffer. They are stored like live ones and
    /// never handed to the decision engine: identity, not a time cut, so a clock that steps back cannot
    /// turn history into live evidence. Bounded by the catch-up read's own bound.
    /// </summary>
    private readonly HashSet<(string Channel, long RecordId)> history = [];
    private readonly Dictionary<string, string> setupErrors = new(StringComparer.Ordinal);
    private readonly List<long> intervals = [];
    private readonly DateTimeOffset started;
    private IDisposable? subscription;
    private bool watching;
    private bool boundaryActive = true;
    private string? restartReason;
    private DateTimeOffset restartAt;
    private DateTimeOffset lastCoverage;
    private DateTimeOffset lastPrune;
    private DateTimeOffset lastExpire;
    private DateTimeOffset lastTick;
    private long reportedDropped;

    private CollectorSession(EvidenceCollector owner, EvidenceStore store, DateTimeOffset started)
    {
        this.owner = owner;
        this.store = store;
        writer = new EvidenceWriter(store);
        settings = new EvidenceSettings(store);
        this.started = started;
        lastCoverage = lastPrune = lastTick = lastExpire = started;
    }

    public bool SecurityReadable { get; private set; }

    public long Inserted { get; private set; }

    internal static CollectorSession Start(EvidenceCollector owner, DateTimeOffset now)
    {
        var store = EvidenceStore.OpenForWriting(owner.StorePath);
        var session = new CollectorSession(owner, store, now);
        try
        {
            session.Begin(now);
            return session;
        }
        catch
        {
            session.Abandon();
            throw;
        }
    }

    private void Begin(DateTimeOffset now)
    {
        // Read at every start, never cached: retention is a NextUse setting.
        var limits = settings.Limits();

        // Anchored on the Security channel's last record, because that channel defines "collected".
        // Remote Desktop's channel can be readable while the Security log is denied - the first run
        // after an install, before Event Log Readers - and anchoring on whichever channel stored
        // something last would then skip every 4625 still in the log once access is granted. A host
        // with no 4625 stored re-reads the raw retention, which is cheap exactly when it is quiet.
        var since = writer.LastRecord(AttemptPairing.SecurityChannel)?.Timestamp ?? now - limits.RawRetention;
        var window = now - since;
        if (window < EvidenceCollector.CoverageInterval) window = EvidenceCollector.CoverageInterval;
        if (window > limits.RawRetention) window = limits.RawRetention;

        // Subscribe first, then read: an attempt written in between is in both and stored once,
        // instead of in neither.
        subscription = owner.Watch(OnFailure, OnError);
        lock (gate) watching = true;

        var snapshot = owner.ReadRecent(now, window);

        // Records near the moment the subscription started go through the buffer, so a 4625 read here
        // and its 140 delivered live are paired instead of counted twice.
        var cut = now - 2 * AttemptPairing.Window;
        Inserted += writer.Append(snapshot.Failures.Where(f => f.Timestamp < cut));
        foreach (var failure in snapshot.Failures.Where(f => f.Timestamp >= cut))
        {
            // Marked before it is buffered, so that its live copy - whichever arrives first - is history too.
            history.Add((failure.Channel, failure.RecordId));
            OnFailure(failure);
        }

        RecordCatchUpCoverage(snapshot, now);
        Prune(now);
        AnnounceEngine(now);

        owner.Logger.LogInformation(
            "Evidence collection started. Store={Store} CatchUpFrom={CatchUpFrom:O} CatchUpRead={CatchUpRead} Inserted={Inserted} " +
            "Security={Security} RemoteDesktop={RemoteDesktop}",
            owner.StorePath, snapshot.WindowStart, snapshot.Failures.Count, Inserted,
            Status(snapshot, AuthFailureFeed.SecurityChannel), Status(snapshot, AuthFailureFeed.RdpCoreChannel));
    }

    /// <summary>One pass of the loop. Returns <see langword="false"/> when the session should end and a new one start.</summary>
    public bool Tick(DateTimeOffset now)
    {
        string? restart;
        DateTimeOffset failedAt;
        lock (gate)
        {
            restart = restartReason;
            failedAt = restartAt;
        }

        Flush(now, flushAll: false);
        ReportDropped(now);

        if (restart is not null)
        {
            // The session vouched up to the failure and no further; Stop must not extend it past it.
            Extend(failedAt);
            intervals.Clear();
            writer.BeginCoverage(EvidenceWriter.RawSource, failedAt, failedAt, "unavailable", restart);
            owner.Logger.LogWarning(
                "An event log subscription failed ({Reason}). Collection restarts and catches up from the last stored record.",
                restart);
            return false;
        }

        if (now - lastCoverage >= EvidenceCollector.CoverageInterval) Extend(now);

        if (boundaryActive && now - started >= EvidenceCollector.CoverageInterval)
        {
            lock (gate)
            {
                boundaryActive = false;
                boundary.Clear();
            }
        }

        if (now - lastPrune >= EvidenceCollector.PruneInterval) Prune(now);

        if (now - lastExpire >= EvidenceCollector.ExpireInterval)
        {
            lastExpire = now;
            Decide("expire", () => owner.Engine.Expire(now));
        }

        // An unreadable Security log rarely fixes itself (group membership reaches a service's token
        // at the next start), but a failed query can. Trying again is one failed read.
        return SecurityReadable || now - started < EvidenceCollector.UnavailableRetryInterval;
    }

    /// <summary>
    /// Stops the subscription, writes everything still buffered and closes the intervals. With
    /// <paramref name="final"/>, the process is stopping: every decision in force ends with it, on the record.
    /// </summary>
    public void Stop(DateTimeOffset now, bool final = false)
    {
        subscription?.Dispose();
        subscription = null;
        Flush(now, flushAll: true);
        ReportDropped(now);
        if (final) Decide("end", () => owner.Engine.EndAll(now));
        Extend(now);
        store.Dispose();
        owner.Logger.LogInformation("Evidence collection stopped. Inserted={Inserted}", Inserted);
    }

    /// <summary>The failure path: release everything, write nothing more. The next session catches up.</summary>
    public void Abandon()
    {
        try { subscription?.Dispose(); }
        catch (Exception exception) when (exception is not OutOfMemoryException) { owner.Logger.LogDebug(exception, "Disposing the subscription failed."); }
        subscription = null;
        try { store.Dispose(); }
        catch (Exception exception) when (exception is not OutOfMemoryException) { owner.Logger.LogDebug(exception, "Closing the store failed."); }
    }

    private void OnFailure(AuthFailure failure)
    {
        lock (gate)
        {
            // The same record can arrive from the catch-up and from the subscription.
            if (boundaryActive && boundary.Count < PairingBuffer.MaxHeld && !boundary.Add((failure.Channel, failure.RecordId))) return;
        }

        buffer.Add(failure);
    }

    private void OnError(string channel, string reason)
    {
        var id = ChannelId(channel);
        lock (gate)
        {
            if (!watching)
            {
                setupErrors.TryAdd(id, reason);
                return;
            }

            // One row per state change, not per callback: the first failure ends the session.
            if (restartReason is not null) return;
            restartReason = $"{id}: {reason}";
            restartAt = owner.Time.GetUtcNow();
        }
    }

    private void RecordCatchUpCoverage(AuthFailureSnapshot snapshot, DateTimeOffset now)
    {
        // The subscription and the read can fail the same channel for different-sounding reasons:
        // unelevated, Windows refuses the Security subscription as a generic query failure and the
        // read as access denied. The specific one is the one an operator can act on.
        var unavailable = new Dictionary<string, string>(StringComparer.Ordinal);
        void Consider(string channel, string reason)
        {
            if (!unavailable.TryGetValue(channel, out var known) || Specificity(reason) > Specificity(known))
                unavailable[channel] = reason;
        }

        lock (gate)
            foreach (var (channel, reason) in setupErrors) Consider(channel, reason);
        foreach (var channel in snapshot.Coverage.Where(c => c.Status == "unavailable"))
            Consider(ChannelId(channel.Channel), channel.Reason ?? "unavailable");

        if (unavailable.TryGetValue(AttemptPairing.SecurityChannel, out var securityReason))
        {
            // Every failed logon is a 4625. Without it, nothing this session sees is a full count.
            SecurityReadable = false;
            var reason = $"{AttemptPairing.SecurityChannel}: {securityReason}";

            // A retry that fails for the same reason continues the interval rather than adding a row
            // every 15 minutes, which over a long misconfiguration would crowd a wide coverage query.
            if (owner.UnavailableInterval is { } prior && prior.Reason == reason)
            {
                writer.ExtendCoverage(prior.Id, now);
                intervals.Add(prior.Id);
            }
            else
            {
                var id = writer.BeginCoverage(EvidenceWriter.RawSource, now, now, "unavailable", reason);
                intervals.Add(id);
                owner.UnavailableInterval = (id, reason);
            }

            owner.ReportSecurityUnavailable(securityReason);
            return;
        }

        SecurityReadable = true;
        owner.ReportSecurityReadable();

        // The catch-up vouches from the latest point every readable channel reached: a bound that
        // stopped the read, or a log that no longer reaches back to the start of the window.
        var from = snapshot.WindowStart;
        foreach (var channel in snapshot.Coverage)
        {
            var id = ChannelId(channel.Channel);
            if (unavailable.ContainsKey(id)) continue;
            var limited = channel.Status == "limited";
            var reached = limited
                ? channel.OldestRead ?? now
                : channel.LogStartsAt is { } logStart && logStart > snapshot.WindowStart ? logStart : snapshot.WindowStart;
            if (reached > now) reached = now;
            if (reached > snapshot.WindowStart)
                writer.BeginCoverage(EvidenceWriter.RawSource, snapshot.WindowStart, reached, limited ? "limited" : "unavailable",
                    $"{id}: {(limited ? "read-bound" : "log-starts-later")}");
            if (reached > from) from = reached;
        }

        intervals.Add(writer.BeginCoverage(EvidenceWriter.RawSource, from, now, "collected"));

        // Another channel missing (Remote Desktop's, in practice) still lets 4625 count every attempt,
        // but NLA attempts lose their address. Recorded beside the collected interval, for as long.
        foreach (var (channel, reason) in unavailable)
        {
            intervals.Add(writer.BeginCoverage(EvidenceWriter.RawSource, now, now, "limited", $"{channel}: {reason}"));
            owner.Logger.LogWarning(
                "The {Channel} channel could not be read ({Reason}). Attempts are still counted from the Security log; " +
                "addresses that only that channel records may be missing.",
                channel, reason);
        }
    }

    private void Flush(DateTimeOffset now, bool flushAll)
    {
        var ready = buffer.TakeReady(now, flushAll);
        if (ready.Count == 0) return;
        Inserted += writer.Append(ready);

        // Paired, stored, and live: only now does the engine see them.
        var live = ready.Where(f => !history.Contains((f.Channel, f.RecordId))).ToArray();
        if (live.Length > 0) Decide("observe", () => owner.Engine.Observe(live, DefenseOptions.Read(settings), now));
    }

    /// <summary>
    /// The engine's first run in this process is written down, so readers count only decisions this run
    /// made as in force. <c>defense.mode</c> is a NextStart setting and read here, once; only monitor exists.
    /// </summary>
    private void AnnounceEngine(DateTimeOffset now)
    {
        if (owner.EngineAnnounced) return;
        writer.RecordEngineStart(now);
        owner.EngineAnnounced = true;
        var mode = settings.Get(DefenseSettings.Mode) is System.Text.Json.Nodes.JsonValue value && value.TryGetValue<string>(out var text)
            ? text : DecisionActions.MonitorMode;
        owner.Logger.LogInformation(
            "Decision engine started. Mode={Mode}: decisions are recorded as would-block and nothing is enforced. It sees live failed " +
            "logons only and keeps its state in memory; nothing is restored from the store.",
            mode == DecisionActions.MonitorMode ? mode : DecisionActions.MonitorMode);
    }

    /// <summary>
    /// Runs one engine step and records what it decided. Nothing in it may stop collection: a failure is
    /// logged with its type and collection continues; the attempts are already stored.
    /// </summary>
    private void Decide(string step, Func<IReadOnlyList<DecisionRecord>> run)
    {
        try
        {
            var decisions = run();
            if (decisions.Count == 0) return;
            foreach (var decision in decisions) writer.RecordDecision(decision);
            // Counts and codes only: targets are addresses, which stay in the store.
            owner.Logger.LogInformation(
                "Decisions recorded ({Step}, monitor - nothing is enforced). WouldBlock={WouldBlock} Protected={Protected} " +
                "Refused={Refused} Report={Report} Expire={Expire} Rules={Rules} Active={Active}",
                step, Count(decisions, DecisionActions.WouldBlock), Count(decisions, DecisionActions.Protected),
                Count(decisions, DecisionActions.Refused), Count(decisions, DecisionActions.Report), Count(decisions, DecisionActions.Expire),
                string.Join(",", decisions.Select(d => d.RuleId).Distinct().Order(StringComparer.Ordinal)), owner.Engine.ActiveCount);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            owner.Logger.LogError(
                "The decision engine failed ({Step}, {ErrorType}). Collection continues; the attempts are stored and nothing is enforced.",
                step, exception.GetType().Name);
        }
    }

    private static int Count(IReadOnlyList<DecisionRecord> decisions, string action) => decisions.Count(d => d.Action == action);

    private void ReportDropped(DateTimeOffset now)
    {
        var dropped = buffer.Dropped;
        if (dropped > reportedDropped)
        {
            var delta = dropped - reportedDropped;
            reportedDropped = dropped;
            writer.BeginCoverage(EvidenceWriter.RawSource, lastTick, now, "limited", $"buffer-full: {delta} dropped");
            owner.Logger.LogWarning(
                "The pairing buffer was full ({Bound} records): {Dropped} failed logons were not recorded ({Total} this session). " +
                "The period is stored as limited.",
                PairingBuffer.MaxHeld, delta, dropped);
        }

        lastTick = now;
    }

    private void Extend(DateTimeOffset to)
    {
        foreach (var id in intervals) writer.ExtendCoverage(id, to);
        lastCoverage = to;
    }

    private void Prune(DateTimeOffset now)
    {
        var result = writer.Prune(now, settings.Limits());
        lastPrune = now;
        if (result.RawRowsDeleted + result.AggregateRowsDeleted + result.DecisionRowsDeleted + result.EventRowsDeleted == 0)
        {
            owner.Logger.LogDebug("Evidence pruning found nothing past its bounds.");
            return;
        }

        owner.Logger.LogInformation(
            "Evidence pruned. RawRows={RawRows} AggregateRows={AggregateRows} DecisionRows={DecisionRows} EventRows={EventRows} " +
            "DetailedFrom={DetailedFrom:O}",
            result.RawRowsDeleted, result.AggregateRowsDeleted, result.DecisionRowsDeleted, result.EventRowsDeleted,
            result.RawNowStartsAt);
    }

    private static int Specificity(string reason) => reason switch
    {
        "access-denied" => 3,
        "channel-missing" => 2,
        "query-failed" => 1,
        _ => 0
    };

    private static string Status(AuthFailureSnapshot snapshot, string channel) =>
        snapshot.Coverage.FirstOrDefault(c => c.Channel == channel) is { } coverage
            ? coverage.Reason is null ? coverage.Status : $"{coverage.Status}:{coverage.Reason}"
            : "not-read";

    /// <summary>The store's channel identifiers, from the Windows log names the feed reports.</summary>
    internal static string ChannelId(string logName) => logName switch
    {
        AuthFailureFeed.SecurityChannel or AttemptPairing.SecurityChannel => AttemptPairing.SecurityChannel,
        AuthFailureFeed.RdpCoreChannel or AttemptPairing.RdpChannel => AttemptPairing.RdpChannel,
        _ => EvidenceText.Clean(logName, 64)
    };
}

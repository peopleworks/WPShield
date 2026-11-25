using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;

namespace WPShield.SecurityMonitor.Tests;

/// <summary>
/// The collector with the event log replaced by fakes and time driven by hand. What is asserted is
/// what a reader of the store will see: the attempts, and the coverage that says whether a quiet
/// period was quiet or unrecorded.
/// </summary>
public sealed class EvidenceCollectorTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);
    private readonly string directory = Path.Combine(Path.GetTempPath(), "wpshield-collector-tests", Guid.NewGuid().ToString("N"));
    private readonly Clock clock = new() { Now = Now };
    private readonly Feed feed = new();
    private readonly RecordingLogger logger = new();
    private long record = 1000;

    public EvidenceCollectorTests() => Directory.CreateDirectory(directory);

    public void Dispose()
    {
        try { Directory.Delete(directory, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string StorePath => Path.Combine(directory, EvidenceStore.FileName);

    // =============================================================================================
    //  The catch-up.
    // =============================================================================================

    [Fact]
    public void AFirstStartCatchesUpTheRawRetentionAndVouchesForIt()
    {
        feed.Snapshot = (end, window) => Snapshot(end, window,
            [Failure(-30, "203.0.113.1"), Failure(-20, "203.0.113.1"), Failure(-10, "198.51.100.7")]);

        Session().Stop(Now);

        Assert.Equal(TimeSpan.FromDays(14), Assert.Single(feed.Windows));
        using var store = EvidenceStore.OpenReadOnly(StorePath);
        var queries = new EvidenceQueries(store);
        Assert.Equal(3, queries.Summary(Now.AddHours(-1), Now).Attempts);
        var collected = Assert.Single(queries.Coverage(Now.AddDays(-15), Now), c => c.Status == "collected");
        Assert.Equal(Now.AddDays(-14), collected.From);
        Assert.Equal(Now, collected.To);
    }

    [Fact]
    public void ARestartCatchesUpOnlySinceTheLastStoredRecord()
    {
        feed.Snapshot = (end, window) => Snapshot(end, window, [Failure(-600, "203.0.113.1")]);
        Session().Stop(Now);

        clock.Now = Now.AddMinutes(30);
        Session(clock.Now).Stop(clock.Now);

        Assert.Equal(TimeSpan.FromMinutes(40), feed.Windows[1]);
    }

    /// <summary>
    /// The documented first run: the Security log is denied while Remote Desktop's channel is not, so
    /// 140s are stored and that channel's state advances. Once the account is in Event Log Readers,
    /// the catch-up must still reach back for the 4625s - the Security channel defines "collected",
    /// so it is the anchor, not whichever channel stored something last.
    /// </summary>
    [Fact]
    public void ASecurityLogThatWasUnreadableIsCaughtUpInFullOnceReadable()
    {
        feed.SetupErrors.Add((AuthFailureFeed.SecurityChannel, "access-denied"));
        feed.Snapshot = (end, window) => new AuthFailureSnapshot(end - window, end,
            [Failure(-60, "203.0.113.80", channel: AttemptPairing.RdpChannel)],
            [
                new ChannelCoverage(AuthFailureFeed.SecurityChannel, "unavailable", "access-denied", null, null, 0),
                new ChannelCoverage(AuthFailureFeed.RdpCoreChannel, "read", null, null, null, 1)
            ]);
        Session().Stop(Now);

        feed.SetupErrors.Clear();
        feed.Snapshot = (end, window) => Snapshot(end, window, []);
        Session(Now.AddMinutes(30)).Stop(Now.AddMinutes(30));

        Assert.Equal(TimeSpan.FromDays(14), feed.Windows[1]);
    }

    [Fact]
    public void ReadingTheSameRecordsTwiceStoresThemOnce()
    {
        AuthFailure[] same = [Failure(-60, "203.0.113.1", id: 1), Failure(-50, "203.0.113.1", id: 2)];
        feed.Snapshot = (end, window) => Snapshot(end, window, same);
        Session().Stop(Now);
        Session().Stop(Now);

        using var store = EvidenceStore.OpenReadOnly(StorePath);
        Assert.Equal(2, new EvidenceQueries(store).Summary(Now.AddHours(-1), Now).Attempts);
    }

    /// <summary>
    /// A read stopped by its bound reached back only to the oldest record it read. Vouching from the
    /// start of the window would turn the unread part into a quiet one.
    /// </summary>
    [Fact]
    public void ALimitedCatchUpVouchesOnlyFromTheOldestRecordRead()
    {
        feed.Snapshot = (end, window) => new AuthFailureSnapshot(end - window, end, [Failure(-60, "203.0.113.1")],
        [
            new ChannelCoverage(AuthFailureFeed.SecurityChannel, "limited", null, Now.AddHours(-2), Now.AddDays(-30), 20_000),
            new ChannelCoverage(AuthFailureFeed.RdpCoreChannel, "read", null, null, null, 0)
        ]);

        Session().Stop(Now);

        var coverage = Coverage();
        Assert.Equal(Now.AddHours(-2), Assert.Single(coverage, c => c.Status == "collected").From);
        var limited = Assert.Single(coverage, c => c.Status == "limited");
        Assert.Equal("security-4625: read-bound", limited.Reason);
        Assert.Equal(Now.AddDays(-14), limited.From);
        Assert.Equal(Now.AddHours(-2), limited.To);
    }

    [Fact]
    public void ALogThatStartsAfterTheWindowIsRecordedAsUnavailableBeforeIt()
    {
        feed.Snapshot = (end, window) => new AuthFailureSnapshot(end - window, end, [],
        [
            new ChannelCoverage(AuthFailureFeed.SecurityChannel, "read", null, null, Now.AddDays(-6), 0),
            new ChannelCoverage(AuthFailureFeed.RdpCoreChannel, "read", null, null, null, 0)
        ]);

        Session().Stop(Now);

        var coverage = Coverage();
        Assert.Equal(Now.AddDays(-6), Assert.Single(coverage, c => c.Status == "collected").From);
        Assert.Equal("security-4625: log-starts-later", Assert.Single(coverage, c => c.Status == "unavailable").Reason);
    }

    /// <summary>
    /// The most likely first run after an install: Event Log Readers is a manual step. The period is
    /// unavailable - never collected, which would draw it as a quiet host - and the log says what to run.
    /// </summary>
    [Fact]
    public void AnUnreadableSecurityLogIsUnavailableNeverCollected()
    {
        feed.SetupErrors.Add((AuthFailureFeed.SecurityChannel, "access-denied"));
        feed.Snapshot = (end, window) => new AuthFailureSnapshot(end - window, end, [],
        [
            new ChannelCoverage(AuthFailureFeed.SecurityChannel, "unavailable", "access-denied", null, null, 0),
            new ChannelCoverage(AuthFailureFeed.RdpCoreChannel, "read", null, null, null, 0)
        ]);

        var session = Session();
        Assert.True(session.Tick(Now.AddMinutes(14)));
        Assert.False(session.Tick(Now.AddMinutes(15)), "An unreadable Security log is retried every 15 minutes.");
        session.Stop(Now.AddMinutes(15));

        var coverage = Coverage();
        Assert.DoesNotContain(coverage, c => c.Status == "collected");
        var unavailable = Assert.Single(coverage);
        Assert.Equal("unavailable", unavailable.Status);
        Assert.Equal("security-4625: access-denied", unavailable.Reason);
        Assert.Equal(Now.AddMinutes(15), unavailable.To);
        var warning = Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("S-1-5-32-573", warning.Message, StringComparison.Ordinal);
        Assert.Contains(@"Add-LocalGroupMember -SID S-1-5-32-573 -Member 'NT SERVICE\WPShield'", warning.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Found running the real gateway unelevated: Windows refuses the Security subscription as a
    /// generic query failure and the read as access denied. Keeping the first would hide the remedy
    /// in exactly the case it exists for.
    /// </summary>
    [Fact]
    public void TheMostSpecificReasonWinsWhenTheSubscriptionAndTheReadDisagree()
    {
        feed.SetupErrors.Add((AuthFailureFeed.SecurityChannel, "query-failed"));
        feed.Snapshot = (end, window) => new AuthFailureSnapshot(end - window, end, [],
        [
            new ChannelCoverage(AuthFailureFeed.SecurityChannel, "unavailable", "access-denied", null, null, 0),
            new ChannelCoverage(AuthFailureFeed.RdpCoreChannel, "read", null, null, null, 0)
        ]);

        Session().Stop(Now);

        Assert.Equal("security-4625: access-denied", Assert.Single(Coverage()).Reason);
        Assert.Contains("Add-LocalGroupMember", Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning).Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A misconfiguration left for weeks must not add a row every 15 minutes: a retry that fails for
    /// the same reason continues the interval, so a wide coverage query is not crowded out by them.
    /// </summary>
    [Fact]
    public void RetriesThatFailForTheSameReasonContinueOneInterval()
    {
        feed.SetupErrors.Add((AuthFailureFeed.SecurityChannel, "access-denied"));
        var collector = Collector();

        CollectorSession.Start(collector, Now).Stop(Now.AddMinutes(15));
        CollectorSession.Start(collector, Now.AddMinutes(15).AddSeconds(5)).Stop(Now.AddMinutes(30));

        var unavailable = Assert.Single(Coverage());
        Assert.Equal(Now, unavailable.From);
        Assert.Equal(Now.AddMinutes(30), unavailable.To);
    }

    [Fact]
    public void TheSameUnavailableReasonIsWarnedOnceAcrossRetries()
    {
        feed.SetupErrors.Add((AuthFailureFeed.SecurityChannel, "access-denied"));
        var collector = Collector();

        CollectorSession.Start(collector, Now).Stop(Now);
        CollectorSession.Start(collector, Now.AddMinutes(15)).Stop(Now.AddMinutes(15));

        Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
    }

    /// <summary>
    /// Without Remote Desktop's channel every attempt is still a 4625, so the period stays collected;
    /// what is lost is the address of an NLA attempt, and that is recorded beside it.
    /// </summary>
    [Fact]
    public void AMissingRemoteDesktopChannelLimitsThePeriodWithoutUncoveringIt()
    {
        feed.SetupErrors.Add((AuthFailureFeed.RdpCoreChannel, "channel-missing"));
        feed.Snapshot = (end, window) => new AuthFailureSnapshot(end - window, end, [],
        [
            new ChannelCoverage(AuthFailureFeed.SecurityChannel, "read", null, null, null, 0),
            new ChannelCoverage(AuthFailureFeed.RdpCoreChannel, "unavailable", "channel-missing", null, null, 0)
        ]);

        var session = Session();
        session.Tick(Now.AddMinutes(2));
        session.Stop(Now.AddMinutes(2));

        var coverage = Coverage();
        Assert.Equal(Now.AddMinutes(2), Assert.Single(coverage, c => c.Status == "collected").To);
        var limited = Assert.Single(coverage, c => c.Status == "limited");
        Assert.Equal("rdpcorets-140: channel-missing", limited.Reason);
        Assert.Equal(Now.AddMinutes(2), limited.To);
    }

    // =============================================================================================
    //  Live.
    // =============================================================================================

    [Fact]
    public void LiveRecordsAreWrittenOnALaterTick()
    {
        var session = Session();
        feed.Deliver(Failure(1, "203.0.113.9"));

        session.Tick(Now.AddSeconds(2));
        Assert.Equal(0, Attempts(Now.AddHours(1)));

        session.Tick(Now.AddSeconds(6));
        Assert.Equal(1, Attempts(Now.AddHours(1)));
        session.Stop(Now.AddSeconds(6));
    }

    /// <summary>
    /// A 4625 read by the catch-up and its 140 delivered live are one attempt. The boundary must not
    /// split the pair, and a record that arrives through both is stored once.
    /// </summary>
    [Fact]
    public void APairSplitAcrossTheCatchUpAndTheSubscriptionIsCountedOnce()
    {
        var nla = Failure(-1, null, type: 3);
        feed.Snapshot = (end, window) => Snapshot(end, window, [nla]);
        var session = Session();

        feed.Deliver(nla);
        feed.Deliver(Failure(-0.5, "203.0.113.20", channel: AttemptPairing.RdpChannel, type: 10));
        session.Stop(Now.AddSeconds(10));

        using var store = EvidenceStore.OpenReadOnly(StorePath);
        var summary = new EvidenceQueries(store).Summary(Now.AddHours(-1), Now.AddHours(1));
        Assert.Equal(1, summary.Attempts);
        Assert.Equal(0, summary.WithoutAddress);
    }

    [Fact]
    public void StoppingWritesWhatIsStillBuffered()
    {
        var session = Session();
        feed.Deliver(Failure(0, "203.0.113.30"));

        session.Stop(Now);

        Assert.Equal(1, Attempts(Now.AddHours(1)));
        Assert.True(feed.Disposed);
    }

    [Fact]
    public void TheCoverageIntervalIsExtendedEveryMinute()
    {
        var session = Session();

        session.Tick(Now.AddSeconds(30));
        Assert.Equal(Now, Assert.Single(Coverage(), c => c.Status == "collected").To);

        session.Tick(Now.AddSeconds(61));
        Assert.Equal(Now.AddSeconds(61), Assert.Single(Coverage(), c => c.Status == "collected").To);
        session.Stop(Now.AddSeconds(61));
    }

    /// <summary>
    /// A failed subscription ends the session: the next one catches up from the last stored record,
    /// which recovers what the subscription missed. The failure is one row, however often it fires.
    /// </summary>
    [Fact]
    public void ALiveChannelErrorEndsTheSessionAndIsRecordedOnce()
    {
        var session = Session();
        clock.Now = Now.AddMinutes(3);

        feed.Fail(AuthFailureFeed.SecurityChannel, "query-failed");
        feed.Fail(AuthFailureFeed.SecurityChannel, "query-failed");
        feed.Fail(AuthFailureFeed.RdpCoreChannel, "query-failed");

        Assert.False(session.Tick(Now.AddMinutes(4)));
        session.Stop(Now.AddMinutes(4));

        var coverage = Coverage();
        var failure = Assert.Single(coverage, c => c.Status == "unavailable");
        Assert.Equal("security-4625: query-failed", failure.Reason);
        Assert.Equal(Now.AddMinutes(3), failure.From);
        Assert.Equal(Now.AddMinutes(3), Assert.Single(coverage, c => c.Status == "collected").To);
    }

    [Fact]
    public void AFullBufferIsRecordedAsLimitedAndLogged()
    {
        var session = Session();
        // Spread out, and ahead of the clock so the tick holds them: pairing scans a two-second
        // window, and a hundred thousand records in one instant would make that scan quadratic.
        for (var index = 0; index <= PairingBuffer.MaxHeld; index++)
        {
            feed.Deliver(new AuthFailure(Now.AddMilliseconds(50.0 * index), AttemptPairing.SecurityChannel,
                IPAddress.Parse("203.0.113.40"), null, "x", "bad-password", 3, ++record));
        }

        session.Tick(Now);
        session.Abandon();

        var limited = Assert.Single(Coverage(), c => c.Status == "limited");
        Assert.Equal("buffer-full: 1 dropped", limited.Reason);
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("pairing buffer was full", StringComparison.Ordinal));
    }

    // =============================================================================================
    //  Retention.
    // =============================================================================================

    /// <summary>Retention is a NextUse setting: the hourly pass reads it again.</summary>
    [Fact]
    public void PruningRunsHourlyWithTheCurrentRetentionSetting()
    {
        var session = Session();
        using (var second = EvidenceStore.OpenForWriting(StorePath))
        {
            new EvidenceSettings(second).Set("retention.raw_days", "1", "test", "a shorter retention", Now);
            new EvidenceWriter(second).Append([Failure(-2 * 24 * 3600, "203.0.113.50")]);
        }

        session.Tick(Now.AddMinutes(30));
        Assert.Equal(1, Attempts(Now, from: Now.AddDays(-3)));
        Assert.DoesNotContain(logger.Entries, e => e.Message.StartsWith("Evidence pruned.", StringComparison.Ordinal));

        session.Tick(Now.AddMinutes(61));
        session.Stop(Now.AddMinutes(61));

        var pruned = Assert.Single(logger.Entries, e => e.Message.StartsWith("Evidence pruned.", StringComparison.Ordinal));
        Assert.Contains("RawRows=1 ", pruned.Message, StringComparison.Ordinal);
        using var store = EvidenceStore.OpenReadOnly(StorePath);
        Assert.False(new EvidenceQueries(store).Summary(Now.AddDays(-3), Now).Detailed,
            "The detailed rows of that period are gone; the aggregates answer and say so.");
    }

    // =============================================================================================
    //  The loop: never throws, never creates the directory.
    // =============================================================================================

    [Fact]
    public async Task AMissingDirectoryIsReportedAndNeverCreated()
    {
        var missing = Path.Combine(directory, "missing", EvidenceStore.FileName);
        var collector = new EvidenceCollector(missing, logger, TimeProvider.System, feed.Read, feed.Watch, Protection);

        var exit = await collector.RunAsync(CancellationToken.None);

        Assert.Equal(EvidenceCollectorExit.StoreMissing, exit);
        Assert.False(Directory.Exists(Path.GetDirectoryName(missing)));
        Assert.Empty(feed.Windows);
        Assert.Contains("wpshield install", Assert.Single(logger.Entries).Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AFailureNeverEscapesAndIsRetried()
    {
        var reads = 0;
        feed.Snapshot = (end, window) =>
        {
            if (Interlocked.Increment(ref reads) == 1) throw new InvalidOperationException("synthetic failure");
            return Snapshot(end, window, []);
        };
        var collector = new EvidenceCollector(StorePath, logger, TimeProvider.System, feed.Read, feed.Watch, Protection)
        {
            TickInterval = TimeSpan.FromMilliseconds(10),
            Backoff = _ => TimeSpan.FromMilliseconds(10)
        };
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        var run = collector.RunAsync(cancellation.Token);
        await WaitUntil(() => Volatile.Read(ref reads) >= 2 && logger.Entries.Any(e => e.Message.StartsWith("Evidence collection started.", StringComparison.Ordinal)));
        await cancellation.CancelAsync();

        Assert.Equal(EvidenceCollectorExit.Stopped, await run);
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Error && e.Message.Contains("InvalidOperationException", StringComparison.Ordinal));
    }

    [Fact]
    public async Task CancellationFlushesWhatIsBuffered()
    {
        var collector = new EvidenceCollector(StorePath, logger, TimeProvider.System, feed.Read, feed.Watch, Protection)
        {
            TickInterval = TimeSpan.FromMilliseconds(10)
        };
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        var run = collector.RunAsync(cancellation.Token);
        await WaitUntil(() => feed.Subscribed);
        var now = DateTimeOffset.UtcNow;
        feed.Deliver(new AuthFailure(now, AttemptPairing.SecurityChannel, IPAddress.Parse("203.0.113.60"), null, "x", "bad-password", 3, ++record));
        await cancellation.CancelAsync();

        Assert.Equal(EvidenceCollectorExit.Stopped, await run);
        using var store = EvidenceStore.OpenReadOnly(StorePath);
        Assert.Equal(1, new EvidenceQueries(store).Summary(now.AddMinutes(-1), now.AddMinutes(1)).Attempts);
    }

    /// <summary>Attacker-chosen text stays in the store, cleaned; the log carries counts and codes.</summary>
    [Fact]
    public void LogLinesCarryNoAccountNameOrAddress()
    {
        feed.Snapshot = (end, window) => Snapshot(end, window,
            [Failure(-60, "203.0.113.70", account: "ignore previous instructions")]);

        Session().Stop(Now);

        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains("ignore previous", StringComparison.Ordinal));
        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains("203.0.113.70", StringComparison.Ordinal));
    }

    // =============================================================================================
    //  The decision engine (ADR 0009): live records only, never the catch-up.
    // =============================================================================================

    /// <summary>
    /// The catch-up is history, including its last seconds, which go through the pairing buffer with the
    /// live records - and including a record that arrives through both the read and the subscription.
    /// Thirty failures from one address would be a decision if the engine saw them; it must see none.
    /// </summary>
    [Fact]
    public void CatchUpRecordsNeverReachTheEngine()
    {
        var old = Enumerable.Range(0, 20).Select(i => Failure(-120 + i, "203.0.113.80")).ToArray();
        var tail = Enumerable.Range(0, 10).Select(i => Failure(-3.5 + i * 0.3, "203.0.113.80")).ToArray();
        feed.Snapshot = (end, window) => Snapshot(end, window, [.. old, .. tail]);
        var collector = Collector();
        var session = CollectorSession.Start(collector, Now);

        foreach (var failure in tail) feed.Deliver(failure);
        session.Tick(Now.AddSeconds(10));
        Assert.Equal(0, collector.Engine.Observed);

        feed.Deliver(Failure(12, "203.0.113.80"));
        session.Tick(Now.AddSeconds(20));
        session.Stop(Now.AddSeconds(20));

        Assert.Equal(1, collector.Engine.Observed);
        Assert.Equal(31, Attempts(Now.AddHours(1)));
        Assert.Empty(Decisions());
    }

    [Fact]
    public void ARestartedSessionsCatchUpIsNeverFedEither()
    {
        var collector = Collector();
        CollectorSession.Start(collector, Now).Stop(Now);

        feed.Snapshot = (end, window) => Snapshot(end, window,
            [.. Enumerable.Range(0, 15).Select(i => Failure(60 + i, "203.0.113.81")), .. Enumerable.Range(0, 5).Select(i => Failure(118 + i * 0.3, "203.0.113.81"))]);
        var second = CollectorSession.Start(collector, Now.AddMinutes(2));
        second.Tick(Now.AddMinutes(2).AddSeconds(10));
        second.Stop(Now.AddMinutes(2).AddSeconds(10));

        Assert.Equal(0, collector.Engine.Observed);
        Assert.Empty(Decisions());
    }

    [Fact]
    public void LiveFailuresAboveTheThresholdAreRecordedAsWouldBlock()
    {
        var collector = Collector();
        var session = CollectorSession.Start(collector, Now);
        for (var i = 1; i <= 10; i++) feed.Deliver(Failure(i, "203.0.113.82"));

        session.Tick(Now.AddSeconds(20));

        var decision = Assert.Single(Decisions());
        Assert.Equal(DecisionActions.WouldBlock, decision.Action);
        Assert.Equal("203.0.113.82", decision.Target);
        Assert.Equal(DecisionRules.RepeatedFailures, decision.RuleId);
        Assert.Equal("monitor", decision.Mode);
        Assert.Equal(AttemptPairing.SecurityChannel, decision.RequestedBy);
        using (var store = EvidenceStore.OpenReadOnly(StorePath))
        {
            var active = new EvidenceQueries(store).ActiveDecisions(Now.AddSeconds(20));
            Assert.Equal(Now, active.EngineStarted);
            Assert.Equal("203.0.113.82", Assert.Single(active.Decisions).Target);
        }
        Assert.Contains(logger.Entries, e => e.Message.StartsWith("Decision engine started. Mode=monitor", StringComparison.Ordinal));
        Assert.Contains(logger.Entries, e => e.Message.Contains("WouldBlock=1", StringComparison.Ordinal));
        session.Stop(Now.AddSeconds(20));
    }

    /// <summary>Thresholds are NextUse settings: a change made while the service runs applies at the next evaluation.</summary>
    [Fact]
    public void ThresholdsAreReadAtEachEvaluation()
    {
        var session = Session();
        using (var operatorTool = EvidenceStore.OpenForWriting(StorePath))
            new EvidenceSettings(operatorTool).Set("defense.failures.count", "3", "test", "stricter", Now);

        for (var i = 1; i <= 3; i++) feed.Deliver(Failure(i, "203.0.113.83"));
        session.Tick(Now.AddSeconds(20));
        session.Stop(Now.AddSeconds(20));

        Assert.Contains("threshold 3 in 10 minutes", Assert.Single(Decisions()).Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ExpiryIsRecordedOnTheMinutesPass()
    {
        var session = Session();
        for (var i = 1; i <= 10; i++) feed.Deliver(Failure(i, "203.0.113.84"));
        session.Tick(Now.AddSeconds(20));

        session.Tick(Now.AddMinutes(60).AddSeconds(10));
        Assert.DoesNotContain(Decisions(), d => d.Action == DecisionActions.Expire);
        session.Tick(Now.AddMinutes(61).AddSeconds(30));
        session.Stop(Now.AddMinutes(61).AddSeconds(30));

        var expire = Assert.Single(Decisions(), d => d.Action == DecisionActions.Expire);
        Assert.Equal(Now.AddSeconds(20).AddMinutes(60), expire.Timestamp);
    }

    [Fact]
    public void StoppingTheProcessEndsEveryDecisionOnTheRecord()
    {
        var collector = Collector();
        var session = CollectorSession.Start(collector, Now);
        for (var i = 1; i <= 10; i++) feed.Deliver(Failure(i, "203.0.113.85"));
        session.Tick(Now.AddSeconds(20));

        session.Stop(Now.AddMinutes(5), final: true);

        var ended = Assert.Single(Decisions(), d => d.Action == DecisionActions.Expire);
        Assert.StartsWith("ended with the process", ended.Reason, StringComparison.Ordinal);
        Assert.Equal(0, collector.Engine.ActiveCount);
    }

    /// <summary>A restarted session is the same process: the decisions in force and the repeat memory survive it.</summary>
    [Fact]
    public void ASessionRestartKeepsTheEngine()
    {
        var collector = Collector();
        var first = CollectorSession.Start(collector, Now);
        for (var i = 1; i <= 10; i++) feed.Deliver(Failure(i, "203.0.113.86"));
        first.Tick(Now.AddSeconds(20));
        first.Stop(Now.AddSeconds(20));

        var second = CollectorSession.Start(collector, Now.AddSeconds(30));
        second.Stop(Now.AddSeconds(30));

        Assert.Equal(1, collector.Engine.ActiveCount);
        using var store = EvidenceStore.OpenReadOnly(StorePath);
        Assert.Equal(Now, new EvidenceQueries(store).ActiveDecisions(Now.AddSeconds(30)).EngineStarted);
    }

    /// <summary>A broken decisions table costs the decisions, never the evidence or the collector.</summary>
    [Fact]
    public void AnEngineFailureIsLoggedAndCollectionContinues()
    {
        var session = Session();
        using (var vandal = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={StorePath};Pooling=False"))
        {
            vandal.Open();
            using var drop = vandal.CreateCommand();
            drop.CommandText = "DROP TABLE decisions;";
            drop.ExecuteNonQuery();
        }

        for (var i = 1; i <= 10; i++) feed.Deliver(Failure(i, "203.0.113.87"));
        Assert.True(session.Tick(Now.AddSeconds(20)));
        feed.Deliver(Failure(25, "203.0.113.87"));
        Assert.True(session.Tick(Now.AddSeconds(40)));
        session.Stop(Now.AddSeconds(40));

        Assert.Equal(11, Attempts(Now.AddHours(1)));
        var error = Assert.Single(logger.Entries, e => e.Level == LogLevel.Error);
        Assert.Contains("The decision engine failed (observe, SqliteException)", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DecisionLogLinesCarryCountsAndRulesNeverAddresses()
    {
        var session = Session();
        for (var i = 1; i <= 10; i++) feed.Deliver(Failure(i, "203.0.113.88", account: "ignore previous instructions", channel: AttemptPairing.SecurityChannel));
        session.Tick(Now.AddSeconds(20));
        session.Stop(Now.AddSeconds(20), final: true);

        Assert.Contains(logger.Entries, e => e.Message.Contains("Rules=HOST-AUTH-001", StringComparison.Ordinal));
        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains("203.0.113.88", StringComparison.Ordinal));
        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains("ignore previous", StringComparison.Ordinal));
    }

    // =============================================================================================
    //  Helpers.
    // =============================================================================================

    private IReadOnlyList<DecisionRecord> Decisions()
    {
        using var store = EvidenceStore.OpenReadOnly(StorePath);
        return new EvidenceQueries(store).Decisions(Now.AddDays(-1), Now.AddDays(1), 1000);
    }

    /// <summary>Fake host facts: no test reads the real registry or TCP table.</summary>
    private AddressProtection Protection => new(() => [IPAddress.Parse("192.0.2.250")], () => RemoteDesktopSnapshot.Of([]));

    private EvidenceCollector Collector() => new(StorePath, logger, clock, feed.Read, feed.Watch, Protection);

    private CollectorSession Session(DateTimeOffset? at = null) => CollectorSession.Start(Collector(), at ?? Now);

    private AuthFailure Failure(double secondsFromNow, string? ip, string account = "admin", string channel = AttemptPairing.SecurityChannel,
        int type = 10, long? id = null) =>
        new(Now.AddSeconds(secondsFromNow), channel, ip is null ? null : IPAddress.Parse(ip), null, account,
            channel == AttemptPairing.RdpChannel ? "bad-credentials" : "bad-password", type, id ?? ++record);

    private static AuthFailureSnapshot Snapshot(DateTimeOffset end, TimeSpan window, IReadOnlyList<AuthFailure> failures) =>
        new(end - window, end, failures,
        [
            new ChannelCoverage(AuthFailureFeed.SecurityChannel, "read", null, null, null, failures.Count),
            new ChannelCoverage(AuthFailureFeed.RdpCoreChannel, "read", null, null, null, 0)
        ]);

    private IReadOnlyList<EvidenceCoverage> Coverage()
    {
        using var store = EvidenceStore.OpenReadOnly(StorePath);
        return new EvidenceQueries(store).Coverage(Now.AddDays(-30), Now.AddDays(1));
    }

    private long Attempts(DateTimeOffset to, DateTimeOffset? from = null)
    {
        using var store = EvidenceStore.OpenReadOnly(StorePath);
        return new EvidenceQueries(store).Summary(from ?? Now.AddHours(-1), to).Attempts;
    }

    private static async Task WaitUntil(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline) throw new TimeoutException("The condition was not reached.");
            await Task.Delay(10);
        }
    }

    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; }

        public override DateTimeOffset GetUtcNow() => Now;
    }

    /// <summary>The event log, faked: a configurable catch-up and a subscription the test drives.</summary>
    private sealed class Feed
    {
        private Action<AuthFailure>? onFailure;
        private Action<string, string>? onError;

        public Func<DateTimeOffset, TimeSpan, AuthFailureSnapshot> Snapshot { get; set; } = (end, window) => EvidenceCollectorTests.Snapshot(end, window, []);
        public List<(string Channel, string Reason)> SetupErrors { get; } = [];
        public List<TimeSpan> Windows { get; } = [];
        public bool Disposed { get; private set; }
        public bool Subscribed => Volatile.Read(ref onFailure) is not null;

        public AuthFailureSnapshot Read(DateTimeOffset end, TimeSpan window)
        {
            lock (Windows) Windows.Add(window);
            return Snapshot(end, window);
        }

        public IDisposable Watch(Action<AuthFailure> failure, Action<string, string> error)
        {
            foreach (var (channel, reason) in SetupErrors) error(channel, reason);
            onError = error;
            Volatile.Write(ref onFailure, failure);
            Disposed = false;
            return new Subscription(this);
        }

        public void Deliver(AuthFailure failure) => onFailure!(failure);

        public void Fail(string channel, string reason) => onError!(channel, reason);

        private sealed class Subscription(Feed owner) : IDisposable
        {
            public void Dispose() => owner.Disposed = true;
        }
    }

    private sealed class RecordingLogger : ILogger
    {
        private readonly ConcurrentQueue<(LogLevel Level, string Message)> entries = new();

        public IReadOnlyList<(LogLevel Level, string Message)> Entries => [.. entries.Where(e => e.Level >= LogLevel.Information)];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            entries.Enqueue((logLevel, formatter(state, exception)));
    }
}

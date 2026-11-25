using System.Globalization;
using System.Net;
using Microsoft.Extensions.Logging;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;

namespace WPShield.WebEvidence;

/// <summary>
/// Reads the IIS W3C log of every site as it is written and records what the request-path rules and the
/// sensor's observations find (ADR 0011). One per collector; a <see cref="WebLogSession"/> per open store.
/// </summary>
/// <remarks>
/// <para>
/// <b>Evidence, never a decision.</b> Nothing here reaches the decision engine: not the live lines and
/// not the catch-up. Web rules for the engine come from a week of this evidence, in an amendment to
/// ADR 0009.
/// </para>
/// <para>
/// <b>Which sites, read from IIS by the caller.</b> The site list and log folders come from a delegate
/// the CLI fills from the IIS configuration, read-only. They are read at start and every
/// <see cref="RefreshInterval"/>, so a site added later is picked up.
/// </para>
/// </remarks>
public sealed class WebLogSensor
{
    public const string LoggerCategory = "WPShield.Evidence.Web";

    /// <summary>How far back the catch-up at start reads: history only.</summary>
    public static readonly TimeSpan CatchUp = TimeSpan.FromMinutes(15);

    public static readonly TimeSpan RefreshInterval = TimeSpan.FromMinutes(15);

    /// <summary>How often the logs are read. HTTP.sys flushes its buffer about once a minute anyway.</summary>
    public static readonly TimeSpan ReadInterval = TimeSpan.FromSeconds(10);

    /// <summary>How often a site's folder is listed for a newer file.</summary>
    public static readonly TimeSpan ListInterval = TimeSpan.FromMinutes(1);

    public static readonly TimeSpan CoverageInterval = TimeSpan.FromMinutes(1);
    public static readonly TimeSpan ReportInterval = TimeSpan.FromMinutes(5);

    public const int MaxLinesPerSitePerTick = 50_000;

    /// <summary>The most a catch-up reads from the end of a file it has no position in.</summary>
    public const long CatchUpTailBytes = 32L * 1024 * 1024;

    /// <summary>Addresses counted per hour in memory; past this, an address's counts are not kept and the period is limited.</summary>
    public const int MaxTrackedSources = 200_000;

    /// <summary>Finding rows kept per address, site and hour; past this they are counted, not stored.</summary>
    public const int MaxFindingRowsPerSourceHour = 200;

    public const string ServiceAccount = @"NT SERVICE\WPShield";

    public WebLogSensor(Func<IisLogConfiguration> sites, Func<IReadOnlyCollection<IPAddress>?> ownAddresses, ILogger logger)
    {
        Sites = sites ?? throw new ArgumentNullException(nameof(sites));
        OwnAddresses = ownAddresses ?? throw new ArgumentNullException(nameof(ownAddresses));
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    internal Func<IisLogConfiguration> Sites { get; }
    internal Func<IReadOnlyCollection<IPAddress>?> OwnAddresses { get; }
    internal ILogger Logger { get; }
    internal WebRequestEvaluator Evaluator { get; } = new();

    /// <summary>The (site, reason) pairs already logged, so a lasting problem is reported once per process.</summary>
    internal HashSet<(long Site, string Reason)> Reported { get; } = [];

    /// <summary>Starts reading into a store the caller opened for writing and keeps open.</summary>
    public WebLogSession Start(EvidenceStore store, DateTimeOffset now) => new(this, store, now);

    /// <summary>The manual grant that lets the service read IIS logs, by its own SID name, which Windows does not translate.</summary>
    public static string ReadAccessRemedy(string directory) =>
        $"From an elevated prompt: icacls \"{directory}\" /grant \"{ServiceAccount}:(OI)(CI)RX\" - then restart the service. " +
        "A server setting, so WPShield does not make it.";
}

/// <summary>One run of the sensor against one open store. Only the collector's loop calls it.</summary>
public sealed class WebLogSession
{
    private const string Collected = "collected";
    private const string Unavailable = "unavailable";
    private const string Limited = "limited";
    private const string Ignored = "ignored";

    private readonly WebLogSensor owner;
    private readonly EvidenceWriter coverage;
    private readonly WebEvidenceWriter writer;
    private readonly EvidenceSettings settings;
    private readonly Dictionary<long, Tail> tails = [];
    private readonly Dictionary<(long Hour, long Site, string Address), SourceCounts> sources = [];
    private readonly DateTimeOffset started;
    private (long Id, string Status, string? Reason)? sensorInterval;
    private IReadOnlySet<string> proxiedSites = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private IReadOnlyCollection<IPAddress>? ownAddresses;
    private DateTimeOffset lastRead;
    private DateTimeOffset lastRefresh;
    private DateTimeOffset lastCoverage;
    private DateTimeOffset lastReport;
    private bool sitesChanged;
    private long untracked;
    private long reportedUntracked;
    private Counts window;

    internal WebLogSession(WebLogSensor owner, EvidenceStore store, DateTimeOffset now)
    {
        this.owner = owner;
        coverage = new EvidenceWriter(store);
        writer = new WebEvidenceWriter(store);
        settings = new EvidenceSettings(store);
        started = now;
        lastCoverage = lastReport = now;
        Refresh(now);
        lastRead = now - WebLogSensor.ReadInterval;
        Read(now);
        var readable = tails.Values.Count(t => t.Status == Collected);
        owner.Logger.LogInformation(
            "Web evidence started (ADR 0011, evidence only - nothing is decided from it). Sites={Sites} Read={Read} NotRead={NotRead} " +
            "CatchUpMinutes={CatchUpMinutes} Sensor={Sensor}",
            tails.Count, readable, tails.Count - readable, (int)WebLogSensor.CatchUp.TotalMinutes,
            sensorInterval is { } s ? s.Reason is null ? s.Status : $"{s.Status}:{s.Reason}" : "not-started");
    }

    /// <summary>The sites the sensor reads, with their state. For tests and the startup line.</summary>
    internal IReadOnlyCollection<(long Site, string Status, string? Reason)> SiteStates =>
        tails.Values.Select(t => (t.Site.Id, t.Status, t.Reason)).ToArray();

    /// <summary>One pass of the collector loop: reads the logs when due, refreshes the site list, extends coverage.</summary>
    public void Tick(DateTimeOffset now)
    {
        if (now - lastRefresh >= WebLogSensor.RefreshInterval) Refresh(now);
        if (now - lastRead >= WebLogSensor.ReadInterval) Read(now);
        if (now - lastCoverage >= WebLogSensor.CoverageInterval) Extend(now);
        if (now - lastReport >= WebLogSensor.ReportInterval) Report(now);
    }

    /// <summary>Reads once more and closes the coverage intervals at <paramref name="now"/>.</summary>
    public void Stop(DateTimeOffset now)
    {
        Read(now);
        Extend(now);
        Report(now);
    }

    // =============================================================================================
    //  The site list
    // =============================================================================================

    private void Refresh(DateTimeOffset now)
    {
        lastRefresh = now;
        IisLogConfiguration configuration;
        try
        {
            configuration = owner.Sites() ?? IisLogConfiguration.Unreadable("no-answer");
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            configuration = IisLogConfiguration.Unreadable(exception.GetType().Name);
        }

        try
        {
            ownAddresses = owner.OwnAddresses()?.Select(AddressRanges.Canonical).ToArray();
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            ownAddresses = null;
        }

        proxiedSites = WebSettings.Read(settings);

        if (configuration.Problem is not null || configuration.CentralLogging is not null)
        {
            var reason = configuration.Problem is not null ? "iis-configuration-unreadable" : "central-logging-mode";
            SetSensor(now, Unavailable, reason);
            Report(-1, reason, configuration.Problem is not null
                ? "Run WPShield elevated on the IIS host; the IIS configuration is read, never written."
                : "Central logging writes one file for every site, which this version does not read. Per-site logging is the IIS default.");
            foreach (var tail in tails.Values) Close(tail, now);
            tails.Clear();
            sitesChanged = false;
            // The site list is unknown now, not empty: every site known before is marked not read, for this reason.
            writer.MarkAllSites(Unavailable, reason, now);
            return;
        }

        SetSensor(now, Collected, null);
        var current = new HashSet<long>();
        foreach (var site in configuration.Sites)
        {
            current.Add(site.Id);
            if (!tails.TryGetValue(site.Id, out var tail))
            {
                tail = new Tail(site) { CatchUpCutoff = now - WebLogSensor.CatchUp };
                tails[site.Id] = tail;
                sitesChanged = true;
            }
            else if (!string.Equals(tail.Site.Folder, site.Folder, StringComparison.OrdinalIgnoreCase))
            {
                // The site's log moved: start over in the new folder, as history first.
                Close(tail, now);
                tail = new Tail(site) { CatchUpCutoff = now - WebLogSensor.CatchUp };
                tails[site.Id] = tail;
                sitesChanged = true;
            }
            else
            {
                tail.Site = site;
            }

            var proxied = proxiedSites.Contains(site.Name);
            if (proxied != tail.Proxied) sitesChanged = true;
            tail.Proxied = proxied;

            string? problem = !site.ServesHttp ? "no-http-binding"
                : !site.LoggingEnabled ? "logging-disabled"
                : !string.Equals(site.LogFormat, "W3C", StringComparison.OrdinalIgnoreCase) ? "log-format-not-w3c"
                : site.Folder is null ? "no-log-directory"
                : null;
            if (problem is "no-http-binding")
                SetSite(tail, now, Ignored, problem, null);
            else if (problem is not null)
                SetSite(tail, now, Unavailable, problem, problem switch
                {
                    "logging-disabled" => "Enable logging for this site in IIS Manager (Logging). By hand.",
                    "log-format-not-w3c" => "Set this site's log format to W3C in IIS Manager (Logging). By hand.",
                    _ => "Set a log directory for this site in IIS Manager (Logging). By hand."
                });
            else if (tail.Status is Ignored or Unavailable && tail.Reason is "no-http-binding" or "logging-disabled" or "log-format-not-w3c" or "no-log-directory")
                tail.Status = "pending";
        }

        foreach (var id in tails.Keys.Where(id => !current.Contains(id)).ToArray())
        {
            Close(tails[id], now);
            tails.Remove(id);
            sitesChanged = true;
        }

        ReportFoldersWithoutSite(configuration, now);
        RecordSites(now);
    }

    /// <summary>A <c>W3SVC</c> folder no site in the configuration owns is ignored, and said so once.</summary>
    private void ReportFoldersWithoutSite(IisLogConfiguration configuration, DateTimeOffset now)
    {
        var roots = configuration.Sites.Select(s => s.LogDirectory).Where(d => !string.IsNullOrWhiteSpace(d))
            .Distinct(StringComparer.OrdinalIgnoreCase).Take(16);
        var known = configuration.Sites.Select(s => "W3SVC" + s.Id.ToString(CultureInfo.InvariantCulture)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var orphans = new List<string>();
        foreach (var root in roots)
        {
            try
            {
                if (!Directory.Exists(root)) continue;
                foreach (var folder in Directory.EnumerateDirectories(root!, "W3SVC*").Take(10_000))
                {
                    var name = Path.GetFileName(folder);
                    if (!known.Contains(name)) orphans.Add(name);
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }
        if (orphans.Count == 0) return;
        var reason = "folders-without-site: " + string.Join(',', orphans.Order(StringComparer.OrdinalIgnoreCase).Take(20)) +
            (orphans.Count > 20 ? $" and {orphans.Count - 20} more" : "");
        if (!owner.Reported.Add((-2, reason))) return;
        coverage.BeginCoverage(WebEvidenceWriter.SensorSource, now, now, Ignored, reason);
        owner.Logger.LogInformation(
            "IIS log folders that no site in the IIS configuration owns are ignored ({Count}): a site that was removed, or one renumbered.",
            orphans.Count);
    }

    // =============================================================================================
    //  Reading
    // =============================================================================================

    private void Read(DateTimeOffset now)
    {
        lastRead = now;
        if (tails.Count == 0) return;
        var batch = new Batch();
        var options = DefenseOptions.Read(settings);
        var hourNow = EvidenceStore_Hour(now);
        foreach (var key in sources.Keys.Where(k => k.Hour < hourNow - 1).ToArray()) sources.Remove(key);

        foreach (var tail in tails.Values)
        {
            if (tail.Status is Ignored || (tail.Status is Unavailable && tail.Reason is "logging-disabled" or "log-format-not-w3c" or "no-log-directory"))
                continue;
            ReadSite(tail, now, batch, options);
        }

        var sourceCounts = new List<WebSourceCounts>();
        foreach (var key in batch.TouchedSources)
        {
            var counts = sources[key];
            if (!counts.Qualifies) continue;
            var delta = counts.Pending();
            if (delta is null) continue;
            sourceCounts.Add(new WebSourceCounts(key.Site, Hour(key.Hour), key.Address, delta.Requests, delta.ClientErrors, delta.Findings,
                delta.Observations, delta.LoginPosts, delta.XmlrpcPosts, counts.First, counts.Last, counts.Protection));
        }

        var siteCounts = batch.Sites.Select(pair => new WebSiteCounts(pair.Key.Site, Hour(pair.Key.Hour), pair.Value.Requests,
            pair.Value.ClientErrors, pair.Value.ServerErrors, pair.Value.Findings, pair.Value.Observations, pair.Value.LoginPosts,
            pair.Value.XmlrpcPosts, pair.Value.BytesReceived)).ToArray();

        // Positions are written in the same transaction as what was read up to them, and applied to the
        // tails only once written: a failure here re-reads the same lines next time, never skips them.
        writer.Write(new WebBatch(batch.Findings, siteCounts, sourceCounts, [.. batch.Extra, .. batch.Positions.Select(p => p.Position)]));
        foreach (var (tail, position, resync) in batch.Positions)
        {
            tail.Offset = position.Offset;
            tail.Resync = resync;
            tail.LastLine = position.LastLine;
        }
        foreach (var key in batch.TouchedSources) if (sources[key].Qualifies) sources[key].MarkWritten();

        if (untracked > reportedUntracked)
        {
            coverage.BeginCoverage(WebEvidenceWriter.SensorSource, now, now, Limited, $"address-bound: {untracked - reportedUntracked} not counted");
            owner.Logger.LogWarning(
                "More than {Bound} addresses in one hour: {Count} requests were counted per site but not per address. The period is stored as limited.",
                WebLogSensor.MaxTrackedSources, untracked - reportedUntracked);
            reportedUntracked = untracked;
        }
        if (sitesChanged) RecordSites(now);
    }

    private void ReadSite(Tail tail, DateTimeOffset now, Batch batch, DefenseOptions options)
    {
        var folder = tail.Site.Folder!;
        if (tail.File is null || now >= tail.NextList)
        {
            tail.NextList = now + WebLogSensor.ListInterval;
            string? newest;
            try
            {
                if (!Directory.Exists(folder))
                {
                    SetSite(tail, now, Unavailable, "no-log-folder",
                        "IIS creates the folder at the site's first logged request. If this site serves traffic, check its logging in IIS Manager.");
                    return;
                }
                newest = Newest(folder);
            }
            catch (UnauthorizedAccessException)
            {
                SetSite(tail, now, Unavailable, "access-denied", WebLogSensor.ReadAccessRemedy(tail.Site.LogDirectory!));
                return;
            }
            catch (IOException exception)
            {
                SetSite(tail, now, Unavailable, "io-error: " + exception.GetType().Name, null);
                return;
            }

            if (newest is null)
            {
                SetSite(tail, now, Unavailable, "no-log-file", "IIS writes the file at the site's next logged request.");
                return;
            }

            if (tail.File is null) Open(tail, newest, now);
            else if (!string.Equals(tail.File, newest, StringComparison.OrdinalIgnoreCase)) tail.Next = newest;
        }

        var budget = WebLogSensor.MaxLinesPerSitePerTick;
        for (var file = 0; file < 2 && budget > 0 && tail.File is not null; file++)
        {
            var path = Path.Combine(folder, tail.File);
            var offset = batch.PositionOf(tail)?.Position.Offset ?? tail.Offset;
            var resync = batch.PositionOf(tail) is { } pending ? pending.Resync : tail.Resync;
            LogReadResult result;
            try
            {
                // The length from an open handle: the directory entry of a file IIS holds open can lag behind it,
                // and a stale, smaller length would look like a file that shrank.
                var length = Length(path);
                if (length < offset)
                {
                    // Shrunk or replaced under the same name: read it again from the start, and say so.
                    owner.Logger.LogWarning(
                        "The IIS log file of site {SiteId} shrank or was replaced; it is read again from its beginning.", tail.Site.Id);
                    coverage.BeginCoverage(WebEvidenceWriter.SiteSource(tail.Site.Id), now, now, Limited, "file-restarted");
                    offset = 0;
                    resync = false;
                    tail.Map = null;
                    tail.MapProblem = null;
                }
                if (tail.Map is null && offset > 0) tail.Map = Directive(path);
                var read = new LineSink(this, tail, batch, options);
                result = LogFileReader.Read(path, offset, budget, read.OnLine, resync);
                budget -= result.Lines;
                batch.Malformed += read.Malformed;
                batch.LongLines += result.LongLinesSkipped;
                window.LongLines += result.LongLinesSkipped;
                window.Malformed += read.Malformed;
                batch.SetPosition(tail, new WebLogPosition(tail.Site.Id, tail.File, result.Offset, read.LastLine ?? tail.LastLine),
                    result.InsideDiscardedLine);
                if (tail.Map is null && (tail.MapProblem is not null || read.Unmapped > 0))
                {
                    SetSite(tail, now, Unavailable, tail.MapProblem ?? "no-fields-directive", tail.MapProblem is null
                        ? "The file has no #Fields directive near its start; IIS writes one at the top of every W3C file."
                        : "Select this field for the site in IIS Manager (Logging, Select Fields). By hand.");
                    return;
                }
            }
            catch (FileNotFoundException)
            {
                // Rotated and removed between listing and opening: take the newest next time.
                tail.File = null;
                return;
            }
            catch (UnauthorizedAccessException)
            {
                SetSite(tail, now, Unavailable, "access-denied", WebLogSensor.ReadAccessRemedy(tail.Site.LogDirectory!));
                return;
            }
            catch (IOException exception)
            {
                SetSite(tail, now, Unavailable, "io-error: " + exception.GetType().Name, null);
                return;
            }

            if (tail.Status != Collected) BeginCollected(tail, now);
            if (!result.AtEnd) break;
            if (tail.CatchingUp) tail.CatchingUp = false;
            if (tail.Next is null) break;

            // The day rolled over: the old file is finished, the new one is read from its start, live.
            var next = tail.Next;
            tail.Next = null;
            batch.Advance(tail, next);
            tail.File = next;
            tail.Map = null;
            tail.MapProblem = null;
        }
    }

    /// <summary>Opens a site's newest file at start or after a rotation: from its stored position, or its last minutes.</summary>
    private void Open(Tail tail, string file, DateTimeOffset now)
    {
        tail.File = file;
        tail.Map = null;
        long length;
        try
        {
            length = Length(Path.Combine(tail.Site.Folder!, file));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            length = 0;
        }

        tail.CatchingUp = true;
        tail.CatchUpCutoff = now - WebLogSensor.CatchUp;
        var path = Path.Combine(tail.Site.Folder!, file);
        var stored = writer.Position(tail.Site.Id, file);
        // Where the catch-up window starts in this file, found by the lines' own times. Lines are written
        // in time order, so a binary search over byte offsets finds it in a few reads, whatever the size.
        var windowStart = length > SearchThreshold ? WindowStart(path, tail.CatchUpCutoff, length) : 0;
        if (stored is not null && stored.Offset <= length && (windowStart is null || stored.Offset >= windowStart))
        {
            // Resume where the last run stopped; the time cut drops anything older than the window.
            tail.Offset = stored.Offset;
            tail.Resync = false;
            tail.Jumped = false;
        }
        else if (windowStart is { } start)
        {
            tail.Offset = start;
            tail.Resync = start > 0;
            tail.Jumped = false;
        }
        else
        {
            // The times could not be read: start near the end, inside a line, and say so if that cut into the window.
            var tailStart = Math.Max(0, length - WebLogSensor.CatchUpTailBytes);
            tail.Offset = tailStart;
            tail.Resync = tailStart > 0;
            tail.Jumped = tailStart > (stored?.Offset ?? 0);
        }
    }

    /// <summary>Below this size a file is simply read from its start; the time cut does the rest.</summary>
    internal const long SearchThreshold = 256 * 1024;

    /// <summary>
    /// A byte offset at or before the first line written at or after <paramref name="cutoff"/>, found by
    /// binary search on the lines' times. <see langword="null"/> when the file's fields cannot be read.
    /// </summary>
    internal static long? WindowStart(string path, DateTimeOffset cutoff, long length)
    {
        var map = Directive(path);
        if (map is null) return null;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, bufferSize: 1);
            var buffer = new byte[2 * LogFileReader.MaxLineBytes + 2];
            long low = 0, high = Math.Min(length, stream.Length);
            for (var probe = 0; probe < 64 && high - low > 64 * 1024; probe++)
            {
                var middle = low + (high - low) / 2;
                var time = FirstTimeAfter(stream, middle, buffer, map);
                if (time is { } t && t < cutoff) low = middle;
                else high = middle;
            }
            return low;
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>The time of the first whole, readable line after <paramref name="offset"/>, or null.</summary>
    private static DateTimeOffset? FirstTimeAfter(FileStream stream, long offset, byte[] buffer, W3cFieldMap map)
    {
        stream.Seek(offset, SeekOrigin.Begin);
        var read = 0;
        int count;
        while (read < buffer.Length && (count = stream.Read(buffer, read, buffer.Length - read)) > 0) read += count;
        var span = buffer.AsSpan(0, read);
        var newline = span.IndexOf((byte)'\n');
        if (newline < 0) return null;
        span = span[(newline + 1)..];
        while ((newline = span.IndexOf((byte)'\n')) >= 0)
        {
            if (W3cLineParser.TryParse(span[..newline], map, out var request) == W3cLineProblem.None) return request!.Timestamp;
            span = span[(newline + 1)..];
        }
        return null;
    }

    private void BeginCollected(Tail tail, DateTimeOffset now)
    {
        // A site read before in this session resumes where it stopped, but nothing vouches for the time in
        // between: it starts again now. The first time, the catch-up vouches for its window.
        var from = tail.EverCollected ? now : tail.CatchUpCutoff;
        tail.EverCollected = true;
        if (from < now && tail.Jumped && tail.FirstLine is { } first && first > from + TimeSpan.FromMinutes(1))
        {
            // The catch-up started past bytes it did not read, and the first line it read is later than the
            // window: the time in between was not read.
            coverage.BeginCoverage(WebEvidenceWriter.SiteSource(tail.Site.Id), from, first, Limited, "catch-up-bound");
            from = first;
        }
        if (from > now) from = now;
        SetSite(tail, now, Collected, null, null, from);
    }

    /// <summary>A file's length as its own handle reports it, opened for reading with the sharing IIS needs.</summary>
    private static long Length(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, bufferSize: 1);
        return stream.Length;
    }

    private static string? Newest(string folder)
    {
        string? best = null;
        var bestTime = DateTime.MinValue;
        // The enumeration carries each file's times, so listing a folder of a year of logs costs one pass.
        foreach (var info in new DirectoryInfo(folder).EnumerateFiles("*.log").Take(100_000))
        {
            var name = info.Name;
            if (!name.StartsWith("u_ex", StringComparison.OrdinalIgnoreCase) && !name.StartsWith("ex", StringComparison.OrdinalIgnoreCase)) continue;
            var time = info.LastWriteTimeUtc;
            if (best is null || time > bestTime || (time == bestTime && string.Compare(name, best, StringComparison.OrdinalIgnoreCase) > 0))
            {
                best = name;
                bestTime = time;
            }
        }
        return best;
    }

    /// <summary>The first <c>#Fields:</c> directive near a file's start, for a read that resumes mid-file.</summary>
    private static W3cFieldMap? Directive(string path)
    {
        W3cFieldMap? map = null;
        LogFileReader.Read(path, 0, 64, line =>
        {
            if (map is null && W3cFieldMap.IsFieldsDirective(line)) map = W3cFieldMap.Parse(line, out _);
        });
        return map;
    }

    // =============================================================================================
    //  One line
    // =============================================================================================

    private sealed class LineSink(WebLogSession session, Tail tail, Batch batch, DefenseOptions options)
    {
        public int Malformed { get; private set; }
        public int Unmapped { get; private set; }
        public DateTimeOffset? LastLine { get; private set; }

        public void OnLine(ReadOnlySpan<byte> line)
        {
            if (W3cFieldMap.IsFieldsDirective(line))
            {
                tail.Map = W3cFieldMap.Parse(line, out var problem);
                tail.MapProblem = tail.Map is null ? problem : null;
                return;
            }
            if (tail.Map is null)
            {
                if (line.IsEmpty || line[0] != (byte)'#') Unmapped++;
                return;
            }
            switch (W3cLineParser.TryParse(line, tail.Map, out var request))
            {
                case W3cLineProblem.Comment:
                    return;
                case W3cLineProblem.Malformed:
                    Malformed++;
                    return;
            }
            tail.FirstLine ??= request!.Timestamp;
            LastLine = request!.Timestamp;
            // The catch-up keeps the last minutes only, and keeps them as history.
            if (tail.CatchingUp && request.Timestamp < tail.CatchUpCutoff) return;
            session.Record(tail, request, batch, options, live: !tail.CatchingUp);
        }
    }

    private void Record(Tail tail, W3cRequest request, Batch batch, DefenseOptions options, bool live)
    {
        var evaluation = owner.Evaluator.Evaluate(tail.Site.Id, request);
        var hour = EvidenceStore_Hour(request.Timestamp);
        var site = batch.Site(tail.Site.Id, hour);
        site.Requests++;
        if (request.Status is >= 400 and < 500) site.ClientErrors++;
        else if (request.Status >= 500) site.ServerErrors++;
        if (evaluation.Rules.Count > 0) site.Findings++;
        if (evaluation.PhpOutsideEntryPoints) site.Observations++;
        if (evaluation.LoginPost) site.LoginPosts++;
        if (evaluation.XmlrpcPost) site.XmlrpcPosts++;
        site.BytesReceived += request.BytesReceived ?? 0;
        window.Requests++;
        if (evaluation.Rules.Count > 0) window.Findings++;
        if (evaluation.PhpOutsideEntryPoints) window.Observations++;
        if (evaluation.LoginPost) window.LoginPosts++;
        if (evaluation.XmlrpcPost) window.XmlrpcPosts++;

        var address = request.Address.ToString();
        var protection = batch.Protection(request.Address, () => Protect(request.Address, options));
        var key = (hour, tail.Site.Id, address);
        if (!sources.TryGetValue(key, out var counts))
        {
            if (sources.Count >= WebLogSensor.MaxTrackedSources)
            {
                untracked++;
                counts = null;
            }
            else
            {
                counts = new SourceCounts(request.Timestamp, protection ?? (tail.Proxied ? "behind a proxy (http.proxied_sites)" : null));
                sources[key] = counts;
            }
        }
        if (counts is not null)
        {
            counts.Add(request, evaluation);
            batch.TouchedSources.Add(key);
        }

        if (!evaluation.Stored) return;
        if (counts is not null && counts.StoredRows >= WebLogSensor.MaxFindingRowsPerSourceHour) return;
        if (counts is not null) counts.StoredRows++;
        batch.Findings.Add(new WebFinding(request.Timestamp, tail.Site.Id, address, request.Method, evaluation.Path, request.Status,
            evaluation.Hits, request.UserAgent, live, tail.Proxied, protection));
    }

    /// <summary>
    /// Why the evidence never counts against an address (ADR 0011, section 5, the protections of ADR 0009,
    /// section 4): the allow-list, loopback and link-local, a private range, this host.
    /// </summary>
    private string? Protect(IPAddress address, DefenseOptions options)
    {
        var single = AddressRanges.Single(address);
        foreach (var allowed in options.Allow)
            if (AddressRanges.Overlaps(allowed, single)) return "on the allow-list";
        if (AddressRanges.SpecialKind(single) is { } kind) return kind;
        if (!options.IncludePrivate && AddressRanges.PrivateRangeOf(single) is not null) return "a private range";
        if (ownAddresses is not null && ownAddresses.Contains(AddressRanges.Canonical(address))) return "an address of this host";
        return null;
    }

    // =============================================================================================
    //  Coverage and state
    // =============================================================================================

    private void SetSensor(DateTimeOffset now, string status, string? reason)
    {
        if (sensorInterval is { } current && current.Status == status && current.Reason == reason) return;
        if (sensorInterval is { } previous) coverage.ExtendCoverage(previous.Id, now);
        var from = status == Collected && sensorInterval is null ? started - WebLogSensor.CatchUp : now;
        sensorInterval = (coverage.BeginCoverage(WebEvidenceWriter.SensorSource, from, now, status, reason), status, reason);
    }

    private void SetSite(Tail tail, DateTimeOffset now, string status, string? reason, string? remedy, DateTimeOffset? from = null)
    {
        if (tail.Status == status && tail.Reason == reason && tail.Interval is not null) return;
        if (tail.Interval is { } open) coverage.ExtendCoverage(open, now);
        tail.Interval = coverage.BeginCoverage(WebEvidenceWriter.SiteSource(tail.Site.Id), from ?? now, now, status, reason);
        tail.Status = status;
        tail.Reason = reason;
        tail.Remedy = remedy;
        sitesChanged = true;
        if (status is Unavailable && reason is not null) Report(tail.Site.Id, reason, remedy);
    }

    private void Close(Tail tail, DateTimeOffset now)
    {
        if (tail.Interval is { } open) coverage.ExtendCoverage(open, now);
        tail.Interval = null;
    }

    private void Extend(DateTimeOffset now)
    {
        lastCoverage = now;
        if (sensorInterval is { } sensor) coverage.ExtendCoverage(sensor.Id, now);
        foreach (var tail in tails.Values)
            if (tail.Interval is { } open) coverage.ExtendCoverage(open, now);
    }

    private void RecordSites(DateTimeOffset now)
    {
        sitesChanged = false;
        writer.RecordSites(tails.Values.Select(t => new WebSiteState(t.Site.Id, t.Site.Name, t.Status == "pending" ? Unavailable : t.Status,
            t.Status == "pending" ? "not-read-yet" : t.Reason, t.Remedy, t.Proxied, now)).ToArray(), now);
    }

    /// <summary>A problem, once per site and reason per process. Site IDs and reason codes only.</summary>
    private void Report(long site, string reason, string? remedy)
    {
        if (!owner.Reported.Add((site, reason))) return;
        if (site < 0)
            owner.Logger.LogWarning("IIS logs are not read ({Reason}). {Remedy}", reason, remedy ?? "");
        else
            owner.Logger.LogWarning("The IIS log of site {SiteId} is not read ({Reason}). {Remedy}", site, reason, remedy ?? "");
    }

    private void Report(DateTimeOffset now)
    {
        lastReport = now;
        var counts = window;
        window = default;
        if (counts.Requests == 0 && counts.Malformed == 0 && counts.LongLines == 0) return;
        // Counts only: paths, user agents and addresses are attacker-chosen and stay in the store.
        owner.Logger.LogInformation(
            "Web evidence recorded (evidence only - nothing is decided from it). Requests={Requests} Findings={Findings} " +
            "Observations={Observations} LoginPosts={LoginPosts} XmlrpcPosts={XmlrpcPosts} Malformed={Malformed} LongLinesSkipped={LongLines}",
            counts.Requests, counts.Findings, counts.Observations, counts.LoginPosts, counts.XmlrpcPosts, counts.Malformed, counts.LongLines);
    }

    private static long EvidenceStore_Hour(DateTimeOffset time) => time.ToUnixTimeMilliseconds() / 3_600_000;

    private static DateTimeOffset Hour(long hour) => DateTimeOffset.FromUnixTimeMilliseconds(hour * 3_600_000);

    // =============================================================================================
    //  State
    // =============================================================================================

    private struct Counts
    {
        public long Requests, Findings, Observations, LoginPosts, XmlrpcPosts, Malformed, LongLines;
    }

    private sealed class Tail(IisLogSite site)
    {
        public IisLogSite Site { get; set; } = site;
        public string? File { get; set; }
        public string? Next { get; set; }
        public long Offset { get; set; }
        public bool Resync { get; set; }
        public W3cFieldMap? Map { get; set; }
        public string? MapProblem { get; set; }
        public bool EverCollected { get; set; }
        public bool CatchingUp { get; set; } = true;
        public DateTimeOffset CatchUpCutoff { get; set; }
        public bool Jumped { get; set; }
        public DateTimeOffset? FirstLine { get; set; }
        public DateTimeOffset LastLine { get; set; }
        public DateTimeOffset NextList { get; set; }
        public string Status { get; set; } = "pending";
        public string? Reason { get; set; }
        public string? Remedy { get; set; }
        public long? Interval { get; set; }
        public bool Proxied { get; set; }
    }

    private sealed class SiteCounts
    {
        public long Requests, ClientErrors, ServerErrors, Findings, Observations, LoginPosts, XmlrpcPosts, BytesReceived;
    }

    private sealed record Delta(long Requests, long ClientErrors, long Findings, long Observations, long LoginPosts, long XmlrpcPosts);

    /// <summary>One address's counts for one site and hour, and how much of them is already stored.</summary>
    private sealed class SourceCounts(DateTimeOffset first, string? protection)
    {
        private Delta written = new(0, 0, 0, 0, 0, 0);

        public long Requests { get; private set; }
        public long ClientErrors { get; private set; }
        public long Findings { get; private set; }
        public long Observations { get; private set; }
        public long LoginPosts { get; private set; }
        public long XmlrpcPosts { get; private set; }
        public DateTimeOffset First { get; private set; } = first;
        public DateTimeOffset Last { get; private set; } = first;
        public string? Protection { get; } = protection;
        public int StoredRows { get; set; }

        /// <summary>An address is kept when it fired something, or sent many client errors.</summary>
        public bool Qualifies => Findings + Observations + LoginPosts + XmlrpcPosts > 0 || ClientErrors > WebEvidenceWriter.ClientErrorThreshold;

        public void Add(W3cRequest request, WebEvaluation evaluation)
        {
            Requests++;
            if (request.Status is >= 400 and < 500) ClientErrors++;
            if (evaluation.Rules.Count > 0) Findings++;
            if (evaluation.PhpOutsideEntryPoints) Observations++;
            if (evaluation.LoginPost) LoginPosts++;
            if (evaluation.XmlrpcPost) XmlrpcPosts++;
            if (request.Timestamp < First) First = request.Timestamp;
            if (request.Timestamp > Last) Last = request.Timestamp;
        }

        /// <summary>What is not stored yet, or <see langword="null"/> when nothing is new.</summary>
        public Delta? Pending()
        {
            var delta = new Delta(Requests - written.Requests, ClientErrors - written.ClientErrors, Findings - written.Findings,
                Observations - written.Observations, LoginPosts - written.LoginPosts, XmlrpcPosts - written.XmlrpcPosts);
            return delta == new Delta(0, 0, 0, 0, 0, 0) ? null : delta;
        }

        public void MarkWritten() => written = new(Requests, ClientErrors, Findings, Observations, LoginPosts, XmlrpcPosts);
    }

    /// <summary>Everything one read produced, written in one transaction.</summary>
    private sealed class Batch
    {
        private readonly Dictionary<Tail, (WebLogPosition Position, bool Resync)> positions = [];
        private readonly Dictionary<IPAddress, string?> protection = [];

        public List<WebFinding> Findings { get; } = [];
        public Dictionary<(long Site, long Hour), SiteCounts> Sites { get; } = [];
        public HashSet<(long Hour, long Site, string Address)> TouchedSources { get; } = [];
        public int Malformed { get; set; }
        public int LongLines { get; set; }

        public IEnumerable<(Tail Tail, WebLogPosition Position, bool Resync)> Positions =>
            positions.Select(p => (p.Key, p.Value.Position, p.Value.Resync));

        public SiteCounts Site(long site, long hour)
        {
            if (!Sites.TryGetValue((site, hour), out var counts)) Sites[(site, hour)] = counts = new SiteCounts();
            return counts;
        }

        public (WebLogPosition Position, bool Resync)? PositionOf(Tail tail) =>
            positions.TryGetValue(tail, out var position) ? position : null;

        public void SetPosition(Tail tail, WebLogPosition position, bool resync) => positions[tail] = (position, resync);

        /// <summary>
        /// The tail moves to a new file within this read: the old file's position is kept as written and the
        /// new file starts at zero.
        /// </summary>
        public void Advance(Tail tail, string next)
        {
            if (positions.TryGetValue(tail, out var old))
            {
                Extra.Add(old.Position);
                positions[tail] = (new WebLogPosition(tail.Site.Id, next, 0, old.Position.LastLine), false);
            }
        }

        /// <summary>Positions of files finished within this read.</summary>
        public List<WebLogPosition> Extra { get; } = [];

        public string? Protection(IPAddress address, Func<string?> classify)
        {
            if (!protection.TryGetValue(address, out var reason)) protection[address] = reason = classify();
            return reason;
        }
    }
}

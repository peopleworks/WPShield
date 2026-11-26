using System.Text.Json;
using System.Text.Json.Nodes;

namespace WPShield.Evidence;

/// <summary>
/// The host facts of ADR 0013: what this server is, as opposed to who attacks it. Names, cadences and
/// bounds, in one place, so the collector, the store and every reader agree on them.
/// </summary>
/// <remarks>
/// <para>
/// <b>Snapshots, never live reads behind a reader.</b> The collector reads each fact on its cadence and
/// stores a bounded snapshot. The CLI, the desktop, the MCP tools and the analyst read those snapshots, so
/// every surface shows the same reading with the same read time, and nothing a model asks for makes
/// WPShield probe the host.
/// </para>
/// <para>
/// <b>Nothing here changes the host.</b> ADR 0005 and AGENTS.md apply: every remedy is text for a person.
/// </para>
/// </remarks>
public static class HostFacts
{
    public const string Health = "host_health";
    public const string Sites = "iis_sites";
    public const string Posture = "iis_posture";
    public const string Ports = "listening_ports";
    public const string Sessions = "rdp_sessions";
    public const string Inventory = "host_inventory";

    public const string Accounts = "accounts";
    public const string Services = "services";
    public const string Tasks = "tasks";

    /// <summary>An unexpected restart, recorded once (section 1.2). Survives the System log being cleared.</summary>
    public const string RestartKind = "host.unexpected-restart";

    /// <summary>An inventory item added, removed or changed between two snapshots (section 1.3).</summary>
    public const string InventoryChangeKind = "host.inventory-change";

    public const string EventSource = "host-facts";

    public static readonly IReadOnlyList<string> All = [Health, Sites, Posture, Ports, Sessions, Inventory];
    public static readonly IReadOnlyList<string> InventoryKinds = [Accounts, Services, Tasks];

    public static readonly TimeSpan HealthCadence = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan RestartCadence = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan SitesCadence = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan PortsCadence = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan SessionsCadence = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan PostureCadence = TimeSpan.FromHours(6);
    public static readonly TimeSpan InventoryCadence = TimeSpan.FromHours(6);

    /// <summary>How far back unexpected restarts are read at the first start, and what the gauge counts.</summary>
    public static readonly TimeSpan RestartWindow = TimeSpan.FromDays(30);

    /// <summary>
    /// How far back the full-name indicator looks for attempted account names. It reads the detailed attempts, which
    /// are kept <c>retention.raw_days</c> - 14 by default - so in practice the window is that, 30 days at most.
    /// </summary>
    public static readonly TimeSpan AttemptWindow = TimeSpan.FromDays(30);

    /// <summary>How far back the RDP logons of <see cref="Sessions"/> reach.</summary>
    public static readonly TimeSpan SessionWindow = TimeSpan.FromDays(7);

    public static readonly TimeSpan SnapshotRetention = TimeSpan.FromDays(7);
    public static readonly TimeSpan PostureRetention = TimeSpan.FromDays(400);
    public static readonly TimeSpan HealthHourlyRetention = TimeSpan.FromDays(90);

    public const int MaxPayloadBytes = 256 * 1024;
    public const int MaxInventoryItems = 2000;
    public const int MaxListeners = 500;
    public const int MaxSites = 2000;
    public const int MaxSessions = 200;
    public const int MaxRecentLogons = 1000;
    public const int MaxRestartEvents = 1000;
    public const int MaxNameLength = 256;
    public const int MaxSignatureChecks = 300;
    public const int MaxChangeEventsPerDay = 500;
    public const int MaxVolumes = 64;

    /// <summary>The time one snapshot may take before it is stored as <c>partial</c>.</summary>
    public static readonly TimeSpan ReadBudget = TimeSpan.FromSeconds(90);

    /// <summary>The cadence of a fact, which also decides when its snapshot counts as stale.</summary>
    public static TimeSpan Cadence(string fact) => fact switch
    {
        Health => HealthCadence,
        Sites => SitesCadence,
        Ports => PortsCadence,
        Sessions => SessionsCadence,
        Posture => PostureCadence,
        Inventory => InventoryCadence,
        _ => throw new ArgumentException($"Unknown host fact '{fact}'.", nameof(fact))
    };

    /// <summary>A snapshot older than three times its cadence is shown as stale, with its age (section 2).</summary>
    public static bool IsStale(string fact, DateTimeOffset takenAt, DateTimeOffset now) => now - takenAt > 3 * Cadence(fact);

    public static bool IsFact(string? fact) => fact is not null && All.Contains(fact, StringComparer.Ordinal);

    public static bool IsInventoryKind(string? kind) => kind is not null && InventoryKinds.Contains(kind, StringComparer.Ordinal);

    /// <summary>A name or a path read from the host, cleaned and bounded the way attacker text is.</summary>
    public static string Clean(string? text) => EvidenceText.Clean(text, MaxNameLength);

    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = false };
}

/// <summary>Whether a fact could be read, as section 2 of ADR 0013 names it. Unreadable is never shown as empty.</summary>
public static class HostFactStatus
{
    public const string Ok = "ok";
    public const string Partial = "partial";
    public const string NeedsElevation = "needs-elevation";
    public const string Unreadable = "unreadable";
    public const string NotMeasured = "not-measured";

    public static bool IsKnown(string? status) => status is Ok or Partial or NeedsElevation or Unreadable or NotMeasured;
}

/// <summary>
/// One reading of one fact, as a source returns it and as the store keeps it.
/// </summary>
/// <param name="Kind">The inventory kind (<c>accounts</c>, <c>services</c>, <c>tasks</c>) or <see langword="null"/>.</param>
/// <param name="Reason">Why the status is not <c>ok</c>; required then.</param>
/// <param name="Remedy">What a person can do about it, as text. Required when the status is not <c>ok</c>.</param>
/// <param name="Payload">The fact itself, already bounded and cleaned; <see langword="null"/> when nothing was read.</param>
public sealed record HostFactReading(string Fact, string? Kind, DateTimeOffset TakenAt, string Status, string? Reason, string? Remedy,
    JsonObject? Payload)
{
    public static HostFactReading Of<T>(string fact, string? kind, DateTimeOffset takenAt, T value, string status = HostFactStatus.Ok,
        string? reason = null, string? remedy = null) =>
        new(fact, kind, takenAt, status, reason, remedy, JsonSerializer.SerializeToNode(value, HostFacts.Json) as JsonObject);

    public static HostFactReading Failed(string fact, string? kind, DateTimeOffset takenAt, string status, string reason, string remedy) =>
        new(fact, kind, takenAt, status, reason, remedy, null);

    /// <summary>The payload as its typed record, or <see langword="null"/> when there is none.</summary>
    public T? Value<T>() where T : class => Payload is null ? null : Payload.Deserialize<T>(HostFacts.Json);
}

// =================================================================================================
//  The payloads. Field names are the wire names every surface shows; nothing here holds a secret, an
//  argument or a full name.
// =================================================================================================

/// <summary><c>host_health</c>: how the machine is doing. Restarts are events, counted by a query.</summary>
/// <param name="Patch">What the operating system reports about its own patch level; <see langword="null"/> when not read.</param>
/// <param name="Logs">
/// How far back the System, Security and Application logs reach and what fills them; <see langword="null"/> when this
/// snapshot did not read them. A log that reaches back only hours loses the evidence of crashes and logons.
/// </param>
public sealed record HostHealth(
    DateTimeOffset LastBoot,
    long UptimeSeconds,
    double? CpuPercent,
    long? MemoryTotalBytes,
    long? MemoryAvailableBytes,
    IReadOnlyList<HostVolume> Volumes,
    long? StoreBytes,
    HostPatchLevel? Patch = null,
    IReadOnlyList<HostLogHorizon>? Logs = null);

/// <summary>
/// How far back one event log reaches, and what fills it. On the first real host a service stuck in a start loop
/// wrote 7036 records until the 20 MB System log reached back only hours, and a bugcheck record was overwritten
/// before anyone read it: the horizon is what tells "no crash" from "no record of the crash".
/// </summary>
/// <param name="Log"><c>System</c>, <c>Security</c> or <c>Application</c>.</param>
/// <param name="Readable">Whether the log could be read. When it could not, every value below is unknown, never zero.</param>
/// <param name="MaximumBytes">The log's configured maximum size.</param>
/// <param name="OldestRecordAt">The oldest record the log still holds: its horizon.</param>
/// <param name="DominantEventId">The most frequent event ID among the newest <see cref="SampleSize"/> records.</param>
/// <param name="DominantProvider">Its provider, cleaned and bounded. A host detail where the MCP tools are concerned.</param>
/// <param name="DominantCount">How many of the sampled records it accounts for.</param>
/// <param name="Sampled">How many records were sampled: <see cref="SampleSize"/>, or fewer in a smaller log.</param>
/// <param name="Problem">Why the log was not read (a fixed code), when it was not.</param>
public sealed record HostLogHorizon(
    string Log,
    bool Readable,
    long? MaximumBytes,
    long? RecordCount,
    DateTimeOffset? OldestRecordAt,
    int? DominantEventId,
    string? DominantProvider,
    int? DominantCount,
    int? Sampled,
    string? Problem = null)
{
    /// <summary>How many of the newest records are sampled for the dominant event.</summary>
    public const int SampleSize = 5000;

    /// <summary>A horizon shorter than this is called out: a week is the least a crash or logon investigation needs.</summary>
    public static readonly TimeSpan ShortHorizon = TimeSpan.FromDays(7);

    /// <summary>The logs read, in the order every surface shows them.</summary>
    public static readonly IReadOnlyList<string> Names = ["System", "Security", "Application"];

    /// <summary>The dominant event's share of the sample, from 0 to 1, or <see langword="null"/> when nothing was sampled.</summary>
    public double? DominantShare => DominantCount is { } count && Sampled is > 0 ? count / (double)Sampled.Value : null;

    /// <summary>How far back the log reaches at <paramref name="now"/>, or <see langword="null"/> when unknown.</summary>
    public TimeSpan? Reach(DateTimeOffset now) => OldestRecordAt is { } oldest ? now - oldest : null;

    /// <summary>Whether the log reaches back less than <see cref="ShortHorizon"/>; <see langword="null"/> when unknown.</summary>
    public bool? IsShort(DateTimeOffset now) => Reach(now) is { } reach ? reach < ShortHorizon : null;

    /// <summary>
    /// The most frequent (event ID, provider) pair among <paramref name="records"/>, at most <see cref="SampleSize"/>
    /// of them, newest first; <see langword="null"/> when there were none.
    /// </summary>
    public static (int EventId, string? Provider, int Count, int Sampled)? Dominant(IEnumerable<(int EventId, string? Provider)> records)
    {
        ArgumentNullException.ThrowIfNull(records);
        var counts = new Dictionary<(int, string), int>();
        var sampled = 0;
        foreach (var (id, provider) in records.Take(SampleSize))
        {
            sampled++;
            var key = (id, provider ?? "");
            counts[key] = counts.GetValueOrDefault(key) + 1;
        }
        if (sampled == 0) return null;
        var top = counts.OrderByDescending(pair => pair.Value).ThenBy(pair => pair.Key.Item1)
            .ThenBy(pair => pair.Key.Item2, StringComparer.Ordinal).First();
        return (top.Key.Item1, top.Key.Item2.Length == 0 ? null : EvidenceText.Clean(top.Key.Item2, HostFacts.MaxNameLength), top.Value, sampled);
    }
}

/// <summary>
/// The patch level as Windows reports it, in three places that can disagree: the registry's build, the kernel
/// file's version and the Windows Update log. Facts only - WPShield has no offline source of the latest build, so
/// it never judges a host "outdated".
/// </summary>
/// <param name="CurrentBuild"><c>CurrentBuild</c> from <c>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion</c>.</param>
/// <param name="Ubr">The update build revision (<c>UBR</c>) from the same key.</param>
/// <param name="DisplayVersion"><c>DisplayVersion</c>, such as <c>21H2</c>; absent on some versions.</param>
/// <param name="KernelVersion">The ProductVersion of <c>%SystemRoot%\System32\ntoskrnl.exe</c>.</param>
/// <param name="UpdateLogReadable">
/// Whether <c>Microsoft-Windows-WindowsUpdateClient/Operational</c> could be read. When it could not, the three
/// update fields below are <see langword="null"/> and mean "unknown", never "none".
/// </param>
/// <param name="LastCumulativeUpdate">The title of the newest successful install (event 19) whose title names a cumulative update, cleaned and bounded at 200 characters.</param>
/// <param name="LastCumulativeUpdateAt">When that install succeeded.</param>
/// <param name="FailedInstalls30Days">Install failures (event 20) in the last 30 days.</param>
/// <param name="UpdateLogStartsAt">The oldest record the update log still holds: "not found" means "not since then".</param>
/// <param name="LastHotfixId">
/// The newest installed hotfix from <c>Win32_QuickFixEngineering</c>, read when the update log names no cumulative
/// update (updates installed from a package or by a management tool write no event 19). Cleaned and bounded.
/// </param>
/// <param name="LastHotfixInstalledOn">When that hotfix was installed, as Windows records it (a date, no time of day).</param>
/// <param name="HotfixListRead">
/// Whether the hotfix list was read: <see langword="null"/> when it was not needed (the update log named a cumulative
/// update), <see langword="false"/> when it could not be read - unknown, never "no hotfix".
/// </param>
public sealed record HostPatchLevel(
    string? CurrentBuild,
    int? Ubr,
    string? DisplayVersion,
    string? KernelVersion,
    bool UpdateLogReadable,
    string? LastCumulativeUpdate,
    DateTimeOffset? LastCumulativeUpdateAt,
    int? FailedInstalls30Days,
    DateTimeOffset? UpdateLogStartsAt = null,
    string? LastHotfixId = null,
    DateTimeOffset? LastHotfixInstalledOn = null,
    bool? HotfixListRead = null)
{
    public const int MaxTitleLength = 200;

    /// <summary>Where <see cref="LastHotfixId"/> comes from, as every surface labels it.</summary>
    public const string HotfixSource = "Win32_QuickFixEngineering";

    /// <summary>The longest hotfix ID kept.</summary>
    public const int MaxHotfixIdLength = 32;

    /// <summary>The window of <see cref="FailedInstalls30Days"/>.</summary>
    public static readonly TimeSpan FailureWindow = TimeSpan.FromDays(30);

    /// <summary><c>20348.2849</c>, or <see langword="null"/> when the registry did not say.</summary>
    public string? Build => CurrentBuild is null ? null : Ubr is { } ubr ? $"{CurrentBuild}.{ubr}" : CurrentBuild;

    /// <summary>Whole days since the last successful cumulative update, or <see langword="null"/> when none is known.</summary>
    public int? DaysSinceCumulativeUpdate(DateTimeOffset now) =>
        LastCumulativeUpdateAt is { } at ? Math.Max(0, (int)(now - at).TotalDays) : null;

    /// <summary>
    /// Whether the kernel file's revision (the last part of its version) differs from the registry's <c>UBR</c> -
    /// stated as a fact, for example while a restart is pending; <see langword="null"/> when either is unknown.
    /// Only the revision is compared: an enablement package raises <c>CurrentBuild</c> (26100 to 26200) while the
    /// kernel file keeps the base build.
    /// </summary>
    public bool? KernelDiffersFromRegistry => KernelRevisionDelta is { } delta ? delta != 0 : null;

    /// <summary>
    /// The kernel file's revision minus the registry's <c>UBR</c>, or <see langword="null"/> when either is unknown. A
    /// small negative value is normal: not every cumulative update replaces <c>ntoskrnl.exe</c>, so the kernel file
    /// keeps the revision of the last update that did (UBR 5761 with a 5756 kernel file, on the first real host).
    /// </summary>
    public int? KernelRevisionDelta
    {
        get
        {
            if (Ubr is not { } ubr || KernelVersion is not { } kernel) return null;
            var dot = kernel.LastIndexOf('.');
            return dot < 0 || !int.TryParse(kernel.AsSpan(dot + 1), System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var revision) ? null : revision - ubr;
        }
    }
}

/// <summary>One row of <c>Win32_QuickFixEngineering</c>, reduced to what the patch level reads.</summary>
/// <param name="InstalledOn">The text Windows records, which is a date in one of a few shapes, or nothing.</param>
public sealed record HotfixRecord(string? HotfixId, string? InstalledOn);

/// <summary>Picks the newest installed hotfix out of <c>Win32_QuickFixEngineering</c> rows.</summary>
public static class Hotfixes
{
    /// <summary>The most rows read.</summary>
    public const int MaxRows = 2000;

    /// <summary>
    /// The newest hotfix with a date, or - when no row has a readable date - the last one listed, with no date;
    /// <see langword="null"/> when there are no rows.
    /// </summary>
    public static (string? Id, DateTimeOffset? InstalledOn)? Newest(IEnumerable<HotfixRecord> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        (string? Id, DateTimeOffset? InstalledOn)? newest = null;
        string? undated = null;
        var any = false;
        foreach (var row in rows.Take(MaxRows))
        {
            any = true;
            var id = string.IsNullOrWhiteSpace(row.HotfixId) ? null : EvidenceText.Clean(row.HotfixId.Trim(), HostPatchLevel.MaxHotfixIdLength);
            if (ParseInstalledOn(row.InstalledOn) is { } at)
            {
                if (newest is null || at > newest.Value.InstalledOn) newest = (id, at);
            }
            else if (id is not null) undated = id;
        }
        if (newest is not null) return newest;
        return any ? (undated, null) : null;
    }

    /// <summary>
    /// <c>InstalledOn</c> as Windows writes it: <c>M/d/yyyy</c> on most systems, <c>yyyyMMdd</c>, or a 16-digit
    /// hexadecimal FILETIME on some older entries. Anything else is unknown, never a guess.
    /// </summary>
    public static DateTimeOffset? ParseInstalledOn(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var value = text.Trim();
        var invariant = System.Globalization.CultureInfo.InvariantCulture;
        if (value.Length == 16 && long.TryParse(value, System.Globalization.NumberStyles.AllowHexSpecifier, invariant, out var filetime) && filetime > 0)
        {
            try { return new DateTimeOffset(DateTime.FromFileTimeUtc(filetime), TimeSpan.Zero); }
            catch (ArgumentOutOfRangeException) { return null; }
        }
        return DateTime.TryParseExact(value, ["M/d/yyyy", "MM/dd/yyyy", "yyyyMMdd", "yyyy-MM-dd"], invariant,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var date)
            ? new DateTimeOffset(DateTime.SpecifyKind(date, DateTimeKind.Utc), TimeSpan.Zero)
            : null;
    }
}

/// <summary>One Windows Update client record: 19 install succeeded, 20 install failed.</summary>
public sealed record UpdateEvent(DateTimeOffset At, int EventId, string? Title);

/// <summary>Reads the patch-level facts out of Windows Update client records, newest first or in any order.</summary>
public static class PatchLevels
{
    public const int InstallSucceeded = 19;
    public const int InstallFailed = 20;

    /// <summary>The most records one reading looks at.</summary>
    public const int MaxEvents = 5000;

    /// <summary>
    /// The newest successful install whose title names a cumulative update, and the failures of the last 30 days.
    /// </summary>
    public static (string? Title, DateTimeOffset? At, int Failed) FromUpdateEvents(IEnumerable<UpdateEvent> events, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(events);
        UpdateEvent? newest = null;
        var failed = 0;
        foreach (var record in events.Take(MaxEvents))
        {
            if (record.EventId == InstallFailed && record.At > now - HostPatchLevel.FailureWindow && record.At <= now) failed++;
            if (record.EventId == InstallSucceeded && IsCumulative(record.Title) && (newest is null || record.At > newest.At)) newest = record;
        }
        return (newest is null ? null : EvidenceText.Clean(newest.Title, HostPatchLevel.MaxTitleLength), newest?.At, failed);
    }

    /// <summary>"Cumulative Update" in the title, whatever the product or language of the rest.</summary>
    public static bool IsCumulative(string? title) =>
        title is not null && title.Contains("Cumulative Update", StringComparison.OrdinalIgnoreCase);
}

/// <param name="HoldsIisLogs">Whether the IIS log folder lives on this volume, or <see langword="null"/> when unknown.</param>
public sealed record HostVolume(string Name, long TotalBytes, long FreeBytes, bool? HoldsIisLogs);

/// <summary>One System log record that says the machine stopped without shutting down (41, 6008 or 1001).</summary>
public sealed record HostRestartRecord(DateTimeOffset At, long RecordId, int EventId, uint? BugCheckCode);

/// <summary>What a restart reader returns: the records, and whether it could read them.</summary>
public sealed record HostRestartReading(DateTimeOffset TakenAt, string Status, string? Reason, string? Remedy, IReadOnlyList<HostRestartRecord> Records);

/// <summary><c>iis_sites</c>.</summary>
public sealed record HostSites(IReadOnlyList<HostSite> Sites);

/// <param name="IdentityType">As IIS names it; never the account's password, which is never read.</param>
/// <param name="IdentityIsAdministrator">Unknown is <see langword="null"/>, never "no".</param>
public sealed record HostSite(long Id, string Name, string State, IReadOnlyList<HostBinding> Bindings, string Pool, string IdentityType,
    bool? IdentityIsAdministrator);

public sealed record HostBinding(string Protocol, int? Port, string Host, bool Loopback);

/// <summary><c>iis_posture</c>: the latest audit summary and the counts behind the gauges.</summary>
/// <param name="Source"><c>collector</c> or <c>audit</c>.</param>
/// <param name="Complete">Whether the audit could look at all (elevated, IIS readable).</param>
public sealed record HostPosture(
    string Source,
    bool Complete,
    IReadOnlyList<HostPostureFinding> Findings,
    int? PoolsTotal,
    int? PoolsAdministrator,
    bool? PhpServerLevel,
    int? WritableSiteFolders,
    int? FtpOverlaps);

public sealed record HostPostureFinding(string Id, string Severity, string Title, int Items);

/// <summary><c>listening_ports</c>. Verdicts are "by the Windows Firewall rules", never "reachable".</summary>
public sealed record HostPorts(IReadOnlyList<HostListener> Listeners, bool FirewallRead);

/// <param name="Binding"><c>any</c>, <c>specific</c> or <c>loopback</c>.</param>
/// <param name="Process">The owning executable's file name, or <see langword="null"/> when it could not be read.</param>
/// <param name="ProcessPath">Its full path; a host detail.</param>
/// <param name="OpenedBy">
/// For a listener judged open to any address, the display names of the enabled inbound allow rules that make it so,
/// at most <see cref="ExposureVerdicts.MaxOpenedBy"/> - the rule an operator restricts - or why no rule was needed.
/// <see langword="null"/> for any other verdict, and in snapshots taken before rules were named.
/// </param>
public sealed record HostListener(string Protocol, int Port, string Binding, string? Address, string? Process, string? ProcessPath,
    string Verdict, bool Red, IReadOnlyList<string>? OpenedBy = null);

/// <summary><c>rdp_sessions</c>.</summary>
public sealed record HostSessions(IReadOnlyList<HostSession> Current, IReadOnlyList<HostRdpLogon> Recent);

public sealed record HostSession(int SessionId, string State, string User, DateTimeOffset? LogonTime);

/// <param name="Kind"><c>logon</c> (event 21) or <c>reconnect</c> (event 25).</param>
/// <param name="Address">From LocalSessionManager, the evidence-grade source; never the client-reported address.</param>
public sealed record HostRdpLogon(DateTimeOffset At, string User, string? Address, string Kind);

/// <summary><c>host_inventory</c> of kind <c>accounts</c>.</summary>
/// <param name="FullNameTargeted">
/// Whether an attempted account name equals the full name of a local account. Computed in memory at snapshot
/// time; the full names are never stored. <see langword="null"/> when it could not be computed.
/// </param>
/// <param name="FullNameMatches">How many local accounts' full names were attempted.</param>
public sealed record HostAccounts(IReadOnlyList<HostAccount> Accounts, bool? FullNameTargeted, int? FullNameMatches);

public sealed record HostAccount(string Name, bool Enabled, bool? Administrator, bool? RemoteDesktopUser, DateTimeOffset? LastLogon,
    int? PasswordAgeDays, bool PasswordNeverExpires);

/// <summary><c>host_inventory</c> of kind <c>services</c>: non-Microsoft services only.</summary>
public sealed record HostServices(IReadOnlyList<HostService> Services, int SignaturesNotChecked);

/// <param name="Signature"><c>signed</c>, <c>unsigned</c> or <c>not-checked</c>.</param>
/// <param name="Flags">From <see cref="CommandFlags"/>. The arguments themselves are never kept.</param>
public sealed record HostService(string Name, string DisplayName, string State, string StartMode, string Account, string? Executable,
    string Signature, string? Signer, IReadOnlyList<string> Flags);

/// <summary><c>host_inventory</c> of kind <c>tasks</c>: non-Microsoft scheduled tasks only.</summary>
public sealed record HostTasks(IReadOnlyList<HostTask> Tasks, int SignaturesNotChecked);

public sealed record HostTask(string Path, string State, string Principal, DateTimeOffset? LastRun, DateTimeOffset? NextRun,
    string? Executable, string Signature, string? Signer, IReadOnlyList<string> Flags);

/// <summary>The values a signature check reports.</summary>
public static class HostSignature
{
    public const string Signed = "signed";
    public const string Unsigned = "unsigned";
    public const string NotChecked = "not-checked";
}

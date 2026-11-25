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
public sealed record HostHealth(
    DateTimeOffset LastBoot,
    long UptimeSeconds,
    double? CpuPercent,
    long? MemoryTotalBytes,
    long? MemoryAvailableBytes,
    IReadOnlyList<HostVolume> Volumes,
    long? StoreBytes);

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
public sealed record HostListener(string Protocol, int Port, string Binding, string? Address, string? Process, string? ProcessPath,
    string Verdict, bool Red);

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

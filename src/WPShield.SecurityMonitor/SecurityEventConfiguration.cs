namespace WPShield.SecurityMonitor;

/// <summary>
/// Configuration for <see cref="SecurityEventMonitor"/>.
/// </summary>
public sealed record SecurityEventConfiguration
{
    /// <summary>
    /// Windows Security log name to monitor. Default: "Security".
    /// </summary>
    public string LogName { get; init; } = "Security";

    /// <summary>
    /// Event IDs to inspect. Default: 4624 (logon success), 4625 (logon failure).
    /// </summary>
    public IReadOnlyList<int> EventIds { get; init; } = new[] { 4624, 4625 };

    /// <summary>
    /// Logon types considered remote interactive (RDP). Default: ["10"].
    /// </summary>
    public IReadOnlyList<string> RemoteLogonTypes { get; init; } = new[] { "10" };

    /// <summary>
    /// Maximum failed logons from one source IP within the window before raising a finding.
    /// Default: 5.
    /// </summary>
    public int MaxFailedLogonsPerWindow { get; init; } = 5;

    /// <summary>
    /// Sliding window in minutes for failed-logon counting. Default: 5.
    /// </summary>
    public int WindowMinutes { get; init; } = 5;

    /// <summary>
    /// Source IPs to always ignore (never flagged, never published).
    /// </summary>
    public IReadOnlyList<string> AllowList { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Whether the monitor should publish findings to the sink. Default: true.
    /// </summary>
    public bool PublishingEnabled { get; init; } = true;
}

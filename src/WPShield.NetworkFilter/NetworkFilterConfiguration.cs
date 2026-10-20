namespace WPShield.NetworkFilter;

/// <summary>
/// Configuration for <see cref="NetworkFilterEngine"/>.
/// </summary>
public sealed record NetworkFilterConfiguration
{
    /// <summary>
    /// WinDivert capture filter string. Default: <c>"tcp.Inbound"</c>.
    /// </summary>
    public string Filter { get; init; } = "tcp.Inbound";

    /// <summary>
    /// Maximum time allowed to inspect a single packet before forwarding it uninspected.
    /// Default: 5 milliseconds.
    /// </summary>
    public TimeSpan MaxInspectionTime { get; init; } = TimeSpan.FromMilliseconds(5);

    /// <summary>
    /// Maximum connections per source IP per minute before rate limiting kicks in.
    /// Default: 60.
    /// </summary>
    public int MaxConnectionsPerMinute { get; init; } = 60;

    /// <summary>
    /// Maximum distinct destination ports per source IP per minute before port-scan
    /// detection flags the IP.
    /// Default: 20.
    /// </summary>
    public int MaxDistinctPortsPerMinute { get; init; } = 20;

    /// <summary>
    /// Source IPs to always block, regardless of other rules.
    /// </summary>
    public IReadOnlyList<string> BlockList { get; init; } = Array.Empty<string>();
}

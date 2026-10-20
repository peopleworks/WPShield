namespace WPShield.Abstractions;

/// <summary>
/// Minimal, bounded context presented to network inspection rules.
/// All string fields are attacker-controlled and must be treated as untrusted input.
/// </summary>
public sealed record NetworkInspectionContext
{
    public required string SourceIp { get; init; }
    public required string DestinationIp { get; init; }
    public required int SourcePort { get; init; }
    public required int DestinationPort { get; init; }
    public required string Protocol { get; init; } // "TCP" or "UDP"
    public required DateTimeOffset Timestamp { get; init; }
    public int PacketSize { get; init; }
    /// <summary>
    /// Bounded leading sample of the payload (never the full packet). Rules must not
    /// retain references to this memory beyond the inspection call.
    /// </summary>
    public ReadOnlyMemory<byte> PayloadSample { get; init; } = default;
}

namespace WPShield.NetworkFilter;

/// <summary>
/// Parsed representation of a single intercepted packet, used by inspection rules.
/// </summary>
public sealed record NetworkPacketInfo
{
    public required string SourceIp { get; init; }
    public required string DestinationIp { get; init; }
    public required int SourcePort { get; init; }
    public required int DestinationPort { get; init; }
    public required string Protocol { get; init; } // "TCP" or "UDP"
    public required int PacketSize { get; init; }
    public required ReadOnlyMemory<byte> PayloadSample { get; init; }
}

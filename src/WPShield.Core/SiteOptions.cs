namespace WPShield.Core;

public sealed class SiteOptions
{
    public required string Id { get; init; }
    public required string[] Hosts { get; init; }
    public required Uri Destination { get; init; }
    public ProtectionMode Mode { get; init; } = ProtectionMode.Monitor;
    public int ObserveThreshold { get; init; } = 30;
    public int BlockThreshold { get; init; } = 80;
}

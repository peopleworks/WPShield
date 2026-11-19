namespace WPShield.Core;

public sealed class SiteOptions
{
    private readonly string[] _hosts = [];

    public required string Id { get; init; }
    public required string[] Hosts
    {
        get => [.. _hosts];
        init => _hosts = [.. value ?? []];
    }
    public required Uri Destination { get; init; }
    public ProtectionMode Mode { get; init; } = ProtectionMode.Monitor;
    public int ObserveThreshold { get; init; } = 30;
    public int BlockThreshold { get; init; } = 80;
}

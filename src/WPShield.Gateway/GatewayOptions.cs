namespace WPShield.Gateway;

public sealed class GatewayOptions
{
    public const long AbsoluteMaximumRequestBytes = 64L * 1024 * 1024;

    public string[] Urls { get; init; } = ["http://127.0.0.1:10000"];
    public bool AllowRemoteHealthChecks { get; init; }
    public int ActivityTimeoutSeconds { get; init; } = 100;
    public long MaximumRequestBytes { get; init; } = 6L * 1024 * 1024;
}

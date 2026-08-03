namespace WPShield.Gateway;

public sealed class GatewayOptions
{
    public string[] Urls { get; init; } = ["http://127.0.0.1:10000"];
    public bool AllowRemoteHealthChecks { get; init; }
    public int ActivityTimeoutSeconds { get; init; } = 100;
}

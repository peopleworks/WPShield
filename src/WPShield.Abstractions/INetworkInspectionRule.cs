namespace WPShield.Abstractions;

/// <summary>
/// Contract for network-layer inspection rules, mirroring <see cref="IInspectionRule"/>
/// but for raw TCP/UDP packets instead of HTTP multipart uploads.
/// </summary>
public interface INetworkInspectionRule
{
    string RuleId { get; }
    NetworkInspectionResult Inspect(
        NetworkInspectionContext context,
        CancellationToken cancellationToken = default);
}

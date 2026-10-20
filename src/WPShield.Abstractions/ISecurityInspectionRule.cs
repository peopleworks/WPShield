namespace WPShield.Abstractions;

/// <summary>
/// Contract for security event inspection rules. Mirrors <see cref="INetworkInspectionRule"/>
/// but operates on Windows Security event log records instead of network packets.
/// </summary>
public interface ISecurityInspectionRule
{
    string RuleId { get; }
    SecurityInspectionResult Inspect(
        SecurityInspectionContext context,
        CancellationToken cancellationToken = default);
}

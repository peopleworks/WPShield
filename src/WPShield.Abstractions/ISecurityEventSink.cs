namespace WPShield.Abstractions;

/// <summary>
/// Sink for security findings. Implementations decide what to do with a finding:
/// write to the JSON Lines log, publish to a dynamic block list, alert an operator, etc.
/// </summary>
public interface ISecurityEventSink
{
    void Publish(SecurityInspectionResult finding, SecurityInspectionContext context);
}

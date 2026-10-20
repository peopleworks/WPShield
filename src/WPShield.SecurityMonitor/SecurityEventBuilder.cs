using System.Collections.Generic;
using WPShield.Abstractions;

namespace WPShield.SecurityMonitor;

/// <summary>
/// Convenience builder that assembles a <see cref="SecurityEventMonitor"/> with the default
/// rule set (RDP brute force detection and generic failed logon detection).
/// </summary>
public static class SecurityEventBuilder
{
    public static SecurityEventMonitor Build(
        SecurityEventConfiguration? configuration = null,
        IEnumerable<ISecurityInspectionRule>? extraRules = null,
        ISecurityEventSink? sink = null)
    {
        configuration ??= new SecurityEventConfiguration();

        var rules = new List<ISecurityInspectionRule>
        {
            new Rules.RdpBruteForceRule(
                maxFailuresPerWindow: configuration.MaxFailedLogonsPerWindow,
                windowMinutes: configuration.WindowMinutes),
            new Rules.FailedLogonRule(
                maxFailuresPerWindow: configuration.MaxFailedLogonsPerWindow,
                windowMinutes: configuration.WindowMinutes)
        };

        if (extraRules is not null)
        {
            rules.AddRange(extraRules);
        }

        sink ??= new NullSecurityEventSink();

        return new SecurityEventMonitor(configuration, rules, sink);
    }

    private sealed class NullSecurityEventSink : ISecurityEventSink
    {
        public void Publish(SecurityInspectionResult finding, SecurityInspectionContext context)
        {
            // Intentionally no-op. Operators provide their own sink.
        }
    }
}

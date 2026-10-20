using System.Collections.Generic;
using WPShield.Abstractions;

namespace WPShield.SecurityMonitor.Rules;

/// <summary>
/// Detects RDP brute-force attempts: repeated failed logons (Logon Type 10 = RemoteInteractive)
/// from the same source IP within a sliding time window.
///
/// This rule complements <see cref="WPShield.NetworkFilter.Rules.PortScanRule"/> and
/// <see cref="WPShield.NetworkFilter.Rules.RateLimitRule"/>, which operate on packet headers.
/// This rule sees the authentication result, which packets alone cannot reveal.
/// </summary>
public sealed class RdpBruteForceRule : ISecurityInspectionRule
{
    private readonly int _maxFailuresPerWindow;
    private readonly int _windowMinutes;
    private readonly Dictionary<string, List<DateTimeOffset>> _failuresByIp = new();
    private readonly object _lock = new();

    public string RuleId => "WP-SEC-001";

    public RdpBruteForceRule(int maxFailuresPerWindow = 5, int windowMinutes = 5)
    {
        _maxFailuresPerWindow = maxFailuresPerWindow;
        _windowMinutes = windowMinutes;
    }

    public SecurityInspectionResult Inspect(
        WPShield.Abstractions.SecurityInspectionContext context,
        CancellationToken cancellationToken = default)
    {
        // Only consider failed logons (4625) with remote interactive logon type (10).
        if (context.EventId != 4625 ||
            !context.LogonType.Equals("10", System.StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityInspectionResult
            {
                RuleId = RuleId,
                Score = 0,
                Action = WPShield.Abstractions.NetworkInspectionAction.Allow,
                MessageKey = "Findings.SecurityEventIgnored",
                Evidence = new Dictionary<string, object>
                {
                    ["event_id"] = context.EventId,
                    ["logon_type"] = context.LogonType,
                    ["reason"] = "not_rdp_failure"
                }
            };
        }

        lock (_lock)
        {
            var now = context.TimeCreated;

            if (!_failuresByIp.TryGetValue(context.SourceIp, out var times))
            {
                times = new List<DateTimeOffset>();
                _failuresByIp[context.SourceIp] = times;
            }

            // Slide the window.
            times.RemoveAll(t => now - t > TimeSpan.FromMinutes(_windowMinutes));
            times.Add(now);

            int count = times.Count;

            int score;
            if (count >= 10)
            {
                score = 100;
            }
            else if (count >= _maxFailuresPerWindow)
            {
                score = 80;
            }
            else if (count >= 3)
            {
                score = 40;
            }
            else
            {
                score = 0;
            }

            return new SecurityInspectionResult
            {
                RuleId = RuleId,
                Score = score,
                Action = score switch
                {
                    0 => WPShield.Abstractions.NetworkInspectionAction.Allow,
                    >= 80 => WPShield.Abstractions.NetworkInspectionAction.Block,
                    _ => WPShield.Abstractions.NetworkInspectionAction.Observe
                },
                MessageKey = "Findings.RdpBruteForce",
                Evidence = new Dictionary<string, object>
                {
                    ["source_ip"] = context.SourceIp,
                    ["user_name"] = context.UserName,
                    ["failed_logons_last_minutes"] = count,
                    ["window_minutes"] = _windowMinutes,
                    ["threshold"] = _maxFailuresPerWindow,
                    ["logon_type"] = context.LogonType,
                    ["event_id"] = context.EventId,
                    ["computer_name"] = context.ComputerName
                }
            };
        }
    }

    /// <summary>
    /// Clears the failure history for a specific IP (for example, after an operator
    /// confirms the IP is legitimate).
    /// </summary>
    public void ClearIp(string sourceIp)
    {
        lock (_lock)
        {
            _failuresByIp.Remove(sourceIp);
        }
    }
}

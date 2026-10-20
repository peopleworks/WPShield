using System.Collections.Generic;
using WPShield.Abstractions;

namespace WPShield.SecurityMonitor.Rules;

/// <summary>
/// Detects any failed logon (Event ID 4625) regardless of logon type, with a lower score
/// than the RDP-specific rule. Useful for detecting local or network authentication attacks
/// that do not use RDP.
/// </summary>
public sealed class FailedLogonRule : ISecurityInspectionRule
{
    private readonly int _maxFailuresPerWindow;
    private readonly int _windowMinutes;
    private readonly Dictionary<string, List<DateTimeOffset>> _failuresByIp = new();
    private readonly object _lock = new();

    public string RuleId => "WP-SEC-002";

    public FailedLogonRule(int maxFailuresPerWindow = 10, int windowMinutes = 10)
    {
        _maxFailuresPerWindow = maxFailuresPerWindow;
        _windowMinutes = windowMinutes;
    }

    public SecurityInspectionResult Inspect(
        WPShield.Abstractions.SecurityInspectionContext context,
        CancellationToken cancellationToken = default)
    {
        if (context.EventId != 4625)
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
                    ["reason"] = "not_failed_logon"
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

            times.RemoveAll(t => now - t > TimeSpan.FromMinutes(_windowMinutes));
            times.Add(now);

            int count = times.Count;

            int score;
            if (count >= 20)
            {
                score = 100;
            }
            else if (count >= _maxFailuresPerWindow)
            {
                score = 70;
            }
            else if (count >= 5)
            {
                score = 30;
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
                    >= 70 => WPShield.Abstractions.NetworkInspectionAction.Block,
                    _ => WPShield.Abstractions.NetworkInspectionAction.Observe
                },
                MessageKey = "Findings.FailedLogon",
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
    /// Clears the failure history for a specific IP.
    /// </summary>
    public void ClearIp(string sourceIp)
    {
        lock (_lock)
        {
            _failuresByIp.Remove(sourceIp);
        }
    }
}

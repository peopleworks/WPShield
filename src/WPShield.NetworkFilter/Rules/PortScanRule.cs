using System.Collections.Generic;
using System.Linq;
using WPShield.Abstractions;

namespace WPShield.NetworkFilter.Rules;

/// <summary>
/// Detects likely port scans: many distinct destination ports from one source IP
/// within a short window, with little or no payload.
///
/// This is a heuristic rule: legitimate clients rarely connect to dozens of ports
/// in seconds. A high score suggests scanning or probing.
/// </summary>
public sealed class PortScanRule : INetworkInspectionRule
{
    private readonly Dictionary<string, List<(int Port, DateTimeOffset Time)>> _portsByIp = new();
    private readonly object _lock = new();
    private readonly int _maxDistinctPorts;

    public string RuleId => "WP-NET-003";

    public PortScanRule(int maxDistinctPortsPerMinute = 20)
    {
        _maxDistinctPorts = maxDistinctPortsPerMinute;
    }

    public NetworkInspectionResult Inspect(
        NetworkInspectionContext context,
        CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            var now = context.Timestamp;

            if (!_portsByIp.TryGetValue(context.SourceIp, out var entries))
            {
                entries = new List<(int, DateTimeOffset)>();
                _portsByIp[context.SourceIp] = entries;
            }

            entries.RemoveAll(e => now - e.Time > TimeSpan.FromMinutes(1));
            entries.Add((context.DestinationPort, now));

            int distinctPorts = entries.Select(e => e.Port).Distinct().Count();

            int score;
            if (distinctPorts >= 50)
            {
                score = 100;
            }
            else if (distinctPorts >= 30)
            {
                score = 80;
            }
            else if (distinctPorts >= _maxDistinctPorts)
            {
                score = 60;
            }
            else
            {
                score = 0;
            }

            return new NetworkInspectionResult
            {
                RuleId = RuleId,
                Score = score,
                Action = score switch
                {
                    0 => WPShield.Abstractions.NetworkInspectionAction.Allow,
                    >= 80 => WPShield.Abstractions.NetworkInspectionAction.Block,
                    _ => WPShield.Abstractions.NetworkInspectionAction.Observe
                },
                MessageKey = "Findings.NetworkPortScan",
                Evidence = new Dictionary<string, object>
                {
                    ["source_ip"] = context.SourceIp,
                    ["distinct_ports_last_minute"] = distinctPorts,
                    ["threshold"] = _maxDistinctPorts
                }
            };
        }
    }
}

using System.Collections.Generic;
using WPShield.Abstractions;

namespace WPShield.NetworkFilter.Rules;

/// <summary>
/// Rate limits inbound connections per source IP. Intended to mitigate volumetric attacks
/// (port scans, brute force, floods) before they reach IIS or WordPress.
///
/// The rule keeps a sliding 60-second window per IP. Scores rise with connection count,
/// and Block is recommended once the window is saturated.
/// </summary>
public sealed class RateLimitRule : INetworkInspectionRule
{
    private readonly int _maxConnectionsPerMinute;
    private readonly Dictionary<string, List<DateTimeOffset>> _timestamps = new();
    private readonly object _lock = new();

    public string RuleId => "WP-NET-002";

    public RateLimitRule(int maxConnectionsPerMinute = 60)
    {
        _maxConnectionsPerMinute = maxConnectionsPerMinute;
    }

    public NetworkInspectionResult Inspect(
        NetworkInspectionContext context,
        CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            var now = context.Timestamp;

            if (!_timestamps.TryGetValue(context.SourceIp, out var times))
            {
                times = new List<DateTimeOffset>();
                _timestamps[context.SourceIp] = times;
            }

            // Slide the 60-second window.
            times.RemoveAll(t => now - t > TimeSpan.FromMinutes(1));
            times.Add(now);

            int count = times.Count;
            int score = count switch
            {
                > 120 => 100,
                > 90 => 70,
                > 60 => 40,
                _ => 0
            };

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
                MessageKey = "Findings.NetworkRateLimit",
                Evidence = new Dictionary<string, object>
                {
                    ["connections_last_minute"] = count,
                    ["limit_per_minute"] = _maxConnectionsPerMinute,
                    ["source_ip"] = context.SourceIp
                }
            };
        }
    }
}

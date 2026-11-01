using WPShield.Abstractions;

namespace WPShield.NetworkFilter.Rules;

/// <summary>
/// <c>WP-NET-003</c>: distinct destination ports one source tried in the last minute.
/// </summary>
/// <remarks>
/// A SYN reaches the observer whether or not anything listens on the port, so a sweep across closed
/// ports counts too. Score 60 (observe) at the threshold, 80 at twice it, 100 at three times it. Like
/// <see cref="RateLimitRule"/>, the evidence is a SYN, so a Block recommendation becomes a block only
/// with <c>--syn-rules-may-block</c>.
/// </remarks>
public sealed class PortScanRule : INetworkInspectionRule
{
    public const string Id = "WP-NET-003";
    public const int DefaultThreshold = 20;

    private static readonly TimeSpan Window = TimeSpan.FromMinutes(1);

    private readonly int _threshold;
    private readonly int _retained;
    private readonly BoundedSourceTable<Dictionary<int, DateTimeOffset>> _ports;
    private readonly object _gate = new();

    public PortScanRule(int maxDistinctPortsPerMinute = DefaultThreshold, int maximumSources = RateLimitRule.DefaultMaximumSources)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxDistinctPortsPerMinute, 1);
        _threshold = maxDistinctPortsPerMinute;
        _retained = (maxDistinctPortsPerMinute * 3) + 1;
        _ports = new BoundedSourceTable<Dictionary<int, DateTimeOffset>>(maximumSources);
    }

    public string RuleId => Id;

    public NetworkInspectionResult Inspect(NetworkInspectionContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        int distinct;
        lock (_gate)
        {
            var ports = _ports.GetOrAdd(context.SourceIp, () => []);
            foreach (var stale in ports.Where(pair => context.Timestamp - pair.Value > Window).Select(pair => pair.Key).ToList())
            {
                ports.Remove(stale);
            }

            if (ports.ContainsKey(context.DestinationPort) || ports.Count < _retained)
            {
                ports[context.DestinationPort] = context.Timestamp;
            }

            distinct = ports.Count;
        }

        var score = distinct >= _threshold * 3 ? 100 : distinct >= _threshold * 2 ? 80 : distinct >= _threshold ? 60 : 0;
        return NetworkFinding.Create(Id, score, "Findings.NetworkPortScan", context, new Dictionary<string, object>
        {
            ["distinct_ports_last_minute"] = distinct,
            ["threshold"] = _threshold,
        });
    }
}

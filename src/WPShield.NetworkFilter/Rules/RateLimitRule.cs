using WPShield.Abstractions;

namespace WPShield.NetworkFilter.Rules;

/// <summary>
/// <c>WP-NET-002</c>: new TCP connection attempts from one source in the last minute.
/// </summary>
/// <remarks>
/// <para>
/// The observer feeds this rule only SYN packets (<see cref="DivertFilterBuilder.ObserverFilter"/>), so
/// the count is connection attempts, not packets. A browser opens a handful of connections per site;
/// the default threshold of 60 a minute is crossed by crawlers, scanners and busy shared NAT addresses.
/// </para>
/// <para>
/// Score 60 (observe) at the threshold, 80 at twice it and 100 at four times it. A score of 80 or more
/// recommends Block, but a SYN proves nothing about its source address, so the recommendation becomes a
/// block only when the operator passed <c>--syn-rules-may-block</c> (ADR 0006, section 5).
/// </para>
/// </remarks>
public sealed class RateLimitRule : INetworkInspectionRule
{
    public const string Id = "WP-NET-002";
    public const int DefaultThreshold = 60;
    public const int DefaultMaximumSources = 50_000;

    private static readonly TimeSpan Window = TimeSpan.FromMinutes(1);

    private readonly int _threshold;
    private readonly int _retained;
    private readonly BoundedSourceTable<Queue<DateTimeOffset>> _attempts;
    private readonly object _gate = new();

    public RateLimitRule(int maxConnectionsPerMinute = DefaultThreshold, int maximumSources = DefaultMaximumSources)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxConnectionsPerMinute, 1);
        _threshold = maxConnectionsPerMinute;
        _retained = (maxConnectionsPerMinute * 4) + 1;
        _attempts = new BoundedSourceTable<Queue<DateTimeOffset>>(maximumSources);
    }

    public string RuleId => Id;

    public NetworkInspectionResult Inspect(NetworkInspectionContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        int count;
        lock (_gate)
        {
            var times = _attempts.GetOrAdd(context.SourceIp, () => new Queue<DateTimeOffset>());
            while (times.Count > 0 && context.Timestamp - times.Peek() > Window)
            {
                times.Dequeue();
            }

            times.Enqueue(context.Timestamp);
            while (times.Count > _retained)
            {
                times.Dequeue();
            }

            count = times.Count;
        }

        var score = count >= _threshold * 4 ? 100 : count >= _threshold * 2 ? 80 : count >= _threshold ? 60 : 0;
        return NetworkFinding.Create(Id, score, "Findings.NetworkConnectionRate", context, new Dictionary<string, object>
        {
            ["attempts_last_minute"] = count,
            ["threshold"] = _threshold,
        });
    }
}

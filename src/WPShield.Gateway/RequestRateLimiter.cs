using System.Threading.RateLimiting;
using WPShield.Abstractions;
using WPShield.Core;

namespace WPShield.Gateway;

/// <summary>
/// The HTTP half of brute-force defence: a fixed window per client, per site, per rule.
/// </summary>
/// <remarks>
/// <para>
/// <b>Partitioned by the resolved client, never by the connecting peer.</b> Under the production
/// traffic path every request reaches this gateway from a local proxy, so partitioning on
/// <c>RemoteIpAddress</c> would put the entire internet in one bucket — the first ten visitors would
/// exhaust the budget for everyone, and a brute force would be indistinguishable from a busy
/// afternoon. <see cref="ClientAddressResolver"/> has already resolved the address once, at the top
/// of the pipeline, and this reads that answer rather than deriving a second one.
/// </para>
/// <para>
/// <b>Nothing here refuses traffic on its own.</b> The verdict is returned and the caller applies
/// the site's mode, the same way the path and upload inspections do: Monitor records what it would
/// have refused and forwards, Block refuses. A limiter that decided for itself would be the one
/// place in this gateway where Monitor is not Monitor.
/// </para>
/// <para>
/// Idle partitions are reclaimed by <see cref="PartitionedRateLimiter"/> on its own timer, which is
/// what keeps a botnet of new addresses from becoming unbounded memory. Requests are never queued —
/// <c>QueueLimit</c> is zero — because making a caller wait on a rate limiter turns a defence into a
/// way to hold connections open.
/// </para>
/// </remarks>
internal sealed class RequestRateLimiter : IDisposable, IAsyncDisposable
{
    private readonly RateLimitOptions _options;
    private readonly PartitionedRateLimiter<RateLimitLookup>? _limiter;

    public RequestRateLimiter(RateLimitOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;

        if (!options.Enabled || options.Rules.Length == 0)
        {
            return;
        }

        _limiter = PartitionedRateLimiter.Create<RateLimitLookup, string>(lookup =>
            RateLimitPartition.GetFixedWindowLimiter(
                lookup.PartitionKey,
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = lookup.Rule.PermitLimit,
                    Window = TimeSpan.FromSeconds(lookup.Rule.WindowSeconds),
                    QueueLimit = 0,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    AutoReplenishment = true
                }));
    }

    /// <summary>Whether any rule is active. Used to skip the work entirely when it is not.</summary>
    public bool IsActive => _limiter is not null;

    /// <summary>
    /// Finds the rule covering this path, if any, and spends one permit against it.
    /// </summary>
    /// <returns>
    /// <see langword="null"/> when no rule covers the path or the request is within its budget, and
    /// the exceeded rule when it is not. The caller decides what that means.
    /// </returns>
    public RateLimitVerdict? Evaluate(string siteId, string client, string path)
    {
        if (_limiter is null)
        {
            return null;
        }

        ArgumentNullException.ThrowIfNull(siteId);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(path);

        var rule = FindRule(path);
        if (rule is null)
        {
            return null;
        }

        // siteId first so two sites sharing a client address keep separate budgets, and ruleId next
        // so a client near its login budget still reaches an unrelated rule with its own.
        var key = string.Concat(siteId, "|", rule.Id, "|", client);

        using var lease = _limiter.AttemptAcquire(new RateLimitLookup(key, rule));
        return lease.IsAcquired ? null : new RateLimitVerdict(rule.Id, rule.PermitLimit, rule.WindowSeconds);
    }

    private RateLimitRuleOptions? FindRule(string path)
    {
        // Trailing slash trimmed once so /wp-login.php/ and /wp-login.php are one path rather than
        // two budgets, which is otherwise a free doubling for anyone who notices.
        var candidate = path.Length > 1 && path.EndsWith('/') ? path[..^1] : path;

        foreach (var rule in _options.Rules)
        {
            foreach (var configured in rule.Paths)
            {
                if (string.Equals(candidate, configured, StringComparison.OrdinalIgnoreCase))
                {
                    return rule;
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Both disposal interfaces, and the synchronous one is not optional.
    /// </summary>
    /// <remarks>
    /// <c>ServiceProvider</c> throws when it is disposed synchronously and holds a singleton that
    /// implements only <see cref="IAsyncDisposable"/> — "type only implements IAsyncDisposable" — and
    /// the host takes that path on some shutdown routes. A gateway that fails while stopping is a
    /// small problem that looks like a large one at three in the morning.
    /// </remarks>
    public void Dispose()
    {
        _limiter?.Dispose();
    }

    public ValueTask DisposeAsync()
    {
        return _limiter?.DisposeAsync() ?? ValueTask.CompletedTask;
    }

    /// <summary>The partition key and the rule that owns it, passed together so the factory has both.</summary>
    private readonly record struct RateLimitLookup(string PartitionKey, RateLimitRuleOptions Rule);
}

/// <summary>What a client spent, once it has spent too much.</summary>
internal sealed record RateLimitVerdict(string RuleId, int PermitLimit, int WindowSeconds);

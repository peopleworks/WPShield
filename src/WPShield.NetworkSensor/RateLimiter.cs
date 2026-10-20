namespace WPShield.NetworkSensor;

/// <summary>
/// A simple token bucket that bounds the number of events emitted per second.
/// Thread-safe. Used to prevent the sensor from becoming a noise amplifier under high traffic.
/// </summary>
public sealed class RateLimiter
{
    private readonly int _maxTokensPerSecond;
    private readonly object _lock = new();
    private double _tokens;
    private DateTimeOffset _lastRefill;

    /// <summary>
    /// Creates a rate limiter with the given maximum tokens per second.
    /// </summary>
    public RateLimiter(int maxTokensPerSecond)
    {
        _maxTokensPerSecond = maxTokensPerSecond;
        _tokens = maxTokensPerSecond;
        _lastRefill = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Attempts to consume one token. Returns <c>true</c> if the event may be emitted,
    /// <c>false</c> if the rate limit has been exceeded and the event should be dropped.
    /// </summary>
    public bool TryConsume()
    {
        lock (_lock)
        {
            Refill();

            if (_tokens < 1.0)
            {
                return false;
            }

            _tokens -= 1.0;
            return true;
        }
    }

    private void Refill()
    {
        var now = DateTimeOffset.UtcNow;
        var elapsed = (now - _lastRefill).TotalSeconds;

        if (elapsed <= 0.0)
        {
            return;
        }

        _tokens += elapsed * _maxTokensPerSecond;

        if (_tokens > _maxTokensPerSecond)
        {
            _tokens = _maxTokensPerSecond;
        }

        _lastRefill = now;
    }
}

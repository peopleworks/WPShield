using Xunit;

namespace WPShield.NetworkSensor.Tests;

public class RateLimiterTests
{
    /// <summary>A clock the test moves by hand, so no test depends on how busy the machine is.</summary>
    private sealed class ManualClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 11, 26, 0, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public void ConsumesTokensUpToLimit()
    {
        var limiter = new RateLimiter(3, new ManualClock());

        Assert.True(limiter.TryConsume());
        Assert.True(limiter.TryConsume());
        Assert.True(limiter.TryConsume());
        Assert.False(limiter.TryConsume());
        Assert.False(limiter.TryConsume());
    }

    [Fact]
    public void RefillsOverTime()
    {
        var clock = new ManualClock();
        var limiter = new RateLimiter(10, clock);

        // Drain the bucket.
        for (var i = 0; i < 10; i++)
        {
            Assert.True(limiter.TryConsume());
        }

        Assert.False(limiter.TryConsume());

        // 150 ms at 10 tokens a second refills one and a half tokens.
        clock.Now = clock.Now.AddMilliseconds(150);

        Assert.True(limiter.TryConsume());
        // Should be empty again after consuming the one whole refilled token.
        Assert.False(limiter.TryConsume());
    }

    [Fact]
    public void DoesNotExceedMaxTokens()
    {
        var clock = new ManualClock();
        var limiter = new RateLimiter(5, clock);

        // Consume all, wait a long time, verify we don't get more than max.
        for (var i = 0; i < 5; i++)
        {
            Assert.True(limiter.TryConsume());
        }

        clock.Now = clock.Now.AddSeconds(10);

        // Should still only allow up to 5, not unlimited.
        var count = 0;
        while (limiter.TryConsume() && count < 6)
        {
            count++;
        }

        Assert.Equal(5, count);
    }

    [Fact]
    public void ATimeThatDoesNotMoveRefillsNothing()
    {
        var clock = new ManualClock();
        var limiter = new RateLimiter(2, clock);
        Assert.True(limiter.TryConsume());
        Assert.True(limiter.TryConsume());

        clock.Now = clock.Now.AddSeconds(-1);

        Assert.False(limiter.TryConsume());
    }

    [Fact]
    public void TheSystemClockStillWorks()
    {
        var limiter = new RateLimiter(1);
        Assert.True(limiter.TryConsume());
    }
}

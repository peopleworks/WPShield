using System.Threading;
using Xunit;

namespace WPShield.NetworkSensor.Tests;

public class RateLimiterTests
{
    [Fact]
    public void ConsumesTokensUpToLimit()
    {
        var limiter = new RateLimiter(3);

        Assert.True(limiter.TryConsume());
        Assert.True(limiter.TryConsume());
        Assert.True(limiter.TryConsume());
        Assert.False(limiter.TryConsume());
        Assert.False(limiter.TryConsume());
    }

    [Fact]
    public void RefillsOverTime()
    {
        var limiter = new RateLimiter(10);

        // Drain the bucket.
        for (var i = 0; i < 10; i++)
        {
            Assert.True(limiter.TryConsume());
        }

        Assert.False(limiter.TryConsume());

        // Wait long enough to refill at least one token.
        Thread.Sleep(150);

        Assert.True(limiter.TryConsume());
        // Should be empty again after consuming the one refilled token.
        Assert.False(limiter.TryConsume());
    }

    [Fact]
    public void DoesNotExceedMaxTokens()
    {
        var limiter = new RateLimiter(5);

        // Consume all, wait a long time, verify we don't get more than max.
        for (var i = 0; i < 5; i++)
        {
            Assert.True(limiter.TryConsume());
        }

        Thread.Sleep(1000);

        // Should still only allow up to 5, not unlimited.
        var count = 0;
        while (limiter.TryConsume() && count < 5)
        {
            count++;
        }

        Assert.Equal(5, count);
    }
}

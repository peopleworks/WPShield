using Xunit;

namespace WPShield.Gateway.Tests;

/// <summary>
/// M3 — the concurrent-inspection semaphore bounds how many multipart bodies may be buffered
/// at once. TryEnter never blocks; Release frees a slot; the count tracks active inspections.
/// </summary>
public sealed class ConcurrentInspectionLimiterTests
{
    [Fact]
    public void ConstructorRejectsZero()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ConcurrentInspectionLimiter(0));
    }

    [Fact]
    public void ConstructorRejectsNegative()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ConcurrentInspectionLimiter(-1));
    }

    [Fact]
    public void ConstructorAcceptsOne()
    {
        using var limiter = new ConcurrentInspectionLimiter(1);
        Assert.Equal(1, limiter.MaxConcurrentInspections);
        Assert.Equal(0, limiter.CurrentCount);
        Assert.Equal(1, limiter.AvailableCount);
    }

    [Fact]
    public void TryEnterTakesASlot()
    {
        using var limiter = new ConcurrentInspectionLimiter(2);
        Assert.True(limiter.TryEnter());
        Assert.Equal(1, limiter.CurrentCount);
        Assert.Equal(1, limiter.AvailableCount);
        limiter.Release();
        Assert.Equal(0, limiter.CurrentCount);
        Assert.Equal(2, limiter.AvailableCount);
    }

    [Fact]
    public void TryEnterRefusesWhenExhausted()
    {
        using var limiter = new ConcurrentInspectionLimiter(1);
        Assert.True(limiter.TryEnter());
        Assert.False(limiter.TryEnter());
        Assert.Equal(1, limiter.CurrentCount);
        Assert.Equal(0, limiter.AvailableCount);
        limiter.Release();
        Assert.True(limiter.TryEnter());
    }

    [Fact]
    public void ReleaseBalancesEnter()
    {
        using var limiter = new ConcurrentInspectionLimiter(2);
        Assert.True(limiter.TryEnter());
        Assert.Equal(1, limiter.CurrentCount);
        limiter.Release();
        Assert.Equal(0, limiter.CurrentCount);
        Assert.Equal(2, limiter.AvailableCount);
    }

    [Fact]
    public void MultipleSlotsTrackedIndependently()
    {
        using var limiter = new ConcurrentInspectionLimiter(3);
        Assert.True(limiter.TryEnter());
        Assert.True(limiter.TryEnter());
        Assert.Equal(2, limiter.CurrentCount);
        Assert.Equal(1, limiter.AvailableCount);
        // One slot remains, so TryEnter still succeeds.
        Assert.True(limiter.TryEnter());
        Assert.Equal(3, limiter.CurrentCount);
        Assert.Equal(0, limiter.AvailableCount);
        // Now exhausted.
        Assert.False(limiter.TryEnter());
        Assert.Equal(3, limiter.CurrentCount);
        limiter.Release();
        Assert.Equal(2, limiter.CurrentCount);
        Assert.True(limiter.TryEnter());
        Assert.Equal(3, limiter.CurrentCount);
    }

    [Fact]
    public void DisposeDoesNotThrow()
    {
        var limiter = new ConcurrentInspectionLimiter(2);
        limiter.TryEnter();
        limiter.Dispose();
        // After dispose the object is unusable; this test only asserts no exception.
        Assert.True(true);
    }
}

using Xunit;

namespace WPShield.Desktop.Tests;

public sealed class AdapterTrafficHistoryTests
{
    private readonly AdapterTrafficHistory history = new();

    private void Add(int seconds, long received, long sent) => history.Add(
        DateTimeOffset.UnixEpoch.AddSeconds(seconds), TimeSpan.FromSeconds(seconds), new(received, sent));

    [Fact]
    public void MeasuresDirectionalDeltasAndIdleIntervals()
    {
        Add(0, 100000, 50000);
        Add(2, 100200, 50600);
        Add(4, 100200, 50600);
        var rows = history.Snapshot();
        Assert.Null(rows[0].Received);
        Assert.Equal(RateStatus.Baseline, rows[0].Status);
        Assert.Equal(100, rows[1].Received);
        Assert.Equal(300, rows[1].Sent);
        Assert.Equal(0, rows[2].Received);
        Assert.Equal(0, rows[2].Sent);
    }

    [Theory]
    [InlineData(2, 99, 200, "CounterReset")]
    [InlineData(6, 120, 200, "Delayed")]
    [InlineData(0, 120, 200, "ClockChanged")]
    public void AGapHasNoRatesAndRebasesTheNextInterval(int seconds, long rx, long tx, string expected)
    {
        Add(0, 100, 100);
        Add(seconds, rx, tx);
        Add(seconds + 2, rx + 20, tx + 10);
        var rows = history.Snapshot();
        Assert.Equal(expected, rows[1].Status.ToString());
        Assert.Null(rows[1].Received);
        Assert.Null(rows[1].Sent);
        Assert.Equal(10, rows[2].Received);
        Assert.Equal(5, rows[2].Sent);
    }

    [Fact]
    public void UnavailableAdapterRequiresTwoFreshReadings()
    {
        Add(0, 4, 8);
        history.Add(DateTimeOffset.UnixEpoch.AddSeconds(2), TimeSpan.FromSeconds(2), null);
        Add(4, 90, 200);
        Add(6, 90, 400);
        var rows = history.Snapshot();
        Assert.Equal(RateStatus.Unavailable, rows[1].Status);
        Assert.Equal(RateStatus.Baseline, rows[2].Status);
        Assert.Null(rows[2].Sent);
        Assert.Equal(100, rows[3].Sent);
    }

    [Fact]
    public void ClockJumpInvalidatesAnOtherwiseNormalInterval()
    {
        Add(0, 0, 0);
        history.Add(DateTimeOffset.UnixEpoch.AddSeconds(20), TimeSpan.FromSeconds(2), new(200, 400));
        Assert.Equal(RateStatus.ClockChanged, history.Snapshot()[1].Status);
        Assert.Null(history.Snapshot()[1].Received);
    }

    [Fact]
    public void PausedSnapshotIsIndependentOfTheRollingWindow()
    {
        Add(0, 0, 0);
        var frozen = history.Snapshot();
        for (var i = 1; i <= 32; i++) Add(2 * i, i, i);
        Assert.Equal(DateTimeOffset.UnixEpoch, Assert.Single(frozen).EndUtc);
        var live = history.Snapshot();
        Assert.Equal(30, live.Length);
        Assert.Equal(DateTimeOffset.UnixEpoch.AddSeconds(6), live[0].EndUtc);
        Assert.Equal(DateTimeOffset.UnixEpoch.AddSeconds(64), live[^1].EndUtc);
    }
}

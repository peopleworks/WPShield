using System.Net;
using WPShield.Evidence;
using Xunit;

namespace WPShield.Evidence.Tests;

/// <summary>
/// How a timeline decides that a bucket was recorded. A quiet bucket and an unrecorded one must never
/// look alike - and a recorded one must not look unrecorded either, or every view grows a permanent
/// grey bar at "now" that teaches the operator to ignore grey.
/// </summary>
public sealed class EvidenceCoverageTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);
    private readonly string directory = Path.Combine(Path.GetTempPath(), "wpshield-evidence-tests", Guid.NewGuid().ToString("N"));

    public EvidenceCoverageTests() => Directory.CreateDirectory(directory);

    public void Dispose()
    {
        try { Directory.Delete(directory, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private EvidenceStore Open() => EvidenceStore.OpenForWriting(Path.Combine(directory, EvidenceStore.FileName));

    [Fact]
    public void TheNewestBucketIsCoveredWhenTheCollectorVouchedForTheLastTwoMinutes()
    {
        using var store = Open();
        var writer = new EvidenceWriter(store);
        // The collector extends its interval periodically, so it always ends a little before "now".
        writer.BeginCoverage(EvidenceWriter.RawSource, Now.AddHours(-3), Now.AddMinutes(-1));

        var buckets = new EvidenceQueries(store).Timeline(Now.AddHours(-2), Now, TimeSpan.FromHours(1));

        Assert.All(buckets, b => Assert.True(b.Covered));
    }

    [Fact]
    public void ACollectorThatStoppedLongerAgoLeavesTheNewestBucketUncovered()
    {
        using var store = Open();
        var writer = new EvidenceWriter(store);
        writer.BeginCoverage(EvidenceWriter.RawSource, Now.AddHours(-3), Now.AddMinutes(-10));

        var buckets = new EvidenceQueries(store).Timeline(Now.AddHours(-2), Now, TimeSpan.FromHours(1));

        Assert.True(buckets[0].Covered);
        Assert.False(buckets[^1].Covered);
    }

    [Fact]
    public void IntervalsThatTouchAfterARestartCoverADayBucketTogether()
    {
        using var store = Open();
        var writer = new EvidenceWriter(store);
        var day = Now.AddDays(-1);
        writer.BeginCoverage(EvidenceWriter.RawSource, day.AddHours(-1), day.AddHours(9));
        writer.BeginCoverage(EvidenceWriter.RawSource, day.AddHours(9), Now);

        var buckets = new EvidenceQueries(store).Timeline(day, Now, TimeSpan.FromDays(1));

        Assert.True(Assert.Single(buckets).Covered);
    }

    [Fact]
    public void ARealGapBetweenIntervalsIsNeverBridged()
    {
        using var store = Open();
        var writer = new EvidenceWriter(store);
        var day = Now.AddDays(-1);
        writer.BeginCoverage(EvidenceWriter.RawSource, day.AddHours(-1), day.AddHours(9));
        writer.BeginCoverage(EvidenceWriter.RawSource, day.AddHours(9).AddMinutes(30), Now);

        var queries = new EvidenceQueries(store);

        Assert.False(Assert.Single(queries.Timeline(day, Now, TimeSpan.FromDays(1))).Covered);
        var hourly = queries.Timeline(day, Now, TimeSpan.FromHours(1));
        Assert.False(hourly[9].Covered);
        Assert.True(hourly[8].Covered);
        Assert.True(hourly[10].Covered);
    }

    [Fact]
    public void AStoreWithRecordsButNoCoverageSaysSoInsteadOfVouching()
    {
        using var store = Open();
        new EvidenceWriter(store).Append([new AuthFailure(Now.AddMinutes(-5), AttemptPairing.SecurityChannel,
            IPAddress.Parse("203.0.113.1"), null, "admin", "bad-password", 10, 1)]);

        var queries = new EvidenceQueries(store);
        var summary = queries.Summary(Now.AddHours(-1), Now);

        Assert.Equal(1, summary.Attempts);
        Assert.Null(summary.CoveredFrom);
        Assert.All(queries.Timeline(Now.AddHours(-1), Now, TimeSpan.FromMinutes(5)), b => Assert.False(b.Covered));
    }
}

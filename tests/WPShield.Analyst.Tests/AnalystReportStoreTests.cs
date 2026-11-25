using System.Text;
using WPShield.Evidence;

namespace WPShield.Analyst.Tests;

/// <summary>The report store: never creates its directory, keeps 90 days and 1,000 reports, and bounds what it keeps.</summary>
public sealed class AnalystReportStoreTests : IDisposable
{
    private readonly TempDirectory directory = new();

    public void Dispose() => directory.Dispose();

    private static ReportStart Start(DateTimeOffset at, string provider = "anthropic", bool pays = true) =>
        new(at, provider, pays, "claude-opus-5-5", AnalystRole.Ask, null, "who attacked?", "en");

    [Fact]
    public void TheStoreNeverCreatesItsDirectoryAndSaysWhatTheEvidenceStoreSays()
    {
        var missing = Path.Combine(directory.Path, "absent", AnalystReportStore.FileName);

        var error = Assert.Throws<DirectoryNotFoundException>(() => AnalystReportStore.Open(missing));

        Assert.False(Directory.Exists(Path.GetDirectoryName(missing)));
        Assert.Equal(EvidenceStore.MissingDirectoryMessage(Path.GetDirectoryName(missing)), error.Message);
    }

    [Fact]
    public void TheStoreLivesBesideTheEvidenceStore()
    {
        var evidence = Path.Combine(directory.Path, EvidenceStore.FileName);

        Assert.Equal(Path.Combine(directory.Path, "wpshield-analyst.db"), AnalystReportStore.PathBeside(evidence));
    }

    [Fact]
    public void ReadingWhereNoReportWasEverWrittenCreatesNothing()
    {
        Assert.Null(AnalystReportStore.OpenReadOnly(directory.ReportStore));
        Assert.False(File.Exists(directory.ReportStore));
    }

    [Fact]
    public void ReportsOlderThanNinetyDaysArePrunedWithTheirToolCalls()
    {
        using var store = AnalystReportStore.Open(directory.ReportStore);
        var old = store.Begin(Start(Fixtures.Now.AddDays(-91)));
        store.AddToolCall(old, 1, "coverage", "{}", false);
        var kept = store.Begin(Start(Fixtures.Now.AddDays(-89)));

        store.Begin(Start(Fixtures.Now));

        Assert.Null(store.Get(old));
        Assert.NotNull(store.Get(kept));
        Assert.Equal(2, store.Count());
    }

    [Fact]
    public void AtMostOneThousandReportsAreKept()
    {
        using var store = AnalystReportStore.Open(directory.ReportStore);
        long first = 0;
        for (var i = 0; i < AnalystReportStore.MaxReports + 5; i++)
        {
            var id = store.Begin(Start(Fixtures.Now.AddMinutes(-2000 + i)));
            if (i == 0) first = id;
        }

        store.Prune(Fixtures.Now);

        Assert.Equal(AnalystReportStore.MaxReports, store.Count());
        Assert.Null(store.Get(first));
    }

    [Fact]
    public void TheTextIsBoundedAtSixtyFourKilobytesAndSaysItWasCut()
    {
        using var store = AnalystReportStore.Open(directory.ReportStore);
        var id = store.Begin(Start(Fixtures.Now));
        var text = string.Join('\n', Enumerable.Repeat(new string('á', 1000), 100));

        store.Finish(id, new ReportEnd(Fixtures.Now, ReportStatus.Completed, "end_turn", Text: text));

        var report = store.Get(id)!;
        Assert.True(report.TextTruncated);
        Assert.True(Encoding.UTF8.GetByteCount(report.Text) <= ReportText.MaxBytes);
        Assert.StartsWith(new string('á', 1000) + "\n", report.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void UsageCountsEveryRunOfTheUtcDayAndOnlyTheTokensTheOperatorPays()
    {
        using var store = AnalystReportStore.Open(directory.ReportStore);
        var paid = store.Begin(Start(Fixtures.Now));
        store.AddTurn(paid, new ProviderTurn("claude-opus-5-5", "end_turn", null, null, "", [], 1200, 10));
        var relay = store.Begin(Start(Fixtures.Now, "relay", pays: false));
        store.AddTurn(relay, new ProviderTurn("claude-opus-5-5", "end_turn", null, null, "", [], 9000, 10));
        store.Begin(Start(Fixtures.Now.AddDays(-1)));

        var usage = store.UsageOn(Fixtures.Now);

        Assert.Equal(2, usage.Runs);
        Assert.Equal(1200, usage.InputTokens);
        Assert.Equal(new DateTimeOffset(2026, 11, 24, 0, 0, 0, TimeSpan.Zero), usage.DayStart);
    }

    [Fact]
    public void AReportRecordsProviderModelRoleQuestionTokensStopReasonAndToolCalls()
    {
        using var store = AnalystReportStore.Open(directory.ReportStore);
        var id = store.Begin(Start(Fixtures.Now));
        store.AddTurn(id, new ProviderTurn("claude-opus-5", "end_turn", null, null, "", [], 100, 20, FellBack: true));
        store.AddToolCall(id, 1, "source_history", """{"address":"203.0.113.7"}""", false);
        store.Finish(id, new ReportEnd(Fixtures.Now.AddMinutes(1), ReportStatus.Completed, "end_turn", Text: "An answer."));

        var report = store.Get(id)!;

        Assert.Equal("anthropic", report.Provider);
        Assert.Equal("claude-opus-5-5", report.Model);
        Assert.Equal("claude-opus-5", report.AnsweredBy);
        Assert.True(report.FellBack);
        Assert.Equal("ask", report.Role);
        Assert.Equal("who attacked?", report.Question);
        Assert.Equal(100, report.InputTokens);
        Assert.Equal(20, report.OutputTokens);
        Assert.Equal("end_turn", report.StopReason);
        var call = Assert.Single(report.ToolCalls);
        Assert.Equal("source_history", call.Name);
        Assert.Equal("""{"address":"203.0.113.7"}""", call.Arguments);
    }

    [Fact]
    public void AReadOnlyStoreRefusesToWrite()
    {
        using (var writer = AnalystReportStore.Open(directory.ReportStore)) writer.Begin(Start(Fixtures.Now));
        using var reader = AnalystReportStore.OpenReadOnly(directory.ReportStore)!;

        Assert.Throws<InvalidOperationException>(() => reader.Begin(Start(Fixtures.Now)));
        Assert.Equal(1, reader.Count());
    }
}

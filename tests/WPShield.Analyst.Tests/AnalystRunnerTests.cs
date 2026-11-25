using System.Net;
using System.Text.Json.Nodes;

namespace WPShield.Analyst.Tests;

/// <summary>
/// The loop: every way a run can end, the bounds, and the budgets, with a scripted provider and a real
/// report store in a temporary directory. The Anthropic SDK round trip runs here too, over a fake handler.
/// </summary>
public sealed class AnalystRunnerTests : IDisposable
{
    private readonly TempDirectory directory = new();
    private readonly FixedClock clock = new(Fixtures.Now);
    private readonly AnalystReportStore store;
    private readonly FakeTool coverage = new("coverage");
    private readonly FakeTool summary = new("attacks_summary");

    public AnalystRunnerTests() => store = AnalystReportStore.Open(directory.ReportStore);

    public void Dispose()
    {
        store.Dispose();
        directory.Dispose();
    }

    private AnalystRunner Runner(IAnalystProvider provider, TimeSpan? timeout = null) =>
        new(provider, [coverage, summary], store, clock) { Timeout = timeout ?? AnalystRunner.RunTimeout };

    private static AnalystRunRequest Digest(AnalystConfiguration? configuration = null) =>
        new(AnalystRole.Digest, "24h", null, configuration ?? Fixtures.Configuration());

    private static ProviderTurn Tools(params (string Id, string Name)[] calls) =>
        new("claude-opus-5-5", "tool_use", null, null, "", [.. calls.Select(c => new AnalystToolCall(c.Id, c.Name, new JsonObject { ["range"] = "24h" }))], 1000, 50);

    private static ProviderTurn Answer(string text, long input = 2000) => new("claude-opus-5-5", "end_turn", null, null, text, [], input, 400);

    [Fact]
    public async Task ACompletedRunRunsEachToolPassesItsAnswerBackAndKeepsTheText()
    {
        IReadOnlyList<AnalystToolOutcome>? seen = null;
        var provider = new SimulatedProvider((turn, outcomes, _) =>
        {
            if (turn == 1) seen = outcomes;
            return Task.FromResult(turn == 0 ? Tools(("t1", "coverage"), ("t2", "attacks_summary")) : Answer("Three failed logons; coverage complete."));
        });

        var report = store.Get(await Runner(provider).RunAsync(Digest(), CancellationToken.None))!;

        Assert.Equal(ReportStatus.Completed, report.Status);
        Assert.Equal("Three failed logons; coverage complete.", report.Text);
        Assert.Equal(["coverage", "attacks_summary"], report.ToolCalls.Select(c => c.Name));
        Assert.Equal("""{"range":"24h"}""", report.ToolCalls[0].Arguments);
        Assert.Equal(["t1", "t2"], seen!.Select(o => o.CallId));
        Assert.Single(coverage.Calls);
        Assert.Equal(3000, report.InputTokens);
        Assert.Equal(450, report.OutputTokens);
        Assert.Equal("digest", report.Role);
        Assert.Equal("24h", report.Subject);
        var spec = Assert.Single(provider.Started);
        Assert.Contains("untrusted", spec.SystemPrompt, StringComparison.Ordinal);
        Assert.Contains("never act", spec.SystemPrompt, StringComparison.Ordinal);
        Assert.Contains("never a quiet period", spec.SystemPrompt, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheAnthropicSdkRoundTripRunsThroughTheLoop()
    {
        var handler = new FakeHandler()
            .ThenJson(FakeHandler.Message("tool_use", FakeHandler.ToolUse("toolu_1", "coverage", """{"range":"24h"}""")))
            .ThenJson(FakeHandler.Message("end_turn", FakeHandler.Text("Coverage was complete."), input: 1800));
        using var provider = MessagesProvider.Anthropic("sk-ant-test-runner-key-000000", "claude-opus-5-5", "medium", handler);

        var report = store.Get(await Runner(provider).RunAsync(Digest(), CancellationToken.None))!;

        Assert.Equal(ReportStatus.Completed, report.Status);
        Assert.Equal("Coverage was complete.", report.Text);
        Assert.Equal("claude-opus-5-5", report.AnsweredBy);
        Assert.Equal("coverage", Assert.Single(report.ToolCalls).Name);
        Assert.Equal(2800, report.InputTokens);
        var result = handler.Requests[1].Json["messages"]![2]!["content"]![0]!;
        Assert.Contains("failed_logons", (string)result["content"]!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheThirteenthToolCallStopsTheRunNamesTheBoundAndKeepsNoText()
    {
        var provider = new SimulatedProvider((turn, _, _) => Task.FromResult(Tools(($"t{turn}", "coverage")) with { Text = "Partial notes" }));

        var report = store.Get(await Runner(provider).RunAsync(Digest(), CancellationToken.None))!;

        Assert.Equal(ReportStatus.Stopped, report.Status);
        Assert.Contains("12 tool calls", report.Bound, StringComparison.Ordinal);
        Assert.Equal(12, report.ToolCalls.Count);
        Assert.Equal(12, coverage.Calls.Count);
        Assert.Equal("", report.Text);
    }

    [Fact]
    public async Task OneTurnAskingForMoreThanTheBoundRunsNoneOfIt()
    {
        var calls = Enumerable.Range(0, 13).Select(i => ($"t{i}", "coverage")).ToArray();
        var provider = SimulatedProvider.Scripted(Tools(calls));

        var report = store.Get(await Runner(provider).RunAsync(Digest(), CancellationToken.None))!;

        Assert.Equal(ReportStatus.Stopped, report.Status);
        Assert.Empty(report.ToolCalls);
        Assert.Empty(coverage.Calls);
    }

    [Fact]
    public async Task TheTimeBoundStopsARunAsATimeout()
    {
        var provider = new SimulatedProvider(async (_, _, token) =>
        {
            await Task.Delay(Timeout.Infinite, token);
            return Answer("never");
        });

        var report = store.Get(await Runner(provider, TimeSpan.FromMilliseconds(200)).RunAsync(Digest(), CancellationToken.None))!;

        Assert.Equal(ReportStatus.TimedOut, report.Status);
        Assert.NotNull(report.Bound);
        Assert.Equal("", report.Text);
    }

    [Fact]
    public async Task CancellingARunRecordsItAsCancelled()
    {
        using var cancel = new CancellationTokenSource();
        var provider = new SimulatedProvider(async (_, _, token) =>
        {
            await cancel.CancelAsync();
            await Task.Delay(Timeout.Infinite, token);
            return Answer("never");
        });

        var report = store.Get(await Runner(provider).RunAsync(Digest(), cancel.Token))!;

        Assert.Equal(ReportStatus.Cancelled, report.Status);
        Assert.Contains("Ctrl+C", report.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheDailyRunBudgetRefusesTheRunBeforeAnythingIsSent()
    {
        var provider = SimulatedProvider.Scripted(Answer("one"), Answer("two"));
        await Runner(provider).RunAsync(Digest(Fixtures.Configuration(dailyRuns: 1)), CancellationToken.None);

        var refused = await Assert.ThrowsAsync<AnalystBudgetException>(() =>
            Runner(provider).RunAsync(Digest(Fixtures.Configuration(dailyRuns: 1)), CancellationToken.None));

        Assert.Equal("analyst.daily_runs", refused.Bound);
        Assert.Contains("analyst.daily_runs", refused.Message, StringComparison.Ordinal);
        Assert.Contains("UTC", refused.Message, StringComparison.Ordinal);
        Assert.Single(provider.Started);
        Assert.Equal(1, store.Count());
    }

    [Fact]
    public async Task TheRunBudgetCountsTheUtcDay()
    {
        var provider = SimulatedProvider.Scripted(Answer("one"), Answer("two"));
        await Runner(provider).RunAsync(Digest(Fixtures.Configuration(dailyRuns: 1)), CancellationToken.None);
        clock.Now = new DateTimeOffset(2026, 11, 25, 0, 0, 1, TimeSpan.Zero);

        var report = store.Get(await Runner(provider).RunAsync(Digest(Fixtures.Configuration(dailyRuns: 1)), CancellationToken.None))!;

        Assert.Equal(ReportStatus.Completed, report.Status);
    }

    [Fact]
    public async Task TheDailyInputTokenBudgetRefusesARunOnAProviderTheOperatorPays()
    {
        var paid = new SimulatedProvider((_, _, _) => Task.FromResult(Answer("spent", input: 60_000))) { OperatorPays = true };
        await Runner(paid).RunAsync(Digest(Fixtures.Configuration(dailyInputTokens: 50_000)), CancellationToken.None);

        var refused = await Assert.ThrowsAsync<AnalystBudgetException>(() =>
            Runner(paid).RunAsync(Digest(Fixtures.Configuration(dailyInputTokens: 50_000)), CancellationToken.None));

        Assert.Equal("analyst.daily_input_tokens", refused.Bound);
        Assert.Contains("50,000", refused.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARelayRunCountsAsARunButItsTokensCostZero()
    {
        var relay = new SimulatedProvider((_, _, _) => Task.FromResult(Answer("free", input: 60_000))) { OperatorPays = false };
        await Runner(relay).RunAsync(Digest(Fixtures.Configuration(dailyInputTokens: 50_000)), CancellationToken.None);

        var report = store.Get(await Runner(relay).RunAsync(Digest(Fixtures.Configuration(dailyInputTokens: 50_000)), CancellationToken.None))!;

        Assert.Equal(ReportStatus.Completed, report.Status);
        Assert.Equal(60_000, report.InputTokens);
        Assert.Equal(new AnalystUsage(2, 0, new DateTimeOffset(2026, 11, 24, 0, 0, 0, TimeSpan.Zero)), store.UsageOn(Fixtures.Now));
    }

    [Fact]
    public async Task TheInputBudgetStopsARunThatReachesItHalfway()
    {
        var paid = new SimulatedProvider((turn, _, _) => Task.FromResult(turn == 0 ? Tools(("t1", "coverage")) with { InputTokens = 30_000 } : Answer("late")))
        { OperatorPays = true };

        var report = store.Get(await Runner(paid).RunAsync(Digest(Fixtures.Configuration(dailyInputTokens: 20_000)), CancellationToken.None))!;

        Assert.Equal(ReportStatus.Stopped, report.Status);
        Assert.Contains("analyst.daily_input_tokens", report.Bound, StringComparison.Ordinal);
        Assert.Equal("", report.Text);
        Assert.Equal(30_000, report.InputTokens);
    }

    [Fact]
    public async Task ARefusalIsRecordedAsARefusalWithItsCategoryNeverAsAnEmptyReport()
    {
        var provider = SimulatedProvider.Scripted(new ProviderTurn("claude-opus-5-5", "refusal", "cyber", "Declined.", "", [], 900, 0));

        var report = store.Get(await Runner(provider).RunAsync(Digest(), CancellationToken.None))!;

        Assert.Equal(ReportStatus.Refused, report.Status);
        Assert.Equal("cyber", report.RefusalCategory);
        var output = new StringWriter();
        ReportRenderer.Render(report, output);
        Assert.Contains("declined", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("cyber", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("not an empty report", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnAnswerCutOffByTheOutputCapIsMarkedTruncated()
    {
        var provider = SimulatedProvider.Scripted(new ProviderTurn("claude-opus-5-5", "max_tokens", null, null, "The first half", [], 900, 16_000));

        var report = store.Get(await Runner(provider).RunAsync(Digest(), CancellationToken.None))!;

        Assert.Equal(ReportStatus.Truncated, report.Status);
        Assert.Equal("The first half", report.Text);
        Assert.Contains("16,000", report.Bound, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnUnknownToolIsAnErrorTheModelReadsNotACrash()
    {
        IReadOnlyList<AnalystToolOutcome>? seen = null;
        var provider = new SimulatedProvider((turn, outcomes, _) =>
        {
            if (turn == 1) seen = outcomes;
            return Task.FromResult(turn == 0 ? Tools(("t1", "run_shell")) : Answer("done"));
        });

        var report = store.Get(await Runner(provider).RunAsync(Digest(), CancellationToken.None))!;

        Assert.Equal(ReportStatus.Completed, report.Status);
        var outcome = Assert.Single(seen!);
        Assert.True(outcome.IsError);
        Assert.Contains("unknown-tool", outcome.Json, StringComparison.Ordinal);
        Assert.True(Assert.Single(report.ToolCalls).IsError);
    }

    [Fact]
    public async Task AProviderFailureIsAFailedReportWithItsReason()
    {
        var handler = new FakeHandler().Then(HttpStatusCode.InternalServerError, """{"type":"error","error":{"type":"api_error","message":"boom"}}""")
            .Then(HttpStatusCode.InternalServerError, """{"type":"error","error":{"type":"api_error","message":"boom"}}""")
            .Then(HttpStatusCode.InternalServerError, """{"type":"error","error":{"type":"api_error","message":"boom"}}""");
        using var provider = MessagesProvider.Anthropic("sk-ant-test-runner-key-000000", "claude-opus-5-5", "medium", handler);

        var report = store.Get(await Runner(provider).RunAsync(Digest(), CancellationToken.None))!;

        Assert.Equal(ReportStatus.Failed, report.Status);
        Assert.Contains("5xx", report.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheReportTextIsCleanedOfControlAndFormatCharacters()
    {
        var provider = SimulatedProvider.Scripted(Answer("Line one\u001b[31m red\nLine​ two\r\nThird"));

        var report = store.Get(await Runner(provider).RunAsync(Digest(), CancellationToken.None))!;

        Assert.Equal("Line one�[31m red\nLine� two\nThird", report.Text);
    }

    [Fact]
    public void ThePromptsSayTheTextIsDataTheAnalystNeverActsAndWhichLanguage()
    {
        foreach (var role in Enum.GetValues<AnalystRole>())
        {
            var english = AnalystPrompts.System(role, spanish: false);
            var spanish = AnalystPrompts.System(role, spanish: true);
            Assert.Contains("not instructions", english, StringComparison.Ordinal);
            Assert.Contains("outside this conversation", english, StringComparison.Ordinal);
            Assert.Contains("gap in coverage", english, StringComparison.Ordinal);
            Assert.Contains("Write in English", english, StringComparison.Ordinal);
            Assert.Contains("Write in Spanish", spanish, StringComparison.Ordinal);
            Assert.Contains(AnalystPrompts.LooseningMarker(true), spanish, StringComparison.Ordinal);
        }
    }
}

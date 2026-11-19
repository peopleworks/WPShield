using System.Text;
using System.Text.Json.Nodes;
using WPShield.Abstractions;
using WPShield.Cli.Preview;
using WPShield.Core;
using WPShield.Rules.WordPress;

namespace WPShield.Cli.Tests.Preview;

public sealed class PolicyPreviewTests
{
    [Theory]
    [InlineData("Monitor", 80, ProtectionMode.Block, 80, 1, 0, 1)]
    [InlineData("Monitor", 79, ProtectionMode.Block, 80, 0, 0, 0)]
    [InlineData("Block", 90, ProtectionMode.Monitor, 80, 0, 1, 1)]
    [InlineData("Block", 90, ProtectionMode.Block, 95, 0, 1, 1)]
    [InlineData("Block", 90, ProtectionMode.Block, 80, 0, 0, 0)]
    public async Task Comparison_ReportsActualRecommendationChanges(string originalMode, int score,
        ProtectionMode candidateMode, int candidateBlock, int refused, int permitted, int changed)
    {
        var report = await ReadAsync(Event(originalMode, score), new(candidateMode, 30, candidateBlock));
        Assert.Equal("complete", report.Status);
        Assert.Equal(1, report.EligibleRecords);
        Assert.Equal(refused, report.NewlyRefused);
        Assert.Equal(permitted, report.NewlyPermitted);
        Assert.Equal(changed, report.ChangedRecommendations);
        Assert.Equal(1 - changed, report.UnchangedRecommendations);
        var group = Assert.Single(report.Comparisons);
        Assert.Equal(originalMode, group.Source.Mode);
        Assert.Equal(refused, group.NewlyRefused);
        Assert.Equal(permitted, group.NewlyPermitted);
    }

    [Fact]
    public async Task Scores_AreNotSummedAcrossPathAndUpload()
    {
        var record = Event(score: 50);
        State(record)["PathScore"] = 50;
        State(record)["PathAction"] = "Observe";
        var report = await ReadAsync(record);
        Assert.Equal(0, report.NewlyRefused);
        Assert.Equal(1, report.UnchangedRecommendations);
    }

    [Fact]
    public async Task ObserveThreshold_ChangesRecommendationWithoutClaimingARefusal()
    {
        var report = await ReadAsync(Event(score: 40), new(ProtectionMode.Block, 50, 80));
        Assert.Equal(1, report.ChangedRecommendations);
        Assert.Equal(0, report.NewlyRefused);
        Assert.Equal(0, report.NewlyPermitted);
    }

    [Theory]
    [InlineData("partial", "malformed")]
    [InlineData("partial", "limit_exceeded")]
    [InlineData("partial", "request_cancelled")]
    [InlineData("not_inspected", "capacity_exhausted")]
    [InlineData("not_inspected", "inspection_disabled")]
    [InlineData("not_started", "not_reached")]
    public async Task MissingInspection_NeverLooksLikeZeroImpact(string status, string reason)
    {
        var record = Event();
        State(record)["UploadStatus"] = status;
        State(record)["UploadReason"] = reason;
        var report = await ReadAsync(record);
        AssertCannotEvaluate(report, "incomplete_inspection");
    }

    [Theory]
    [InlineData("non_multipart")]
    [InlineData("empty_body")]
    public async Task OutOfScopeBody_IsSkippedRatherThanAssignedAScore(string reason)
    {
        var record = Event(score: 0);
        var state = State(record);
        state["UploadStatus"] = "not_inspected";
        state["UploadReason"] = reason;
        state["UploadAction"] = null;
        state["UploadScore"] = null;
        var report = await ReadAsync(record, new(ProtectionMode.Block, 0, 1));
        Assert.Equal("complete", report.Status);
        Assert.Equal(1, report.ChangedRecommendations); // Path 0 crosses observe 0; no fabricated upload score.
        Assert.Equal(0, report.NewlyRefused);
    }

    [Theory]
    [InlineData("disabled", "disabled_or_unknown_mode")]
    [InlineData("rate", "rate_budget_or_missing_state")]
    [InlineData("transport", "incomplete_exchange")]
    [InlineData("cancelled", "incomplete_exchange")]
    [InlineData("provenance", "missing_provenance")]
    [InlineData("schema", "unsupported_schema")]
    [InlineData("contradiction", "inconsistent_outcome")]
    [InlineData("truncated_ids", "incomplete_inspection")]
    [InlineData("missing_score", "incomplete_inspection")]
    [InlineData("coverage", "inconsistent_file_coverage")]
    public async Task UnsupportedEvidence_IsExcludedWithReason(string kind, string reason)
    {
        var record = Event();
        var state = State(record);
        switch (kind)
        {
            case "disabled": state["Mode"] = "Disabled"; break;
            case "rate": state["RateLimitRuleId"] = "login"; break;
            case "transport": state["Disposition"] = "forwarding_failed"; break;
            case "cancelled": state["Disposition"] = "cancelled"; break;
            case "provenance": state["EngineVersion"] = "unknown"; break;
            case "schema": state["SchemaVersion"] = 2; break;
            case "contradiction": state["ForwardingAttempted"] = false; break;
            case "truncated_ids": state["UploadRuleIdsTruncated"] = true; break;
            case "missing_score": state.Remove("UploadScore"); break;
            case "coverage": state["FilesInspected"] = 0; break;
        }
        AssertCannotEvaluate(await ReadAsync(record), reason);
    }

    [Fact]
    public async Task DuplicateRequests_AreCountedOnceAndReportedAsExcluded()
    {
        var record = Event();
        var report = await ReadTextAsync(Line(record) + Line(record));
        Assert.Equal("partial", report.Status);
        Assert.Equal(2, report.SelectedRecords);
        Assert.Equal(1, report.EligibleRecords);
        Assert.Equal(1, report.Exclusions["duplicate_request"]);
        Assert.Equal(1, report.NewlyRefused);
    }

    [Fact]
    public async Task SiteAndActivation_IsolationAndWindowAreExplicit()
    {
        var first = Event();
        var second = Event();
        State(second)["ConfigurationRevision"] = new string('b', 32);
        second["timestamp"] = "2026-11-17T11:00:00Z";
        var otherSite = Event();
        State(otherSite)["SiteId"] = "another.example";
        var report = await ReadTextAsync(Line(second) + Line(otherSite) + Line(first));
        Assert.Equal(2, report.EligibleRecords);
        Assert.Equal(1, report.OtherSiteRecords);
        Assert.Equal(2, report.Comparisons.Count);
        Assert.Equal(DateTimeOffset.Parse("2026-11-17T10:00:00Z"), report.WindowStart);
        Assert.Equal(DateTimeOffset.Parse("2026-11-17T11:00:00Z"), report.WindowEnd);
        Assert.Equal(2, report.NewlyRefused);
    }

    [Fact]
    public async Task ExcessProvenance_IsBoundedWithoutMergingUnknownPolicies()
    {
        var records = Enumerable.Range(1, 65).Select(index =>
        {
            var record = Event();
            State(record)["ConfigurationRevision"] = index.ToString("x32");
            return Line(record);
        });
        var report = await ReadTextAsync(string.Concat(records));
        Assert.Equal(64, report.Comparisons.Count);
        Assert.Equal(64, report.EligibleRecords);
        Assert.Equal(1, report.Exclusions["provenance_limit"]);
        Assert.Equal("partial", report.Status);
    }

    [Theory]
    [InlineData("{not-json}\n")]
    [InlineData("{\"category\":\"\\uD800\"}\n")]
    [InlineData("{\"category\":\"WPShield.Gateway.Evidence\",\"state\":{}}\n")]
    [InlineData("[]\n")]
    [InlineData("{\"state\":{},\"state\":{}}\n")]
    public async Task InvalidLines_AreVisibleAlongsideUsableEvidence(string invalid)
    {
        var report = await ReadTextAsync(invalid + Line(Event()));
        Assert.Equal("partial", report.Status);
        Assert.Equal(1, report.InvalidLines);
        Assert.Equal(1, report.EligibleRecords);
    }

    [Fact]
    public async Task TruncatedFinalLine_IsNotAcceptedEvenIfItsJsonParses()
    {
        var report = await ReadTextAsync(Event().ToJsonString());
        Assert.Equal("cannot_evaluate", report.Status);
        Assert.Equal("unterminated_record", report.StopReason);
        Assert.Null(report.NewlyRefused);
    }

    [Fact]
    public async Task EmptyAndLegacyLogs_CannotEstablishZeroImpact()
    {
        var report = await ReadTextAsync("\n{\"message\":\"Upload inspection complete.\",\"state\":{\"Score\":90}}\n");
        Assert.Equal("cannot_evaluate", report.Status);
        Assert.Equal(2, report.IgnoredLines);
        Assert.Null(report.NewlyRefused);
        Assert.Null(report.WindowStart);
    }

    [Fact]
    public async Task KnownLossNotice_MakesCoveragePartial()
    {
        var report = await ReadTextAsync("{\"category\":\"WPShield.Gateway.Logging\",\"state\":{\"DroppedEntries\":3}}\n" + Line(Event()));
        Assert.Equal("partial", report.Status);
        Assert.Equal(1, report.EvidenceLossNotices);
        Assert.False(report.ProvesLogCompleteness);
    }

    [Theory]
    [InlineData("lines", "line_limit")]
    [InlineData("bytes", "byte_limit")]
    [InlineData("long_line", "line_too_long")]
    public async Task Bounds_StopWithExplicitPartialCoverage(string kind, string stopReason)
    {
        var first = Line(Event());
        var input = first + (kind == "long_line" ? new string(' ', PreviewLimits.MaximumLineBytes + 1) : first);
        var limits = kind switch
        {
            "lines" => new PreviewLimits(MaximumLines: 1),
            "bytes" => new PreviewLimits(MaximumBytes: Encoding.UTF8.GetByteCount(first)),
            _ => new PreviewLimits()
        };
        var report = await ReadTextAsync(input, limits: limits);
        Assert.Equal("partial", report.Status);
        Assert.Equal(stopReason, report.StopReason);
        Assert.Equal(1, report.EligibleRecords);
        Assert.True(report.BytesRead <= limits.MaximumBytes);
    }

    [Fact]
    public async Task ExactLineBoundary_AtEndOfInputIsComplete()
    {
        var report = await ReadTextAsync(Line(Event()), limits: new(MaximumLines: 1));
        Assert.Equal("complete", report.Status);
        Assert.Equal("end_of_input", report.StopReason);
    }

    [Fact]
    public async Task Deadline_StopsSlowInputAndCallerCancellationPropagates()
    {
        using var slow = new SlowStream();
        var report = await PolicyPreview.ReadAsync(slow, "one", new(ProtectionMode.Block, 30, 80), new(TimeoutSeconds: 1));
        Assert.Equal("timeout", report.StopReason);
        Assert.Equal("cannot_evaluate", report.Status);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            PolicyPreview.ReadAsync(slow, "one", new(ProtectionMode.Block, 30, 80), new(), cancellation.Token));
    }

    [Fact]
    public async Task RealEngineScores_SupportThresholdComparisonWithoutReplayingContent()
    {
        var site = new SiteOptions { Id = "one", Hosts = ["one.example"], Destination = new Uri("http://127.0.0.1:8081") };
        var engine = new InspectionEngine([new ExecutableUploadExtensionRule()]);
        var result = await engine.InspectAsync(new InspectionContext("one", "one.example", "POST", "/upload", "synthetic.php", null, ReadOnlyMemory<byte>.Empty), site);
        var record = Event(score: result.Score);
        State(record)["UploadAction"] = result.RecommendedAction.ToString();
        var report = await ReadAsync(record);
        Assert.Equal(InspectionAction.Observe, result.RecommendedAction);
        Assert.Equal(1, report.NewlyRefused);
    }

    internal static JsonObject Event(string mode = "Monitor", int score = 90)
    {
        var action = mode == "Block" && score >= 80 ? "Block" : score >= 30 ? "Observe" : "Allow";
        return new JsonObject
        {
            ["timestamp"] = "2026-11-17T10:00:00Z",
            ["category"] = "WPShield.Gateway.Evidence",
            ["message"] = "Request completed.",
            ["state"] = new JsonObject
            {
                ["EventType"] = "request_completed",
                ["SchemaVersion"] = 1,
                ["SiteId"] = "one",
                ["RequestId"] = "synthetic-request",
                ["ConfigurationRevision"] = new string('a', 32),
                ["GatewayVersion"] = "0.1.0+synthetic",
                ["EngineVersion"] = "0.1.0+synthetic",
                ["WindowsRulesVersion"] = "0.1.0+synthetic",
                ["WordPressRulesVersion"] = "0.1.0+synthetic",
                ["Mode"] = mode,
                ["RateLimitRuleId"] = null,
                ["Disposition"] = action == "Block" ? "rejected" : "forwarded",
                ["Reason"] = action == "Block" ? "upload_blocked" : "exchange_completed",
                ["ForwardingAttempted"] = action != "Block",
                ["PathStatus"] = "complete",
                ["PathReason"] = "rules_completed",
                ["PathAction"] = "Allow",
                ["PathScore"] = 0,
                ["PathRuleIds"] = "",
                ["PathRuleIdsTruncated"] = false,
                ["UploadStatus"] = "complete",
                ["UploadReason"] = "sampled_scope",
                ["UploadAction"] = action,
                ["UploadScore"] = score,
                ["UploadRuleIds"] = score > 0 ? "WP-UPLOAD-001" : "",
                ["UploadRuleIdsTruncated"] = false,
                ["FilesRead"] = 1,
                ["FilesInspected"] = 1
            }
        };
    }

    internal static JsonObject State(JsonObject record) => record["state"]!.AsObject();
    internal static string Line(JsonObject record) => record.ToJsonString() + "\n";

    private static Task<PreviewReport> ReadAsync(JsonObject record, CandidatePolicy? candidate = null) => ReadTextAsync(Line(record), candidate);

    internal static async Task<PreviewReport> ReadTextAsync(string text, CandidatePolicy? candidate = null, PreviewLimits? limits = null)
    {
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(text));
        return await PolicyPreview.ReadAsync(input, "one", candidate ?? new(ProtectionMode.Block, 30, 80), limits ?? new());
    }

    private static void AssertCannotEvaluate(PreviewReport report, string reason)
    {
        Assert.Equal("cannot_evaluate", report.Status);
        Assert.Equal(1, report.ExcludedRecords);
        Assert.Equal(1, report.Exclusions[reason]);
        Assert.Equal(0, report.EligibleRecords);
        Assert.Null(report.NewlyRefused);
        Assert.Null(report.NewlyPermitted);
    }

    private sealed class SlowStream : MemoryStream
    {
        public override long Length => 1;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }
    }
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WPShield.Cli.Preview;
using WPShield.Core;

namespace WPShield.Cli.Tests.Preview;

public sealed class PreviewCommandTests
{
    [Fact]
    public async Task CommunityFormat_ExposesOnlyAllowlistedAggregatesForSelectedSite()
    {
        var selected = PolicyPreviewTests.Event();
        selected["message"] = "private-query\n\u001b[31mprivate-body";
        var state = PolicyPreviewTests.State(selected);
        state["SiteId"] = "private-one";
        state["GatewayVersion"] = "private-build";
        state["Cookie"] = "private-cookie";
        state["Authorization"] = "private-header";
        var other = PolicyPreviewTests.Event();
        PolicyPreviewTests.State(other)["SiteId"] = "private-two";
        const string gap = """{"category":"WPShield.Gateway.Logging","level":"Warning","state":{"DroppedEntries":3000000000}}""";
        using var files = new InputFiles(PolicyPreviewTests.Line(selected) + PolicyPreviewTests.Line(other) + gap + "\n");
        using var output = new StringWriter();
        var exit = await PreviewCommand.RunAsync(CliOptions.Parse(
            ["--log-file", files.Input, "--site", "private-one", "--mode", "Block", "--format", "community"]), output);
        Assert.Equal(2, exit);
        using var json = JsonDocument.Parse(output.ToString());
        var root = json.RootElement;
        Assert.Equal(new[] { "schemaVersion", "site", "status", "sourceCoverage", "provesLogCompleteness", "candidate", "eligibleRecords",
            "excludedRecords", "newlyRefused", "newlyPermitted", "changedRecommendations", "unchangedRecommendations" },
            root.EnumerateObject().Select(x => x.Name));
        Assert.Equal(new[] { "mode", "observeThreshold", "blockThreshold" },
            root.GetProperty("candidate").EnumerateObject().Select(x => x.Name));
        Assert.Equal("site-1", root.GetProperty("site").GetString());
        Assert.Equal("partial", root.GetProperty("status").GetString());
        Assert.Equal("partial", root.GetProperty("sourceCoverage").GetString());
        Assert.False(root.GetProperty("provesLogCompleteness").GetBoolean());
        Assert.Equal(1, root.GetProperty("eligibleRecords").GetInt32());
        Assert.Equal(1, root.GetProperty("newlyRefused").GetInt32());
        Assert.DoesNotContain("private-", output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("001b", output.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task UnknownFormat_FailsBeforeWritingOperatorOutput()
    {
        using var output = new StringWriter();
        await Assert.ThrowsAsync<CliArgumentException>(() => PreviewCommand.RunAsync(CliOptions.Parse(
            ["--log-file", "synthetic.jsonl", "--site", "one", "--format", "comunity"]), output));
        Assert.Equal("", output.ToString());
    }

    [Fact]
    public async Task OfflineCommand_ProducesAggregateJsonAndLeavesInputsUntouched()
    {
        var record = PolicyPreviewTests.Event();
        record["message"] = "private-body private-query \u001b[31m";
        var state = PolicyPreviewTests.State(record);
        state["Client"] = "192.0.2.99";
        state["Path"] = "/private-path";
        state["Authorization"] = "private-token";
        state["FileName"] = "private-filename";
        using var files = new InputFiles(PolicyPreviewTests.Line(record));
        var before = SHA256.HashData(await File.ReadAllBytesAsync(files.Input));
        using var output = new StringWriter();
        var exit = await PreviewCommand.RunAsync(CliOptions.Parse(
            ["--log-file", files.Input, "--site", "one", "--mode", "Block"]), output);
        using var json = JsonDocument.Parse(output.ToString());
        Assert.Equal(0, exit);
        Assert.Equal("complete", json.RootElement.GetProperty("status").GetString());
        Assert.Equal(1, json.RootElement.GetProperty("newlyRefused").GetInt32());
        Assert.Equal("score-policy-v1/Block/30/80", json.RootElement.GetProperty("candidatePolicyId").GetString());
        Assert.False(json.RootElement.GetProperty("appliesChanges").GetBoolean());
        Assert.DoesNotContain("private-", output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("192.0.2.99", output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic-request", output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(files.Input, output.ToString(), StringComparison.Ordinal);
        Assert.Equal(before, SHA256.HashData(await File.ReadAllBytesAsync(files.Input)));
        Assert.Equal("synthetic unchanged configuration", await File.ReadAllTextAsync(files.Configuration));
        Assert.Equal(2, Directory.GetFiles(files.DirectoryPath).Length);
    }

    [Fact]
    public async Task DefaultCandidate_IsMonitorAndDoesNotBlock()
    {
        using var files = new InputFiles(PolicyPreviewTests.Line(PolicyPreviewTests.Event()));
        using var output = new StringWriter();
        var exit = await PreviewCommand.RunAsync(CliOptions.Parse(["--log-file", files.Input, "--site", "one"]), output);
        using var json = JsonDocument.Parse(output.ToString());
        Assert.Equal(0, exit);
        Assert.Equal("Monitor", json.RootElement.GetProperty("candidate").GetProperty("mode").GetString());
        Assert.Equal(0, json.RootElement.GetProperty("newlyRefused").GetInt32());
    }

    [Fact]
    public async Task MissingSource_IsUnavailableWithoutDisclosingThePath()
    {
        using var output = new StringWriter();
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "private-source.jsonl");
        var exit = await PreviewCommand.RunAsync(CliOptions.Parse(["--log-file", path, "--site", "one"]), output);
        using var json = JsonDocument.Parse(output.ToString());
        Assert.Equal(1, exit);
        Assert.Equal("unavailable", json.RootElement.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("newlyRefused").ValueKind);
        Assert.DoesNotContain("private-source", output.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("empty", 3, "cannot_evaluate")]
    [InlineData("partial", 2, "partial")]
    public async Task ExitCodes_DoNotHideIncompleteEvidence(string kind, int expected, string status)
    {
        var text = kind == "empty" ? "" : "not-json\n" + PolicyPreviewTests.Line(PolicyPreviewTests.Event());
        using var files = new InputFiles(text);
        using var output = new StringWriter();
        var exit = await PreviewCommand.RunAsync(CliOptions.Parse(["--log-file", files.Input, "--site", "one"]), output);
        using var json = JsonDocument.Parse(output.ToString());
        Assert.Equal(expected, exit);
        Assert.Equal(status, json.RootElement.GetProperty("status").GetString());
    }

    [Theory]
    [InlineData("--mode", "Disabled")]
    [InlineData("--mode", "2")]
    [InlineData("--mode", "+2")]
    [InlineData("--mode", "Monitor,Block")]
    [InlineData("--mode", "")]
    [InlineData("--observe-threshold", "81")]
    [InlineData("--block-threshold", "101")]
    [InlineData("--block-threshold", "0")]
    [InlineData("--max-lines", "100001")]
    [InlineData("--max-lines", "0")]
    [InlineData("--max-bytes", "67108865")]
    [InlineData("--timeout-seconds", "61")]
    [InlineData("--timeout-seconds", "-1")]
    [InlineData("--out", "unexpected-file")]
    public async Task InvalidCandidatesOrLimits_AreRefusedBeforeReading(string option, string value)
    {
        using var output = new StringWriter();
        await Assert.ThrowsAsync<CliArgumentException>(() => PreviewCommand.RunAsync(CliOptions.Parse(
            ["--log-file", "missing.jsonl", "--site", "one", option, value]), output));
        Assert.Equal("", output.ToString());
    }

    [Theory]
    [InlineData("--mode", "Block", "--MODE=Monitor")]
    [InlineData("--block-threshold", "80", "--block-threshold=90")]
    public async Task RepeatedOptions_AreNotSilentlyOverwritten(string name, string value, string repeated)
    {
        using var output = new StringWriter();
        await Assert.ThrowsAsync<CliArgumentException>(() => PreviewCommand.RunAsync(CliOptions.Parse(
            ["--log-file", "missing.jsonl", "--site", "one", name, value, repeated]), output));
        Assert.Equal("", output.ToString());
    }

    [Fact]
    public async Task InvalidUtf8AndDuplicateStateKeys_AreNotTrusted()
    {
        var bytes = Encoding.UTF8.GetBytes("{\"state\":\"").Concat(new byte[] { 0xff }).Concat(Encoding.UTF8.GetBytes("\"}\n")).ToArray();
        using var stream = new MemoryStream(bytes);
        var report = await PolicyPreview.ReadAsync(stream, "one", new(ProtectionMode.Block, 30, 80), new());
        Assert.Equal("cannot_evaluate", report.Status);
        Assert.Equal(1, report.InvalidLines);
        var duplicate = PolicyPreviewTests.Line(PolicyPreviewTests.Event()).Replace("\"SchemaVersion\":1", "\"SchemaVersion\":1,\"SchemaVersion\":2", StringComparison.Ordinal);
        var duplicateReport = await PolicyPreviewTests.ReadTextAsync(duplicate);
        Assert.Equal(1, duplicateReport.InvalidLines);
        Assert.Equal(0, duplicateReport.EligibleRecords);
    }

    [Fact]
    public async Task ReadFailure_IsNotAnEmptySuccessfulReport()
    {
        using var stream = new FailingStream();
        var report = await PolicyPreview.ReadAsync(stream, "one", new(ProtectionMode.Block, 30, 80), new());
        Assert.Equal("unavailable", report.Status);
        Assert.Equal("read_failed", report.StopReason);
        Assert.Null(report.NewlyRefused);
    }

    private sealed class FailingStream : MemoryStream
    {
        public override long Length => 1;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromException<int>(new IOException("private-exception"));
    }

    private sealed class InputFiles : IDisposable
    {
        public string DirectoryPath { get; } = Path.Combine(Path.GetTempPath(), "wpshield-preview-" + Guid.NewGuid().ToString("N"));
        public string Input => Path.Combine(DirectoryPath, "synthetic.jsonl");
        public string Configuration => Path.Combine(DirectoryPath, "appsettings.Local.json");

        public InputFiles(string text)
        {
            Directory.CreateDirectory(DirectoryPath);
            File.WriteAllText(Input, text, new UTF8Encoding(false));
            File.WriteAllText(Configuration, "synthetic unchanged configuration");
        }
        public void Dispose()
        {
            File.Delete(Input);
            File.Delete(Configuration);
            Directory.Delete(DirectoryPath);
        }
    }
}

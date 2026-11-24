using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WPShield.NetworkSensor;
using WPShield.SecurityMonitor;
using Xunit;

namespace WPShield.Cli.Tests;

public sealed class AuditReferenceTests
{
    private static readonly DateTimeOffset When = DateTimeOffset.UnixEpoch.ToOffset(TimeSpan.FromHours(-4));
    private static readonly SqlLoginAuditWindow Sql = new("MSSQL$Example", When, "read",
        [new(18456, 20, When, "failure"), new(18453, 10, When.AddSeconds(2), "success")]);

    private static async Task<(int Code, string Output, string Error)> Select(string json, string source, string id)
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, json, Encoding.UTF8);
            using var output = new StringWriter();
            using var error = new StringWriter();
            var args = CliOptions.Parse(["--snapshot", path, "--source", source, source == "iis" ? "--line" : "--record-id", id]);
            var code = await AuditReferenceCommand.RunAsync(args, output, error);
            return (code, output.ToString(), error.ToString());
        }
        finally { File.Delete(path); }
    }

    private static async Task<AuditReferenceList> Browse(string json)
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, json, Encoding.UTF8);
            return await SavedAuditSnapshot.BrowseAsync(path, CancellationToken.None);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task BrowserAndCliExportIdenticalReferencesAcrossSourcesWithTheSameId()
    {
        var json = JsonSerializer.Serialize(new
        {
            SqlAudit = Sql with { AuditStatus = "limited" },
            RdpAudit = new { Flows = new[] { new { Remote = "private-sentinel", Events = new[] { new { RecordId = 10, Timestamp = When } } } } }
        });
        var list = await Browse(json);
        Assert.Equal(3, list.Rows.Count);
        Assert.Equal("limited", list.Coverage["sql"]);
        Assert.Equal("unknown", list.Coverage["rdp"]);
        foreach (var row in list.Rows)
        {
            var cli = await Select(json, row.Source.ToLowerInvariant(), row.Id.ToString());
            Assert.Equal(0, cli.Code);
            Assert.Equal(row.Json, cli.Output.Trim());
            Assert.DoesNotContain("private-sentinel", row.Json);
            Assert.Equal(TimeSpan.Zero, row.Timestamp!.Value.Offset);
        }
    }

    [Theory]
    [InlineData(0, "read")]
    [InlineData(1, "limited")]
    public async Task IisBrowserUsesPhysicalLinesAndPreservesCoverage(int malformed, string status)
    {
        var json = JsonSerializer.Serialize(new
        {
            InputPrefixSha256 = new string('F', 64),
            InputPrefixBytes = 42,
            Report = new
            {
                StopReason = "end_of_file",
                UnattributedRows = 0,
                MalformedRows = malformed,
                Evidence = new[] { new { Line = 4, ChallengeLine = 3, Username = "private-sentinel" } }
            }
        });
        var list = await Browse(json);
        var row = Assert.Single(list.Rows);
        Assert.Equal("IIS", row.Source);
        Assert.Null(row.Timestamp);
        Assert.Equal(status, list.Coverage["iis"]);
        var cli = await Select(json, "iis", "4");
        Assert.Equal(row.Json, cli.Output.Trim());
        Assert.DoesNotContain("private-sentinel", row.Json);
    }

    [Fact]
    public async Task EmptyUnavailableSourceKeepsItsCoverage()
    {
        var list = await Browse(JsonSerializer.Serialize(Sql with { AuditStatus = "unavailable", Events = [] }));
        Assert.Empty(list.Rows);
        Assert.Equal("unavailable", list.Coverage["sql"]);
    }

    [Fact]
    public async Task DuplicateInOneSourceRejectsTheEntireList()
    {
        var json = JsonSerializer.Serialize(Sql with { Events = [Sql.Events[0], Sql.Events[1], Sql.Events[0]] });
        await Assert.ThrowsAsync<DuplicateAuditRowException>(() => Browse(json));
    }

    [Fact]
    public async Task ReferenceBudgetAcceptsTheLimitAndRejectsOverflow()
    {
        string Make(int count) => JsonSerializer.Serialize(Sql with
        {
            Events = Enumerable.Range(1, count).Select(i => Sql.Events[0] with { RecordId = i }).ToArray()
        });
        Assert.Equal(1024, (await Browse(Make(1024))).Rows.Count);
        await Assert.ThrowsAsync<ReferenceLimitException>(() => Browse(Make(1025)));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"RdpAudit":{"Flows":[]},"RdpAudit":{"Flows":[]}}""")]
    [InlineData("""{"RdpAudit":{"Flows":[]}} {"RdpAudit":{"Flows":[]}}""")]
    [InlineData("""{"RdpAudit":{"Flows":[{"Events":[{"RecordId":0}]}]}}""")]
    public async Task UnsupportedOrAmbiguousInputsCannotPopulateTheBrowser(string json) =>
        await Assert.ThrowsAnyAsync<JsonException>(() => Browse(json));

    [Theory]
    [InlineData("rdp", "Security", "Microsoft-Windows-Security-Auditing", 3)]
    [InlineData("sql", "Application", "MSSQL$Example", 2)]
    public async Task SourceAndRecordIdIdentifyOneEventInACombinedSnapshot(string source, string channel, string provider, int seconds)
    {
        var traffic = new FlowSnapshot("private-sentinel", When, 0, 0, 0, null, []);
        var rdp = new RdpFlowReport(3389, "read", [new("private-local", "private-remote",
            [new(4625, 30, When), new(4624, 10, When.AddSeconds(3))])]);
        using var snapshot = new StringWriter();
        NetworkMonitorCommand.WriteSnapshot(snapshot, traffic, true, rdp, Sql);
        var result = await Select(snapshot.ToString(), source, "10");
        Assert.Equal(0, result.Code);
        Assert.Empty(result.Error);
        using var document = JsonDocument.Parse(result.Output);
        var reference = document.RootElement;
        Assert.Equal(["Channel", "Provider", "Timestamp", "RecordId"], reference.EnumerateObject().Select(p => p.Name));
        Assert.Equal(channel, reference.GetProperty("Channel").GetString());
        Assert.Equal(provider, reference.GetProperty("Provider").GetString());
        var timestamp = reference.GetProperty("Timestamp").GetDateTimeOffset();
        Assert.Equal(TimeSpan.Zero, timestamp.Offset);
        Assert.Equal(When.AddSeconds(seconds), timestamp);
        Assert.Equal(10, reference.GetProperty("RecordId").GetInt64());
        Assert.DoesNotContain("private", result.Output);
    }

    [Fact]
    public async Task StandaloneSqlReportAndLargeRecordIdsAreSupported()
    {
        var sql = Sql with { Events = [new(18456, long.MaxValue, When, "failure")] };
        using var output = new StringWriter();
        NetworkMonitorCommand.WriteStandaloneSqlAudit(output, sql, true);
        var result = await Select(output.ToString(), "sql", "9223372036854775807");
        Assert.Equal(0, result.Code);
        using var document = JsonDocument.Parse(result.Output);
        Assert.Equal(long.MaxValue, document.RootElement.GetProperty("RecordId").GetInt64());
    }

    [Fact]
    public async Task IisReferenceKeepsPrefixAndBothPhysicalLinesOnly()
    {
        var path = Path.GetTempFileName();
        try
        {
            const string fields = "#Fields: date time s-sitename c-ip c-port s-ip s-port cs-version cs-method cs-uri-stem cs-username sc-status sc-substatus sc-win32-status";
            const string row = "2026-11-01 12:00:00 W3SVC7 192.0.2.8 51000 192.0.2.10 443 HTTP/1.1 GET /private";
            var bytes = Encoding.UTF8.GetBytes($"{fields}\n{row} - 401 2 5\n{row} private-user 200 0 0\n");
            await File.WriteAllBytesAsync(path, bytes);
            using var snapshot = new StringWriter();
            Assert.Equal(0, await IisLoginCommand.RunAsync(CliOptions.Parse(["--log-file", path, "--site", "W3SVC7", "--json"]), snapshot));
            var result = await Select(snapshot.ToString(), "iis", "3");
            Assert.Equal(0, result.Code);
            using var document = JsonDocument.Parse(result.Output);
            var reference = document.RootElement;
            Assert.Equal(["InputPrefixSha256", "InputPrefixBytes", "Line", "ChallengeLine"], reference.EnumerateObject().Select(p => p.Name));
            Assert.Equal(Convert.ToHexString(SHA256.HashData(bytes)), reference.GetProperty("InputPrefixSha256").GetString());
            Assert.Equal(bytes.Length, reference.GetProperty("InputPrefixBytes").GetInt32());
            Assert.Equal(3, reference.GetProperty("Line").GetInt32());
            Assert.Equal(2, reference.GetProperty("ChallengeLine").GetInt32());
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("missing", 3)]
    [InlineData("duplicate-id", 1)]
    [InlineData("duplicate-property", 1)]
    [InlineData("two-snapshots", 1)]
    [InlineData("no-offset", 1)]
    [InlineData("wrong-provider", 1)]
    public async Task UnresolvedSelectionNeverWritesAReference(string scenario, int code)
    {
        var json = JsonSerializer.Serialize(Sql);
        json = scenario switch
        {
            "duplicate-id" => JsonSerializer.Serialize(Sql with { Events = [Sql.Events[1], Sql.Events[1]] }),
            "duplicate-property" => json.Replace("\"RecordId\":10", "\"RecordId\":10,\"RecordId\":10"),
            "two-snapshots" => json + "\n" + json,
            "no-offset" => json.Replace("-04:00\"", "\""),
            "wrong-provider" => JsonSerializer.Serialize(Sql with { Provider = "private-sentinel" }),
            _ => json
        };
        var result = await Select(json, "sql", scenario == "missing" ? "1" : "10");
        Assert.Equal(code, result.Code);
        Assert.Empty(result.Output);
        Assert.NotEmpty(result.Error);
        Assert.DoesNotContain("private-sentinel", result.Error);
    }

    [Fact]
    public async Task OlderRdpReportUsesTheProviderAndChannelOfTheOriginalReader()
    {
        var result = await Select("""{"RdpAudit":{"Flows":[{"Events":[{"RecordId":7,"Timestamp":"2026-01-01T00:00:00Z"}]}]}}""", "rdp", "7");
        Assert.Equal(0, result.Code);
        using var document = JsonDocument.Parse(result.Output);
        Assert.Equal("Security", document.RootElement.GetProperty("Channel").GetString());
        Assert.Equal(RdpAuditReader.Provider, document.RootElement.GetProperty("Provider").GetString());
    }

    [Theory]
    [InlineData("invalid", 1)]
    [InlineData("hash", 3)]
    public async Task InvalidIisPrefixOrLinePairCannotProduceAReference(string hash, int challengeLine)
    {
        var json = JsonSerializer.Serialize(new
        {
            InputPrefixSha256 = hash == "hash" ? new string('a', 64) : hash,
            InputPrefixBytes = 100,
            Report = new { Evidence = new[] { new { Line = 3, ChallengeLine = challengeLine } } }
        });
        var result = await Select(json, "iis", "3");
        Assert.Equal(1, result.Code);
        Assert.Empty(result.Output);
    }

    [Theory]
    [InlineData("sql", "--line", "7")]
    [InlineData("iis", "--record-id", "7")]
    [InlineData("rdp", "--record-id", "-1")]
    public async Task WrongSelectorIsRejectedBeforeReadingTheSnapshot(string source, string selector, string value)
    {
        var args = CliOptions.Parse(["--snapshot", "missing.example", "--source", source, selector, value]);
        await Assert.ThrowsAsync<CliArgumentException>(() => AuditReferenceCommand.RunAsync(args, TextWriter.Null, TextWriter.Null));
    }

    [Fact]
    public async Task RejectsOversizeSnapshotBeforeParsingAndHonorsCancellation()
    {
        var path = Path.GetTempFileName();
        try
        {
            using (var file = File.OpenWrite(path)) file.SetLength(SavedAuditSnapshot.MaxBytes + 1);
            var args = CliOptions.Parse(["--snapshot", path, "--source", "iis", "--line", "2"]);
            using var output = new StringWriter();
            using var error = new StringWriter();
            Assert.Equal(1, await AuditReferenceCommand.RunAsync(args, output, error));
            Assert.Contains("8 MiB", error.ToString());
            await File.WriteAllTextAsync(path, "{}");
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => AuditReferenceCommand.RunAsync(args, output, error, new CancellationToken(true)));
            Assert.Empty(output.ToString());
        }
        finally { File.Delete(path); }
    }
}

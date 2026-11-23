using System.Text;
using System.Text.Json;
using Xunit;

namespace WPShield.Cli.Tests;

public sealed class IisLoginTests
{
    private const string Fields = "#Fields: date time s-sitename c-ip c-port s-ip s-port cs-version cs-method cs-uri-stem cs-username sc-status sc-substatus sc-win32-status";
    private const string Start = "2026-11-01 12:00:00 W3SVC7 192.0.2.8 51000 192.0.2.10 443 HTTP/1.1 GET /private";
    private const string Challenge = Start + " - 401 2 5";
    private const string Success = Start + " private-user 200 0 0";
    private static IisLoginReport Read(params string[] lines) =>
        IisLoginAudit.Scan(Encoding.UTF8.GetBytes(string.Join('\n', lines) + "\n"), false, "W3SVC7", default);

    [Fact]
    public void NegotiationKeepsBothLineReferencesAndNoRejection()
    {
        var report = Read(Fields, Challenge, Success);
        Assert.Equal("challenge-compatible", report.Evidence[0].Observation);
        var success = report.Evidence[1];
        Assert.Equal("challenge-followed-by-success", success.Observation);
        Assert.Equal(2, success.ChallengeLine);
        Assert.Equal(3, success.Line);
        Assert.DoesNotContain("private", JsonSerializer.Serialize(report));
    }

    [Theory]
    [InlineData("51000", "51001")]
    [InlineData("51000", "-")]
    [InlineData("12:00:00", "12:00:11")]
    [InlineData("12:00:00", "11:59:59")]
    [InlineData("HTTP/1.1", "HTTP/2")]
    [InlineData("/private", "/other")]
    public void DifferentOrUncertainExchangeKeepsRequestsSeparate(string from, string to)
    {
        var report = Read(Fields, Challenge, Success.Replace(from, to, StringComparison.Ordinal));
        Assert.Null(report.Evidence[1].ChallengeLine);
        Assert.Equal("authenticated-request", report.Evidence[1].Observation);
    }

    [Fact]
    public void SharedListenerNeverSuppliesTheSiteAndOtherSitesInterruptPairing()
    {
        var report = Read(Fields, Challenge, Success.Replace("W3SVC7", "W3SVC8"), Success,
            (Start + " - 401 1 1326").Replace("W3SVC7", "-"));
        Assert.Null(report.Evidence[1].ChallengeLine);
        Assert.Equal(1, report.UnattributedRows);
        Assert.Equal(2, report.SelectedRows);
        var missing = Read("#Fields: date time cs-host sc-status", "2026-11-01 00:00:00 W3SVC7 401");
        Assert.Equal("unknown", missing.SiteAttribution);
        Assert.Empty(missing.Evidence);
    }

    [Fact]
    public void OnlyCorroboratedLogonFailureIsReportedAsRejected()
    {
        var report = Read(Fields, Start + " - 401 1 1326", Start + " - 401 1 0", Start + " - 200 0 0");
        Assert.Equal(["login-rejected", "unknown"], report.Evidence.Select(x => x.Observation));
        Assert.Equal(1326u, report.Evidence[0].Win32Status);
    }

    [Fact]
    public void NewOrInvalidSchemaNeverReusesOldFieldPositions()
    {
        var report = Read(Fields, Challenge, "#Fields: date date", Success,
            "#Fields: sc-status time s-sitename date sc-win32-status sc-substatus",
            "401 12:00:00 W3SVC7 2026-11-01 1326 1");
        Assert.Equal(2, report.MalformedRows);
        Assert.Equal(6, report.Evidence[^1].Line);
        Assert.Equal("login-rejected", report.Evidence[^1].Observation);
        var restart = Read(Fields, "#Software: IIS", Success, "#fields invalid", Success);
        Assert.Empty(restart.Evidence);
    }

    [Fact]
    public void TruncatedAndOversizeRowsCannotGenerateACompleteResult()
    {
        var bytes = Encoding.UTF8.GetBytes(Fields + "\n" + Success);
        Assert.Equal("unterminated_line", IisLoginAudit.Scan(bytes, false, "W3SVC7", default).StopReason);
        Assert.Equal("byte_limit", IisLoginAudit.Scan(bytes, true, "W3SVC7", default).StopReason);
        Assert.Equal("line_limit", Read(new string('a', IisLoginAudit.MaxLineBytes + 1)).StopReason);
        var report = Read([Fields, .. Enumerable.Repeat(Success, IisLoginAudit.MaxRows + 1)]);
        Assert.Equal("evidence_limit", report.StopReason);
        Assert.Equal(IisLoginAudit.MaxRows, report.Evidence.Count);
    }

    [Fact]
    public async Task CommandReadsOnlyTheSelectedSiteAndFingerprintsTheCopiedInput()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, Fields + "\r\n" + Start + " - 401 1 1326\r\n");
            using var output = new StringWriter();
            var options = CliOptions.Parse(["--log-file", path, "--site", "W3SVC7", "--json"]);
            Assert.Equal(0, await IisLoginCommand.RunAsync(options, output));
            using var json = JsonDocument.Parse(output.ToString());
            Assert.Equal(64, json.RootElement.GetProperty("InputPrefixSha256").GetString()!.Length);
            Assert.Equal(2, json.RootElement.GetProperty("Report").GetProperty("Evidence")[0].GetProperty("Line").GetInt32());
            Assert.DoesNotContain(path, output.ToString());
            using var stop = new CancellationTokenSource();
            stop.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => IisLoginCommand.RunAsync(options, TextWriter.Null, stop.Token));
        }
        finally { File.Delete(path); }
    }
}

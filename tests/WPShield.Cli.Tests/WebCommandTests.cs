using System.Text.Json;
using WPShield.Cli;
using WPShield.Evidence;

namespace WPShield.Cli.Tests;

/// <summary>
/// <c>wpshield web</c> starts with what was and was not read, then counts, then the flagged addresses and
/// the findings - with attacker-chosen paths cleaned and labelled. Synthetic RFC 5737 addresses and
/// <c>.example</c> names only.
/// </summary>
public sealed class WebCommandTests : IDisposable
{
    private static readonly DateTimeOffset Now = EvidenceTestStore.Now;
    private static readonly DateTimeOffset Hour = new(2026, 11, 24, 11, 0, 0, TimeSpan.Zero);
    private readonly EvidenceTestStore store = new();

    public void Dispose() => store.Dispose();

    private (int Exit, string Output, string Error) Run(bool elevated, params string[] args)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var exit = WebCommand.Run(CliOptions.Parse(args), output, error, store.Path, () => elevated, () => Now);
        return (exit, output.ToString(), error.ToString());
    }

    private (int Exit, string Output, string Error) Run(params string[] args) => Run(true, args);

    private void Recorded() => store.Write(s =>
    {
        new EvidenceWriter(s).BeginCoverage(WebEvidenceWriter.SensorSource, Now.AddDays(-2), Now, "collected");
        new EvidenceWriter(s).BeginCoverage(WebEvidenceWriter.SiteSource(4), Now.AddDays(-2), Now, "collected");
        var writer = new WebEvidenceWriter(s);
        writer.RecordSites([
            new WebSiteState(4, "shop.example", "collected", null, null, false, Now),
            new WebSiteState(7, "blog.example", "unavailable", "access-denied", "grant read to the service", false, Now),
            new WebSiteState(9, "ftp.example", "ignored", "no-http-binding", null, false, Now)], Now);
        writer.Write(new WebBatch(
            [new WebFinding(Now.AddMinutes(-30), 4, "203.0.113.7", "POST", "/wp-content/uploads/x.php\u001b[2J", 200,
                [new WebHit("WP-PATH-001", 100), new WebHit("WEB-OBS-001", 0)], "agent\u0007", true, false, null)],
            [new WebSiteCounts(4, Hour, 1200, 80, 3, 1, 1, 12, 4, 90_000)],
            [new WebSourceCounts(4, Hour, "203.0.113.7", 60, 52, 1, 1, 12, 4, Now.AddMinutes(-50), Now.AddMinutes(-30), null),
             new WebSourceCounts(4, Hour, "10.0.0.5", 5, 0, 0, 0, 1, 0, Now.AddMinutes(-40), Now.AddMinutes(-40), "a private range")],
            []));
    });

    [Fact]
    public void CoverageComesFirstAndANotReadSiteNamesItsRemedy()
    {
        Recorded();

        var (exit, output, _) = Run();

        Assert.Equal(0, exit);
        Assert.Contains("Sites            3 known: 1 read, 1 not read, 1 ignored (no HTTP binding)", output, StringComparison.Ordinal);
        Assert.Contains("7 blog.example: not read (access-denied)", output, StringComparison.Ordinal);
        Assert.Contains("remedy: grant read to the service", output, StringComparison.Ordinal);
        Assert.True(output.IndexOf("Sites ", StringComparison.Ordinal) < output.IndexOf("Requests ", StringComparison.Ordinal));
        Assert.Contains("evidence only - nothing is decided from web evidence", output, StringComparison.Ordinal);
    }

    [Fact]
    public void TotalsAddressesAndFindingsAreShownWithAttackerTextCleaned()
    {
        Recorded();

        var (_, output, _) = Run();

        Assert.Contains("Requests         1,200  (4xx 80, 5xx 3)", output, StringComparison.Ordinal);
        Assert.Contains("wp-login POSTs 12, xmlrpc POSTs 4", output, StringComparison.Ordinal);
        Assert.Contains("203.0.113.7", output, StringComparison.Ordinal);
        Assert.Contains("and 1 the evidence never counts against", output, StringComparison.Ordinal);
        Assert.Contains("WP-PATH-001,WEB-OBS-001", output, StringComparison.Ordinal);
        Assert.Contains("observation (evidence only)", output, StringComparison.Ordinal);
        Assert.Contains("untrusted text", output, StringComparison.Ordinal);
        Assert.DoesNotContain('\u001b', output);
        Assert.DoesNotContain('\u0007', output);
    }

    [Fact]
    public void OneSourceShowsItsOwnCounts()
    {
        Recorded();

        var (exit, output, _) = Run("--source", "203.0.113.7");

        Assert.Equal(0, exit);
        Assert.Contains("Source           203.0.113.7  (network 203.0.113.0/24)", output, StringComparison.Ordinal);
        Assert.Contains("requests 60, 4xx 52, findings 1", output, StringComparison.Ordinal);
    }

    [Fact]
    public void ASiteIsChosenByIdOrByName()
    {
        Recorded();

        Assert.Contains("Site             4 shop.example: read", Run("--site", "4").Output, StringComparison.Ordinal);
        Assert.Contains("Site             7 blog.example: not read (access-denied)", Run("--site", "BLOG.example").Output, StringComparison.Ordinal);
        var (exit, _, error) = Run("--site", "nowhere.example");
        Assert.Equal(1, exit);
        Assert.Contains("knows no site", error, StringComparison.Ordinal);
    }

    [Fact]
    public void NothingRecordedIsNoDataNeverZero()
    {
        store.Write(_ => { });

        var (exit, output, _) = Run();

        Assert.Equal(2, exit);
        Assert.Contains("Requests         no data", output, StringComparison.Ordinal);
        Assert.Contains("not the same as no requests", output, StringComparison.Ordinal);
    }

    [Fact]
    public void JsonWrapsTheAttackersTextAsUntrusted()
    {
        Recorded();

        var (exit, output, _) = Run("--json");

        Assert.Equal(0, exit);
        using var document = JsonDocument.Parse(output);
        var finding = document.RootElement.GetProperty("findings")[0];
        Assert.StartsWith("/wp-content/uploads/x.php", finding.GetProperty("path").GetProperty("value").GetString(), StringComparison.Ordinal);
        Assert.Equal("evidence-only", document.RootElement.GetProperty("mode").GetString());
        Assert.Equal(3, document.RootElement.GetProperty("sites").GetArrayLength());
    }

    [Theory]
    [InlineData("--range", "2d")]
    [InlineData("--source", "not-an-address")]
    [InlineData("--site", "")]
    public void BadArgumentsAreRefused(string option, string value)
    {
        Assert.Throws<CliArgumentException>(() => Run(option, value));
    }

    [Fact]
    public void WithoutElevationItSaysItCouldNotLook()
    {
        var (exit, _, error) = Run(false);

        Assert.Equal(1, exit);
        Assert.Contains("not elevated", error, StringComparison.Ordinal);
    }
}

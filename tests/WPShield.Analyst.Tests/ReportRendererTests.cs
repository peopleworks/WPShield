using WPShield.Evidence;

namespace WPShield.Analyst.Tests;

/// <summary>What a printed report says about itself: that it is an opinion, and which lines would loosen protection.</summary>
public sealed class ReportRendererTests
{
    private static AnalystReport Report(string text, string language = "en", string status = ReportStatus.Completed) =>
        new(7, Fixtures.Now, Fixtures.Now, "anthropic", true, "claude-opus-5-5", "claude-opus-5-5", "digest", "24h", null, language, status,
            "end_turn", null, null, null, false, 1000, 200, null, text, false, [new AnalystReportToolCall(1, "coverage", """{"range":"24h"}""", false)]);

    private static string Render(AnalystReport report)
    {
        var output = new StringWriter();
        ReportRenderer.Render(report, output);
        return output.ToString();
    }

    [Fact]
    public void EveryReportStartsWithTheOpinionLabelInItsLanguage()
    {
        Assert.StartsWith("AI analysis: opinion, not evidence", Render(Report("Quiet day.")), StringComparison.Ordinal);
        Assert.StartsWith("Análisis de IA: opinión, no evidencia", Render(Report("Día tranquilo.", "es")), StringComparison.Ordinal);
    }

    [Fact]
    public void ALineTheModelMarkedAsLooseningIsFlaggedAndCounted()
    {
        var output = Render(Report("Top source 203.0.113.7.\nLOOSENS PROTECTION: add 198.51.100.7 to the office label set."));

        Assert.Contains("1 line(s) below recommend loosening protection", output, StringComparison.Ordinal);
        Assert.Contains("!! LOOSENS PROTECTION: add 198.51.100.7", output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("- Add 203.0.113.7 to defense.allow so it stops appearing.")]
    [InlineData("Raise defense.failures.count to 50.")]
    [InlineData("Put the monitoring service on the allow-list.")]
    [InlineData("Disable the evidence collector for a day.")]
    [InlineData("Añada la red a la lista de permitidos.")]
    public void AnUnmarkedLineThatCouldLoosenProtectionIsFlaggedAnyway(string line)
    {
        var (lines, count) = ReportRenderer.Mark("Summary first.\n" + line, spanish: false);

        Assert.Equal(1, count);
        Assert.Equal("Summary first.", lines[0]);
        Assert.StartsWith("[may loosen protection: check it] ", lines[1], StringComparison.Ordinal);
    }

    [Fact]
    public void ALineThatTightensNothingIsLeftAlone()
    {
        var (lines, count) = ReportRenderer.Mark("203.0.113.7 tried 40 accounts; check 'wpshield decisions --target 203.0.113.7'.", spanish: false);

        Assert.Equal(0, count);
        Assert.DoesNotContain("[", lines[0][..1], StringComparison.Ordinal);
    }

    [Fact]
    public void ToolCallsAreListedWithTheirArguments()
    {
        Assert.Contains("1. coverage {\"range\":\"24h\"}", Render(Report("Text.")), StringComparison.Ordinal);
    }

    [Fact]
    public void AStoppedRunSaysWhichBoundAndThatItIsNotAnAnalysis()
    {
        var report = Report("") with { Status = ReportStatus.Stopped, Bound = "12 tool calls per run: the model asked for 13.", Error = "A bound stopped the run." };

        var output = Render(report);

        Assert.Contains("Stopped by a bound: 12 tool calls", output, StringComparison.Ordinal);
    }

    [Fact]
    public void TheRelaysCostIsShownAsCountedAsZero()
    {
        Assert.Contains("cost counted as zero", Render(Report("x") with { Provider = "relay", OperatorPays = false }), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("anthropic", false, "It goes to Anthropic", "no account names")]
    [InlineData("anthropic", true, "It goes to Anthropic", "account names tried")]
    [InlineData("relay", false, "own local tools", "decided by the Relay's configuration")]
    public void TheDisclosureSaysWhatLeavesTheHostForEachProvider(string provider, bool detailed, string where, string what)
    {
        var text = string.Join("\n", ProviderDisclosure.Lines(provider, new Uri("https://relay.example"), detailed, spanish: false));

        Assert.Contains(where, text, StringComparison.Ordinal);
        Assert.Contains(what, text, StringComparison.Ordinal);
        Assert.Contains("labels", text, StringComparison.Ordinal);
        Assert.Contains("never blocks", text, StringComparison.Ordinal);
    }

    [Fact]
    public void WithNoProviderTheDisclosureSaysNothingLeaves()
    {
        Assert.Contains("nothing leaves", Assert.Single(ProviderDisclosure.Lines("", null, false, false)), StringComparison.Ordinal);
    }

    [Fact]
    public void TheConfigurationFallsBackToDefaultsAndReadsStoredValues()
    {
        using var directory = new TempDirectory();
        var path = Path.Combine(directory.Path, EvidenceStore.FileName);
        using (var store = EvidenceStore.OpenForWriting(path))
        {
            var settings = new EvidenceSettings(store);
            Assert.Equal(new AnalystConfiguration(), AnalystConfiguration.Read(settings));
            settings.Set(AnalystSettings.Provider, "\"relay\"", "test", "test");
            settings.Set(AnalystSettings.RelayUrl, "\"https://relay.example\"", "test", "test");
            settings.Set(AnalystSettings.Language, "\"es\"", "test", "test");
            var configuration = AnalystConfiguration.Read(settings);
            Assert.Equal("relay", configuration.Provider);
            Assert.Equal(new Uri("https://relay.example"), configuration.RelayUrl);
            Assert.True(configuration.Spanish);
            Assert.False(configuration.Enabled);
        }
    }
}

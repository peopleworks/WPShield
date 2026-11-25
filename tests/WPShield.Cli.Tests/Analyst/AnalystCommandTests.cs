using System.Net;
using System.Text;
using WPShield.Analyst;
using WPShield.Cli.Tests.Mcp;
using WPShield.Evidence;

namespace WPShield.Cli.Tests.Analyst;

/// <summary>
/// <c>wpshield analyst</c>: the gate before anything leaves the host, the verbs, and the key, which must
/// never appear in console output, a report or the store. No test calls a real provider.
/// </summary>
public sealed class AnalystCommandTests : IDisposable
{
    private const string Sentinel = "sk-ant-api03-SENTINEL0123456789abcdefSENTINEL";
    private const string RelaySentinel = "pwr_SENTINEL0123456789abcdefSENTINEL";
    private static readonly DateTimeOffset Now = EvidenceTestStore.Now;
    private readonly EvidenceTestStore store = new();
    private readonly Dictionary<string, string> environment = new(StringComparer.Ordinal);
    private Func<AnalystConfiguration, string, IAnalystProvider>? providers;
    private int providersBuilt;

    public void Dispose() => store.Dispose();

    private string ReportStore => Path.Combine(store.DirectoryPath, AnalystReportStore.FileName);

    private AnalystHost Host(bool elevated = true) => new(
        store.Path, () => elevated, name => environment.GetValueOrDefault(name), _ => false, new FixedClock(Now),
        (configuration, key) =>
        {
            providersBuilt++;
            return providers?.Invoke(configuration, key) ?? throw new InvalidOperationException("No provider in this test.");
        });

    private (int Exit, string Output, string Error) Run(params string[] args) => Run(Host(), args);

    private static (int Exit, string Output, string Error) Run(AnalystHost host, params string[] args)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var exit = AnalystCommand.Run(args, output, error, host, CancellationToken.None);
        return (exit, output.ToString(), error.ToString());
    }

    private void Enable(string provider = "anthropic")
    {
        store.Covered(Now.AddHours(-30), Now);
        store.Append(store.Failure(30, "203.0.113.7"), store.Failure(29, "203.0.113.7", "administrator"));
        store.Setting(AnalystSettings.Provider, $"\"{provider}\"");
        if (provider == "relay") store.Setting(AnalystSettings.RelayUrl, "\"https://relay.example\"");
        store.Setting(AnalystSettings.Enabled, "true");
    }

    /// <summary>A fake provider endpoint that echoes the key it was sent back in every answer, the worst case.</summary>
    private static HttpMessageHandler Echoing(params Func<string, (HttpStatusCode Status, string Body)>[] answers) => new EchoHandler(answers);

    private void AssertNoKeyAnywhere(params string[] texts)
    {
        foreach (var text in texts)
        {
            Assert.DoesNotContain(Sentinel, text, StringComparison.Ordinal);
            Assert.DoesNotContain(RelaySentinel, text, StringComparison.Ordinal);
            Assert.DoesNotContain("SENTINEL", text, StringComparison.Ordinal);
        }
        foreach (var file in Directory.GetFiles(store.DirectoryPath))
        {
            var bytes = File.ReadAllBytes(file);
            Assert.DoesNotContain("SENTINEL", Encoding.UTF8.GetString(bytes), StringComparison.Ordinal);
            Assert.DoesNotContain("SENTINEL", Encoding.Unicode.GetString(bytes), StringComparison.Ordinal);
        }
    }

    // ---------------------------------------------------------------------------------------------
    //  The gate
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void OffByDefault_ARunIsRefusedAndNoProviderIsBuilt()
    {
        store.Covered(Now.AddHours(-1), Now);
        environment["ANTHROPIC_API_KEY"] = Sentinel;

        var (exit, _, error) = Run("digest");

        Assert.Equal(1, exit);
        Assert.Contains("analyst.enabled is false", error, StringComparison.Ordinal);
        Assert.Equal(0, providersBuilt);
        Assert.False(File.Exists(ReportStore));
    }

    [Fact]
    public void WithoutAChosenProviderARunIsRefused()
    {
        store.Setting(AnalystSettings.Enabled, "true");
        environment["ANTHROPIC_API_KEY"] = Sentinel;

        var (exit, _, error) = Run("ask", "who attacked?");

        Assert.Equal(1, exit);
        Assert.Contains("analyst.provider", error, StringComparison.Ordinal);
        Assert.Equal(0, providersBuilt);
    }

    [Fact]
    public void WithoutTheKeyInTheEnvironmentARunIsRefusedNamingTheVariable()
    {
        Enable();

        var (exit, _, error) = Run("digest");

        Assert.Equal(1, exit);
        Assert.Contains("ANTHROPIC_API_KEY is not set", error, StringComparison.Ordinal);
        Assert.Equal(0, providersBuilt);
    }

    [Fact]
    public void TheRelayNeedsItsAddress()
    {
        store.Setting(AnalystSettings.Provider, "\"relay\"");
        store.Setting(AnalystSettings.Enabled, "true");
        environment["RELAY_API_KEY"] = RelaySentinel;

        var (exit, _, error) = Run("test");

        Assert.Equal(1, exit);
        Assert.Contains("analyst.relay_url", error, StringComparison.Ordinal);
    }

    [Fact]
    public void WithoutAStoreNothingRunsAndNoReportFileIsCreated()
    {
        environment["ANTHROPIC_API_KEY"] = Sentinel;

        var (exit, _, error) = Run("digest");

        Assert.Equal(3, exit);
        Assert.Contains("There is no evidence store", error, StringComparison.Ordinal);
        Assert.False(File.Exists(ReportStore));
    }

    [Fact]
    public void UnelevatedItSaysItCouldNotLook()
    {
        var (exit, _, error) = Run(Host(elevated: false), "status");

        Assert.Equal(1, exit);
        Assert.Contains("not elevated", error, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------------------------------
    //  Verbs
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void StatusSaysWhetherTheKeyIsPresentNeverWhatItIsAndWhatLeavesTheHost()
    {
        Enable();
        environment["ANTHROPIC_API_KEY"] = Sentinel;

        var (exit, output, _) = Run("status");

        Assert.Equal(0, exit);
        Assert.Contains("ANTHROPIC_API_KEY present: yes", output, StringComparison.Ordinal);
        Assert.Contains("0 of 10 runs", output, StringComparison.Ordinal);
        Assert.Contains("It goes to Anthropic", output, StringComparison.Ordinal);
        Assert.Contains("no account names", output, StringComparison.Ordinal);
        AssertNoKeyAnywhere(output);
    }

    [Fact]
    public void StatusWithoutAKeySaysARunWouldBeRefused()
    {
        Enable("relay");

        var (_, output, _) = Run("status");

        Assert.Contains("RELAY_API_KEY present: no", output, StringComparison.Ordinal);
        Assert.Contains("https://relay.example", output, StringComparison.Ordinal);
        Assert.Contains("A run would be refused now", output, StringComparison.Ordinal);
    }

    [Fact]
    public void ASimulatedDigestRunsTheLoopOverTheRealToolsAndStoresAReport()
    {
        Enable();

        var (exit, output, _) = Run("digest", "--since", "24h", "--simulated");

        Assert.Equal(0, exit);
        Assert.Contains("nothing leaves this host", output, StringComparison.Ordinal);
        Assert.Contains("reading coverage", output, StringComparison.Ordinal);
        Assert.Contains("AI analysis: opinion, not evidence", output, StringComparison.Ordinal);
        Assert.Equal(0, providersBuilt);
        using var reports = AnalystReportStore.OpenReadOnly(ReportStore)!;
        var report = Assert.Single(reports.Recent(10));
        Assert.Equal("simulated", report.Provider);
        Assert.Equal(["coverage", "attacks_summary", "top_sources"], report.ToolCalls.Select(c => c.Name));
        Assert.All(report.ToolCalls, c => Assert.False(c.IsError));

        var (listed, list, _) = Run("reports", "--last", "5");
        Assert.Equal(0, listed);
        Assert.StartsWith("AI analysis: opinion, not evidence", list, StringComparison.Ordinal);
        Assert.Contains($"#{report.Id}", list, StringComparison.Ordinal);

        var (shown, show, _) = Run("show", report.Id.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal(0, shown);
        Assert.StartsWith("AI analysis: opinion, not evidence", show, StringComparison.Ordinal);
    }

    [Fact]
    public void TheLabelFollowsTheLanguageSetting()
    {
        Enable();
        store.Setting(AnalystSettings.Language, "\"es\"");

        var (_, output, _) = Run("investigate", "203.0.113.0/24", "--simulated");

        Assert.Contains("Análisis de IA: opinión, no evidencia", output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("203.0.113.5/24")]
    [InlineData("not-an-address")]
    [InlineData("203.0.113.7; rm")]
    public void InvestigateRefusesAnythingButAnAddressOrAnExactNetwork(string target)
    {
        Enable();

        Assert.Throws<CliArgumentException>(() => Run("investigate", target, "--simulated"));
    }

    [Fact]
    public void ADigestRangeOutsideTheToolsBoundsIsRefused()
    {
        Assert.Throws<CliArgumentException>(() => Run("digest", "--since", "1y"));
    }

    [Fact]
    public void AnUnknownReportIsAnErrorNotAnEmptyPage()
    {
        Enable();

        var (exit, _, error) = Run("show", "42");

        Assert.Equal(1, exit);
        Assert.Contains("no analyst report #42", error, StringComparison.Ordinal);
    }

    [Fact]
    public void TheDailyRunBudgetRefusesARunNamingIt()
    {
        Enable();
        store.Setting(AnalystSettings.DailyRuns, "1");
        Run("digest", "--simulated");

        var (exit, _, error) = Run("digest", "--simulated");

        Assert.Equal(1, exit);
        Assert.Contains("analyst.daily_runs", error, StringComparison.Ordinal);
    }

    [Fact]
    public void EnablingTheAnalystPrintsWhatWillLeaveTheHost()
    {
        store.Setting(AnalystSettings.Provider, "\"anthropic\"");
        var output = new StringWriter();
        var exit = SettingsCommand.Run(["set", AnalystSettings.Enabled, "true", "--reason", "first digest"], output, new StringWriter(),
            store.Path, () => true, () => @"HOST\operator", () => Now);

        Assert.Equal(0, exit);
        Assert.Contains("What leaves this host when the analyst runs", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("It goes to Anthropic", output.ToString(), StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------------------------------
    //  The key
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void AProviderThatEchoesTheKeyNeverGetsItIntoTheConsoleTheReportOrTheStore()
    {
        Enable();
        environment["ANTHROPIC_API_KEY"] = Sentinel;
        providers = (configuration, key) => MessagesProvider.Anthropic(key, configuration.Model, configuration.Effort, Echoing(
            key => (HttpStatusCode.OK, Message("tool_use",
                "{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"coverage\",\"input\":{\"range\":\"24h\"},\"caller\":{\"type\":\"direct\"}}")),
            key => (HttpStatusCode.Unauthorized,
                "{\"type\":\"error\",\"error\":{\"type\":\"authentication_error\",\"message\":\"invalid x-api-key " + key + "\"}}")));

        var (exit, output, error) = Run("digest");

        Assert.Equal(2, exit);
        Assert.Contains("refused the key (401)", output, StringComparison.Ordinal);
        using (var reports = AnalystReportStore.OpenReadOnly(ReportStore)!)
        {
            var report = Assert.Single(reports.Recent(1));
            Assert.Equal(ReportStatus.Failed, report.Status);
            AssertNoKeyAnywhere(output, error, report.Error ?? "", report.Text);
        }
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        AssertNoKeyAnywhere(output, error);
    }

    [Fact]
    public void AModelThatRepeatsTheKeyInItsTextOrItsToolArgumentsNeverGetsItStored()
    {
        Enable();
        environment["ANTHROPIC_API_KEY"] = Sentinel;
        providers = (configuration, key) => MessagesProvider.Anthropic(key, configuration.Model, configuration.Effort, Echoing(
            key => (HttpStatusCode.OK, Message("tool_use",
                "{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"coverage\",\"input\":{\"range\":\"" + key + "\"},\"caller\":{\"type\":\"direct\"}}")),
            key => (HttpStatusCode.OK, Message("end_turn",
                "{\"type\":\"text\",\"text\":\"Your key is " + key + ".\\nSecond line.\",\"citations\":null}"))));

        var (exit, output, error) = Run("digest");

        Assert.Equal(0, exit);
        Assert.Contains("Your key is [redacted].", output, StringComparison.Ordinal);
        Assert.Contains("Second line.", output, StringComparison.Ordinal);
        using (var reports = AnalystReportStore.OpenReadOnly(ReportStore)!)
        {
            var report = Assert.Single(reports.Recent(1));
            Assert.Equal("Your key is [redacted].\nSecond line.", report.Text);
            Assert.Contains("[redacted]", Assert.Single(report.ToolCalls).Arguments, StringComparison.Ordinal);
        }
        AssertNoKeyAnywhere(output, error);
    }

    [Fact]
    public void AnExceptionCarryingTheKeyIsScrubbedAtTheChokePoint()
    {
        Enable();
        environment["ANTHROPIC_API_KEY"] = Sentinel;
        providers = (_, key) => throw new InvalidOperationException("could not build a client for " + key);

        var (exit, output, error) = Run("digest");

        Assert.Equal(2, exit);
        Assert.Contains("[redacted]", error, StringComparison.Ordinal);
        AssertNoKeyAnywhere(output, error);
    }

    [Fact]
    public void TheRelayTestNamesTheProjectAndARefusedTokenIsScrubbed()
    {
        Enable("relay");
        environment["RELAY_API_KEY"] = RelaySentinel;
        var handler = Echoing(
            _ => (HttpStatusCode.OK, """{"proyecto":"wpshield-example","etiqueta":"server-1","modelo_default":"claude-opus-5-5","facturacion":"relay"}"""),
            key => (HttpStatusCode.Unauthorized, "{\"type\":\"error\",\"error\":{\"type\":\"authentication_error\",\"message\":\"bad token " + key + "\"}}"));
        providers = (configuration, key) => MessagesProvider.Relay(key, configuration.RelayUrl!, configuration.Model, configuration.Effort, handler);

        var (ok, passed, _) = Run("test");
        var (failed, refused, refusedError) = Run("test");

        Assert.Equal(0, ok);
        Assert.Contains("project 'wpshield-example'", passed, StringComparison.Ordinal);
        Assert.Contains("a token of another project would still be answered", passed, StringComparison.Ordinal);
        Assert.Equal(1, failed);
        Assert.Contains("401", refused, StringComparison.Ordinal);
        AssertNoKeyAnywhere(passed, refused, refusedError);
    }

    private static string Message(string stopReason, string content) =>
        "{\"id\":\"msg_test\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-opus-5-5\",\"content\":[" + content + "]," +
        "\"stop_reason\":\"" + stopReason + "\",\"stop_sequence\":null,\"stop_details\":null," +
        "\"usage\":{\"input_tokens\":1000,\"output_tokens\":50,\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":0}}";

    /// <summary>Answers in order, each answer able to see the key header the request carried.</summary>
    private sealed class EchoHandler(Func<string, (HttpStatusCode Status, string Body)>[] answers) : HttpMessageHandler
    {
        private int next;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var key = request.Headers.TryGetValues("x-api-key", out var apiKey) ? apiKey.First()
                : request.Headers.Authorization?.Parameter ?? "";
            var (status, body) = answers[Math.Min(next++, answers.Length - 1)](key);
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }
}

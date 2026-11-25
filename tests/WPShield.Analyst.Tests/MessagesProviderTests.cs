using System.Net;
using System.Text.Json.Nodes;

namespace WPShield.Analyst.Tests;

/// <summary>
/// The Anthropic SDK over a fake <see cref="HttpMessageHandler"/>: what goes on the wire, and how each
/// answer is read. Nothing here reaches a provider.
/// </summary>
public sealed class MessagesProviderTests
{
    private const string Key = "sk-ant-test-0000-SENTINEL-KEY-do-not-print";
    private static readonly Uri Relay = new("https://relay.example");

    private static AnalystConversationSpec Spec(params IAnalystTool[] tools) =>
        new("You are a test.", "Write the digest for the last 24h.", tools, AnalystRunner.MaxOutputTokensPerTurn);

    [Fact]
    public async Task AToolUseRoundTripEchoesThinkingAndToolUseAndAnswersEveryCall()
    {
        var handler = new FakeHandler()
            .ThenJson(FakeHandler.Message("tool_use",
                FakeHandler.Thinking("sig-1") + "," + FakeHandler.ToolUse("toolu_1", "coverage", """{"range":"24h"}""")))
            .ThenJson(FakeHandler.Message("end_turn", FakeHandler.Text("Nothing was recorded after 08:00."), input: 1500, output: 300));
        using var provider = MessagesProvider.Anthropic(Key, "claude-opus-5-5", "medium", handler);
        var conversation = provider.Begin(Spec(new FakeTool("coverage")));

        var first = await conversation.NextAsync([], CancellationToken.None);
        Assert.Equal("tool_use", first.StopReason);
        var call = Assert.Single(first.ToolCalls);
        Assert.Equal("coverage", call.Name);
        Assert.Equal("24h", (string)call.Arguments["range"]!);

        var second = await conversation.NextAsync([new AnalystToolOutcome("toolu_1", """{"answer":"coverage"}""", false)], CancellationToken.None);
        Assert.Equal("end_turn", second.StopReason);
        Assert.Equal("Nothing was recorded after 08:00.", second.Text);
        Assert.Equal(1500, second.InputTokens);
        Assert.Equal("claude-opus-5-5", second.Model);

        var request = handler.Requests[0];
        Assert.Equal("api.anthropic.com", request.Uri.Host);
        Assert.Equal("/v1/messages", request.Uri.AbsolutePath);
        var body = request.Json;
        Assert.Equal("claude-opus-5-5", (string)body["model"]!);
        Assert.Equal("auto", (string)body["tool_choice"]!["type"]!);
        Assert.Equal("adaptive", (string)body["thinking"]!["type"]!);
        Assert.Equal("medium", (string)body["output_config"]!["effort"]!);
        var tool = body["tools"]![0]!;
        Assert.True((bool)tool["strict"]!);
        Assert.False((bool)tool["input_schema"]!["additionalProperties"]!);
        Assert.Null(body["stream"]);

        var echo = handler.Requests[1].Json["messages"]!.AsArray();
        Assert.Equal(3, echo.Count);
        var assistant = echo[1]!["content"]!.AsArray();
        Assert.Equal("thinking", (string)assistant[0]!["type"]!);
        Assert.Equal("sig-1", (string)assistant[0]!["signature"]!);
        Assert.Equal("tool_use", (string)assistant[1]!["type"]!);
        var result = echo[2]!["content"]![0]!;
        Assert.Equal("tool_result", (string)result["type"]!);
        Assert.Equal("toolu_1", (string)result["tool_use_id"]!);
    }

    [Fact]
    public async Task TheAnthropicProviderAsksForServerSideFallback()
    {
        var handler = new FakeHandler().ThenJson(FakeHandler.Message("end_turn", FakeHandler.Text("ok")));
        using var provider = MessagesProvider.Anthropic(Key, "claude-opus-5-5", "high", handler);

        await provider.Begin(Spec()).NextAsync([], CancellationToken.None);

        var request = handler.Requests.Single();
        Assert.Contains(MessagesProvider.FallbackBeta, request.Headers["anthropic-beta"], StringComparison.Ordinal);
        Assert.Equal("default", (string)request.Json["fallbacks"]!);
        Assert.Equal("high", (string)request.Json["output_config"]!["effort"]!);
        Assert.Equal("ephemeral", (string)request.Json["cache_control"]!["type"]!);
    }

    [Fact]
    public async Task TheRelayUsesItsAddressAndTheMessagesLaneWithNoFallbackAndNoBetaHeader()
    {
        var handler = new FakeHandler().ThenJson(FakeHandler.Message("end_turn", FakeHandler.Text("ok")));
        using var provider = MessagesProvider.Relay(Key, Relay, "claude-opus-5-5", "medium", handler);

        await provider.Begin(Spec(new FakeTool("coverage"))).NextAsync([], CancellationToken.None);

        var request = handler.Requests.Single();
        Assert.Equal("relay.example", request.Uri.Host);
        Assert.Equal("/v1/messages", request.Uri.AbsolutePath);
        Assert.False(request.Headers.ContainsKey("anthropic-beta"));
        Assert.Null(request.Json["fallbacks"]);
        // The SDK sends the key in one header (Authorization or x-api-key); the Relay accepts both.
        Assert.Single(request.Headers, h => h.Value.Contains(Key, StringComparison.Ordinal));
        Assert.False(provider.OperatorPays);
    }

    [Fact]
    public void TheRelayRefusesAnAddressThatIsNotHttps()
    {
        Assert.Throws<ArgumentException>(() => MessagesProvider.Relay(Key, new Uri("http://relay.example"), "claude-opus-5-5", "medium", new FakeHandler()));
    }

    [Fact]
    public async Task ARefusalIsReadWithItsCategory()
    {
        var handler = new FakeHandler().ThenJson(FakeHandler.Message("refusal", "",
            stopDetails: """{"type":"refusal","category":"cyber","explanation":"Declined by a safety classifier."}"""));
        using var provider = MessagesProvider.Anthropic(Key, "claude-opus-5-5", "medium", handler);

        var turn = await provider.Begin(Spec()).NextAsync([], CancellationToken.None);

        Assert.Equal("refusal", turn.StopReason);
        Assert.Equal("cyber", turn.RefusalCategory);
        Assert.Equal("Declined by a safety classifier.", turn.RefusalExplanation);
        Assert.Empty(turn.ToolCalls);
    }

    [Fact]
    public async Task AFallbackNamesTheModelThatAnsweredAndKeepsTheMarkerWhereItWas()
    {
        var fallback = """{"type":"fallback","from":{"model":"claude-opus-5-5"},"to":{"model":"claude-opus-5"},"trigger":{"type":"refusal","category":"cyber"}}""";
        var handler = new FakeHandler()
            .ThenJson(FakeHandler.Message("tool_use",
                FakeHandler.Thinking("declined") + "," + fallback + "," + FakeHandler.ToolUse("toolu_2", "coverage", "{}"), model: "claude-opus-5",
                iterations: """[{"type":"message","model":"claude-opus-5-5","input_tokens":10,"output_tokens":0,"cache_creation_input_tokens":0,"cache_read_input_tokens":0},{"type":"fallback_message","model":"claude-opus-5","input_tokens":1000,"output_tokens":200,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}]"""))
            .ThenJson(FakeHandler.Message("end_turn", FakeHandler.Text("done"), model: "claude-opus-5"));
        using var provider = MessagesProvider.Anthropic(Key, "claude-opus-5-5", "medium", handler);
        var conversation = provider.Begin(Spec(new FakeTool("coverage")));

        var turn = await conversation.NextAsync([], CancellationToken.None);
        Assert.True(turn.FellBack);
        Assert.Equal("claude-opus-5", turn.Model);
        // Both attempts, not only the one that answered.
        Assert.Equal(1010, turn.InputTokens);
        Assert.Equal(200, turn.OutputTokens);
        await conversation.NextAsync([new AnalystToolOutcome("toolu_2", "{}", false)], CancellationToken.None);

        var assistant = handler.Requests[1].Json["messages"]![1]!["content"]!.AsArray();
        Assert.Equal(["fallback", "tool_use"], assistant.Select(b => (string)b!["type"]!));
    }

    [Fact]
    public async Task AMalformedUsageBreakdownFallsBackToTheTopLevelCount()
    {
        var handler = new FakeHandler().ThenJson(FakeHandler.Message("end_turn", FakeHandler.Text("ok"), input: 1000,
            iterations: """[{"type":"message","input_tokens":10,"output_tokens":0}]"""));
        using var provider = MessagesProvider.Anthropic(Key, "claude-opus-5-5", "medium", handler);

        var turn = await provider.Begin(Spec()).NextAsync([], CancellationToken.None);

        Assert.Equal(1000, turn.InputTokens);
    }

    [Fact]
    public async Task AProviderErrorIsScrubbedOfTheKey()
    {
        var handler = new FakeHandler().Then(HttpStatusCode.Unauthorized,
            "{\"type\":\"error\",\"error\":{\"type\":\"authentication_error\",\"message\":\"invalid x-api-key: " + Key + "\"}}");
        using var provider = MessagesProvider.Anthropic(Key, "claude-opus-5-5", "medium", handler);

        var error = await Assert.ThrowsAsync<AnalystProviderException>(() => provider.Begin(Spec()).NextAsync([], CancellationToken.None));

        Assert.DoesNotContain(Key, error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("SENTINEL", error.Message, StringComparison.Ordinal);
        Assert.Contains("401", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheAnthropicTestReadsTheModelWithoutSpendingTokens()
    {
        var handler = new FakeHandler().ThenJson("""{"type":"model","id":"claude-opus-5-5","display_name":"Claude Opus 5.5","created_at":"2026-10-01T00:00:00Z"}""");
        using var provider = MessagesProvider.Anthropic(Key, "claude-opus-5-5", "medium", handler);

        var check = await provider.TestAsync(CancellationToken.None);

        Assert.True(check.Ok, check.Summary);
        var request = handler.Requests.Single();
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal("/v1/models/claude-opus-5-5", request.Uri.AbsolutePath);
    }

    [Fact]
    public async Task TheRelayTestCallsWhoamiAndNamesTheProject()
    {
        var handler = new FakeHandler().ThenJson("""{"proyecto":"wpshield-example","etiqueta":"server-1","modelo_default":"claude-opus-5-5","facturacion":"relay"}""");
        using var provider = MessagesProvider.Relay(Key, Relay, "claude-opus-5-5", "medium", handler);

        var check = await provider.TestAsync(CancellationToken.None);

        Assert.True(check.Ok, check.Summary);
        Assert.Contains("wpshield-example", check.Summary, StringComparison.Ordinal);
        var request = handler.Requests.Single();
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal("https://relay.example/v1/auth/whoami", request.Uri.ToString());
        Assert.Equal(Key, request.Headers["x-api-key"]);
    }

    [Fact]
    public async Task ARelayUnderAPathPrefixKeepsItForBothLanes()
    {
        var handler = new FakeHandler()
            .ThenJson("""{"proyecto":"wpshield-example"}""")
            .ThenJson(FakeHandler.Message("end_turn", FakeHandler.Text("ok")));
        using var provider = MessagesProvider.Relay(Key, new Uri("https://relay.example/gateway"), "claude-opus-5-5", "medium", handler);

        await provider.TestAsync(CancellationToken.None);
        await provider.Begin(Spec()).NextAsync([], CancellationToken.None);

        Assert.Equal("/gateway/v1/auth/whoami", handler.Requests[0].Uri.AbsolutePath);
        Assert.Equal("/gateway/v1/messages", handler.Requests[1].Uri.AbsolutePath);
    }

    [Fact]
    public async Task ARefusedRelayTokenIsAFailedTestScrubbedOfTheKey()
    {
        var handler = new FakeHandler().Then(HttpStatusCode.Unauthorized,
            "{\"type\":\"error\",\"error\":{\"type\":\"authentication_error\",\"message\":\"Invalid relay credential " + Key + "\"}}");
        using var provider = MessagesProvider.Relay(Key, Relay, "claude-opus-5-5", "medium", handler);

        var check = await provider.TestAsync(CancellationToken.None);

        Assert.False(check.Ok);
        Assert.Contains("401", check.Summary, StringComparison.Ordinal);
        Assert.DoesNotContain(Key, check.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AWhoamiWithoutAProjectIsNotAPass()
    {
        var handler = new FakeHandler().ThenJson("""{"ok":true}""");
        using var provider = MessagesProvider.Relay(Key, Relay, "claude-opus-5-5", "medium", handler);

        Assert.False((await provider.TestAsync(CancellationToken.None)).Ok);
    }

    [Theory]
    [InlineData("""{"proyecto":"wpshield","etiqueta":"srv","modelo_default":"claude-opus-5-5","facturacion":"relay"}""", "wpshield", "srv")]
    [InlineData("""{"proyecto":"p\u001b[31m","etiqueta":""}""", "p�[31m", null)]
    public void WhoamiIsParsedAndCleaned(string body, string project, string? label)
    {
        var identity = RelayIdentity.Parse(body);

        Assert.NotNull(identity);
        Assert.Equal(project, identity.Project);
        Assert.Equal(label, identity.Label);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("""{"proyecto":""}""")]
    [InlineData("""{"proyecto":42}""")]
    public void AWhoamiWithNoProjectParsesToNothing(string body)
    {
        Assert.Null(RelayIdentity.Parse(body));
    }
}

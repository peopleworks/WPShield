namespace WPShield.Analyst.Tests;

/// <summary>Tests that change this process's environment run alone, so no other test reads it meanwhile.</summary>
[CollectionDefinition(nameof(ProcessEnvironment), DisableParallelization = true)]
public sealed class ProcessEnvironment;

/// <summary>
/// Left to itself the SDK reads <c>ANTHROPIC_BASE_URL</c> and <c>ANTHROPIC_AUTH_TOKEN</c>, and a Claude Code
/// pointed at a Relay sets exactly those two. The analyst passes its key and address explicitly; this pins
/// that they win, because if they did not, evidence would go to a host nobody chose.
/// </summary>
[Collection(nameof(ProcessEnvironment))]
public sealed class EnvironmentOverrideTests
{
    private const string Key = "sk-ant-test-explicit-key-0000000000";
    private const string EnvironmentToken = "env-token-0000000000000000000000";

    [Fact]
    public async Task TheExplicitKeyAndAddressWinOverTheSdksEnvironmentVariables()
    {
        var saved = (Base: Environment.GetEnvironmentVariable("ANTHROPIC_BASE_URL"), Token: Environment.GetEnvironmentVariable("ANTHROPIC_AUTH_TOKEN"));
        Environment.SetEnvironmentVariable("ANTHROPIC_BASE_URL", "https://wrong.example");
        Environment.SetEnvironmentVariable("ANTHROPIC_AUTH_TOKEN", EnvironmentToken);
        try
        {
            var handler = new FakeHandler()
                .ThenJson(FakeHandler.Message("end_turn", FakeHandler.Text("ok")))
                .ThenJson(FakeHandler.Message("end_turn", FakeHandler.Text("ok")));
            using (var anthropic = MessagesProvider.Anthropic(Key, "claude-opus-5-5", "medium", handler))
                await anthropic.Begin(new("system", "first", [], 1000)).NextAsync([], CancellationToken.None);
            using (var relay = MessagesProvider.Relay(Key, new Uri("https://relay.example"), "claude-opus-5-5", "medium", handler))
                await relay.Begin(new("system", "first", [], 1000)).NextAsync([], CancellationToken.None);

            Assert.Equal("api.anthropic.com", handler.Requests[0].Uri.Host);
            Assert.Equal("relay.example", handler.Requests[1].Uri.Host);
            foreach (var request in handler.Requests)
            {
                Assert.Single(request.Headers, h => h.Value.Contains(Key, StringComparison.Ordinal));
                Assert.DoesNotContain(request.Headers, h => h.Value.Contains(EnvironmentToken, StringComparison.Ordinal));
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("ANTHROPIC_BASE_URL", saved.Base);
            Environment.SetEnvironmentVariable("ANTHROPIC_AUTH_TOKEN", saved.Token);
        }
    }
}

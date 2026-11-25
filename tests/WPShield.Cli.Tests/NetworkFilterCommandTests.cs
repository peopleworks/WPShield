using System.Text.Json;
using WPShield.NetworkFilter;
using WPShield.NetworkFilter.Tests.Support;

namespace WPShield.Cli.Tests;

public sealed class NetworkFilterCommandTests
{
    [Fact]
    public void DefaultMonitorDoesNotOpenWfp()
    {
        using var output = new StringWriter();
        var code = NetworkFilterCommand.Run(CliOptions.Parse(["--block", "198.51.100.4"]), output,
            () => throw new InvalidOperationException("Monitor opened WFP."),
            () => throw new InvalidOperationException("Monitor should exit after previewing."));

        Assert.Equal(0, code);
        Assert.Contains("Would block (Monitor mode)", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void DuplicateAllowListsAreRejected()
    {
        Assert.Throws<CliArgumentException>(() => NetworkFilterCommand.Run(
            CliOptions.Parse(["--allow", "192.0.2.1", "--allow", "192.0.2.2"]), TextWriter.Null));
    }

    [Theory]
    [InlineData("--install-driver")]
    [InlineData("--syn-rules-may-block")]
    [InlineData("--block-list")]
    public void RetiredOptionsAreRejected(string option)
    {
        Assert.Equal(1, ProgramMain.Run(["network-filter", option]));
    }

    [Fact]
    public void CheckExercisesTheNativeOperationsThroughTheCurrentIdentity()
    {
        using var output = new StringWriter();
        var session = new FakeWfpSession();

        var code = NetworkFilterCommand.Run(CliOptions.Parse(["--check"]), output, () => session, () => { });

        Assert.Equal(0, code);
        Assert.Contains("Windows identity:", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("PASS", output.ToString(), StringComparison.Ordinal);
        Assert.Single(session.Added);
        Assert.Single(session.Deleted);
        Assert.True(session.Disposed);
    }

    [Fact]
    public void CheckReturnsFailureWhenWfpAccessIsDenied()
    {
        using var output = new StringWriter();
        var code = NetworkFilterCommand.Run(CliOptions.Parse(["--check"]), output,
            () => throw new WfpException("Open dynamic session was denied."), () => { });

        Assert.Equal(1, code);
        Assert.Contains("Open dynamic session was denied.", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void TheJsonLineUsesTheGatewayEnvelope()
    {
        var json = NetworkFilterEventWriter.ToJson(new NetworkFilterEvent(
            new DateTimeOffset(2026, 11, 1, 12, 0, 0, TimeSpan.Zero),
            NetworkFilterEventLevel.Warning,
            "Blocked.",
            new Dictionary<string, object> { ["action"] = "blocked", ["source_ip"] = "198.51.100.9", ["lifetime_minutes"] = 60 }));

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal(["timestamp", "level", "category", "message", "state"], root.EnumerateObject().Select(p => p.Name));
        Assert.Equal("WPShield.NetworkFilter", root.GetProperty("category").GetString());
        Assert.Equal("Warning", root.GetProperty("level").GetString());
        Assert.Equal(60, root.GetProperty("state").GetProperty("lifetime_minutes").GetInt32());
        Assert.DoesNotContain('\n', json);
    }
}

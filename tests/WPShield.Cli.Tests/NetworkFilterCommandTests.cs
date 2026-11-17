using System.Text.Json;
using WPShield.NetworkFilter;
using WPShield.NetworkFilter.Tests.Support;

namespace WPShield.Cli.Tests;

public sealed class NetworkFilterCommandTests
{
    private readonly FakeDivertDriver _driver = new();

    private (int ExitCode, string Output) Run(bool elevated, params string[] args)
    {
        using var output = new StringWriter();
        var exit = NetworkFilterCommand.Run(CliOptions.Parse(args), output, _ => _driver, () => elevated, () => { });
        return (exit, output.ToString());
    }

    [Fact]
    public void AnAllowListGivenTwice_IsRefusedRatherThanHalfApplied()
    {
        var exception = Assert.Throws<CliArgumentException>(() =>
            Run(true, "--mode", "Block", "--allow", "203.0.113.50", "--allow", "198.51.100.7"));

        Assert.Contains("--allow", exception.Message, StringComparison.Ordinal);
        Assert.Empty(_driver.Opened);
    }

    [Theory]
    [InlineData("--mode", "Blok")]
    [InlineData("--allow", "1.2.3")]
    [InlineData("--block", "203.0.113.7/24")]
    [InlineData("--block", "10.0.0.0/8")]
    [InlineData("--block", "127.0.0.1")]
    [InlineData("--block-ttl-minutes", "0")]
    [InlineData("--max-blocks", "0")]
    public void AWrongValue_IsAnArgumentError(string option, string value)
    {
        Assert.Throws<CliArgumentException>(() => Run(true, option, value));
        Assert.Empty(_driver.Opened);
    }

    [Fact]
    public void ABlockOverlappingTheAllowList_IsAnArgumentError()
    {
        var exception = Assert.Throws<CliArgumentException>(() =>
            Run(true, "--allow", "94.0.0.7", "--block", "94.0.0.0/24"));

        Assert.Contains("94.0.0.0/24", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheDefault_IsMonitorAndDropsNothing()
    {
        var (exit, output) = Run(true, "--block", "94.0.0.0/24");

        Assert.Equal(0, exit);
        Assert.Contains("Monitor mode drops nothing", output, StringComparison.Ordinal);
        Assert.Empty(_driver.Live(DivertHandleKind.Drop));
        Assert.All(_driver.Opened, handle => Assert.True(handle.IsDisposed));
    }

    [Fact]
    public void Block_WithoutAnAllowList_ExitsOneAndOpensNothing()
    {
        var (exit, output) = Run(true, "--mode", "Block", "--block", "94.0.0.0/24");

        Assert.Equal(1, exit);
        Assert.Contains("--allow", output, StringComparison.Ordinal);
        Assert.Empty(_driver.Opened);
    }

    [Fact]
    public void WithoutElevation_ItRefuses()
    {
        var (exit, output) = Run(false);

        Assert.Equal(1, exit);
        Assert.Contains("elevation", output, StringComparison.Ordinal);
        Assert.Empty(_driver.Opened);
    }

    [Fact]
    public void Check_NeedsNoElevationAndOpensNoHandle()
    {
        var (exit, output) = Run(false, "--check", "--allow", "203.0.113.50", "--block", "94.0.0.0/24");

        Assert.Equal(0, exit);
        Assert.Contains("Self-test passed", output, StringComparison.Ordinal);
        Assert.Empty(_driver.Opened);
    }

    [Fact]
    public void Check_ReportsFailuresAndExitsOne()
    {
        _driver.EvaluateOverride = (_, source) => source.ToString() == "198.51.101.0" ? true : null;

        var (exit, output) = Run(false, "--check");

        Assert.Equal(1, exit);
        Assert.Contains("FAIL", output, StringComparison.Ordinal);
        Assert.Contains("Block mode will refuse to start", output, StringComparison.Ordinal);
    }

    [Fact]
    public void TheJsonLine_UsesTheGatewayEnvelope()
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

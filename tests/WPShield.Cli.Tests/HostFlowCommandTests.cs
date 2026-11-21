using System.Text.Json;
using WPShield.NetworkSensor;
using Xunit;

namespace WPShield.Cli.Tests;

public sealed class HostFlowCommandTests
{
    [Theory]
    [InlineData("--flows --all-ports")]
    [InlineData("--flows --interfaces Ethernet")]
    [InlineData("--flows --interfaces Ethernet --ports 0")]
    [InlineData("--flows --interfaces Ethernet --ports 443 --all-ports")]
    [InlineData("--flows --interfaces Ethernet --all-ports=false")]
    [InlineData("--flows --interfaces Ethernet --all-ports --output example.ndjson")]
    public void InvalidScopeFailsBeforeElevationOrDriverLookup(string arguments)
    {
        Assert.Throws<CliArgumentException>(() => NetworkMonitorCommand.Run(
            CliOptions.Parse(arguments.Split(' ')), TextWriter.Null));
    }

    [Fact]
    public void ConsoleAndJsonExposeUnknownsAndVisibleRowCount()
    {
        var now = DateTimeOffset.UnixEpoch;
        var snapshot = new FlowSnapshot("synthetic", now, 3, 7, 2, null,
            [new FlowRow("TCP", "192.0.2.1:443", "198.51.100.2:54123", "unknown", 60, 40, now)]);
        using var display = new StringWriter();
        NetworkMonitorCommand.WriteSnapshot(display, snapshot, false);
        Assert.Contains("Showing 1/3", display.ToString());
        Assert.Contains("unavailable", display.ToString());
        Assert.Contains("unknown", display.ToString());
        using var output = new StringWriter();
        NetworkMonitorCommand.WriteSnapshot(output, snapshot, true);
        using var json = JsonDocument.Parse(output.ToString());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("DriverDrops").ValueKind);
        Assert.Equal(2, json.RootElement.GetProperty("CapacityDrops").GetInt64());
    }
}

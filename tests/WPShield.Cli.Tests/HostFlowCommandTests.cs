using System.Net;
using System.Text.Json;
using WPShield.NetworkSensor;
using WPShield.SecurityMonitor;
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
    [InlineData("--flows --interfaces Ethernet --ports 443 --rdp-port 3389")]
    [InlineData("--flows --interfaces Ethernet --all-ports --rdp-port")]
    [InlineData("--flows --interfaces Ethernet --all-ports --rdp-port 65536")]
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

    private static readonly DateTimeOffset Start = DateTimeOffset.UnixEpoch;
    private static readonly IPEndPoint Peer = IPEndPoint.Parse("198.51.100.2:54123");
    private static readonly FlowRow Incoming = new("TCP", "192.0.2.1:3390", Peer.ToString(), "remote", 80, 40, Start.AddSeconds(10))
    { FirstSeen = Start };

    private static FlowSnapshot Snapshot(params FlowRow[] rows) => new("synthetic", Start.AddSeconds(15), rows.Length, 0, 0, null, rows);

    [Fact]
    public void AuditOutputPreservesBothOutcomesAndTheirRecordReferences()
    {
        var snapshot = Snapshot(Incoming);
        var audit = new RdpAuditWindow("read", [new(4625, 123, Start, Peer), new(4624, 125, Incoming.LastSeen, Peer)]);
        using var output = new StringWriter();
        NetworkMonitorCommand.WriteAuditedSnapshot(output, snapshot, true, 3390, audit);
        using var json = JsonDocument.Parse(output.ToString());
        var auditRow = json.RootElement.GetProperty("RdpAudit").GetProperty("Flows")[0];
        Assert.Equal("mixed", auditRow.GetProperty("Outcome").GetString());
        var events = auditRow.GetProperty("Events");
        Assert.Equal(123, events[0].GetProperty("RecordId").GetInt64());
        Assert.Equal(4624, events[1].GetProperty("EventId").GetInt32());
        Assert.Equal(1, json.RootElement.GetProperty("Traffic").GetProperty("ActiveFlows").GetInt32());
    }

    [Fact]
    public void AmbiguityOutsideTheFortyVisibleRowsStillPreventsAttribution()
    {
        var unrelated = Incoming with { Protocol = "UDP" };
        var rows = new[] { Incoming }.Concat(Enumerable.Repeat(unrelated, 39))
            .Append(Incoming with { Local = "192.0.2.2:3390", Initiator = "unknown" }).ToArray();
        using var display = new StringWriter();
        NetworkMonitorCommand.WriteAuditedSnapshot(display, Snapshot(rows), false, 3390,
            new("read", [new(4625, 123, Start, Peer)]));
        Assert.Contains("Showing 40/41", display.ToString());
        Assert.Contains("unknown", display.ToString());
        Assert.DoesNotContain("Security record 123", display.ToString());
        Assert.DoesNotContain("192.0.2.2", display.ToString());
    }

    [Theory]
    [InlineData("remote", -1, 54123)]
    [InlineData("remote", 11, 54123)]
    [InlineData("remote", 2, 54124)]
    [InlineData("unknown", 2, 54123)]
    [InlineData("local", 2, 54123)]
    public void TimeEndpointAndObservedDirectionAllMatter(string initiator, int seconds, int sourcePort)
    {
        var report = RdpFlowReport.Create(Snapshot(Incoming with { Initiator = initiator }), 3390,
            new("read", [new(4625, 123, Start.AddSeconds(seconds), new(Peer.Address, sourcePort))]));
        Assert.Equal("unknown", Assert.Single(report.Flows).Outcome);
    }

    [Theory]
    [InlineData("unavailable")]
    [InlineData("limited")]
    [InlineData("read")]
    public void EmptyAuditPreservesUnknownAndExplainsSourceCoverage(string status)
    {
        var report = RdpFlowReport.Create(Snapshot(Incoming), 3390, new(status, []));
        Assert.Equal(status, report.AuditStatus);
        Assert.Equal("unknown", Assert.Single(report.Flows).Outcome);
    }
}

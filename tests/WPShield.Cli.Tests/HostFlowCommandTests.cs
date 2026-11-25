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
    [InlineData("--flows --interfaces Ethernet --all-ports --history=false")]
    [InlineData("--history")]
    [InlineData("--listeners --flows")]
    [InlineData("--listeners --list-interfaces")]
    [InlineData("--listeners --ports")]
    [InlineData("--listeners --ports 0")]
    [InlineData("--listeners --json=false")]
    [InlineData("--listeners=true")]
    [InlineData("--owners")]
    [InlineData("--port-hints")]
    [InlineData("--listeners --port-hints=false")]
    [InlineData("--flows --interfaces Ethernet --all-ports --port-hints")]
    [InlineData("--listeners --owners=false")]
    [InlineData("--listeners --listeners")]
    [InlineData("--list-interfaces --flows")]
    [InlineData("--list-interfaces --output example.ndjson")]
    [InlineData("--list-interfaces=true")]
    [InlineData("--list-interfaces --json=false")]
    [InlineData("--list-interfaces --list-interfaces")]
    [InlineData("--flows --interfaces Ethernet")]
    [InlineData("--flows --interfaces Ethernet --ports 0")]
    [InlineData("--flows --interfaces Ethernet --ports 443 --all-ports")]
    [InlineData("--flows --interfaces Ethernet --all-ports=false")]
    [InlineData("--flows --interfaces Ethernet --all-ports --output example.ndjson")]
    [InlineData("--flows --interfaces Ethernet --ports 443 --rdp-port 3389")]
    [InlineData("--flows --interfaces Ethernet --all-ports --rdp-port")]
    [InlineData("--flows --interfaces Ethernet --all-ports --rdp-port 65536")]
    [InlineData("--flows --interfaces Ethernet --all-ports --sql-instance")]
    [InlineData("--sql-instance Test --json=true")]
    [InlineData("--sql-instance Test --ports 1433")]
    [InlineData("--sql-instance First --sql-instance Second")]
    [InlineData("--sql-instance server.example\\Example")]
    public void InvalidScopeFailsBeforeElevationOrDriverLookup(string arguments)
    {
        Assert.Throws<CliArgumentException>(() => NetworkMonitorCommand.Run(
            CliOptions.Parse(arguments.Split(' ')), TextWriter.Null));
    }

    [Fact]
    public void InventoryShowsSelectableDeviceIdAndAddressFamiliesInBothFormats()
    {
        FlowInterface[] interfaces = [new(@"\\example", "Example\nname", "Example adapter", true, false),
            new("example2", null, null, false, false)];
        using var display = new StringWriter();
        var args = CliOptions.Parse(["--list-interfaces"]);
        Assert.Equal(0, NetworkMonitorCommand.ListInterfaces(args, display, TextWriter.Null, () => interfaces));
        Assert.Contains(@"\\example  |  Example?name  |  IPv4", display.ToString());
        Assert.Contains("none (flow direction unavailable)", display.ToString());
        using var output = new StringWriter();
        var jsonArgs = CliOptions.Parse(["--list-interfaces", "--json"]);
        Assert.Equal(0, NetworkMonitorCommand.ListInterfaces(jsonArgs, output, TextWriter.Null, () => interfaces));
        Assert.Equal(interfaces, JsonSerializer.Deserialize<FlowInterface[]>(output.ToString()));
    }

    [Fact]
    public void EmptyInventoryAndUnavailableDriverAreDistinct()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var args = CliOptions.Parse(["--list-interfaces", "--json"]);
        Assert.Equal(0, NetworkMonitorCommand.ListInterfaces(args, output, error, () => []));
        Assert.Equal("[]", output.ToString().Trim());
        output.GetStringBuilder().Clear();
        Assert.Equal(1, NetworkMonitorCommand.ListInterfaces(args, output, error, () => throw new DllNotFoundException()));
        Assert.Empty(output.ToString());
        Assert.StartsWith("ERROR: Npcap is not installed on this computer", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void ARefusalIsNotReportedAsAMissingNpcap()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var args = CliOptions.Parse(["--list-interfaces"]);

        Assert.Equal(1, NetworkMonitorCommand.ListInterfaces(args, output, error, () => throw new UnauthorizedAccessException()));

        Assert.StartsWith("ERROR: Npcap refused access to the capture adapters", error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("not installed", error.ToString(), StringComparison.Ordinal);
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
        Assert.False(json.RootElement.TryGetProperty("History", out _));
    }

    [Fact]
    public void ConsoleShowsFiveIntervalsAndAuditJsonKeepsAllSuppliedIntervalsInTraffic()
    {
        var rows = Enumerable.Range(1, 6).Select(i => new TrafficInterval(Start.AddSeconds(i - 1), Start.AddSeconds(i),
            1, 100, 50, 0, 1, ["driver-drops"])).ToArray();
        var snapshot = Snapshot() with { History = rows };
        using var console = new StringWriter();
        NetworkMonitorCommand.WriteSnapshot(console, snapshot, false);
        Assert.Equal(5, console.ToString().Split("gap (driver-drops)").Length - 1);
        Assert.Contains("--", console.ToString());
        using var writer = new StringWriter();
        NetworkMonitorCommand.WriteSnapshot(writer, snapshot, true, RdpFlowReport.Create(snapshot, 3389, new("read", [])));
        using var json = JsonDocument.Parse(writer.ToString());
        var history = json.RootElement.GetProperty("Traffic").GetProperty("History");
        Assert.Equal(6, history.GetArrayLength());
        Assert.Equal(JsonValueKind.Null, history[0].GetProperty("ReceivedBytesPerSecond").ValueKind);
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
        NetworkMonitorCommand.WriteSnapshot(output, snapshot, true, RdpFlowReport.Create(snapshot, 3390, audit));
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
        var snapshot = Snapshot(rows);
        var report = RdpFlowReport.Create(snapshot, 3390, new("read", [new(4625, 123, Start, Peer)]));
        NetworkMonitorCommand.WriteSnapshot(display, snapshot, false, report);
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

    [Fact]
    public void EmptySourcesReportIndependentWindowsReasonsAndCaptureStatus()
    {
        var snapshot = Snapshot() with { CaptureStatus = "interrupted", CapturePorts = [1433, 3389] };
        var end = snapshot.Timestamp;
        var rdp = RdpFlowReport.Create(snapshot, 3389, new("unavailable", [])
        { WindowEnd = end, UnavailableReason = "access-denied" });
        var sql = new SqlLoginAuditWindow("MSSQLSERVER", end, "read", []);
        using var output = new StringWriter();
        NetworkMonitorCommand.WriteSnapshot(output, snapshot, true, rdp, sql);
        using var document = JsonDocument.Parse(output.ToString());
        var report = document.RootElement;
        Assert.Equal("interrupted", report.GetProperty("Traffic").GetProperty("CaptureStatus").GetString());
        var security = report.GetProperty("RdpAudit");
        Assert.Equal(end.AddMinutes(-1), security.GetProperty("WindowStart").GetDateTimeOffset());
        Assert.Equal(end, security.GetProperty("WindowEnd").GetDateTimeOffset());
        Assert.Equal("access-denied", security.GetProperty("UnavailableReason").GetString());
        Assert.Equal("read", report.GetProperty("SqlAudit").GetProperty("AuditStatus").GetString());
        Assert.Equal(JsonValueKind.Null, report.GetProperty("SqlAudit").GetProperty("UnavailableReason").ValueKind);
        using var display = new StringWriter();
        NetworkMonitorCommand.WriteSnapshot(display, snapshot, false, rdp, sql);
        Assert.Contains("TCP/UDP ports: 1433,3389  Capture: interrupted", display.ToString());
        Assert.Contains("Security log: unavailable (access-denied)", display.ToString());
        Assert.Contains("Application log: read", display.ToString());
        using var standalone = new StringWriter();
        Assert.Equal(1, NetworkMonitorCommand.WriteStandaloneSqlAudit(standalone, sql with
        { AuditStatus = "unavailable", UnavailableReason = "query-failed" }, false));
        Assert.Contains("Application log: unavailable (query-failed)", standalone.ToString());
    }

    [Theory]
    [InlineData("read", 0)]
    [InlineData("limited", 2)]
    [InlineData("unavailable", 1)]
    public void StandaloneSqlAuditDistinguishesEmptyPartialAndUnreadableWindows(string status, int exitCode)
    {
        var sql = new SqlLoginAuditWindow("MSSQLSERVER", Start, status, []);
        using var output = new StringWriter();
        Assert.Equal(exitCode, NetworkMonitorCommand.WriteStandaloneSqlAudit(output, sql, true));
        using var json = JsonDocument.Parse(output.ToString());
        Assert.Equal(status, json.RootElement.GetProperty("AuditStatus").GetString());
        Assert.Equal("unknown", json.RootElement.GetProperty("ObservedOutcome").GetString());
        using var console = new StringWriter();
        Assert.Equal(exitCode, NetworkMonitorCommand.WriteStandaloneSqlAudit(console, sql, false));
        Assert.Contains($"Application log: {status}", console.ToString());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void SqlAuditIsInstanceScopedEvenWhenTheCapturedFlowUsesTheSqlPort(bool includeRdp)
    {
        var snapshot = Snapshot(Incoming with { Local = "192.0.2.1:1433" });
        var sql = new SqlLoginAuditWindow("MSSQL$Example", Start, "limited", [new(18456, 431, Start, "failure")]);
        var rdp = includeRdp ? RdpFlowReport.Create(snapshot, 3389, new("read", [])) : null;
        using var output = new StringWriter();
        NetworkMonitorCommand.WriteSnapshot(output, snapshot, true, rdp, sql);
        using var json = JsonDocument.Parse(output.ToString());
        Assert.Equal(includeRdp, json.RootElement.TryGetProperty("RdpAudit", out _));
        var section = json.RootElement.GetProperty("SqlAudit");
        Assert.Equal("unknown", section.GetProperty("FlowAttribution").GetString());
        Assert.Equal("limited", section.GetProperty("AuditStatus").GetString());
        Assert.Equal(431, section.GetProperty("Events")[0].GetProperty("RecordId").GetInt32());
        var traffic = json.RootElement.GetProperty("Traffic").GetProperty("Flows")[0];
        Assert.False(traffic.TryGetProperty("Outcome", out _));
        using var console = new StringWriter();
        NetworkMonitorCommand.WriteSnapshot(console, snapshot, false, rdp, sql);
        Assert.Contains("MSSQL$Example", console.ToString());
        Assert.Contains("failure  Event 18456  Application record 431", console.ToString());
    }
}

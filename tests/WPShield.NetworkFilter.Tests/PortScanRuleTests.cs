namespace WPShield.NetworkFilter.Tests;

public sealed class PortScanRuleTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);

    private static NetworkInspectionContext Attempt(string source, int port, DateTimeOffset at) => new()
    {
        SourceIp = source,
        DestinationIp = "192.0.2.1",
        SourcePort = 49152,
        DestinationPort = port,
        Protocol = "TCP",
        Timestamp = at,
    };

    private static NetworkInspectionResult Sweep(PortScanRule rule, string source, int ports)
    {
        NetworkInspectionResult? last = null;
        for (var port = 1; port <= ports; port++)
        {
            last = rule.Inspect(Attempt(source, port, Start));
        }

        return last!;
    }

    [Fact]
    public void ManyAttemptsAtOnePort_AreNotAScan()
    {
        var rule = new PortScanRule(maxDistinctPortsPerMinute: 5);
        NetworkInspectionResult? last = null;
        for (var i = 0; i < 100; i++)
        {
            last = rule.Inspect(Attempt("198.51.100.7", 443, Start));
        }

        Assert.Equal("WP-NET-003", last!.RuleId);
        Assert.Equal(0, last.Score);
    }

    [Theory]
    [InlineData(4, 0, NetworkInspectionAction.Allow)]
    [InlineData(5, 60, NetworkInspectionAction.Observe)]
    [InlineData(10, 80, NetworkInspectionAction.Block)]
    [InlineData(15, 100, NetworkInspectionAction.Block)]
    public void DistinctPorts_RaiseTheScore(int ports, int score, NetworkInspectionAction action)
    {
        var result = Sweep(new PortScanRule(maxDistinctPortsPerMinute: 5), "198.51.100.7", ports);

        Assert.Equal(score, result.Score);
        Assert.Equal(action, result.Action);
    }

    [Fact]
    public void PortsOlderThanAMinute_AreForgotten()
    {
        var rule = new PortScanRule(maxDistinctPortsPerMinute: 5);
        Sweep(rule, "198.51.100.7", 4);

        var later = rule.Inspect(Attempt("198.51.100.7", 9999, Start.AddMinutes(2)));

        Assert.Equal(1, later.Evidence["distinct_ports_last_minute"]);
    }

    [Fact]
    public void AFullSweep_KeepsPerSourceStateBounded()
    {
        var rule = new PortScanRule(maxDistinctPortsPerMinute: 5);

        var result = Sweep(rule, "198.51.100.7", 65_535);

        Assert.Equal(100, result.Score);
        Assert.Equal(16, result.Evidence["distinct_ports_last_minute"]);
    }
}

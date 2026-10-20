namespace WPShield.NetworkFilter.Tests;

public class PortScanRuleTests
{
    [Fact]
    public void Few_ports_returns_allow_with_zero_score()
    {
        var rule = new PortScanRule(maxDistinctPortsPerMinute: 20);

        var result = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = DateTimeOffset.UtcNow
        });

        Assert.Equal(0, result.Score);
        Assert.Equal(NetworkInspectionAction.Allow, result.Action);
        Assert.Equal("WP-NET-003", result.RuleId);
    }

    [Fact]
    public void Many_distinct_ports_returns_block()
    {
        var rule = new PortScanRule(maxDistinctPortsPerMinute: 20);
        var now = DateTimeOffset.UtcNow;

        // Connect to 30 distinct ports
        for (int port = 1000; port < 1030; port++)
        {
            rule.Inspect(new NetworkInspectionContext
            {
                SourceIp = "10.0.0.1",
                DestinationIp = "10.0.0.2",
                SourcePort = 51422,
                DestinationPort = port,
                Protocol = "TCP",
                Timestamp = now
            });
        }

        var result = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 1030,
            Protocol = "TCP",
            Timestamp = now
        });

        Assert.Equal(80, result.Score);
        Assert.Equal(NetworkInspectionAction.Block, result.Action);
        Assert.True((int)result.Evidence["distinct_ports_last_minute"] >= 30);
    }

    [Fact]
    public void Repeated_connections_to_same_port_do_not_increase_distinct_count()
    {
        var rule = new PortScanRule(maxDistinctPortsPerMinute: 20);
        var now = DateTimeOffset.UtcNow;

        for (int i = 0; i < 100; i++)
        {
            rule.Inspect(new NetworkInspectionContext
            {
                SourceIp = "10.0.0.1",
                DestinationIp = "10.0.0.2",
                SourcePort = 51422,
                DestinationPort = 443,
                Protocol = "TCP",
                Timestamp = now
            });
        }

        var result = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = now
        });

        Assert.Equal(0, result.Score);
        Assert.Equal(NetworkInspectionAction.Allow, result.Action);
    }

    [Fact]
    public void Different_ips_are_tracked_separately()
    {
        var rule = new PortScanRule(maxDistinctPortsPerMinute: 5);
        var now = DateTimeOffset.UtcNow;

        // IP1 connects to 6 distinct ports -> score 60 (Observe), crosses threshold of 5
        for (int port = 1000; port < 1006; port++)
        {
            rule.Inspect(new NetworkInspectionContext
            {
                SourceIp = "10.0.0.1",
                DestinationIp = "10.0.0.2",
                SourcePort = 51422,
                DestinationPort = port,
                Protocol = "TCP",
                Timestamp = now
            });
        }

        var ip1 = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 1010,
            Protocol = "TCP",
            Timestamp = now
        });

        // IP2 connects to just one port -> score 0 (Allow)
        var ip2 = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.2",
            DestinationIp = "10.0.0.2",
            SourcePort = 51423,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = now
        });

        Assert.Equal(NetworkInspectionAction.Observe, ip1.Action);
        Assert.Equal(NetworkInspectionAction.Allow, ip2.Action);
    }

    [Fact]
    public void Window_expires_old_entries()
    {
        var rule = new PortScanRule(maxDistinctPortsPerMinute: 5);
        var now = DateTimeOffset.UtcNow;
        var oneMinuteAgo = now.AddMinutes(-1).AddSeconds(-1);

        for (int port = 1000; port < 1006; port++)
        {
            rule.Inspect(new NetworkInspectionContext
            {
                SourceIp = "10.0.0.1",
                DestinationIp = "10.0.0.2",
                SourcePort = 51422,
                DestinationPort = port,
                Protocol = "TCP",
                Timestamp = oneMinuteAgo
            });
        }

        var result = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = now
        });

        Assert.Equal(0, result.Score);
        Assert.Equal(NetworkInspectionAction.Allow, result.Action);
    }
}

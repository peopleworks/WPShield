namespace WPShield.Integration.Tests;

public class NetworkFilterBlockListSinkTests
{
    [Fact]
    public void Block_finding_adds_ip_to_block_list_rule()
    {
        var rule = new BlockListRule(Array.Empty<string>());
        var sink = new NetworkFilterBlockListSink(rule);

        var finding = new SecurityInspectionResult
        {
            RuleId = "WP-SEC-001",
            Score = 100,
            Action = NetworkInspectionAction.Block,
            MessageKey = "Findings.RdpBruteForce",
            Evidence = new Dictionary<string, object>
            {
                ["source_ip"] = "10.0.0.1"
            }
        };

        var context = new SecurityInspectionContext
        {
            EventId = 4625,
            SourceIp = "10.0.0.1",
            UserName = "Administrator",
            LogonType = "10",
            ProcessName = "svchost.exe",
            ComputerName = "SERVER01",
            TimeCreated = DateTimeOffset.UtcNow,
            Message = "An account failed to log on."
        };

        sink.Publish(finding, context);

        var result = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = DateTimeOffset.UtcNow
        });

        Assert.Equal(NetworkInspectionAction.Block, result.Action);
        Assert.Equal(100, result.Score);
    }

    [Fact]
    public void Observe_finding_does_not_add_ip()
    {
        var rule = new BlockListRule(Array.Empty<string>());
        var sink = new NetworkFilterBlockListSink(rule);

        var finding = new SecurityInspectionResult
        {
            RuleId = "WP-SEC-001",
            Score = 40,
            Action = NetworkInspectionAction.Observe,
            MessageKey = "Findings.RdpBruteForce",
            Evidence = new Dictionary<string, object>
            {
                ["source_ip"] = "10.0.0.1"
            }
        };

        var context = new SecurityInspectionContext
        {
            EventId = 4625,
            SourceIp = "10.0.0.1",
            UserName = "Administrator",
            LogonType = "10",
            ProcessName = "svchost.exe",
            ComputerName = "SERVER01",
            TimeCreated = DateTimeOffset.UtcNow,
            Message = "An account failed to log on."
        };

        sink.Publish(finding, context);

        var result = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = DateTimeOffset.UtcNow
        });

        Assert.Equal(NetworkInspectionAction.Allow, result.Action);
    }

    [Fact]
    public void Missing_source_ip_is_ignored()
    {
        var rule = new BlockListRule(Array.Empty<string>());
        var sink = new NetworkFilterBlockListSink(rule);

        var finding = new SecurityInspectionResult
        {
            RuleId = "WP-SEC-001",
            Score = 100,
            Action = NetworkInspectionAction.Block,
            MessageKey = "Findings.RdpBruteForce",
            Evidence = new Dictionary<string, object>()
        };

        var context = new SecurityInspectionContext
        {
            EventId = 4625,
            SourceIp = "10.0.0.1",
            UserName = "Administrator",
            LogonType = "10",
            ProcessName = "svchost.exe",
            ComputerName = "SERVER01",
            TimeCreated = DateTimeOffset.UtcNow,
            Message = "An account failed to log on."
        };

        // Should not throw
        sink.Publish(finding, context);

        var result = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = DateTimeOffset.UtcNow
        });

        Assert.Equal(NetworkInspectionAction.Allow, result.Action);
    }

    [Fact]
    public void Pending_ips_are_tracked()
    {
        var rule = new BlockListRule(Array.Empty<string>());
        var sink = new NetworkFilterBlockListSink(rule);

        var finding1 = new SecurityInspectionResult
        {
            RuleId = "WP-SEC-001",
            Score = 100,
            Action = NetworkInspectionAction.Block,
            MessageKey = "Findings.RdpBruteForce",
            Evidence = new Dictionary<string, object> { ["source_ip"] = "10.0.0.1" }
        };

        var finding2 = new SecurityInspectionResult
        {
            RuleId = "WP-SEC-001",
            Score = 100,
            Action = NetworkInspectionAction.Block,
            MessageKey = "Findings.RdpBruteForce",
            Evidence = new Dictionary<string, object> { ["source_ip"] = "10.0.0.2" }
        };

        var context = new SecurityInspectionContext
        {
            EventId = 4625,
            SourceIp = "10.0.0.1",
            UserName = "Administrator",
            LogonType = "10",
            ProcessName = "svchost.exe",
            ComputerName = "SERVER01",
            TimeCreated = DateTimeOffset.UtcNow,
            Message = "An account failed to log on."
        };

        sink.Publish(finding1, context);
        sink.Publish(finding2, context);

        Assert.Equal(2, sink.PendingIps.Count);
        Assert.Contains("10.0.0.1", sink.PendingIps);
        Assert.Contains("10.0.0.2", sink.PendingIps);
    }

    [Fact]
    public void Duplicate_ip_is_not_added_twice()
    {
        var rule = new BlockListRule(Array.Empty<string>());
        var sink = new NetworkFilterBlockListSink(rule);

        var finding = new SecurityInspectionResult
        {
            RuleId = "WP-SEC-001",
            Score = 100,
            Action = NetworkInspectionAction.Block,
            MessageKey = "Findings.RdpBruteForce",
            Evidence = new Dictionary<string, object> { ["source_ip"] = "10.0.0.1" }
        };

        var context = new SecurityInspectionContext
        {
            EventId = 4625,
            SourceIp = "10.0.0.1",
            UserName = "Administrator",
            LogonType = "10",
            ProcessName = "svchost.exe",
            ComputerName = "SERVER01",
            TimeCreated = DateTimeOffset.UtcNow,
            Message = "An account failed to log on."
        };

        sink.Publish(finding, context);
        sink.Publish(finding, context);

        Assert.Single(sink.PendingIps);
    }
}

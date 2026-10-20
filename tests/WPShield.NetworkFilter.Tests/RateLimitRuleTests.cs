namespace WPShield.NetworkFilter.Tests;

public class RateLimitRuleTests
{
    [Fact]
    public void Below_threshold_returns_allow_with_zero_score()
    {
        var rule = new RateLimitRule(maxConnectionsPerMinute: 60);

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
        Assert.Equal("WP-NET-002", result.RuleId);
    }

    [Fact]
    public void Above_threshold_returns_block_with_high_score()
    {
        var rule = new RateLimitRule(maxConnectionsPerMinute: 60);
        var now = DateTimeOffset.UtcNow;

        // 61 connections in the same minute -> score 40 (Observe)
        for (int i = 0; i < 61; i++)
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

        var observe40 = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = now
        });

        Assert.Equal(40, observe40.Score);
        Assert.Equal(NetworkInspectionAction.Observe, observe40.Action);

        // Push past 90 -> score 70 (still Observe)
        for (int i = 0; i < 31; i++)
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

        var observe70 = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = now
        });

        Assert.Equal(70, observe70.Score);
        Assert.Equal(NetworkInspectionAction.Observe, observe70.Action);

        // Push past 120 -> score 100 (Block)
        for (int i = 0; i < 31; i++)
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

        var block = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = now
        });

        Assert.Equal(100, block.Score);
        Assert.Equal(NetworkInspectionAction.Block, block.Action);
        Assert.True((int)block.Evidence["connections_last_minute"] > 120);
    }

    [Fact]
    public void Different_ips_are_tracked_separately()
    {
        var rule = new RateLimitRule(maxConnectionsPerMinute: 1);
        var now = DateTimeOffset.UtcNow;

        var first = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = now
        });

        var second = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.2",
            DestinationIp = "10.0.0.2",
            SourcePort = 51423,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = now
        });

        Assert.Equal(0, first.Score);
        Assert.Equal(0, second.Score);
    }

    [Fact]
    public void Window_expires_old_entries()
    {
        var rule = new RateLimitRule(maxConnectionsPerMinute: 1);
        var now = DateTimeOffset.UtcNow;
        var oneMinuteAgo = now.AddMinutes(-1).AddSeconds(-1);

        // Fill the window in the past
        rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = oneMinuteAgo
        });

        // Now the window should have expired, so this should be 0
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

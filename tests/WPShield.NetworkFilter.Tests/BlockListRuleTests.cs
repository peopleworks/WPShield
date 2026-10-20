namespace WPShield.NetworkFilter.Tests;

public class BlockListRuleTests
{
    [Fact]
    public void Blocked_ip_returns_block_with_score_100()
    {
        var rule = new BlockListRule(new[] { "10.0.0.1", "10.0.0.2" });

        var result = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = DateTimeOffset.UtcNow
        });

        Assert.Equal(100, result.Score);
        Assert.Equal(NetworkInspectionAction.Block, result.Action);
        Assert.Equal("WP-NET-001", result.RuleId);
        Assert.True((bool)result.Evidence["is_blocked"]);
    }

    [Fact]
    public void Non_blocked_ip_returns_allow_with_zero_score()
    {
        var rule = new BlockListRule(new[] { "10.0.0.1" });

        var result = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.99",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = DateTimeOffset.UtcNow
        });

        Assert.Equal(0, result.Score);
        Assert.Equal(NetworkInspectionAction.Allow, result.Action);
        Assert.False((bool)result.Evidence["is_blocked"]);
    }

    [Fact]
    public void Case_insensitive_matching()
    {
        var rule = new BlockListRule(new[] { "10.0.0.1" });

        var lower = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = DateTimeOffset.UtcNow
        });

        var upper = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = DateTimeOffset.UtcNow
        });

        Assert.Equal(NetworkInspectionAction.Block, lower.Action);
        Assert.Equal(NetworkInspectionAction.Block, upper.Action);
    }

    [Fact]
    public void Add_and_remove_ip_are_thread_safe()
    {
        var rule = new BlockListRule(Array.Empty<string>());

        rule.AddIp("10.0.0.1");
        var blocked = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = DateTimeOffset.UtcNow
        });
        Assert.Equal(NetworkInspectionAction.Block, blocked.Action);

        rule.RemoveIp("10.0.0.1");
        var allowed = rule.Inspect(new NetworkInspectionContext
        {
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            SourcePort = 51422,
            DestinationPort = 443,
            Protocol = "TCP",
            Timestamp = DateTimeOffset.UtcNow
        });
        Assert.Equal(NetworkInspectionAction.Allow, allowed.Action);
    }

    [Fact]
    public void Empty_or_null_ip_is_ignored()
    {
        var rule = new BlockListRule(Array.Empty<string>());

        rule.AddIp("");
        rule.AddIp(null!);

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
}

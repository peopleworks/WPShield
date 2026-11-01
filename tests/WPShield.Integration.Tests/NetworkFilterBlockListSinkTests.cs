using WPShield.NetworkFilter.Tests.Support;

namespace WPShield.Integration.Tests;

/// <summary>
/// A Security-log finding reaches the network filter as a block request, and everything about whether
/// it becomes a block is decided by the filter, not by the sink.
/// </summary>
public sealed class NetworkFilterBlockListSinkTests
{
    private static NetworkFilterService StartedFilter(NetworkFilterMode mode, string allow = "203.0.113.50")
    {
        IpRange.TryParseAllow(allow, out var allowed, out _);
        var service = new NetworkFilterService(
            new NetworkFilterOptions { Mode = mode, AllowList = [allowed!] },
            new FakeDivertDriver(),
            new RecordingSink(),
            lockoutProbe: () => new LockoutProbe(3389, []));
        Assert.True(service.Start().Started);
        return service;
    }

    private static SecurityInspectionResult Finding(NetworkInspectionAction action, string ruleId = "WP-SEC-002") => new()
    {
        RuleId = ruleId,
        Score = action == NetworkInspectionAction.Block ? 100 : 40,
        Action = action,
        MessageKey = "Findings.FailedLogon",
        Evidence = new Dictionary<string, object>(),
    };

    private static SecurityInspectionContext Logon(string sourceIp) => new()
    {
        EventId = 4625,
        SourceIp = sourceIp,
        UserName = "synthetic-user",
        LogonType = "3",
        ProcessName = string.Empty,
        ComputerName = "host.example",
        TimeCreated = DateTimeOffset.UtcNow,
        Message = string.Empty,
    };

    [Fact]
    public void ABlockFinding_BecomesADynamicBlockInBlockMode()
    {
        using var filter = StartedFilter(NetworkFilterMode.Block);
        var sink = new NetworkFilterBlockListSink(filter);

        sink.Publish(Finding(NetworkInspectionAction.Block), Logon("198.51.100.9"));

        var entry = Assert.Single(filter.Blocks.Snapshot());
        Assert.Equal("198.51.100.9", entry.Range.ToString());
        Assert.Equal("WP-SEC-002", entry.Source);
        Assert.NotNull(entry.ExpiresAt);
    }

    [Fact]
    public void AnObserveFinding_BlocksNothing()
    {
        using var filter = StartedFilter(NetworkFilterMode.Block);

        new NetworkFilterBlockListSink(filter).Publish(Finding(NetworkInspectionAction.Observe), Logon("198.51.100.9"));

        Assert.Equal(0, filter.Blocks.Count);
    }

    [Theory]
    [InlineData("")]
    [InlineData("-")]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    public void ALocalOrMissingAddress_BlocksNothing(string sourceIp)
    {
        using var filter = StartedFilter(NetworkFilterMode.Block);

        new NetworkFilterBlockListSink(filter).Publish(Finding(NetworkInspectionAction.Block), Logon(sourceIp));

        Assert.Equal(0, filter.Blocks.Count);
    }

    [Fact]
    public void TheAllowList_WinsOverTheSecurityLog()
    {
        using var filter = StartedFilter(NetworkFilterMode.Block, allow: "198.51.100.0/24");

        new NetworkFilterBlockListSink(filter).Publish(Finding(NetworkInspectionAction.Block), Logon("198.51.100.9"));

        Assert.Equal(0, filter.Blocks.Count);
    }

    [Fact]
    public void MonitorMode_BlocksNothing()
    {
        using var filter = StartedFilter(NetworkFilterMode.Monitor);

        new NetworkFilterBlockListSink(filter).Publish(Finding(NetworkInspectionAction.Block), Logon("198.51.100.9"));

        Assert.Equal(0, filter.Blocks.Count);
    }
}

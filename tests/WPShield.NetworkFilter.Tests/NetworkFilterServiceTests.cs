using System.Net;

namespace WPShield.NetworkFilter.Tests;

public sealed class NetworkFilterServiceTests
{
    private readonly FakeWfpSession _session = new();
    private readonly RecordingSink _sink = new();
    private readonly ManualTimeProvider _time = new();

    [Fact]
    public void MonitorReportsOperatorAndLogRequestsWithoutOpeningWfp()
    {
        using var service = new NetworkFilterService(new NetworkFilterOptions { Blocks = [Ranges.Block("203.0.113.20")] },
            () => throw new InvalidOperationException("Monitor opened WFP."), _sink);

        Assert.True(service.Start().Started);
        service.RequestBlock(Ranges.Ip("198.51.100.4"), "WP-SEC-002");

        Assert.Equal(2, _sink.WithAction(NetworkFilterActions.WouldBlock).Count());
        Assert.Empty(_sink.WithAction(NetworkFilterActions.Blocked));
    }

    [Fact]
    public void BlockRefusesAnEmptyAllowListWithoutOpeningWfp()
    {
        using var service = new NetworkFilterService(new NetworkFilterOptions { Mode = NetworkFilterMode.Block },
            () => throw new InvalidOperationException("Opened WFP without an allow-list."), _sink,
            lockoutProbe: () => new LockoutProbe(3389, []));

        Assert.False(service.Start().Started);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void BlockRefusesWhenProbeCannotBeReadOrRemoved(bool removeFails)
    {
        var session = new FakeWfpSession { EnumerationSucceeds = removeFails, RejectDeletes = removeFails };
        using var service = new NetworkFilterService(
            new NetworkFilterOptions
            {
                Mode = NetworkFilterMode.Block,
                AllowList = [Ranges.Allow("203.0.113.1")],
                Blocks = [Ranges.Block("203.0.113.8")],
            },
            () => session, _sink, _time, () => new LockoutProbe(3389, []));

        Assert.False(service.Start().Started);
        Assert.Single(session.Added);
        Assert.True(session.Disposed);
        Assert.Empty(session.Filters);
    }

    [Fact]
    public void DynamicBlockExpiresAfterItsLastFindingAndLeavesOperatorBlock()
    {
        var operatorBlock = Ranges.Block("203.0.113.8");
        var source = Ranges.Ip("198.51.100.4");
        using var service = CreateService([operatorBlock]);

        Assert.True(service.Start().Started);
        Assert.Equal(BlockAddOutcome.Added, service.RequestBlock(source, "WP-SEC-002"));
        _time.Advance(TimeSpan.FromMinutes(59));
        Assert.Equal(BlockAddOutcome.Extended, service.RequestBlock(source, "WP-SEC-002"));
        _time.Advance(TimeSpan.FromMinutes(59));
        service.Maintain();
        Assert.Equal(2, _session.Filters.Count);
        _time.Advance(TimeSpan.FromMinutes(1));
        service.Maintain();

        Assert.Equal(operatorBlock, Assert.Single(_session.Filters.Values));
        var expired = Assert.Single(_sink.WithAction(NetworkFilterActions.Expired));
        Assert.Equal("WP-NET-001", expired.State["rule_id"]);
        Assert.Equal("WP-SEC-002", expired.State["requested_by"]);
        service.Dispose();
        Assert.Empty(_session.Filters);
    }

    [Fact]
    public void RdpClientAndAllowListAreCheckedBeforeDynamicEnforcement()
    {
        var rdpClient = Ranges.Ip("198.51.100.4");
        var local = new IPEndPoint(Ranges.Ip("192.0.2.10"), 3390);
        var remote = new IPEndPoint(rdpClient, 50023);
        var connected = false;
        using var service = CreateService([], () => new LockoutProbe(local.Port, connected ? [new(local, remote)] : []));

        Assert.True(service.Start().Started);
        connected = true;
        Assert.Null(service.RequestBlock(rdpClient, "WP-SEC-002"));
        Assert.Equal(BlockAddOutcome.RefusedAllowListed, service.RequestBlock(Ranges.Ip("203.0.113.1"), "WP-SEC-002"));
        Assert.Empty(_session.Filters);
        Assert.Single(_sink.WithAction(NetworkFilterActions.RefusedRdpClient));
    }

    [Fact]
    public void AFailedExpirationClosesTheSessionAndLiftsEveryBlock()
    {
        using var service = CreateService([Ranges.Block("203.0.113.8")]);
        Assert.True(service.Start().Started);
        Assert.Equal(BlockAddOutcome.Added, service.RequestBlock(Ranges.Ip("198.51.100.4"), "WP-SEC-002"));
        _session.RejectDeletes = true;

        _time.Advance(TimeSpan.FromHours(1));
        service.Maintain();

        Assert.True(_session.Disposed);
        Assert.Empty(_session.Filters);
        Assert.Empty(_sink.WithAction(NetworkFilterActions.Expired));
        Assert.Single(_sink.WithAction(NetworkFilterActions.EnforcementFailed));
    }

    [Fact]
    public void NativeAddFailureDuringStartupClosesTheSessionAndDoesNotReportBlocks()
    {
        _session.RejectAdd = range => range.Equals(Ranges.Block("203.0.113.9"));
        using var service = CreateService([Ranges.Block("203.0.113.8"), Ranges.Block("203.0.113.9")]);

        Assert.False(service.Start().Started);
        Assert.True(_session.Disposed);
        Assert.Empty(_session.Filters);
        Assert.Empty(_sink.WithAction(NetworkFilterActions.Blocked));
    }

    private NetworkFilterService CreateService(IReadOnlyList<IpRange> blocks, Func<LockoutProbe>? probe = null) => new(
        new NetworkFilterOptions { Mode = NetworkFilterMode.Block, AllowList = [Ranges.Allow("203.0.113.1")], Blocks = blocks },
        () => _session, _sink, _time, probe ?? (() => new LockoutProbe(3389, [])));
}

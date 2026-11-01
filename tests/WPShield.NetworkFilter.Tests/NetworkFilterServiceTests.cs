using System.Net;

namespace WPShield.NetworkFilter.Tests;

/// <summary>
/// The safety properties of ADR 0006, asserted end to end through a fake driver.
/// </summary>
public sealed class NetworkFilterServiceTests
{
    private const string Operator = "203.0.113.50";

    private readonly FakeDivertDriver _driver = new();
    private readonly RecordingSink _sink = new();
    private readonly ManualTimeProvider _time = new();

    private NetworkFilterService Create(NetworkFilterOptions options, params TcpConnectionSnapshot[] connections) =>
        new(options, _driver, _sink, _time, () => new LockoutProbe(3770, connections));

    private static NetworkFilterOptions Block(params string[] blocks) => new()
    {
        Mode = NetworkFilterMode.Block,
        AllowList = [Ranges.Allow(Operator)],
        Blocks = [.. blocks.Select(Ranges.Block)],
        MaxConnectionsPerMinute = 5,
        MaxDistinctPortsPerMinute = 3,
    };

    private static byte[] Syn(string source, int port = 443) =>
        SyntheticPacket.Tcp(IPAddress.Parse(source), IPAddress.Parse("192.0.2.1"), (ushort)port);

    [Fact]
    public void Monitor_NeverOpensADropHandle_EvenWithBlocksAndBlockFindings()
    {
        using var service = Create(new NetworkFilterOptions
        {
            AllowList = [Ranges.Allow(Operator)],
            Blocks = [Ranges.Block("94.0.0.0/24")],
            MaxDistinctPortsPerMinute = 3,
            SynRulesMayBlock = true,
        });

        Assert.True(service.Start().Started);
        for (var port = 1; port <= 20; port++)
        {
            service.InspectPacket(Syn("198.51.100.9", port));
        }

        service.RequestBlock(IPAddress.Parse("198.51.100.10"), "WP-SEC-002", EvidenceGrade.Authenticated);
        service.Maintain();

        Assert.Empty(_driver.Live(DivertHandleKind.Drop));
        Assert.False(service.IsEnforcing);
        Assert.NotEmpty(_sink.WithAction(NetworkFilterActions.WouldBlock));
        Assert.Single(_driver.Live(DivertHandleKind.Observe));
    }

    [Fact]
    public void Monitor_IsTheDefault()
    {
        Assert.Equal(NetworkFilterMode.Monitor, new NetworkFilterOptions().Mode);
    }

    [Fact]
    public void Block_AppliesOperatorBlocksBeforeObserving()
    {
        using var service = Create(Block("94.0.0.0/24"));

        Assert.True(service.Start().Started);

        var drop = Assert.Single(_driver.Live(DivertHandleKind.Drop));
        Assert.Contains("94.0.0.0", drop.Filter, StringComparison.Ordinal);
        Assert.True(_driver.Opened.ToList().IndexOf(drop) < _driver.Opened.ToList().IndexOf(_driver.Live(DivertHandleKind.Observe)[0]));
    }

    [Fact]
    public void Block_WithoutAnAllowList_IsRefusedAndOpensNothing()
    {
        using var service = Create(Block("94.0.0.0/24") with { AllowList = [] });

        var outcome = service.Start();

        Assert.False(outcome.Started);
        Assert.Contains("--allow", outcome.Refusal, StringComparison.Ordinal);
        Assert.Empty(_driver.Opened);
    }

    [Fact]
    public void Block_WithAnRdpClientNotOnTheAllowList_IsRefused()
    {
        var connection = new TcpConnectionSnapshot(
            new IPEndPoint(IPAddress.Parse("192.0.2.1"), 3770),
            new IPEndPoint(IPAddress.Parse("198.51.100.200"), 50000));
        using var service = Create(Block(), connection);

        var outcome = service.Start();

        Assert.False(outcome.Started);
        Assert.Contains("198.51.100.200", outcome.Refusal, StringComparison.Ordinal);
        Assert.Empty(_driver.Opened);
    }

    [Fact]
    public void Block_WhenTheSelfTestFails_IsRefusedAndOpensNothing()
    {
        _driver.EvaluateOverride = (_, source) => source.ToString() == "198.51.101.0" ? true : null;
        using var service = Create(Block());

        var outcome = service.Start();

        Assert.False(outcome.Started);
        Assert.Contains("self-test", outcome.Refusal, StringComparison.Ordinal);
        Assert.Empty(_driver.Opened);
    }

    [Fact]
    public void Monitor_WhenTheSelfTestFails_StartsAndWarns()
    {
        _driver.EvaluateOverride = (_, source) => source.ToString() == "198.51.101.0" ? true : null;
        using var service = Create(new NetworkFilterOptions());

        Assert.True(service.Start().Started);
        Assert.Single(_sink.WithAction(NetworkFilterActions.SelfTestFailed));
    }

    [Fact]
    public void Block_WhenTheDriverIsMissing_IsRefusedWithTheDriverMessage()
    {
        _driver.OpenFails = (_, _) => true;
        using var service = Create(Block("94.0.0.0/24"));

        var outcome = service.Start();

        Assert.False(outcome.Started);
        Assert.Contains("fake: open refused", outcome.Refusal, StringComparison.Ordinal);
        Assert.Empty(_driver.Live(DivertHandleKind.Drop));
    }

    [Fact]
    public void SynFindings_DoNotBlockUnlessTheOperatorOptedIn()
    {
        using var service = Create(Block());
        service.Start();

        for (var port = 1; port <= 20; port++)
        {
            service.InspectPacket(Syn("198.51.100.9", port));
        }

        service.Maintain();

        Assert.Equal(0, service.Blocks.Count);
        Assert.NotEmpty(_sink.WithAction(NetworkFilterActions.NotBlockedSpoofable));
        Assert.Empty(_driver.Live(DivertHandleKind.Drop));
    }

    [Fact]
    public void SynFindings_BlockWithTheOptInAndTheBlockIsEnforcedAtTheNextMaintenance()
    {
        using var service = Create(Block() with { SynRulesMayBlock = true });
        service.Start();

        for (var port = 1; port <= 20; port++)
        {
            service.InspectPacket(Syn("198.51.100.9", port));
        }

        Assert.Equal(1, service.Blocks.Count);
        service.Maintain();

        Assert.Contains("198.51.100.9", Assert.Single(_driver.Live(DivertHandleKind.Drop)).Filter, StringComparison.Ordinal);
        Assert.Single(_sink.WithAction(NetworkFilterActions.Blocked));
    }

    [Fact]
    public void AnAllowListedAddress_IsNeitherObservedNorBlocked()
    {
        using var service = Create(Block() with { SynRulesMayBlock = true });
        service.Start();

        for (var port = 1; port <= 20; port++)
        {
            service.InspectPacket(Syn(Operator, port));
        }

        var outcome = service.RequestBlock(IPAddress.Parse(Operator), "WP-SEC-002", EvidenceGrade.Authenticated);

        Assert.Equal(BlockAddOutcome.RefusedAllowListed, outcome);
        Assert.Equal(0, service.Blocks.Count);
        Assert.Empty(_sink.WithAction(NetworkFilterActions.Observed));
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("0.0.0.0")]
    public void AnUnblockableAddressFromALogRecord_IsRefused(string address)
    {
        using var service = Create(Block());
        service.Start();

        Assert.Null(service.RequestBlock(IPAddress.Parse(address), "WP-SEC-002", EvidenceGrade.Authenticated));
        Assert.Equal(0, service.Blocks.Count);
    }

    [Fact]
    public void ADynamicBlock_ExpiresAndTheDropHandleCloses()
    {
        using var service = Create(Block() with { DynamicBlockLifetime = TimeSpan.FromMinutes(10) });
        service.Start();
        service.RequestBlock(IPAddress.Parse("198.51.100.9"), "WP-SEC-002", EvidenceGrade.Authenticated);
        service.Maintain();
        Assert.Single(_driver.Live(DivertHandleKind.Drop));

        _time.Advance(TimeSpan.FromMinutes(10));
        service.Maintain();

        Assert.Empty(_driver.Live(DivertHandleKind.Drop));
        Assert.Single(_sink.WithAction(NetworkFilterActions.Expired));
    }

    [Fact]
    public void Stop_ClosesEveryHandleAndLiftsEveryBlock()
    {
        var service = Create(Block("94.0.0.0/24"));
        service.Start();
        Assert.NotEmpty(_driver.Live(DivertHandleKind.Drop));

        service.Stop();

        Assert.All(_driver.Opened, handle => Assert.True(handle.IsDisposed));
        Assert.Single(_sink.WithAction(NetworkFilterActions.Stopped));
    }

    [Fact]
    public void TheObserverThread_FeedsDeliveredPacketsToTheRules()
    {
        using var service = Create(new NetworkFilterOptions { MaxDistinctPortsPerMinute = 3 });
        service.Start();
        var observer = Assert.Single(_driver.Live(DivertHandleKind.Observe));

        for (var port = 1; port <= 3; port++)
        {
            observer.Deliver(Syn("198.51.100.9", port));
        }

        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!_sink.WithAction(NetworkFilterActions.Observed).Any() && DateTime.UtcNow < deadline)
        {
            Thread.Sleep(10);
        }

        Assert.NotEmpty(_sink.WithAction(NetworkFilterActions.Observed));
        service.Stop();
    }

    [Fact]
    public void Findings_AreThrottledPerSourceNotLoggedPerPacket()
    {
        using var service = Create(new NetworkFilterOptions { MaxConnectionsPerMinute = 5 });
        service.Start();

        for (var i = 0; i < 1_000; i++)
        {
            service.InspectPacket(Syn("198.51.100.9"));
        }

        Assert.InRange(_sink.WithAction(NetworkFilterActions.Observed).Count(), 1, 3);
    }

    [Fact]
    public void EventState_CarriesNormalizedValuesOnly()
    {
        using var service = Create(new NetworkFilterOptions { MaxDistinctPortsPerMinute = 3 });
        service.Start();
        for (var port = 1; port <= 3; port++)
        {
            service.InspectPacket(Syn("198.51.100.9", port));
        }

        foreach (var value in _sink.Events.SelectMany(e => e.State.Values))
        {
            Assert.True(value is int or bool || (value is string text && text.All(c => c is >= ' ' and <= '~')), $"unexpected state value {value}");
        }
    }

    [Fact]
    public void OptionsThatOverlap_AreRefusedBeforeAnythingOpens()
    {
        using var service = Create(Block("94.0.0.0/24") with { AllowList = [Ranges.Allow("94.0.0.7")] });

        var outcome = service.Start();

        Assert.False(outcome.Started);
        Assert.Contains("overlap", outcome.Refusal, StringComparison.Ordinal);
        Assert.Empty(_driver.Opened);
    }
}

using System.Net;

namespace WPShield.NetworkFilter.Tests;

public sealed class LockoutGuardTests
{
    private static TcpConnectionSnapshot Connection(int localPort, string remote) =>
        new(new IPEndPoint(IPAddress.Parse("192.0.2.1"), localPort), new IPEndPoint(IPAddress.Parse(remote), 51000));

    [Fact]
    public void AnEmptyAllowList_IsRefused()
    {
        var result = LockoutGuard.Evaluate(3389, [], []);

        Assert.False(result.MayBlock);
        Assert.Contains("--allow", result.Refusal, StringComparison.Ordinal);
    }

    [Fact]
    public void AnRdpClientOnTheAllowList_MayBlock()
    {
        var result = LockoutGuard.Evaluate(3770, [Connection(3770, "203.0.113.50")], [Ranges.Allow("203.0.113.50")]);

        Assert.True(result.MayBlock);
    }

    [Fact]
    public void AnRdpClientNotOnTheAllowList_IsRefusedAndNamed()
    {
        var result = LockoutGuard.Evaluate(
            3770,
            [Connection(3770, "203.0.113.50"), Connection(3770, "198.51.100.9")],
            [Ranges.Allow("203.0.113.50")]);

        Assert.False(result.MayBlock);
        Assert.Equal("198.51.100.9", Assert.Single(result.UnlistedRdpClients).ToString());
        Assert.Contains("198.51.100.9", result.Refusal, StringComparison.Ordinal);
        Assert.Contains("3770", result.Refusal, StringComparison.Ordinal);
    }

    [Fact]
    public void TheRegistryPort_IsTheOneChecked_NotThreeThreeEightNine()
    {
        var result = LockoutGuard.Evaluate(3770, [Connection(3389, "198.51.100.9")], [Ranges.Allow("203.0.113.50")]);

        Assert.True(result.MayBlock);
    }

    [Fact]
    public void AMappedAddressInsideAnAllowListedRange_IsRecognised()
    {
        var result = LockoutGuard.Evaluate(
            3389,
            [Connection(3389, "::ffff:203.0.113.77")],
            [Ranges.Allow("203.0.113.0/24")]);

        Assert.True(result.MayBlock);
    }

    [Fact]
    public void ALoopbackRdpSession_IsIgnored()
    {
        var result = LockoutGuard.Evaluate(3389, [Connection(3389, "127.0.0.1")], [Ranges.Allow("203.0.113.50")]);

        Assert.True(result.MayBlock);
    }
}

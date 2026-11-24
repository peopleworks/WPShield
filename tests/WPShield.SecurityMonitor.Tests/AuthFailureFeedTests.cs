using System.Net;
using WPShield.Evidence;
using WPShield.SecurityMonitor;
using Xunit;

namespace WPShield.SecurityMonitor.Tests;

public sealed class AuthFailureFeedTests
{
    private static readonly DateTime When = new(2026, 11, 24, 6, 0, 0, DateTimeKind.Utc);

    // Order: TargetUserName, Status, SubStatus, LogonType, IpAddress, IpPort.
    private static object?[] Values(string user, uint status, uint subStatus, uint logonType, string ip, string port) =>
        [user, status, subStatus, logonType, ip, port];

    [Fact]
    public void ReadsAnRdpFailureWithItsAddressAndAccount()
    {
        var failure = AuthFailureFeed.From4625(7, When, Values("administrator", 0xC000006D, 0xC000006A, 10, "203.0.113.7", "51234"));
        Assert.NotNull(failure);
        Assert.Equal(IPAddress.Parse("203.0.113.7"), failure.Address);
        Assert.Equal(51234, failure.Port);
        Assert.Equal("administrator", failure.Account);
        Assert.Equal("bad-password", failure.Reason);
        Assert.Equal(10, failure.LogonType);
        Assert.Equal("security-4625", failure.Channel);
        Assert.Equal(7, failure.RecordId);
        Assert.Equal(TimeSpan.Zero, failure.Timestamp.Offset);
    }

    [Fact]
    public void AnNlaFailureWithoutAddressStaysUnattributed()
    {
        var failure = AuthFailureFeed.From4625(8, When, Values("admin", 0xC000006D, 0xC0000064, 3, "-", "-"));
        Assert.NotNull(failure);
        Assert.Null(failure.Address);
        Assert.Null(failure.Port);
        Assert.Equal("unknown-account", failure.Reason);
        Assert.Equal(3, failure.LogonType);
    }

    [Theory]
    [InlineData(0xC000006Du, 0xC0000064u, "unknown-account")]
    [InlineData(0xC000006Du, 0xC000006Au, "bad-password")]
    [InlineData(0xC0000234u, 0u, "locked-out")]
    [InlineData(0xC000006Eu, 0xC0000072u, "disabled")]
    [InlineData(0xC000006Du, 0u, "bad-credentials")]
    [InlineData(0xC000006Eu, 0xC000015Bu, "logon-type-denied")]
    [InlineData(0x12345678u, 0u, "other")]
    public void MapsStatusCodesToStableReasons(uint status, uint subStatus, string reason) =>
        Assert.Equal(reason, AuthFailureFeed.Reason(status, subStatus));

    [Fact]
    public void AcceptsStatusCodesSpelledAsHexText()
    {
        object?[] values = ["admin", "0xC000006D", "0xc0000064", "3", "198.51.100.4", "0"];
        var failure = AuthFailureFeed.From4625(9, When, values);
        Assert.NotNull(failure);
        Assert.Equal("unknown-account", failure.Reason);
        Assert.Equal(3, failure.LogonType);
        Assert.Null(failure.Port);
    }

    [Theory]
    [InlineData("-")]
    [InlineData("")]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("1")]
    [InlineData("010.1.1.1")]
    [InlineData("not an address")]
    public void RejectsAddressesThatNameNobody(string text) => Assert.Null(AuthFailureFeed.ParseAddress(text));

    [Fact]
    public void MapsIPv4InIPv6BackToIPv4() =>
        Assert.Equal(IPAddress.Parse("192.0.2.9"), AuthFailureFeed.ParseAddress("::ffff:192.0.2.9"));

    [Fact]
    public void CleansAndBoundsTheAttackerChosenAccountName()
    {
        Assert.Equal("adm�in", AuthFailureFeed.CleanAccount("adm\u001bin"));
        Assert.Equal("evil�gpj", AuthFailureFeed.CleanAccount("evil‮gpj"));
        Assert.Equal("José", AuthFailureFeed.CleanAccount("José"));
        Assert.Equal("", AuthFailureFeed.CleanAccount("-"));
        Assert.Equal(AuthFailureFeed.MaxAccountLength, AuthFailureFeed.CleanAccount(new string('a', 500)).Length);
    }

    [Fact]
    public void ReadsRemoteDesktopsOwnRecordOfABadPassword()
    {
        var failure = AuthFailureFeed.From140(11, When, ["198.51.100.20"]);
        Assert.NotNull(failure);
        Assert.Equal("rdpcorets-140", failure.Channel);
        Assert.Equal(IPAddress.Parse("198.51.100.20"), failure.Address);
        Assert.Equal("", failure.Account);
        Assert.Equal(10, failure.LogonType);
        Assert.Null(AuthFailureFeed.From140(12, When, ["-"]));
        Assert.Null(AuthFailureFeed.From140(13, When, []));
    }

    [Fact]
    public void ShortRecordsAreSkippedNotGuessed() =>
        Assert.Null(AuthFailureFeed.From4625(1, When, ["admin", 0xC000006Du]));
}

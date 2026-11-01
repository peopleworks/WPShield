namespace WPShield.NetworkFilter.Tests;

public sealed class IpRangeTests
{
    [Theory]
    [InlineData("203.0.113.7", "203.0.113.7", "203.0.113.7")]
    [InlineData("198.51.100.0/24", "198.51.100.0", "198.51.100.255")]
    [InlineData("10.20.0.0/16", "10.20.0.0", "10.20.255.255")]
    [InlineData("2001:db8::7", "2001:db8::7", "2001:db8::7")]
    [InlineData("2001:db8:1::/48", "2001:db8:1::", "2001:db8:1:ffff:ffff:ffff:ffff:ffff")]
    [InlineData("::ffff:203.0.113.9", "203.0.113.9", "203.0.113.9")]
    public void ABlock_ParsesToItsFirstAndLastAddress(string text, string first, string last)
    {
        Assert.True(IpRange.TryParseBlock(text, out var range, out var error), error);
        Assert.Equal(first, range!.First.ToString());
        Assert.Equal(last, range.Last.ToString());
    }

    [Theory]
    [InlineData("1.2.3")]
    [InlineData("0x7f.0.0.1")]
    [InlineData("010.1.1.1")]
    [InlineData("1.2.3.4.5")]
    [InlineData("256.1.1.1")]
    [InlineData("fe80::1%3")]
    [InlineData("example.com")]
    [InlineData("")]
    [InlineData("203.0.113.0/33")]
    [InlineData("203.0.113.0/-1")]
    [InlineData("203.0.113.0/+8")]
    public void NonCanonicalOrMalformedText_IsRefused(string text)
    {
        Assert.False(IpRange.TryParseBlock(text, out _, out var error));
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Fact]
    public void HostBitsSet_IsRefusedAndTheErrorNamesTheNetwork()
    {
        Assert.False(IpRange.TryParseBlock("203.0.113.7/24", out _, out var error));
        Assert.Contains("203.0.113.0/24", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("10.0.0.0/8")]
    [InlineData("10.0.0.0/15")]
    [InlineData("2001:db8::/32")]
    public void ABlockWiderThanTheCeiling_IsRefused(string text)
    {
        Assert.False(IpRange.TryParseBlock(text, out _, out var error));
        Assert.Contains("wider than", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.1.0.0/16")]
    [InlineData("0.0.0.0")]
    [InlineData("255.255.255.255")]
    [InlineData("224.0.0.1")]
    [InlineData("169.254.10.10")]
    [InlineData("::1")]
    [InlineData("::")]
    [InlineData("fe80::1")]
    [InlineData("ff02::1")]
    public void AnAddressThatCanNeverBeBlocked_IsRefused(string text)
    {
        Assert.False(IpRange.TryParseBlock(text, out _, out _));
    }

    [Fact]
    public void AnAllowListEntry_MayBeAnyWidth()
    {
        Assert.True(IpRange.TryParseAllow("10.0.0.0/8", out var range, out _));
        Assert.Equal(8, range!.PrefixLength);
        Assert.True(IpRange.TryParseAllow("127.0.0.1", out _, out _));
    }

    [Fact]
    public void ContainsAndOverlaps_RespectBoundariesAndFamilies()
    {
        var block = Ranges.Block("198.51.100.0/24");

        Assert.True(block.Contains(Ranges.Ip("198.51.100.0")));
        Assert.True(block.Contains(Ranges.Ip("198.51.100.255")));
        Assert.False(block.Contains(Ranges.Ip("198.51.101.0")));
        Assert.False(block.Contains(Ranges.Ip("2001:db8::1")));
        Assert.True(block.Contains(Ranges.Ip("::ffff:198.51.100.9")));
        Assert.True(block.Overlaps(Ranges.Allow("198.51.100.77")));
        Assert.True(block.Overlaps(Ranges.Allow("198.51.0.0/16")));
        Assert.False(block.Overlaps(Ranges.Allow("198.51.101.0/24")));
        Assert.True(block.Covers(Ranges.Block("198.51.100.9")));
        Assert.False(Ranges.Block("198.51.100.9").Covers(block));
    }

    [Fact]
    public void TheNeighbours_AreOneOutsideEachEdge()
    {
        var block = Ranges.Block("198.51.100.0/24");

        Assert.Equal("198.51.99.255", block.AddressBefore()!.ToString());
        Assert.Equal("198.51.101.0", block.AddressAfter()!.ToString());
    }

    [Fact]
    public void ErrorText_EchoesOnlyPrintableAscii()
    {
        Assert.False(IpRange.TryParseBlock("1.2.3.4\u001b[31m", out _, out var error));
        Assert.DoesNotContain('\u001b', error!);
    }
}

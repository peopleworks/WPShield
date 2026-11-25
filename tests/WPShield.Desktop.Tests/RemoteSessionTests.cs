using Xunit;

namespace WPShield.Desktop.Tests;

/// <summary>
/// <c>WTS_CLIENT_ADDRESS</c> parsing, from synthetic structures: a little-endian family, then 20
/// address bytes. RFC 5737 and RFC 3849 documentation addresses only.
/// </summary>
public sealed class RemoteSessionTests
{
    private static byte[] Structure(uint family, int offset, params byte[] address)
    {
        var bytes = new byte[RemoteSession.StructureSize];
        BitConverter.GetBytes(family).CopyTo(bytes, 0);
        address.CopyTo(bytes, 4 + offset);
        return bytes;
    }

    [Theory]
    [InlineData(192, 0, 2, 44, "192.0.2.44")]
    [InlineData(198, 51, 100, 7, "198.51.100.7")]
    [InlineData(203, 0, 113, 250, "203.0.113.250")]
    public void AnIpv4ClientIsReadFromOffsetTwoOfTheAddressField(byte a, byte b, byte c, byte d, string expected)
    {
        var client = RemoteSession.Parse(Structure(2, 2, a, b, c, d));
        Assert.Equal(expected, client.Address);
        Assert.Null(client.Problem);
    }

    [Fact]
    public void BytesOutsideTheIpv4PositionAreNotPartOfTheAddress()
    {
        // The first two bytes of the field are not the address; reading from offset 0 would give 13.10.192.0.
        var bytes = Structure(2, 0, 0x0D, 0x0A, 192, 0, 2, 9, 0xFF, 0xFF);
        Assert.Equal("192.0.2.9", RemoteSession.Parse(bytes).Address);
    }

    [Fact]
    public void AnIpv6ClientIsReportedAsUnknownNotGuessed()
    {
        byte[] documentation = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x17];
        foreach (var offset in new[] { 0, 2 })
        {
            var client = RemoteSession.Parse(Structure(23, offset, documentation));
            Assert.Null(client.Address);
            Assert.Equal(RemoteClient.Ipv6, client.Problem);
        }
    }

    [Theory]
    [InlineData(2u)]
    [InlineData(23u)]
    [InlineData(0u)]
    public void NoAddressIsNotReported(uint family)
    {
        var client = RemoteSession.Parse(Structure(family, 0));
        Assert.Null(client.Address);
        Assert.Equal(RemoteClient.NotReported, client.Problem);
    }

    [Fact]
    public void AnotherFamilyOrATruncatedStructureFillsNothing()
    {
        Assert.Equal(RemoteClient.OtherFamily, RemoteSession.Parse(Structure(6, 2, 192, 0, 2, 1)).Problem);
        var truncated = RemoteSession.Parse(Structure(2, 2, 192, 0, 2, 1).AsSpan(0, 10));
        Assert.Null(truncated.Address);
        Assert.Equal(RemoteClient.QueryFailed, truncated.Problem);
    }

    [Fact]
    public void ReadingTheCurrentSessionNeverThrows()
    {
        // On a build agent this is a console or service session; whatever it is, it answers.
        var client = RemoteSession.Current();
        Assert.True(client.Address is not null ^ client.Problem is not null);
    }
}

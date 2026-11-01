using System.Net;

namespace WPShield.NetworkFilter.Tests;

public sealed class PacketHeaderParserTests
{
    [Fact]
    public void Ipv4Ports_AreReadInNetworkByteOrder()
    {
        var packet = SyntheticPacket.Tcp(IPAddress.Parse("198.51.100.7"), IPAddress.Parse("192.0.2.1"), 443);

        Assert.True(PacketHeaderParser.TryParse(packet, out var headers));
        Assert.Equal(443, headers.DestinationPort);
        Assert.Equal(49152, headers.SourcePort);
        Assert.Equal("198.51.100.7", headers.Source.ToString());
        Assert.Equal("192.0.2.1", headers.Destination.ToString());
        Assert.True(headers.Syn);
        Assert.False(headers.Ack);
    }

    [Fact]
    public void Ipv6_IsParsed()
    {
        var packet = SyntheticPacket.Tcp(IPAddress.Parse("2001:db8::7"), IPAddress.Parse("2001:db8::1"), 5432, syn: true, ack: true);

        Assert.True(PacketHeaderParser.TryParse(packet, out var headers));
        Assert.Equal(5432, headers.DestinationPort);
        Assert.Equal("2001:db8::7", headers.Source.ToString());
        Assert.True(headers.Ack);
    }

    [Fact]
    public void Ipv4Options_MoveTheTcpHeader()
    {
        var plain = SyntheticPacket.Tcp(IPAddress.Parse("198.51.100.7"), IPAddress.Parse("192.0.2.1"), 3389);
        var withOptions = new byte[plain.Length + 4];
        plain.AsSpan(0, 20).CopyTo(withOptions);
        withOptions[0] = 0x46;
        plain.AsSpan(20).CopyTo(withOptions.AsSpan(24));

        Assert.True(PacketHeaderParser.TryParse(withOptions, out var headers));
        Assert.Equal(3389, headers.DestinationPort);
    }

    [Fact]
    public void ATruncatedPacket_IsNotParsed()
    {
        var packet = SyntheticPacket.Tcp(IPAddress.Parse("198.51.100.7"), IPAddress.Parse("192.0.2.1"), 443);

        for (var length = 0; length < packet.Length; length++)
        {
            Assert.False(PacketHeaderParser.TryParse(packet.AsSpan(0, length), out _));
        }
    }

    [Fact]
    public void ANonFirstFragment_IsNotParsed()
    {
        var packet = SyntheticPacket.Tcp(IPAddress.Parse("198.51.100.7"), IPAddress.Parse("192.0.2.1"), 443);
        packet[7] = 0x10;

        Assert.False(PacketHeaderParser.TryParse(packet, out _));
    }

    [Fact]
    public void UdpAndIpv6ExtensionHeaders_AreNotParsed()
    {
        var v4 = SyntheticPacket.Tcp(IPAddress.Parse("198.51.100.7"), IPAddress.Parse("192.0.2.1"), 53);
        v4[9] = 17;
        var v6 = SyntheticPacket.Tcp(IPAddress.Parse("2001:db8::7"), IPAddress.Parse("2001:db8::1"), 443);
        v6[6] = 0;

        Assert.False(PacketHeaderParser.TryParse(v4, out _));
        Assert.False(PacketHeaderParser.TryParse(v6, out _));
    }

    [Fact]
    public void AnUnknownIpVersion_IsNotParsed()
    {
        var packet = SyntheticPacket.Tcp(IPAddress.Parse("198.51.100.7"), IPAddress.Parse("192.0.2.1"), 443);
        packet[0] = 0x55;

        Assert.False(PacketHeaderParser.TryParse(packet, out _));
    }
}

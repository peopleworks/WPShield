using System.Buffers.Binary;
using System.Net;

namespace WPShield.NetworkFilter;

/// <summary>The fields the observer reads from a TCP packet.</summary>
public readonly record struct PacketHeaders(
    IPAddress Source,
    IPAddress Destination,
    ushort SourcePort,
    ushort DestinationPort,
    bool Syn,
    bool Ack);

/// <summary>
/// Reads IPv4 or IPv6 + TCP headers from a packet as WinDivert delivers it, starting at the IP header.
/// </summary>
/// <remarks>
/// Every multi-byte field is big-endian: network byte order. Reading them little-endian, as the
/// 2026-10-20 parser did, turns port 443 into 47873. Every read is bounds-checked; a packet that is
/// truncated, fragmented past its first fragment, or carries IPv6 extension headers is not parsed,
/// because the observer would rather miss a packet than read a port from the wrong offset.
/// </remarks>
public static class PacketHeaderParser
{
    private const int TcpProtocol = 6;
    private const int TcpMinimumHeader = 20;
    private const int Ipv6Header = 40;

    public static bool TryParse(ReadOnlySpan<byte> packet, out PacketHeaders headers)
    {
        headers = default;
        if (packet.IsEmpty)
        {
            return false;
        }

        return (packet[0] >> 4) switch
        {
            4 => TryParseIpv4(packet, out headers),
            6 => TryParseIpv6(packet, out headers),
            _ => false,
        };
    }

    private static bool TryParseIpv4(ReadOnlySpan<byte> packet, out PacketHeaders headers)
    {
        headers = default;
        if (packet.Length < 20)
        {
            return false;
        }

        var headerLength = (packet[0] & 0x0F) * 4;
        if (headerLength < 20 || packet.Length < headerLength + TcpMinimumHeader || packet[9] != TcpProtocol)
        {
            return false;
        }

        var fragmentOffset = BinaryPrimitives.ReadUInt16BigEndian(packet[6..]) & 0x1FFF;
        if (fragmentOffset != 0)
        {
            return false;
        }

        return TryParseTcp(
            packet[headerLength..],
            new IPAddress(packet.Slice(12, 4)),
            new IPAddress(packet.Slice(16, 4)),
            out headers);
    }

    private static bool TryParseIpv6(ReadOnlySpan<byte> packet, out PacketHeaders headers)
    {
        headers = default;
        if (packet.Length < Ipv6Header + TcpMinimumHeader || packet[6] != TcpProtocol)
        {
            return false;
        }

        return TryParseTcp(
            packet[Ipv6Header..],
            new IPAddress(packet.Slice(8, 16)),
            new IPAddress(packet.Slice(24, 16)),
            out headers);
    }

    private static bool TryParseTcp(ReadOnlySpan<byte> tcp, IPAddress source, IPAddress destination, out PacketHeaders headers)
    {
        headers = default;
        if (tcp.Length < TcpMinimumHeader)
        {
            return false;
        }

        var flags = tcp[13];
        headers = new PacketHeaders(
            source,
            destination,
            BinaryPrimitives.ReadUInt16BigEndian(tcp),
            BinaryPrimitives.ReadUInt16BigEndian(tcp[2..]),
            Syn: (flags & 0x02) != 0,
            Ack: (flags & 0x10) != 0);
        return true;
    }
}

/// <summary>
/// Builds minimal, well-formed TCP packets for the self-test. Harmless by construction: headers only,
/// no payload, checksums zero.
/// </summary>
public static class SyntheticPacket
{
    public static byte[] Tcp(IPAddress source, IPAddress destination, ushort destinationPort, bool syn = true, bool ack = false)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(destination);
        if (source.AddressFamily != destination.AddressFamily)
        {
            throw new ArgumentException("Source and destination must be the same address family.", nameof(destination));
        }

        var ipv6 = source.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        var ipLength = ipv6 ? 40 : 20;
        var packet = new byte[ipLength + 20];
        if (ipv6)
        {
            packet[0] = 0x60;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), 20);
            packet[6] = 6;
            packet[7] = 64;
            source.GetAddressBytes().CopyTo(packet, 8);
            destination.GetAddressBytes().CopyTo(packet, 24);
        }
        else
        {
            packet[0] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
            packet[8] = 64;
            packet[9] = 6;
            source.GetAddressBytes().CopyTo(packet, 12);
            destination.GetAddressBytes().CopyTo(packet, 16);
        }

        var tcp = packet.AsSpan(ipLength);
        BinaryPrimitives.WriteUInt16BigEndian(tcp, 49152);
        BinaryPrimitives.WriteUInt16BigEndian(tcp[2..], destinationPort);
        tcp[12] = 0x50;
        tcp[13] = (byte)((syn ? 0x02 : 0) | (ack ? 0x10 : 0));
        BinaryPrimitives.WriteUInt16BigEndian(tcp[14..], 64240);
        return packet;
    }
}

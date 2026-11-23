using System.Buffers.Binary;
using System.Net;
using PacketDotNet;

namespace WPShield.NetworkSensor;

public sealed record FlowRow(string Protocol, string Local, string Remote, string Initiator,
    long ReceivedBytes, long SentBytes, DateTimeOffset LastSeen)
{
    public DateTimeOffset? FirstSeen { get; init; }
}

public sealed record FlowSnapshot(string Interface, DateTimeOffset Timestamp, int ActiveFlows,
    long SkippedPackets, long CapacityDrops, uint? DriverDrops, IReadOnlyList<FlowRow> Flows)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<TrafficInterval>? History { get; init; }
    public string CaptureStatus { get; init; } = "unknown";
    public IReadOnlyList<int>? CapturePorts { get; init; }
}

/// <summary>A single capture reader owns this bounded table. Only endpoint metadata survives Observe.</summary>
internal sealed class FlowTable(IEnumerable<IPAddress> localAddresses, IReadOnlySet<int> ports)
{
    internal const int Capacity = 4096;
    private readonly IReadOnlyList<int> _capturePorts = Array.AsReadOnly(ports.Order().ToArray());
    private readonly HashSet<IPAddress> _local = localAddresses.Select(WithoutScope).ToHashSet();
    private readonly Dictionary<Key, Totals> _flows = [];
    private long _skipped;
    private long _capacityDrops;
    private TrafficHistory? _history;

    internal void StartHistory(TimeProvider clock, uint? drops) =>
        _history = new(clock, clock.GetUtcNow(), drops, _skipped);

    private readonly record struct Key(byte Protocol, IPEndPoint Local, IPEndPoint Remote);
    private sealed class Totals(DateTimeOffset firstSeen)
    {
        public DateTimeOffset FirstSeen = firstSeen;
        public long Received;
        public long Sent;
        public DateTimeOffset LastSeen;
        public string Initiator = "unknown";
        public uint? OpeningSequence;
    }

    private static IPAddress WithoutScope(IPAddress address) =>
        address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? new IPAddress(address.GetAddressBytes()) : address;

    internal void Observe(LinkLayers link, ReadOnlySpan<byte> frame, DateTimeOffset seen, uint? wireLength = null)
    {
        if (!TryGetIp(link, frame, out var ip))
        {
            _skipped++;
            return;
        }
        var linkHeaderBytes = frame.Length - ip.Length;
        var ipBytesOnWire = (long)(wireLength ?? (uint)frame.Length) - linkHeaderBytes;
        if (!TryReadHeader(ip, ipBytesOnWire, out var source, out var destination,
                out var protocol, out var transport, out var length))
        {
            _skipped++;
            return;
        }
        var srcPort = BinaryPrimitives.ReadUInt16BigEndian(transport);
        var dstPort = BinaryPrimitives.ReadUInt16BigEndian(transport[2..]);
        if (ports.Count > 0 && !ports.Contains(srcPort) && !ports.Contains(dstPort)) return;
        var outbound = _local.Contains(source);
        if (outbound == _local.Contains(destination))
        {
            _skipped++;
            return;
        }
        _history?.Count(outbound, length);
        var src = new IPEndPoint(source, srcPort);
        var dst = new IPEndPoint(destination, dstPort);
        var key = outbound ? new Key(protocol, src, dst) : new Key(protocol, dst, src);
        if (!_flows.TryGetValue(key, out var totals))
        {
            if (_flows.Count == Capacity)
            {
                _capacityDrops++;
                return;
            }
            totals = new Totals(seen);
            _flows.Add(key, totals);
        }
        else if (seen - totals.LastSeen >= TimeSpan.FromMinutes(1))
        {
            totals = new Totals(seen);
            _flows[key] = totals;
        }
        if (protocol == 6 && (transport[13] & 0x17) == 0x02)
        {
            var sequence = BinaryPrimitives.ReadUInt32BigEndian(transport[4..]);
            var initiator = outbound ? "local" : "remote";
            if (totals.OpeningSequence != sequence || totals.Initiator != initiator)
            {
                // A fresh opening on a reused tuple starts a new observation.
                totals.Received = totals.Sent = 0;
                totals.FirstSeen = seen;
                totals.OpeningSequence = sequence;
                totals.Initiator = initiator;
            }
        }
        if (outbound) totals.Sent += length;
        else totals.Received += length;
        totals.LastSeen = seen;
    }

    internal FlowSnapshot Snapshot(string device, DateTimeOffset now, uint? driverDrops, bool includeAllRows = false,
        bool interrupted = false)
    {
        var history = _history?.Finish(now, driverDrops, _skipped, interrupted);
        foreach (var key in _flows.Where(pair => now - pair.Value.LastSeen >= TimeSpan.FromMinutes(1))
                     .Select(pair => pair.Key).ToArray())
            _flows.Remove(key);
        var rows = _flows.OrderByDescending(pair => pair.Value.LastSeen).Take(includeAllRows ? Capacity : 40)
            .Select(pair => new FlowRow(pair.Key.Protocol == 6 ? "TCP" : "UDP",
                pair.Key.Local.ToString(), pair.Key.Remote.ToString(), pair.Value.Initiator,
                pair.Value.Received, pair.Value.Sent, pair.Value.LastSeen)
            { FirstSeen = pair.Value.FirstSeen }).ToArray();
        return new(device, now, _flows.Count, _skipped, _capacityDrops, driverDrops, rows)
        {
            History = history,
            CapturePorts = _capturePorts
        };
    }

    private static bool TryGetIp(LinkLayers link, ReadOnlySpan<byte> frame, out ReadOnlySpan<byte> ip)
    {
        ip = default;
        if (link == LinkLayers.Ethernet)
        {
            if (frame.Length < 14 || BinaryPrimitives.ReadUInt16BigEndian(frame[12..]) is not (0x0800 or 0x86dd))
                return false;
            ip = frame[14..];
        }
        else if (link is LinkLayers.Raw or LinkLayers.RawLegacy or LinkLayers.IPv4 or LinkLayers.IPv6)
            ip = frame;
        else if (link is LinkLayers.Null or LinkLayers.Loop && frame.Length >= 4)
            ip = frame[4..];
        else return false;
        return ip.Length >= 20;
    }

    private static bool TryReadHeader(ReadOnlySpan<byte> ip, long wireIpBytes, out IPAddress source, out IPAddress destination,
        out byte protocol, out ReadOnlySpan<byte> transport, out int length)
    {
        source = destination = IPAddress.None;
        transport = default;
        length = protocol = 0;
        int offset;
        if (ip[0] >> 4 == 4)
        {
            offset = (ip[0] & 15) * 4;
            if (offset < 20 || (BinaryPrimitives.ReadUInt16BigEndian(ip[6..]) & 0x3fff) != 0) return false;
            length = BinaryPrimitives.ReadUInt16BigEndian(ip[2..]);
            protocol = ip[9];
            source = new IPAddress(ip.Slice(12, 4));
            destination = new IPAddress(ip.Slice(16, 4));
        }
        else if (ip[0] >> 4 == 6 && ip.Length >= 40)
        {
            offset = 40;
            length = offset + BinaryPrimitives.ReadUInt16BigEndian(ip[4..]);
            protocol = ip[6];
            source = new IPAddress(ip.Slice(8, 16));
            destination = new IPAddress(ip.Slice(24, 16));
        }
        else return false;
        if (length > wireIpBytes || offset > Math.Min(ip.Length, length)) return false;
        transport = ip[offset..Math.Min(length, ip.Length)];
        if (protocol == 17)
            return transport.Length >= 8 && BinaryPrimitives.ReadUInt16BigEndian(transport[4..]) == length - offset;
        if (protocol != 6 || transport.Length < 20) return false;
        var tcpHeaderBytes = (transport[12] >> 4) * 4;
        return tcpHeaderBytes >= 20 && tcpHeaderBytes <= transport.Length;
    }
}

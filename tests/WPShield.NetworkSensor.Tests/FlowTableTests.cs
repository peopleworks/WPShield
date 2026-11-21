using System.Buffers.Binary;
using System.Net;
using System.Text.Json;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using Xunit;

namespace WPShield.NetworkSensor.Tests;

public sealed class FlowTableTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UnixEpoch;
    private static readonly IPAddress Local = IPAddress.Parse("192.0.2.1");
    private static readonly IPAddress Remote = IPAddress.Parse("198.51.100.2");

    [Fact]
    public void ExistingHttpMode_DeliversTheSelectedTcpPayloadFromTypedCaptureEvents()
    {
        var content = "GET /example HTTP/1.1\r\n\r\n"u8.ToArray();
        var frame = Frame(Remote, Local, 51000, 80, flags: 16, bodyBytes: content.Length);
        content.CopyTo(frame, frame.Length - content.Length);
        using var device = new SyntheticCapture(frame, false);
        HttpMetadata? observed = null;
        using var capture = new PcapCapture([device], ["synthetic"], [80], false,
            (buffer, offset, count) => observed = HttpMetadataParser.TryParse(buffer, offset, count));
        capture.Start();
        Assert.Equal("/example", observed?.Path);
        Assert.Equal("tcp port 80", device.Filter);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CaptureLoop_ConsumesTypedEvents_AndDistinguishesCancellationFromDriverStop(bool driverStopped)
    {
        var frame = Frame(Remote, Local, 51000, 443, flags: 2);
        using var device = new SyntheticCapture(frame, driverStopped);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var snapshots = new List<FlowSnapshot>();
        var error = Record.Exception(() => HostFlowMonitor.RunOpened(device, new FlowTable([Local], new HashSet<int>()),
            snapshot =>
            {
                snapshots.Add(snapshot);
                if (!driverStopped) stop.Cancel();
            }, stop.Token));
        if (driverStopped) Assert.IsType<InvalidOperationException>(error);
        else Assert.Null(error);
        Assert.False(device.Started);
        Assert.NotEmpty(snapshots);
        Assert.All(snapshots, snapshot =>
        {
            Assert.Null(snapshot.DriverDrops);
            Assert.Equal("remote", Assert.Single(snapshot.Flows).Initiator);
        });
        Assert.Equal(driverStopped ? 1 : 2, snapshots.Count);
    }

    private sealed class SyntheticCapture(byte[] frame, bool stopUnexpectedly) : ICaptureDevice
    {
        public string Name => "synthetic";
        public string Description => Name;
        public string LastError => string.Empty;
        public string? Filter { get; set; }
        public System.Net.NetworkInformation.PhysicalAddress? MacAddress => null;
        public LinkLayers LinkType => LinkLayers.Ethernet;
        public bool Started { get; private set; }
        public TimeSpan StopCaptureTimeout { get; set; }
        public ICaptureStatistics? Statistics => null;
        public TimestampResolution TimestampResolution => TimestampResolution.Microsecond;
        public event PacketArrivalEventHandler? OnPacketArrival;
        public event CaptureStoppedEventHandler? OnCaptureStopped;
        public void StartCapture()
        {
            Started = true;
            var header = new PcapHeader((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds(), 0, (uint)frame.Length, (uint)frame.Length);
            OnPacketArrival?.Invoke(this, new PacketCapture(this, header, frame));
            if (stopUnexpectedly)
            {
                Started = false;
                OnCaptureStopped?.Invoke(this, CaptureStoppedEventStatus.ErrorWhileCapturing);
            }
        }
        public void StopCapture() => Started = false;
        public void Open(DeviceConfiguration configuration) => Assert.Equal(DeviceModes.None, configuration.Mode);
        public void Close() => StopCapture();
        public void Dispose() => Close();
        public void Capture() => throw new NotSupportedException();
        public GetPacketStatus GetNextPacket(out PacketCapture e) => throw new NotSupportedException();
    }

    [Fact]
    public void HttpsReplyAndIndependentOutboundConnection_KeepSeparateDirectionsAndTotals()
    {
        var table = new FlowTable([Local], new HashSet<int> { 443 });
        var opening = Frame(Remote, Local, 51000, 443, flags: 2);
        var reply = Frame(Local, Remote, 443, 51000, flags: 18, bodyBytes: 256);
        "synthetic-private-marker"u8.CopyTo(reply.AsSpan(54));
        table.Observe(LinkLayers.Ethernet, opening, Now);
        table.Observe(LinkLayers.Ethernet, opening, Now); // Retransmitted SYN is also observed traffic.
        table.Observe(LinkLayers.Ethernet, reply.AsSpan(0, 160), Now, (uint)reply.Length);
        table.Observe(LinkLayers.Ethernet, Frame(Local, Remote, 52000, 443, flags: 2), Now);
        var view = table.Snapshot("synthetic", Now, 7);
        Assert.Equal(2, view.ActiveFlows);
        var incoming = Assert.Single(view.Flows, row => row.Local == "192.0.2.1:443");
        Assert.Equal("remote", incoming.Initiator);
        Assert.Equal(80, incoming.ReceivedBytes);
        Assert.Equal(296, incoming.SentBytes);
        var outgoing = Assert.Single(view.Flows, row => row.Initiator == "local");
        Assert.Equal(40, outgoing.SentBytes);
        Assert.Equal(0, outgoing.ReceivedBytes);
        Assert.Equal(7u, view.DriverDrops);
        Assert.DoesNotContain("synthetic-private-marker", JsonSerializer.Serialize(view));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void IPv6UdpAndMidstreamTcp_HaveUnknownInitiator(bool udp)
    {
        var local = IPAddress.Parse("2001:db8::1");
        var remote = IPAddress.Parse("2001:db8::2");
        var table = new FlowTable([local], new HashSet<int>());
        var bytes = Frame(remote, local, 50100, 14433, udp, flags: 16);
        table.Observe(LinkLayers.Ethernet, bytes, Now);
        var snapshot = table.Snapshot("synthetic", Now, null);
        var row = Assert.Single(snapshot.Flows);
        Assert.Equal("unknown", row.Initiator);
        Assert.Equal(udp ? "UDP" : "TCP", row.Protocol);
        Assert.Equal("[2001:db8::1]:14433", row.Local);
        Assert.Equal(bytes.Length - 14, row.ReceivedBytes);
        Assert.Null(snapshot.DriverDrops);
    }

    [Fact]
    public void FilterAndUnusablePackets_NeverProduceAnInventedFlow()
    {
        var table = new FlowTable([Local], new HashSet<int> { 443 });
        var frame = Frame(Remote, Local, 54000, 443);
        for (var i = 0; i < frame.Length; i++)
            table.Observe(LinkLayers.Ethernet, frame.AsSpan(0, i), Now);
        frame[20] = 0x20; // More IPv4 fragments.
        table.Observe(LinkLayers.Ethernet, frame, Now);
        table.Observe(LinkLayers.Ethernet, Frame(Local, Local, 54000, 443), Now);
        table.Observe(LinkLayers.Ethernet, Frame(Remote, Local, 54000, 5555), Now);
        var view = table.Snapshot("synthetic", Now, null);
        Assert.Empty(view.Flows);
        Assert.Equal(frame.Length + 2, view.SkippedPackets);
    }

    [Fact]
    public void TableCapsRetentionAndDisplay_AndCanAdmitNewFlowsAfterExpiry()
    {
        var table = new FlowTable([Local], new HashSet<int>());
        for (var port = 1; port <= FlowTable.Capacity + 1; port++)
            table.Observe(LinkLayers.Ethernet, Frame(Local, Remote, port, 443), Now);
        var full = table.Snapshot("synthetic", Now, null);
        Assert.Equal(FlowTable.Capacity, full.ActiveFlows);
        Assert.Equal(40, full.Flows.Count);
        Assert.Equal(FlowTable.Capacity, table.Snapshot("synthetic", Now, null, includeAllRows: true).Flows.Count);
        Assert.Equal(1, full.CapacityDrops);
        var later = Now.AddMinutes(1);
        Assert.Empty(table.Snapshot("synthetic", later, null).Flows);
        table.Observe(LinkLayers.Ethernet, Frame(Local, Remote, 60000, 443), later);
        Assert.Single(table.Snapshot("synthetic", later, null).Flows);
    }

    private static byte[] Frame(IPAddress src, IPAddress dst, int srcPort, int dstPort,
        bool udp = false, byte flags = 0, int bodyBytes = 0)
    {
        var v6 = src.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        var header = v6 ? 40 : 20;
        var transportSize = (udp ? 8 : 20) + bodyBytes;
        var bytes = new byte[14 + header + transportSize];
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(12), (ushort)(v6 ? 0x86dd : 0x0800));
        var ip = bytes.AsSpan(14);
        ip[0] = (byte)(v6 ? 0x60 : 0x45);
        BinaryPrimitives.WriteUInt16BigEndian(ip[(v6 ? 4 : 2)..], (ushort)(v6 ? transportSize : ip.Length));
        ip[v6 ? 6 : 9] = (byte)(udp ? 17 : 6);
        src.GetAddressBytes().CopyTo(ip[(v6 ? 8 : 12)..]);
        dst.GetAddressBytes().CopyTo(ip[(v6 ? 24 : 16)..]);
        var segment = ip[header..];
        BinaryPrimitives.WriteUInt16BigEndian(segment, (ushort)srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(segment[2..], (ushort)dstPort);
        if (udp) BinaryPrimitives.WriteUInt16BigEndian(segment[4..], (ushort)transportSize);
        else
        {
            segment[12] = 0x50;
            segment[13] = flags;
        }
        return bytes;
    }
}

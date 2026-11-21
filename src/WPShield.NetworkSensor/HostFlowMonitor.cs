using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace WPShield.NetworkSensor;

public static class HostFlowMonitor
{
    public static void Run(string interfaceName, IReadOnlyList<int> ports, bool allPorts,
        Action<FlowSnapshot> publish, CancellationToken cancellationToken, bool includeAllRows = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(interfaceName);
        ArgumentNullException.ThrowIfNull(publish);
        if (allPorts == (ports.Count > 0) || ports.Count > 64 || ports.Any(p => p is < 1 or > 65535))
            throw new ArgumentException("Select 1..64 ports or explicitly select all ports.");
        cancellationToken.ThrowIfCancellationRequested();
        var matches = LibPcapLiveDeviceList.Instance.Where(d =>
            string.Equals(d.Name, interfaceName, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(d.Interface?.FriendlyName, interfaceName, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(d.Description, interfaceName, StringComparison.OrdinalIgnoreCase)).Take(2).ToArray();
        if (matches.Length != 1)
            throw new InvalidOperationException("Specify one interface by its unique Windows adapter name or Npcap device name.");
        var device = matches[0];
        var addresses = device.Addresses.Select(a => a.Addr?.ipAddress).OfType<System.Net.IPAddress>().ToArray();
        if (addresses.Length == 0)
            throw new InvalidOperationException("The selected interface has no IP addresses to determine traffic direction.");
        var table = new FlowTable(addresses, ports.ToHashSet());
        try
        {
            device.Open(new DeviceConfiguration { Mode = DeviceModes.None, ReadTimeout = 100, Snaplen = 160 });
            device.Filter = allPorts ? "tcp or udp" :
                "(tcp or udp) and (" + string.Join(" or ", ports.Distinct().Select(p => FormattableString.Invariant($"port {p}"))) + ")";
            var link = device.LinkType;
            if (link is not (LinkLayers.Ethernet or LinkLayers.Raw or LinkLayers.RawLegacy
                or LinkLayers.IPv4 or LinkLayers.IPv6 or LinkLayers.Null or LinkLayers.Loop))
                throw new InvalidOperationException("The selected interface uses an unsupported capture link type.");
            RunOpened(device, table, publish, cancellationToken, includeAllRows);
        }
        finally
        {
            if (device.Opened) device.Close();
        }
    }

    internal static void RunOpened(ICaptureDevice device, FlowTable table, Action<FlowSnapshot> publish,
        CancellationToken cancellationToken, bool includeAllRows = false)
    {
        var ended = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var link = device.LinkType;
        var gate = new object();
        void Arrived(object sender, PacketCapture packet)
        {
            lock (gate)
                table.Observe(link, packet.Data, packet.Header.Timeval.Date, (packet.Header as PcapHeader)?.PacketLength);
        }
        void Stopped(object sender, CaptureStoppedEventStatus status) => ended.TrySetResult();
        void Publish()
        {
            var drops = ReadDrops(device);
            FlowSnapshot snapshot;
            lock (gate)
                snapshot = table.Snapshot(device.Name, DateTimeOffset.UtcNow, drops, includeAllRows);
            publish(snapshot);
        }

        device.OnPacketArrival += Arrived;
        device.OnCaptureStopped += Stopped;
        try
        {
            device.StartCapture();
            while (!cancellationToken.IsCancellationRequested)
            {
                Publish();
                if (ended.Task.Wait(TimeSpan.FromSeconds(2), cancellationToken))
                    throw new InvalidOperationException("Capture stopped unexpectedly. Check the adapter and Npcap.");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        finally
        {
            device.OnCaptureStopped -= Stopped;
            device.OnPacketArrival -= Arrived;
            if (device.Started) device.StopCapture();
        }
        Publish();
    }

    private static uint? ReadDrops(ICaptureDevice device)
    {
        try { return device.Statistics?.DroppedPackets; }
        catch (PcapException) { return null; }
        catch (NotSupportedException) { return null; }
    }
}

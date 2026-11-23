using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace WPShield.NetworkSensor;

public static class HostFlowMonitor
{
    public static IReadOnlyList<FlowInterface> ListInterfaces() =>
        PcapInterface.GetAllPcapInterfaces().Select(FlowInterface.Describe)
            .OrderBy(i => i.DeviceId, StringComparer.OrdinalIgnoreCase).ToArray();

    public static void Run(string interfaceName, IReadOnlyList<int> ports, bool allPorts,
        Action<FlowSnapshot> publish, CancellationToken cancellationToken, bool includeAllRows = false) =>
        Run(interfaceName, ports, allPorts, publish, cancellationToken, includeAllRows, includeHistory: false);

    public static void Run(string interfaceName, IReadOnlyList<int> ports, bool allPorts,
        Action<FlowSnapshot> publish, CancellationToken cancellationToken, bool includeAllRows, bool includeHistory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(interfaceName);
        ArgumentNullException.ThrowIfNull(publish);
        if (allPorts == (ports.Count > 0) || ports.Count > 64 || ports.Any(p => p is < 1 or > 65535))
            throw new ArgumentException("Select 1..64 ports or explicitly select all ports.");
        cancellationToken.ThrowIfCancellationRequested();
        var interfaces = PcapInterface.GetAllPcapInterfaces();
        var selected = FlowInterface.Resolve(interfaces.Select(FlowInterface.Describe), interfaceName);
        using var device = new LibPcapLiveDevice(interfaces.Single(i => i.Name == selected.DeviceId));
        var addresses = device.Addresses.Select(a => a.Addr?.ipAddress).OfType<System.Net.IPAddress>().ToArray();
        if (addresses.Length == 0)
            throw new InvalidOperationException("The selected interface has no IP addresses to determine traffic direction.");
        var table = new FlowTable(addresses, ports.ToHashSet());
        device.Open(new DeviceConfiguration { Mode = DeviceModes.None, ReadTimeout = 100, Snaplen = 160 });
        device.Filter = allPorts ? "tcp or udp" :
            "(tcp or udp) and (" + string.Join(" or ", ports.Distinct().Select(p => FormattableString.Invariant($"port {p}"))) + ")";
        var link = device.LinkType;
        if (link is not (LinkLayers.Ethernet or LinkLayers.Raw or LinkLayers.RawLegacy
            or LinkLayers.IPv4 or LinkLayers.IPv6 or LinkLayers.Null or LinkLayers.Loop))
            throw new InvalidOperationException("The selected interface uses an unsupported capture link type.");
        RunOpened(device, table, publish, cancellationToken, includeAllRows, includeHistory);
    }

    internal static void RunOpened(ICaptureDevice device, FlowTable table, Action<FlowSnapshot> publish,
        CancellationToken cancellationToken, bool includeAllRows = false, bool includeHistory = false)
    {
        var ended = new TaskCompletionSource<CaptureStoppedEventStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        var link = device.LinkType;
        var gate = new object();
        void Arrived(object sender, PacketCapture packet)
        {
            lock (gate)
                table.Observe(link, packet.Data, packet.Header.Timeval.Date, (packet.Header as PcapHeader)?.PacketLength);
        }
        void Stopped(object sender, CaptureStoppedEventStatus status) => ended.TrySetResult(status);
        void Publish(string status)
        {
            var drops = ReadDrops(device);
            FlowSnapshot snapshot;
            lock (gate)
                snapshot = table.Snapshot(device.Name, DateTimeOffset.UtcNow, drops, includeAllRows, status == "interrupted");
            publish(snapshot with { CaptureStatus = status });
        }

        device.OnPacketArrival += Arrived;
        device.OnCaptureStopped += Stopped;
        try
        {
            if (includeHistory) table.StartHistory(TimeProvider.System, ReadDrops(device));
            device.StartCapture();
            try
            {
                while (!cancellationToken.IsCancellationRequested && !ended.Task.IsCompleted)
                {
                    Publish("running");
                    if (ended.Task.Wait(TimeSpan.FromSeconds(2), cancellationToken)) break;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }

            var interrupted = ended.Task.IsCompleted;
            if (device.Started) device.StopCapture();
            interrupted |= ended.Task.IsCompletedSuccessfully && ended.Task.Result == CaptureStoppedEventStatus.ErrorWhileCapturing;
            Publish(interrupted ? "interrupted" : "stopped");
            if (interrupted && !cancellationToken.IsCancellationRequested)
                throw new InvalidOperationException("Capture stopped unexpectedly. Check the adapter and Npcap.");
        }
        finally
        {
            device.OnCaptureStopped -= Stopped;
            device.OnPacketArrival -= Arrived;
            if (device.Started) device.StopCapture();
        }
    }

    private static uint? ReadDrops(ICaptureDevice device)
    {
        try { return device.Statistics?.DroppedPackets; }
        catch (PcapException) { return null; }
        catch (NotSupportedException) { return null; }
    }
}

namespace WPShield.NetworkSensor;

using PacketDotNet;
using SharpPcap;

/// <summary>
/// Live packet capture on operator-named interfaces and ports.
///
/// The capture is read-only: it never injects, modifies, or blocks packets. It extracts
/// TCP payloads and hands them to the HTTP metadata parser. Full bodies, credentials,
/// cookies, and query strings are never retained.
/// </summary>
public sealed class PcapCapture : IDisposable
{
    private readonly List<ICaptureDevice> _devices = [];
    private readonly HashSet<int> _ports;
    private readonly bool _promiscuousMode;
    private readonly Action<byte[], int, int> _onTcpPayload;
    private bool _disposed;

    /// <summary>
    /// Creates a capture instance for the given interfaces and ports.
    /// </summary>
    public PcapCapture(
        IReadOnlyList<string> interfaces,
        IReadOnlyList<int> ports,
        bool promiscuousMode,
        Action<byte[], int, int> onTcpPayload)
        : this(CaptureDeviceList.Instance, interfaces, ports, promiscuousMode, onTcpPayload) { }

    internal PcapCapture(IEnumerable<ICaptureDevice> allDevices, IReadOnlyList<string> interfaces,
        IReadOnlyList<int> ports, bool promiscuousMode, Action<byte[], int, int> onTcpPayload)
    {
        _ports = new HashSet<int>(ports);
        _promiscuousMode = promiscuousMode;
        _onTcpPayload = onTcpPayload ?? throw new ArgumentNullException(nameof(onTcpPayload));

        // If no interfaces are named, capture from all adapters that have an IP address.
        var candidateDevices = interfaces.Count > 0
            ? allDevices.Where(d => interfaces.Contains(d.Name, StringComparer.OrdinalIgnoreCase) ||
                                    interfaces.Contains(d.Description, StringComparer.OrdinalIgnoreCase))
            : allDevices;

        foreach (var device in candidateDevices)
        {
            TryOpenDevice(device);
        }

        if (_devices.Count == 0)
        {
            throw new InvalidOperationException(
                "No network interfaces could be opened for capture. " +
                "Check that the interface names are correct and that the process is elevated.");
        }
    }

    /// <summary>
    /// Starts capturing on all opened devices.
    /// </summary>
    public void Start()
    {
        foreach (var device in _devices)
        {
            device.OnPacketArrival += OnPacketArrival;
            device.StartCapture();
        }
    }

    /// <summary>
    /// Stops capturing on all devices.
    /// </summary>
    public void Stop()
    {
        foreach (var device in _devices)
        {
            try
            {
                device.StopCapture();
            }
            catch
            {
                // Stopping is best-effort during shutdown.
            }
            device.OnPacketArrival -= OnPacketArrival;
        }
    }

    private void TryOpenDevice(ICaptureDevice device)
    {
        try
        {
            // Open in capture mode. The read timeout is short so StopCapture can break the loop.
            device.Open(new DeviceConfiguration { Mode = _promiscuousMode ? DeviceModes.Promiscuous : DeviceModes.None, ReadTimeout = 100 });

            // Build a BPF filter for the configured ports: "tcp port 80 or tcp port 443"
            var filter = BuildBpfFilter();
            if (!string.IsNullOrEmpty(filter))
            {
                device.Filter = filter;
            }

            _devices.Add(device);
        }
        catch
        {
            // A single interface failing is not fatal: capture continues on the others.
            try { device.Close(); } catch { }
        }
    }

    private string BuildBpfFilter()
    {
        if (_ports.Count == 0)
        {
            return string.Empty;
        }

        var parts = _ports.Select(p => $"tcp port {p}");
        return string.Join(" or ", parts);
    }

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            if (e.Data.IsEmpty) return;
            var packet = Packet.ParsePacket(e.Device.LinkType, e.Data.ToArray());
            var tcpPacket = packet.Extract<TcpPacket>();
            if (tcpPacket is null)
            {
                return;
            }

            var sourcePort = tcpPacket.SourcePort;
            var destinationPort = tcpPacket.DestinationPort;

            // Only process packets to or from a configured port.
            if (!_ports.Contains(sourcePort) && !_ports.Contains(destinationPort))
            {
                return;
            }

            var payload = tcpPacket.PayloadData;
            if (payload is null || payload.Length == 0)
            {
                return;
            }

            _onTcpPayload(payload, 0, payload.Length);
        }
        catch
        {
            // Malformed packets are skipped silently. Capture must not stop on a bad packet.
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Stop();

        foreach (var device in _devices)
        {
            try { device.Close(); } catch { }
            if (device is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }

        _devices.Clear();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}

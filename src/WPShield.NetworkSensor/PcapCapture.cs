namespace WPShield.NetworkSensor;

using PacketDotNet;
using SharpPcap;

/// <summary>
/// Live packet capture on operator-named interfaces and ports.
///
/// The capture is read-only: it never injects, modifies, or blocks packets. It extracts
/// TCP payloads and hands them to the HTTP metadata parser. Full bodies, credentials,
/// cookies, and query strings are never retained.
///
/// The SharpPcap API surface used here is accessed through <c>dynamic</c> because the
/// 4.1.0 NuGet package ships concrete device types in platform-specific sub-assemblies
/// (SharpPcap.WinPcap, SharpPcap.LibPcap) while the base package exposes only the
/// <c>ICaptureDevice</c> interface. Using <c>dynamic</c> keeps this project independent of
/// the underlying capture backend while remaining type-safe at the boundaries we control.
/// </summary>
public sealed class PcapCapture : IDisposable
{
    private readonly List<dynamic> _devices = [];
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
    {
        _ports = new HashSet<int>(ports);
        _promiscuousMode = promiscuousMode;
        _onTcpPayload = onTcpPayload ?? throw new ArgumentNullException(nameof(onTcpPayload));

        var allDevices = CaptureDeviceList.Instance;

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
            var handler = new Action<object, dynamic>(OnPacketArrival);
            device.OnPacketArrival += handler;
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
            var handler = new Action<object, dynamic>(OnPacketArrival);
            device.OnPacketArrival -= handler;
        }
    }

    private void TryOpenDevice(dynamic device)
    {
        try
        {
            // Open in capture mode. The read timeout is short so StopCapture can break the loop.
            device.Open();

            // Build a BPF filter for the configured ports: "tcp port 80 or tcp port 443"
            var filter = BuildBpfFilter();
            if (!string.IsNullOrEmpty(filter))
            {
                device.Filter = filter;
            }

            device.PromiscuousMode = _promiscuousMode;
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

    private void OnPacketArrival(object sender, dynamic e)
    {
        try
        {
            // Cast from dynamic to concrete types so the compiler can perform nullability analysis.
            var data = (byte[])e.Packet.Data;
            if (data is null || data.Length == 0)
            {
                return;
            }

            var linkLayer = (PacketDotNet.LinkLayers)e.Packet.LinkLayerType;
            var packet = Packet.ParsePacket(linkLayer, data);
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

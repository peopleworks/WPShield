using System.Net.Sockets;
using SharpPcap.LibPcap;

namespace WPShield.NetworkSensor;

public sealed record FlowInterface(string DeviceId, string? FriendlyName, string? Description, bool HasIPv4, bool HasIPv6)
{
    internal static FlowInterface Describe(PcapInterface adapter) => new(
        adapter.Name, adapter.FriendlyName, adapter.Description,
        adapter.Addresses.Any(a => a.Addr?.ipAddress?.AddressFamily == AddressFamily.InterNetwork),
        adapter.Addresses.Any(a => a.Addr?.ipAddress?.AddressFamily == AddressFamily.InterNetworkV6));

    internal static FlowInterface Resolve(IEnumerable<FlowInterface> interfaces, string selector)
    {
        // An absent Npcap device path must never resolve to another interface through a display alias.
        var deviceIdOnly = selector.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase);
        var matches = interfaces.Where(i => string.Equals(i.DeviceId, selector, StringComparison.OrdinalIgnoreCase) ||
            !deviceIdOnly && (string.Equals(i.FriendlyName, selector, StringComparison.OrdinalIgnoreCase) ||
                              string.Equals(i.Description, selector, StringComparison.OrdinalIgnoreCase))).Take(2).ToArray();
        return matches.Length switch
        {
            1 => matches[0],
            0 => throw new InvalidOperationException("The selected capture interface is unavailable. Run --list-interfaces."),
            _ => throw new InvalidOperationException("The interface name is ambiguous. Select a device ID from --list-interfaces.")
        };
    }
}

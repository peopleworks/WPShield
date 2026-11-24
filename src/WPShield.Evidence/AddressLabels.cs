using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;

namespace WPShield.Evidence;

/// <summary>
/// The operator's names for known addresses and networks (the <c>labels.addresses</c> setting),
/// matched the same way by every reader: the desktop, the CLI and a future MCP server.
/// </summary>
/// <remarks>
/// <para>
/// An exact address wins over any network that contains it, and a longer prefix wins over a shorter
/// one, so "203.0.113.7 = my office" can sit inside "203.0.113.0/24 = the office's provider".
/// </para>
/// <para>
/// A label describes an address; it never allows or blocks one (ADR 0007, amendment). Nothing in
/// this type is consulted by a decision. Labels are cleaned again on read, because the setting was
/// written by a tool this build did not necessarily come from.
/// </para>
/// </remarks>
public sealed class AddressLabels
{
    public const string SettingKey = "labels.addresses";
    public static readonly AddressLabels None = new(new Dictionary<string, string>(StringComparer.Ordinal), []);

    private readonly Dictionary<string, string> exact;
    private readonly Network[] networks;

    private AddressLabels(Dictionary<string, string> exact, Network[] networks)
    {
        this.exact = exact;
        this.networks = networks;
    }

    public int Count => exact.Count + networks.Length;

    /// <summary>Reads the setting from a store. Throws only what reading the store throws.</summary>
    public static AddressLabels Read(EvidenceStore store) => From(new EvidenceSettings(store).Get(SettingKey));

    /// <summary>
    /// Builds the matcher from the setting's value. An entry that is not an address or a network is
    /// skipped rather than refused: the catalog already refused it on write, and a reader must not
    /// fail because a newer writer accepted something this build does not understand.
    /// </summary>
    public static AddressLabels From(JsonNode? value)
    {
        if (value is not JsonObject map || map.Count == 0) return None;
        var exact = new Dictionary<string, string>(StringComparer.Ordinal);
        var networks = new List<Network>();
        foreach (var (key, node) in map.Take(SettingCatalog.MaxLabels))
        {
            if (node is not JsonValue text || !text.TryGetValue<string>(out var raw)) continue;
            var label = EvidenceText.Clean(raw, 64);
            if (label.Length == 0) continue;
            var slash = key.IndexOf('/');
            if (!IPAddress.TryParse(slash < 0 ? key : key[..slash], out var ip)) continue;
            var bits = -1;
            if (slash >= 0 && !int.TryParse(key[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out bits)) continue;
            if (ip.IsIPv4MappedToIPv6)
            {
                ip = ip.MapToIPv4();
                if (bits >= 0) bits -= 96;
                if (slash >= 0 && bits < 0) continue;
            }
            var max = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            if (bits > max) continue;
            if (bits < 0 || bits == max)
            {
                exact.TryAdd(Canonical(ip), label);
                continue;
            }
            networks.Add(new Network(Mask(ip.GetAddressBytes(), bits), bits, ip.AddressFamily, label));
        }
        // Longest prefix first; among equal prefixes the first entry written wins, deterministically.
        return new AddressLabels(exact, [.. networks.OrderByDescending(n => n.Bits)]);
    }

    /// <summary>The label for an address, or <see langword="null"/>. Text that is not an address has none.</summary>
    public string? For(string? address) =>
        address is not null && IPAddress.TryParse(address.Trim(), out var ip) ? For(ip) : null;

    public string? For(IPAddress address)
    {
        if (Count == 0) return null;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (exact.TryGetValue(Canonical(address), out var label)) return label;
        var bytes = address.GetAddressBytes();
        foreach (var network in networks)
            if (network.Family == address.AddressFamily && network.Contains(bytes)) return network.Label;
        return null;
    }

    private static string Canonical(IPAddress ip) => new IPAddress(ip.GetAddressBytes()).ToString();

    private static byte[] Mask(byte[] bytes, int bits)
    {
        for (var i = 0; i < bytes.Length; i++)
        {
            var keep = Math.Clamp(bits - i * 8, 0, 8);
            bytes[i] &= (byte)(0xFF << (8 - keep));
        }
        return bytes;
    }

    private sealed record Network(byte[] Prefix, int Bits, AddressFamily Family, string Label)
    {
        internal bool Contains(byte[] address)
        {
            if (address.Length != Prefix.Length) return false;
            for (var i = 0; i < Prefix.Length; i++)
            {
                var keep = Math.Clamp(Bits - i * 8, 0, 8);
                if (keep == 0) return true;
                var mask = (byte)(0xFF << (8 - keep));
                if ((address[i] & mask) != Prefix[i]) return false;
            }
            return true;
        }
    }
}

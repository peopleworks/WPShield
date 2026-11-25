using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace WPShield.Evidence.Decisions;

/// <summary>Addresses and networks as the engine compares them: canonical, prefix-aligned, one family.</summary>
public static class AddressRanges
{
    /// <summary>The widest allow-list entry accepted for IPv4: a /16.</summary>
    public const int MinIPv4Prefix = 16;

    /// <summary>The widest allow-list entry accepted for IPv6: a /48.</summary>
    public const int MinIPv6Prefix = 48;

    private static readonly IPNetwork[] PrivateRanges =
    [
        IPNetwork.Parse("10.0.0.0/8"),
        IPNetwork.Parse("172.16.0.0/12"),
        IPNetwork.Parse("192.168.0.0/16"),
        IPNetwork.Parse("100.64.0.0/10"),
        IPNetwork.Parse("fc00::/7")
    ];

    /// <summary>An IPv4-mapped IPv6 address as the IPv4 address it is; anything else unchanged.</summary>
    public static IPAddress Canonical(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    /// <summary>One address as a network of one: /32 or /128.</summary>
    public static IPNetwork Single(IPAddress address)
    {
        var canonical = Canonical(address);
        return new IPNetwork(canonical, canonical.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
    }

    /// <summary>The /24 of an IPv4 address or the /64 of an IPv6 one - the network <c>HOST-AUTH-003</c> counts.</summary>
    public static IPNetwork NetworkOf(IPAddress address)
    {
        var canonical = Canonical(address);
        var prefix = canonical.AddressFamily == AddressFamily.InterNetwork ? 24 : 64;
        return new IPNetwork(Mask(canonical, prefix), prefix);
    }

    /// <summary>
    /// Parses an address or a network written canonically: the address as <see cref="IPAddress.ToString"/>
    /// writes it, and no bit set after the prefix. <c>203.0.113.7/24</c> is refused rather than rounded down
    /// to a different network than the one written.
    /// </summary>
    public static bool TryParseCanonical(string? text, out IPNetwork network)
    {
        network = default;
        if (string.IsNullOrEmpty(text) || text.Length > 64) return false;
        var slash = text.IndexOf('/', StringComparison.Ordinal);
        var host = slash < 0 ? text : text[..slash];
        if (!IPAddress.TryParse(host, out var address) || address.ToString() != host || address.IsIPv4MappedToIPv6) return false;
        var max = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var prefix = max;
        if (slash >= 0 && (!int.TryParse(text[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out prefix) ||
                           prefix < 0 || prefix > max || prefix.ToString(CultureInfo.InvariantCulture) != text[(slash + 1)..]))
            return false;
        if (!Mask(address, prefix).Equals(address)) return false;
        network = new IPNetwork(address, prefix);
        return true;
    }

    /// <summary>The text a decision's target is stored as: an address alone, or a network with its prefix.</summary>
    public static string Text(IPNetwork network) =>
        network.PrefixLength == (network.BaseAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128)
            ? network.BaseAddress.ToString()
            : network.ToString();

    /// <summary>Whether two prefix-aligned networks share any address: one contains the other's base.</summary>
    public static bool Overlaps(IPNetwork a, IPNetwork b) =>
        a.BaseAddress.AddressFamily == b.BaseAddress.AddressFamily && (a.Contains(b.BaseAddress) || b.Contains(a.BaseAddress));

    /// <summary>The private range (RFC 1918, CGNAT 100.64.0.0/10 or ULA fc00::/7) the network lies in, if any.</summary>
    public static IPNetwork? PrivateRangeOf(IPNetwork network)
    {
        foreach (var range in PrivateRanges)
            if (Overlaps(range, network)) return range;
        return null;
    }

    /// <summary>Loopback, link-local or unspecified - addresses that are never an attacker's.</summary>
    public static string? SpecialKind(IPNetwork network)
    {
        var address = network.BaseAddress;
        if (IPAddress.IsLoopback(address)) return "a loopback address";
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return "the unspecified address";
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] == 169 && bytes[1] == 254 ? "a link-local address" : null;
        }
        return address.IsIPv6LinkLocal ? "a link-local address" : null;
    }

    private static IPAddress Mask(IPAddress address, int prefix)
    {
        var bytes = address.GetAddressBytes();
        for (var bit = prefix; bit < bytes.Length * 8; bit++) bytes[bit / 8] &= (byte)~(0x80 >> (bit % 8));
        return new IPAddress(bytes);
    }
}

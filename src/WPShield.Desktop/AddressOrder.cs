using System.Globalization;
using System.Net;
using System.Text;

namespace WPShield.Desktop;

/// <summary>
/// A sort key that orders addresses as numbers, not as text: <c>203.0.113.7</c> before <c>203.0.113.20</c>,
/// IPv4 before IPv6, a network (<c>203.0.113.0/24</c>) where its first address would be. Text that is not an
/// address sorts last, by itself.
/// </summary>
/// <remarks>Sorting the address column as text put <c>.20</c> before <c>.7</c>, which an operator reads as a bug.</remarks>
internal static class AddressOrder
{
    internal static string Key(string? text)
    {
        if (string.IsNullOrEmpty(text)) return "9:";
        var slash = text.IndexOf('/', StringComparison.Ordinal);
        var address = slash < 0 ? text : text[..slash];
        var bits = slash < 0 ? "" : text[(slash + 1)..];
        if (!IPAddress.TryParse(address, out var ip)) return "9:" + text;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        var family = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "4:" : "6:";
        var key = new StringBuilder(family);
        foreach (var b in ip.GetAddressBytes()) key.Append(b.ToString("x2", CultureInfo.InvariantCulture));
        // The single address before its network, and a wider network before a narrower one at the same start.
        key.Append(int.TryParse(bits, NumberStyles.None, CultureInfo.InvariantCulture, out var prefix) ? "/" + prefix.ToString("D3", CultureInfo.InvariantCulture) : "");
        return key.ToString();
    }
}

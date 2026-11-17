using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace WPShield.NetworkFilter;

/// <summary>
/// One address, or one CIDR block, as the operator or a rule named it.
/// </summary>
/// <remarks>
/// <para>
/// Parsing is deliberately strict. <see cref="IPAddress.TryParse(string, out IPAddress)"/> accepts
/// <c>1.2.3</c> as <c>1.2.0.3</c> and <c>0x7f.1</c> as <c>127.0.0.1</c>; on a block list either reading
/// blocks an address the operator did not type. IPv4 must be four decimal octets that print back
/// exactly as written, and a block with host bits set is refused rather than silently widened, because
/// <c>203.0.113.7/24</c> is far more often a typo for one address than a request for 256.
/// </para>
/// <para>
/// A block may not be wider than <c>/16</c> (IPv4) or <c>/48</c> (IPv6), and may not name loopback,
/// unspecified, link-local, multicast or broadcast addresses. An allow-list entry may be any width.
/// </para>
/// </remarks>
public sealed partial class IpRange : IEquatable<IpRange>
{
    public const int WidestIpv4Block = 16;
    public const int WidestIpv6Block = 48;

    private readonly UInt128 _first;
    private readonly UInt128 _last;

    private IpRange(AddressFamily family, UInt128 first, int prefixLength)
    {
        Family = family;
        PrefixLength = prefixLength;
        var hostBits = TotalBits(family) - prefixLength;
        _first = first;
        _last = hostBits == 0 ? first : first | (hostBits == 128 ? UInt128.MaxValue : (UInt128.One << hostBits) - 1);
        First = ToAddress(family, _first);
        Last = ToAddress(family, _last);
    }

    public AddressFamily Family { get; }

    public bool IsIpv6 => Family == AddressFamily.InterNetworkV6;

    public int PrefixLength { get; }

    public bool IsSingleAddress => PrefixLength == TotalBits(Family);

    public IPAddress First { get; }

    public IPAddress Last { get; }

    public static IpRange Single(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        address = Normalize(address);
        return new IpRange(address.AddressFamily, ToNumber(address), TotalBits(address.AddressFamily));
    }

    /// <summary>Parses a block-list entry. Returns false with an operator-facing reason.</summary>
    public static bool TryParseBlock(string? text, out IpRange? range, out string? error) =>
        TryParse(text, forBlock: true, out range, out error);

    /// <summary>Parses an allow-list entry. Any width is accepted.</summary>
    public static bool TryParseAllow(string? text, out IpRange? range, out string? error) =>
        TryParse(text, forBlock: false, out range, out error);

    public bool Contains(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        address = Normalize(address);
        if (address.AddressFamily != Family)
        {
            return false;
        }

        var value = ToNumber(address);
        return value >= _first && value <= _last;
    }

    public bool Overlaps(IpRange other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return other.Family == Family && other._first <= _last && _first <= other._last;
    }

    public bool Covers(IpRange other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return other.Family == Family && _first <= other._first && other._last <= _last;
    }

    /// <summary>The address one below <see cref="First"/>, or null at the bottom of the family.</summary>
    public IPAddress? AddressBefore() => _first == UInt128.Zero ? null : ToAddress(Family, _first - 1);

    /// <summary>The address one above <see cref="Last"/>, or null at the top of the family.</summary>
    public IPAddress? AddressAfter() => _last == MaxValue(Family) ? null : ToAddress(Family, _last + 1);

    public override string ToString() => IsSingleAddress
        ? First.ToString()
        : string.Create(CultureInfo.InvariantCulture, $"{First}/{PrefixLength}");

    public bool Equals(IpRange? other) =>
        other is not null && other.Family == Family && other._first == _first && other.PrefixLength == PrefixLength;

    public override bool Equals(object? obj) => Equals(obj as IpRange);

    public override int GetHashCode() => HashCode.Combine(Family, _first, PrefixLength);

    /// <summary>Orders by family, then by first address, then narrowest first.</summary>
    public static int Compare(IpRange left, IpRange right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        var family = left.Family.CompareTo(right.Family);
        if (family != 0)
        {
            return family;
        }

        var first = left._first.CompareTo(right._first);
        return first != 0 ? first : right.PrefixLength.CompareTo(left.PrefixLength);
    }

    private static bool TryParse(string? text, bool forBlock, out IpRange? range, out string? error)
    {
        range = null;
        error = null;
        var trimmed = text?.Trim();
        if (string.IsNullOrEmpty(trimmed))
        {
            error = "an empty address";
            return false;
        }

        var slash = trimmed.IndexOf('/', StringComparison.Ordinal);
        var addressText = slash < 0 ? trimmed : trimmed[..slash];
        if (!TryParseAddress(addressText, out var address))
        {
            error = $"'{Printable(trimmed)}' is not an IPv4 or IPv6 address in canonical form";
            return false;
        }

        var bits = TotalBits(address.AddressFamily);
        var prefix = bits;
        if (slash >= 0)
        {
            var prefixText = trimmed[(slash + 1)..];
            if (!PrefixPattern().IsMatch(prefixText) ||
                !int.TryParse(prefixText, NumberStyles.None, CultureInfo.InvariantCulture, out prefix) ||
                prefix > bits)
            {
                error = $"'{Printable(trimmed)}' has an invalid prefix length";
                return false;
            }
        }

        var number = ToNumber(address);
        var hostBits = bits - prefix;
        var hostMask = hostBits == 0 ? UInt128.Zero : hostBits == 128 ? UInt128.MaxValue : (UInt128.One << hostBits) - 1;
        if ((number & hostMask) != UInt128.Zero)
        {
            var network = ToAddress(address.AddressFamily, number & ~hostMask);
            error = string.Create(
                CultureInfo.InvariantCulture,
                $"'{Printable(trimmed)}' has host bits set; the block starting there is {network}/{prefix}, and a single address is written without a prefix");
            return false;
        }

        var candidate = new IpRange(address.AddressFamily, number, prefix);
        if (forBlock)
        {
            var widest = candidate.IsIpv6 ? WidestIpv6Block : WidestIpv4Block;
            if (prefix < widest)
            {
                error = string.Create(
                    CultureInfo.InvariantCulture,
                    $"'{candidate}' is wider than /{widest}, the widest block WPShield accepts");
                return false;
            }

            if (IsNeverBlockable(candidate))
            {
                error = $"'{candidate}' is a loopback, unspecified, link-local, multicast or broadcast address and cannot be blocked";
                return false;
            }
        }

        range = candidate;
        return true;
    }

    private static bool TryParseAddress(string text, out IPAddress address)
    {
        address = IPAddress.None;
        if (text.Contains('%', StringComparison.Ordinal))
        {
            return false;
        }

        if (text.Contains(':', StringComparison.Ordinal))
        {
            if (!IPAddress.TryParse(text, out var v6) || v6.AddressFamily != AddressFamily.InterNetworkV6)
            {
                return false;
            }

            address = Normalize(v6);
            return true;
        }

        if (!Ipv4Pattern().IsMatch(text) || !IPAddress.TryParse(text, out var v4) ||
            !string.Equals(v4.ToString(), text, StringComparison.Ordinal))
        {
            return false;
        }

        address = v4;
        return true;
    }

    private static bool IsNeverBlockable(IpRange range)
    {
        foreach (var address in new[] { range.First, range.Last })
        {
            if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) ||
                address.Equals(IPAddress.Broadcast) || address.IsIPv6LinkLocal || address.IsIPv6Multicast)
            {
                return true;
            }

            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                var bytes = address.GetAddressBytes();
                if (bytes[0] == 0 || bytes[0] == 127 || (bytes[0] == 169 && bytes[1] == 254) || bytes[0] >= 224)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static int TotalBits(AddressFamily family) => family == AddressFamily.InterNetworkV6 ? 128 : 32;

    private static UInt128 MaxValue(AddressFamily family) =>
        family == AddressFamily.InterNetworkV6 ? UInt128.MaxValue : uint.MaxValue;

    private static UInt128 ToNumber(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        UInt128 value = UInt128.Zero;
        foreach (var b in bytes)
        {
            value = (value << 8) | b;
        }

        return value;
    }

    private static IPAddress ToAddress(AddressFamily family, UInt128 value)
    {
        var length = family == AddressFamily.InterNetworkV6 ? 16 : 4;
        var bytes = new byte[length];
        for (var index = length - 1; index >= 0; index--)
        {
            bytes[index] = (byte)(value & 0xFF);
            value >>= 8;
        }

        return new IPAddress(bytes);
    }

    /// <summary>Operator text is echoed in errors; keep it printable ASCII and short.</summary>
    private static string Printable(string text)
    {
        var limited = text.Length > 64 ? text[..64] : text;
        return new string(limited.Select(c => c is >= ' ' and <= '~' ? c : '?').ToArray());
    }

    [GeneratedRegex(@"^\d{1,3}(\.\d{1,3}){3}$", RegexOptions.CultureInvariant)]
    private static partial Regex Ipv4Pattern();

    [GeneratedRegex(@"^\d{1,3}$", RegexOptions.CultureInvariant)]
    private static partial Regex PrefixPattern();
}

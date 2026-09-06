using System.Net;
using System.Net.Sockets;

namespace WPShield.Gateway;

/// <summary>
/// The origin WPShield attributes to a request after applying the trusted-proxy policy.
/// </summary>
/// <param name="Address">
/// The client address, or <see langword="null"/> when the connection reported none and no trusted
/// proxy supplied one.
/// </param>
/// <param name="Scheme">
/// The scheme the client used, which under the production traffic path is not the scheme of the
/// local hop: the client speaks HTTPS to IIS and IIS speaks HTTP to the gateway over loopback.
/// </param>
/// <param name="ViaTrustedProxy">
/// Whether these values came from a trusted proxy's forwarding headers rather than from the
/// connection itself.
/// </param>
internal sealed record ResolvedClient(IPAddress? Address, string Scheme, bool ViaTrustedProxy);

/// <summary>
/// Resolves the address and scheme WPShield attributes to a request, honoring forwarding headers
/// only when the connection itself comes from a configured trusted proxy.
/// </summary>
/// <remarks>
/// <para>
/// Through M2 the gateway was the only hop, so every inbound forwarding header was untrusted without
/// exception. ADR 0001 places WPShield behind IIS and ARR, where every request arrives from a local
/// proxy and discarding <c>X-Forwarded-For</c> would make every visitor appear to come from
/// <c>127.0.0.1</c> — per-IP rate limiting would throttle all of them as one, and logged evidence
/// would name the proxy instead of the attacker. More immediately, discarding
/// <c>X-Forwarded-Proto</c> makes WordPress generate <c>http://</c> URLs behind an HTTPS site, which
/// is a redirect loop rather than a subtle degradation.
/// </para>
/// <para>
/// So the invariant becomes conditional, and narrowly: <b>trust forwarding headers only when the peer
/// is a configured trusted proxy, and never otherwise.</b> Trust unlocks exactly two headers,
/// <c>X-Forwarded-For</c> and <c>X-Forwarded-Proto</c>. Everything else in the untrusted set —
/// <c>Forwarded</c>, the client-address family, and the <c>X-Original-URL</c> and
/// <c>X-Rewrite-URL</c> path-override vectors — stays stripped unconditionally, because those are
/// never legitimate from any peer.
/// </para>
/// <para>
/// <b>The rightmost entry wins, and trusted entries are deliberately not skipped.</b> A proxy appends
/// the address it actually saw to the end of the chain, so the rightmost entry is the only one the
/// trusted hop wrote; everything to its left is whatever the client chose to send. The conventional
/// alternative — walking right to left while skipping entries that are themselves trusted proxies —
/// is what creates the classic spoof: a client appends its own trusted-looking entry, the skip logic
/// steps over it, and the attacker pins the resolved address to any value it likes. WPShield's
/// supported topology has exactly one proxy hop on loopback, so there is never a legitimate trusted
/// entry to skip. Multi-hop chains are a later design decision, not an accident of this one.
/// </para>
/// </remarks>
internal static class ClientAddressResolver
{
    /// <summary>
    /// The longest chain entry that is even attempted as an address. The widest legitimate form is a
    /// bracketed IPv6 address with a scope identifier and a port, which stays well inside this, so a
    /// longer entry is padding rather than an address and is not worth parsing.
    /// </summary>
    internal const int MaximumEntryLength = 64;

    internal const string ForwardedForHeaderName = "X-Forwarded-For";
    internal const string ForwardedProtoHeaderName = "X-Forwarded-Proto";

    /// <summary>
    /// Parses the configured trusted proxy addresses into a set the request path can test cheaply.
    /// Entries are normalized exactly as peer addresses are, so an operator who writes
    /// <c>127.0.0.1</c> still matches a dual-stack socket reporting <c>::ffff:127.0.0.1</c>.
    /// </summary>
    /// <remarks>
    /// Unparsable entries are skipped rather than throwing, because
    /// <see cref="GatewayConfigurationValidator"/> has already refused to start on them. This method
    /// is the second line of the same check, not the operator-facing one.
    /// </remarks>
    public static IReadOnlySet<IPAddress> CreateTrustedProxySet(IEnumerable<string>? configured)
    {
        var set = new HashSet<IPAddress>();
        if (configured is null)
        {
            return set;
        }

        foreach (var entry in configured)
        {
            if (!string.IsNullOrWhiteSpace(entry) && IPAddress.TryParse(entry.Trim(), out var address))
            {
                set.Add(Normalize(address)!);
            }
        }

        return set;
    }

    public static ResolvedClient Resolve(HttpContext context, IReadOnlySet<IPAddress> trustedProxies)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(trustedProxies);

        var peer = Normalize(context.Connection.RemoteIpAddress);
        var scheme = context.Request.Scheme;

        // The empty default is the whole safety story: an operator who never configures a trusted
        // proxy keeps the strip-everything behavior WPShield shipped with, so an incomplete
        // configuration fails in the direction that trusts nothing.
        if (trustedProxies.Count == 0 || peer is null || !trustedProxies.Contains(peer))
        {
            return new ResolvedClient(peer, scheme, ViaTrustedProxy: false);
        }

        // Falling back to the peer when a header is absent or unusable is deliberate. It reports the
        // proxy rather than a guess, which is wrong in an obvious and visible way: an operator
        // watching every request arrive from 127.0.0.1 investigates, where an operator watching a
        // plausible but attacker-chosen address does not.
        var address = ResolveForwardedFor(context.Request.Headers[ForwardedForHeaderName].ToString()) ?? peer;
        var forwardedScheme = ResolveForwardedProto(context.Request.Headers[ForwardedProtoHeaderName].ToString()) ?? scheme;

        return new ResolvedClient(address, forwardedScheme, ViaTrustedProxy: true);
    }

    internal static IPAddress? ResolveForwardedFor(string header)
    {
        var entry = LastEntry(header);
        if (entry.IsEmpty || entry.Length > MaximumEntryLength)
        {
            return null;
        }

        // IPEndPoint covers the proxies that append a source port, in both the 203.0.113.5:41234 and
        // the [2001:db8::1]:41234 forms. IPAddress is tried first so that a bare IPv6 address is
        // never mistaken for an address followed by a port.
        if (IPAddress.TryParse(entry, out var address))
        {
            return Normalize(address);
        }

        return IPEndPoint.TryParse(entry, out var endpoint) ? Normalize(endpoint.Address) : null;
    }

    /// <summary>
    /// Resolves the client scheme, returning a canonical literal rather than the received bytes.
    /// </summary>
    /// <remarks>
    /// The resolved value is written straight into the header WordPress reads, so echoing the
    /// received text would forward attacker-controlled bytes into <c>$_SERVER</c> even after the
    /// comparison succeeded. Anything that is not exactly <c>http</c> or <c>https</c> resolves to
    /// nothing, and the connection scheme is used instead.
    /// </remarks>
    internal static string? ResolveForwardedProto(string header)
    {
        var entry = LastEntry(header);

        if (entry.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            return "https";
        }

        return entry.Equals("http", StringComparison.OrdinalIgnoreCase) ? "http" : null;
    }

    /// <summary>
    /// Returns the rightmost comma-separated entry of a header value, trimmed.
    /// </summary>
    /// <remarks>
    /// A header that arrives on several lines is joined with commas, in the order the lines arrived,
    /// before it reaches here, so the rightmost entry of the joined value is the rightmost entry of
    /// the whole chain. A trailing comma leaves an empty entry, which resolves to nothing rather than
    /// reaching further left into whatever the client sent.
    /// </remarks>
    private static ReadOnlySpan<char> LastEntry(string header)
    {
        var span = header.AsSpan();
        var separator = span.LastIndexOf(',');
        return (separator < 0 ? span : span[(separator + 1)..]).Trim();
    }

    /// <summary>
    /// Reduces an address to the form an operator would write in configuration.
    /// </summary>
    /// <remarks>
    /// Two Windows-specific traps live here. A dual-stack Kestrel socket reports an IPv4 peer as the
    /// IPv4-mapped <c>::ffff:127.0.0.1</c>, which is not equal to <c>127.0.0.1</c> under
    /// <see cref="IPAddress.Equals"/>, so an operator's <c>127.0.0.1</c> entry would never match and
    /// the trusted path would silently never engage. An IPv6 address also carries a scope identifier
    /// that participates in equality, so <c>fe80::1%12</c> and <c>fe80::1</c> are different keys.
    /// Both are normalized away, on the configured entries and on the peer alike, so the comparison
    /// is between like and like.
    /// </remarks>
    private static IPAddress? Normalize(IPAddress? address)
    {
        if (address is null)
        {
            return null;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            return address.MapToIPv4();
        }

        return address is { AddressFamily: AddressFamily.InterNetworkV6, ScopeId: not 0 }
            ? new IPAddress(address.GetAddressBytes())
            : address;
    }
}

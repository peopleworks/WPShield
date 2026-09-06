using System.Net;
using Microsoft.AspNetCore.Http;

namespace WPShield.Gateway.Tests;

/// <summary>
/// Covers the trusted-proxy policy at the unit level: which peer earns trust, which header entry is
/// believed, and what happens to everything that does not parse.
/// </summary>
public sealed class ClientAddressResolverTests
{
    [Fact]
    public void Resolve_WithNoTrustedProxies_UsesTheConnectionAndIgnoresHeaders()
    {
        var context = CreateContext(
            peer: "127.0.0.1",
            forwardedFor: "203.0.113.99",
            forwardedProto: "https");

        var resolved = ClientAddressResolver.Resolve(context, TrustedProxies());

        Assert.Equal(IPAddress.Loopback, resolved.Address);
        Assert.Equal("http", resolved.Scheme);
        Assert.False(resolved.ViaTrustedProxy);
    }

    [Fact]
    public void Resolve_WithUntrustedPeer_IgnoresHeadersEvenWhenOtherProxiesAreTrusted()
    {
        var context = CreateContext(
            peer: "198.51.100.7",
            forwardedFor: "203.0.113.99",
            forwardedProto: "https");

        var resolved = ClientAddressResolver.Resolve(context, TrustedProxies("127.0.0.1"));

        Assert.Equal(IPAddress.Parse("198.51.100.7"), resolved.Address);
        Assert.Equal("http", resolved.Scheme);
        Assert.False(resolved.ViaTrustedProxy);
    }

    [Fact]
    public void Resolve_WithTrustedPeer_HonorsForwardedAddressAndScheme()
    {
        var context = CreateContext(
            peer: "127.0.0.1",
            forwardedFor: "203.0.113.99",
            forwardedProto: "https");

        var resolved = ClientAddressResolver.Resolve(context, TrustedProxies("127.0.0.1"));

        Assert.Equal(IPAddress.Parse("203.0.113.99"), resolved.Address);
        Assert.Equal("https", resolved.Scheme);
        Assert.True(resolved.ViaTrustedProxy);
    }

    /// <summary>
    /// The spoof this design exists to refuse. A client that appends the trusted proxy's own address
    /// to its chain is trying to make the resolver step over it and believe the entry to its left.
    /// The rightmost entry is what the trusted hop actually wrote, so that is what wins.
    /// </summary>
    [Fact]
    public void Resolve_WithTrustedProxyAddressAppendedByClient_DoesNotStepOverIt()
    {
        var context = CreateContext(
            peer: "127.0.0.1",
            forwardedFor: "8.8.8.8, 127.0.0.1");

        var resolved = ClientAddressResolver.Resolve(context, TrustedProxies("127.0.0.1"));

        Assert.Equal(IPAddress.Loopback, resolved.Address);
        Assert.NotEqual(IPAddress.Parse("8.8.8.8"), resolved.Address);
    }

    [Fact]
    public void Resolve_WithLongerChain_BelievesOnlyTheRightmostEntry()
    {
        var context = CreateContext(
            peer: "127.0.0.1",
            forwardedFor: "10.0.0.1, 172.16.0.9, 203.0.113.5");

        var resolved = ClientAddressResolver.Resolve(context, TrustedProxies("127.0.0.1"));

        Assert.Equal(IPAddress.Parse("203.0.113.5"), resolved.Address);
    }

    [Theory]
    [InlineData("203.0.113.5:41234", "203.0.113.5")]
    [InlineData("[2001:db8::1]:41234", "2001:db8::1")]
    [InlineData("2001:db8::1", "2001:db8::1")]
    [InlineData("  203.0.113.5  ", "203.0.113.5")]
    public void ResolveForwardedFor_AcceptsTheFormsRealProxiesEmit(string header, string expected)
    {
        Assert.Equal(IPAddress.Parse(expected), ClientAddressResolver.ResolveForwardedFor(header));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("unknown")]
    [InlineData("not-an-address")]
    [InlineData("203.0.113.5,")]
    [InlineData("<script>alert(1)</script>")]
    public void ResolveForwardedFor_RefusesAnythingThatIsNotAnAddress(string header)
    {
        Assert.Null(ClientAddressResolver.ResolveForwardedFor(header));
    }

    /// <summary>
    /// A padded entry is refused before it is parsed rather than after, so a client cannot spend the
    /// gateway's time on a header it engineered to be expensive.
    /// </summary>
    [Fact]
    public void ResolveForwardedFor_RefusesAnOverlongEntry()
    {
        var padded = new string('9', ClientAddressResolver.MaximumEntryLength + 1);

        Assert.Null(ClientAddressResolver.ResolveForwardedFor(padded));
    }

    [Fact]
    public void Resolve_WithUnusableForwardedFor_FallsBackToTheProxyRatherThanGuessing()
    {
        var context = CreateContext(peer: "127.0.0.1", forwardedFor: "unknown");

        var resolved = ClientAddressResolver.Resolve(context, TrustedProxies("127.0.0.1"));

        Assert.Equal(IPAddress.Loopback, resolved.Address);
        Assert.True(resolved.ViaTrustedProxy);
    }

    [Theory]
    [InlineData("https", "https")]
    [InlineData("HTTPS", "https")]
    [InlineData("http", "http")]
    [InlineData("http, https", "https")]
    public void ResolveForwardedProto_ReturnsACanonicalLiteral(string header, string expected)
    {
        Assert.Equal(expected, ClientAddressResolver.ResolveForwardedProto(header));
    }

    [Theory]
    [InlineData("")]
    [InlineData("ftp")]
    [InlineData("https evil")]
    [InlineData("https\r\nX-Injected: 1")]
    public void ResolveForwardedProto_RefusesAnythingElse(string header)
    {
        Assert.Null(ClientAddressResolver.ResolveForwardedProto(header));
    }

    [Fact]
    public void Resolve_WithUnusableForwardedProto_KeepsTheConnectionScheme()
    {
        var context = CreateContext(peer: "127.0.0.1", forwardedProto: "ftp");

        var resolved = ClientAddressResolver.Resolve(context, TrustedProxies("127.0.0.1"));

        Assert.Equal("http", resolved.Scheme);
    }

    /// <summary>
    /// A dual-stack socket reports an IPv4 peer in its IPv4-mapped form, which is not equal to the
    /// plain address an operator writes in configuration. Without normalization the trusted path
    /// would silently never engage on exactly the deployment it was built for.
    /// </summary>
    [Fact]
    public void Resolve_MatchesAnIPv4MappedPeerAgainstAnIPv4ConfigurationEntry()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Loopback.MapToIPv6();
        context.Request.Headers[ClientAddressResolver.ForwardedForHeaderName] = "203.0.113.5";

        var resolved = ClientAddressResolver.Resolve(context, TrustedProxies("127.0.0.1"));

        Assert.True(resolved.ViaTrustedProxy);
        Assert.Equal(IPAddress.Parse("203.0.113.5"), resolved.Address);
    }

    [Fact]
    public void Resolve_MatchesTheIPv6Loopback()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.IPv6Loopback;
        context.Request.Headers[ClientAddressResolver.ForwardedForHeaderName] = "203.0.113.5";

        var resolved = ClientAddressResolver.Resolve(context, TrustedProxies("::1"));

        Assert.True(resolved.ViaTrustedProxy);
        Assert.Equal(IPAddress.Parse("203.0.113.5"), resolved.Address);
    }

    [Fact]
    public void Resolve_WithNoRemoteAddress_TrustsNothing()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers[ClientAddressResolver.ForwardedForHeaderName] = "203.0.113.5";

        var resolved = ClientAddressResolver.Resolve(context, TrustedProxies("127.0.0.1"));

        Assert.Null(resolved.Address);
        Assert.False(resolved.ViaTrustedProxy);
    }

    [Fact]
    public void CreateTrustedProxySet_NormalizesAndDeduplicates()
    {
        var set = ClientAddressResolver.CreateTrustedProxySet(
            ["127.0.0.1", " 127.0.0.1 ", "::ffff:127.0.0.1", "::1"]);

        Assert.Equal(2, set.Count);
        Assert.Contains(IPAddress.Loopback, set);
        Assert.Contains(IPAddress.IPv6Loopback, set);
    }

    [Fact]
    public void CreateTrustedProxySet_WithNoConfiguration_IsEmpty()
    {
        Assert.Empty(ClientAddressResolver.CreateTrustedProxySet(null));
        Assert.Empty(ClientAddressResolver.CreateTrustedProxySet([]));
    }

    private static IReadOnlySet<IPAddress> TrustedProxies(params string[] addresses)
    {
        return ClientAddressResolver.CreateTrustedProxySet(addresses);
    }

    private static DefaultHttpContext CreateContext(
        string peer,
        string? forwardedFor = null,
        string? forwardedProto = null)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(peer);

        // DefaultHttpContext leaves the scheme empty, and the loopback hop is plain HTTP in every
        // deployment this resolver serves, so the connection scheme is set explicitly here.
        context.Request.Scheme = "http";

        if (forwardedFor is not null)
        {
            context.Request.Headers[ClientAddressResolver.ForwardedForHeaderName] = forwardedFor;
        }

        if (forwardedProto is not null)
        {
            context.Request.Headers[ClientAddressResolver.ForwardedProtoHeaderName] = forwardedProto;
        }

        return context;
    }
}

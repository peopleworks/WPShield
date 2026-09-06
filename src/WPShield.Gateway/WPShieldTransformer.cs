using Yarp.ReverseProxy.Forwarder;

namespace WPShield.Gateway;

/// <summary>
/// Replaces every client-supplied forwarding header with values WPShield derived from the actual
/// connection, then stamps the request with a correlation identifier.
/// </summary>
/// <remarks>
/// <para>
/// The threat model requires that untrusted forwarding metadata never reach WordPress. Removing only
/// <c>X-Forwarded-For</c>, <c>-Proto</c> and <c>-Host</c> is not enough: WordPress plugins, IIS URL
/// Rewrite and security tooling read a wider set of headers to determine the client address, and
/// <c>X-Original-URL</c> and <c>X-Rewrite-URL</c> are established authentication-bypass vectors
/// because IIS URL Rewrite treats them as the effective request path.
/// </para>
/// <para>
/// Which values are <i>derived</i> is now decided one step earlier. <see cref="ClientAddressResolver"/>
/// runs at the top of the pipeline and produces a <see cref="ResolvedClient"/>: the connection's own
/// address and scheme when the peer is not a configured trusted proxy — the M1 and M2 behavior,
/// unchanged and still the default — or the values a trusted local proxy forwarded, when it is. This
/// transformer consumes that decision and never makes it, so the headers WordPress receives and the
/// evidence WPShield logs cannot disagree about who sent the request.
/// </para>
/// <para>
/// Trust unlocks exactly two headers. Every name in <see cref="UntrustedClientHeaders"/> and every
/// remaining <c>X-Forwarded-*</c> variant is still removed unconditionally, from every peer,
/// including a trusted one — <c>X-Original-URL</c> and <c>X-Rewrite-URL</c> are authentication-bypass
/// vectors regardless of which hop presents them.
/// </para>
/// </remarks>
public sealed class WPShieldTransformer : HttpTransformer
{
    internal const string RequestIdHeaderName = "X-WPShield-Request-ID";

    private const string ForwardedHeaderPrefix = "X-Forwarded-";

    /// <summary>
    /// Headers an internet client must never influence. Every <c>X-Forwarded-*</c> variant is removed
    /// separately by prefix, so this list covers only the differently named ones.
    /// </summary>
    private static readonly string[] UntrustedClientHeaders =
    [
        // RFC 7239 standard form.
        "Forwarded",

        // Client-address headers honored by common plugins, CDNs and reverse proxies.
        "X-Real-IP",
        "X-Client-IP",
        "X-Cluster-Client-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
        "Fastly-Client-IP",
        "X-Azure-ClientIP",
        "X-Azure-SocketIP",

        // Path-override headers. IIS URL Rewrite and several WordPress security plugins resolve the
        // effective request path from these, which lets a client reach a route the gateway believed
        // it had already evaluated.
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Original-Host",

        // WPShield's own correlation header. A client must not be able to forge or pin it.
        RequestIdHeaderName
    ];

    public override async ValueTask TransformRequestAsync(
        HttpContext httpContext,
        HttpRequestMessage proxyRequest,
        string destinationPrefix,
        CancellationToken cancellationToken)
    {
        await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix, cancellationToken);

        proxyRequest.Headers.Host = httpContext.Request.Host.Value;

        RemoveUntrustedHeaders(proxyRequest);

        // The fallback is not defensive noise. It covers a pipeline where the resolving middleware
        // never ran - a transformer exercised directly by a test, or a future reordering - and it
        // falls back to the connection itself, which is the answer that trusts nothing.
        var client = httpContext.Features.Get<ResolvedClient>()
            ?? new ResolvedClient(
                httpContext.Connection.RemoteIpAddress,
                httpContext.Request.Scheme,
                ViaTrustedProxy: false);

        var remoteIp = client.Address?.ToString();
        if (!string.IsNullOrWhiteSpace(remoteIp))
        {
            proxyRequest.Headers.TryAddWithoutValidation("X-Forwarded-For", remoteIp);
        }

        proxyRequest.Headers.TryAddWithoutValidation("X-Forwarded-Proto", client.Scheme);
        proxyRequest.Headers.TryAddWithoutValidation("X-Forwarded-Host", httpContext.Request.Host.Value);
        proxyRequest.Headers.TryAddWithoutValidation(RequestIdHeaderName, httpContext.TraceIdentifier);
    }

    /// <summary>
    /// Strips untrusted headers before WPShield adds its own, so the sweep cannot remove the trusted
    /// values this transformer just produced.
    /// </summary>
    private static void RemoveUntrustedHeaders(HttpRequestMessage proxyRequest)
    {
        foreach (var name in UntrustedClientHeaders)
        {
            proxyRequest.Headers.Remove(name);
        }

        // Remove every remaining X-Forwarded-* variant, including ones this project has not seen.
        // The collection cannot be modified while it is being enumerated.
        List<string>? forwardedHeaders = null;
        foreach (var header in proxyRequest.Headers)
        {
            if (header.Key.StartsWith(ForwardedHeaderPrefix, StringComparison.OrdinalIgnoreCase))
            {
                (forwardedHeaders ??= []).Add(header.Key);
            }
        }

        if (forwardedHeaders is null)
        {
            return;
        }

        foreach (var name in forwardedHeaders)
        {
            proxyRequest.Headers.Remove(name);
        }
    }
}

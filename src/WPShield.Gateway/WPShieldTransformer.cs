using Yarp.ReverseProxy.Forwarder;

namespace WPShield.Gateway;

public sealed class WPShieldTransformer : HttpTransformer
{
    public override async ValueTask TransformRequestAsync(
        HttpContext httpContext,
        HttpRequestMessage proxyRequest,
        string destinationPrefix,
        CancellationToken cancellationToken)
    {
        await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix, cancellationToken);

        proxyRequest.Headers.Host = httpContext.Request.Host.Value;
        proxyRequest.Headers.Remove("X-Forwarded-For");
        proxyRequest.Headers.Remove("X-Forwarded-Proto");
        proxyRequest.Headers.Remove("X-Forwarded-Host");

        var remoteIp = httpContext.Connection.RemoteIpAddress?.ToString();
        if (!string.IsNullOrWhiteSpace(remoteIp))
        {
            proxyRequest.Headers.TryAddWithoutValidation("X-Forwarded-For", remoteIp);
        }

        proxyRequest.Headers.TryAddWithoutValidation("X-Forwarded-Proto", httpContext.Request.Scheme);
        proxyRequest.Headers.TryAddWithoutValidation("X-Forwarded-Host", httpContext.Request.Host.Value);

        var requestId = httpContext.TraceIdentifier;
        proxyRequest.Headers.Remove("X-WPShield-Request-ID");
        proxyRequest.Headers.TryAddWithoutValidation("X-WPShield-Request-ID", requestId);
    }
}

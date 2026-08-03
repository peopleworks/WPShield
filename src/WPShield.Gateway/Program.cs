using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text.Json.Serialization;
using WPShield.Core;
using WPShield.Gateway;
using Yarp.ReverseProxy.Forwarder;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.Sources.Clear();
builder.Configuration
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddEnvironmentVariables(prefix: "WPSHIELD_")
    .AddCommandLine(args);

builder.Services.Configure<GatewayOptions>(builder.Configuration.GetSection("Gateway"));
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddHttpForwarder();

var sites = builder.Configuration.GetSection("Sites").Get<SiteOptions[]>() ?? [];
var resolver = new SiteResolver(sites);
builder.Services.AddSingleton(resolver);
builder.Services.AddSingleton<IReadOnlyList<SiteOptions>>(sites);
builder.Services.AddSingleton<WPShieldTransformer>();

var gatewayOptions = builder.Configuration.GetSection("Gateway").Get<GatewayOptions>() ?? new GatewayOptions();
if (gatewayOptions.Urls.Length == 0)
{
    throw new InvalidOperationException("Gateway:Urls must contain at least one loopback URL.");
}

foreach (var url in gatewayOptions.Urls)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || !IPAddress.TryParse(uri.Host, out var ip) || !IPAddress.IsLoopback(ip))
    {
        throw new InvalidOperationException($"M1 laboratory gateway may listen only on a loopback IP. Invalid URL: '{url}'.");
    }
}

builder.WebHost.UseUrls(gatewayOptions.Urls);

var app = builder.Build();

var httpClient = new HttpMessageInvoker(new SocketsHttpHandler
{
    UseProxy = false,
    AllowAutoRedirect = false,
    AutomaticDecompression = DecompressionMethods.None,
    UseCookies = false,
    EnableMultipleHttp2Connections = true,
    ActivityHeadersPropagator = new ReverseProxyPropagator(DistributedContextPropagator.Current),
    ConnectTimeout = TimeSpan.FromSeconds(10)
});

var requestConfig = new ForwarderRequestConfig
{
    ActivityTimeout = TimeSpan.FromSeconds(Math.Clamp(gatewayOptions.ActivityTimeoutSeconds, 10, 300))
};

app.Use(async (context, next) =>
{
    context.TraceIdentifier = Guid.NewGuid().ToString("N");
    context.Response.Headers["X-WPShield-Request-ID"] = context.TraceIdentifier;
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    await next();
});

app.MapGet("/_wpshield/health/live", (HttpContext context) =>
{
    if (!HealthAccess.IsAllowed(context, gatewayOptions)) return Results.NotFound();
    return Results.Ok(new { status = "live", service = "WPShield.Gateway" });
});

app.MapGet("/_wpshield/health/ready", (HttpContext context, IReadOnlyList<SiteOptions> configuredSites) =>
{
    if (!HealthAccess.IsAllowed(context, gatewayOptions)) return Results.NotFound();
    return configuredSites.Count == 0
        ? Results.Json(new { status = "not-ready", reason = "No sites configured." }, statusCode: 503)
        : Results.Ok(new { status = "ready", sites = configuredSites.Count });
});

app.MapFallback(async (
    HttpContext context,
    SiteResolver siteResolver,
    IHttpForwarder forwarder,
    WPShieldTransformer transformer,
    ILoggerFactory loggerFactory) =>
{
    var logger = loggerFactory.CreateLogger("WPShield.Gateway.Request");
    var host = context.Request.Host.Host;
    var site = siteResolver.Resolve(host);

    if (site is null)
    {
        logger.LogWarning("Unknown host rejected. RequestId={RequestId} Host={Host} Method={Method} Path={Path}",
            context.TraceIdentifier, host, context.Request.Method, context.Request.Path.Value);
        context.Response.StatusCode = StatusCodes.Status421MisdirectedRequest;
        await context.Response.WriteAsJsonAsync(new
        {
            error = "unknown_host",
            requestId = context.TraceIdentifier
        });
        return;
    }

    if (site.Mode == ProtectionMode.Disabled)
    {
        logger.LogInformation("Site protection disabled; request forwarded. RequestId={RequestId} SiteId={SiteId}",
            context.TraceIdentifier, site.Id);
    }

    logger.LogInformation("Request forwarding. RequestId={RequestId} SiteId={SiteId} Method={Method} Path={Path}",
        context.TraceIdentifier, site.Id, context.Request.Method, context.Request.Path.Value);

    var error = await forwarder.SendAsync(
        context,
        site.Destination.ToString().TrimEnd('/') + "/",
        httpClient,
        requestConfig,
        transformer);

    if (error != ForwarderError.None)
    {
        var feature = context.GetForwarderErrorFeature();
        logger.LogError(feature?.Exception,
            "Proxy failure. RequestId={RequestId} SiteId={SiteId} Error={Error}",
            context.TraceIdentifier, site.Id, error);
    }
});

app.Run();

internal static class HealthAccess
{
    public static bool IsAllowed(HttpContext context, GatewayOptions options)
    {
        return options.AllowRemoteHealthChecks ||
               (context.Connection.RemoteIpAddress is { } ip && IPAddress.IsLoopback(ip));
    }
}

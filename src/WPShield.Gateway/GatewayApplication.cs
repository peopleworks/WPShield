using System.Diagnostics;
using System.Net;
using System.Text.Json.Serialization;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WPShield.Core;
using Yarp.ReverseProxy.Forwarder;

namespace WPShield.Gateway;

public static class GatewayApplication
{
    public static WebApplication Build(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Configuration.Sources.Clear();
        builder.Configuration
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .AddEnvironmentVariables(prefix: "WPSHIELD_")
            .AddCommandLine(args);

        return Build(builder);
    }

    public static WebApplication Build(WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var gatewayOptions = builder.Configuration.GetSection("Gateway").Get<GatewayOptions>() ?? new GatewayOptions();
        var sites = builder.Configuration.GetSection("Sites").Get<SiteOptions[]>() ?? [];
        GatewayConfigurationValidator.Validate(gatewayOptions, sites);

        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
        builder.Logging.AddFilter("Yarp.ReverseProxy", LogLevel.Warning);
        builder.Services.Configure<GatewayOptions>(builder.Configuration.GetSection("Gateway"));
        builder.Services.ConfigureHttpJsonOptions(options =>
            options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
        builder.Services.AddHttpForwarder();
        builder.Services.AddSingleton(new SiteResolver(sites));
        builder.Services.AddSingleton<IReadOnlyList<SiteOptions>>(sites);
        builder.Services.AddSingleton<WPShieldTransformer>();
        builder.Services.TryAddSingleton(_ => CreateProxyClient());

        builder.WebHost.UseUrls(gatewayOptions.Urls);

        var app = builder.Build();
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
            return Results.Ok(new { status = "ready", sites = configuredSites.Count });
        });

        // Reserve the complete health namespace locally, including unsupported methods and unknown probes.
        app.Map("/_wpshield/health/{**path}", () => Results.NotFound());

        app.MapFallback(ForwardRequestAsync);

        return app;

        async Task ForwardRequestAsync(
            HttpContext context,
            SiteResolver siteResolver,
            IHttpForwarder forwarder,
            HttpMessageInvoker httpClient,
            WPShieldTransformer transformer,
            ILoggerFactory loggerFactory)
        {
            var logger = loggerFactory.CreateLogger("WPShield.Gateway.Request");
            var host = context.Request.Host.Host;
            var site = siteResolver.Resolve(host);

            if (site is null)
            {
                logger.LogWarning(
                    "Unknown host rejected. RequestId={RequestId} Host={Host} Method={Method} Path={Path}",
                    context.TraceIdentifier,
                    host,
                    context.Request.Method,
                    context.Request.Path.Value);
                context.Response.StatusCode = StatusCodes.Status421MisdirectedRequest;
                await context.Response.WriteAsJsonAsync(new
                {
                    error = "unknown_host",
                    requestId = context.TraceIdentifier
                }, context.RequestAborted);
                return;
            }

            if (site.Mode == ProtectionMode.Disabled)
            {
                logger.LogInformation(
                    "Site protection disabled; request forwarded. RequestId={RequestId} SiteId={SiteId}",
                    context.TraceIdentifier,
                    site.Id);
            }

            logger.LogInformation(
                "Request forwarding. RequestId={RequestId} SiteId={SiteId} Method={Method} Path={Path}",
                context.TraceIdentifier,
                site.Id,
                context.Request.Method,
                context.Request.Path.Value);

            var error = await forwarder.SendAsync(
                context,
                site.Destination.ToString().TrimEnd('/') + "/",
                httpClient,
                requestConfig,
                transformer);

            if (error == ForwarderError.None)
            {
                return;
            }

            logger.LogError(
                "Proxy failure. RequestId={RequestId} SiteId={SiteId} Error={Error}",
                context.TraceIdentifier,
                site.Id,
                error);

            if (context.Response.HasStarted)
            {
                return;
            }

            context.Response.Clear();
            context.Response.StatusCode = StatusCodes.Status502BadGateway;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "backend_unavailable",
                requestId = context.TraceIdentifier
            }, context.RequestAborted);
        }
    }

    private static HttpMessageInvoker CreateProxyClient()
    {
        return new HttpMessageInvoker(new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            EnableMultipleHttp2Connections = true,
            ActivityHeadersPropagator = new ReverseProxyPropagator(DistributedContextPropagator.Current),
            ConnectTimeout = TimeSpan.FromSeconds(10)
        });
    }
}

internal static class HealthAccess
{
    public static bool IsAllowed(HttpContext context, GatewayOptions options)
    {
        return options.AllowRemoteHealthChecks ||
               (context.Connection.RemoteIpAddress is { } ip && IPAddress.IsLoopback(ip));
    }
}

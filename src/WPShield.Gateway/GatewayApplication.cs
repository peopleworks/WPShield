using System.Diagnostics;
using System.Net;
using System.Text.Json.Serialization;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting.WindowsServices;
using WPShield.Abstractions;
using WPShield.Core;
using WPShield.Gateway.Logging;
using WPShield.Rules.WordPress;
using Yarp.ReverseProxy.Forwarder;

namespace WPShield.Gateway;

public static class GatewayApplication
{
    /// <summary>
    /// The service name WPShield registers under, and the source name its Windows Event Log entries
    /// carry. The installation script uses the same literal.
    /// </summary>
    public const string WindowsServiceName = "WPShield";

    public static WebApplication Build(string[] args)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            // A Windows service starts with the current directory set to C:\Windows\System32, not to
            // the directory the executable lives in. Pinning the content root here rather than
            // letting UseWindowsService do it later is what keeps the two agreeing: the host refuses
            // a content root that changes after the builder exists, so setting it up front is the
            // only order in which both calls can succeed. Outside a service this stays null and the
            // ordinary console behaviour is untouched.
            ContentRootPath = WindowsServiceHelpers.IsWindowsService() ? AppContext.BaseDirectory : null
        });

        // A complete no-op unless the process really was started by the service control manager, so
        // console runs, the test host and `dotnet run` are unaffected. When it is a service it
        // installs the lifetime that answers stop and shutdown requests, and adds the Windows Event
        // Log as a second destination — which matters because a service has no console to write to,
        // and a gateway that fails to start would otherwise fail invisibly.
        builder.Host.UseWindowsService(options => options.ServiceName = WindowsServiceName);

        builder.Configuration.Sources.Clear();
        builder.Configuration
            .SetBasePath(AppContext.BaseDirectory)
            // Reload is intentionally disabled. Gateway and site options are validated once and
            // captured for the lifetime of the process, so a watched file would silently promise
            // hot reload that never happens. Restart the gateway to apply configuration changes.
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
            // Operator overlay with real hostnames and destinations. Absent from the repository.
            .AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: false)
            .AddEnvironmentVariables(prefix: "WPSHIELD_")
            .AddCommandLine(args);

        return Build(builder);
    }

    public static WebApplication Build(WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var gatewayOptions = builder.Configuration.GetSection("Gateway").Get<GatewayOptions>() ?? new GatewayOptions();

        // Bound once, validated once, used once. Re-binding Gateway:Multipart into a second
        // instance would create two objects that are equal today and could differ after any future
        // edit, and the one that got validated would not provably be the one that runs.
        var multipartOptions = gatewayOptions.Multipart;
        var sites = builder.Configuration.GetSection("Sites").Get<SiteOptions[]>() ?? [];
        GatewayConfigurationValidator.Validate(gatewayOptions, multipartOptions, sites);

        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
        builder.Logging.AddFilter("Yarp.ReverseProxy", LogLevel.Warning);

        // Attached before the host is built, because a configuration failure here must stop startup
        // rather than produce a gateway that runs with nowhere to record what it did.
        var logDirectory = builder.AddJsonLinesFileLogging();
        builder.Services.Configure<GatewayOptions>(builder.Configuration.GetSection("Gateway"));
        builder.Services.ConfigureHttpJsonOptions(options =>
            options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
        builder.Services.AddHttpForwarder();
        builder.Services.AddSingleton(new SiteResolver(sites));
        builder.Services.AddSingleton<IReadOnlyList<SiteOptions>>(sites);
        builder.Services.AddSingleton(multipartOptions);
        builder.Services.AddSingleton<WPShieldTransformer>();
        builder.Services.TryAddSingleton(_ => CreateProxyClient());

        RegisterInspection(builder.Services);

        builder.WebHost.ConfigureKestrel(options =>
            options.Limits.MaxRequestBodySize = GatewayOptions.AbsoluteMaximumRequestBytes);
        builder.WebHost.UseUrls(gatewayOptions.Urls);

        var app = builder.Build();
        var loggerFactory = app.Services.GetRequiredService<ILoggerFactory>();
        LogLogDestination(loggerFactory, logDirectory);
        LogResolvedSites(loggerFactory, sites);
        LogInspectionConfiguration(loggerFactory, gatewayOptions, multipartOptions);

        // Parsed once at startup rather than per request. The validator has already refused to start
        // on anything that is not an exact IP address, so every entry that reaches here parses.
        var trustedProxies = ClientAddressResolver.CreateTrustedProxySet(gatewayOptions.TrustedProxies);
        LogTrustedProxies(loggerFactory, trustedProxies);

        // Captured rather than injected as a route-handler parameter, for the same reason
        // gatewayOptions is: it is a process-lifetime singleton, and capturing it keeps the
        // signature of the fallback handler down to what actually varies per request.
        var inspectionService = app.Services.GetRequiredService<UploadInspectionService>();

        var requestConfig = new ForwarderRequestConfig
        {
            ActivityTimeout = TimeSpan.FromSeconds(Math.Clamp(gatewayOptions.ActivityTimeoutSeconds, 1, 300))
        };

        app.Use(async (context, next) =>
        {
            context.TraceIdentifier = Guid.NewGuid().ToString("N");
            context.Response.Headers["X-WPShield-Request-ID"] = context.TraceIdentifier;
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";

            // Resolved here, at the very top, so that every later stage - the request log, the
            // refusal log, the forwarded headers - reads one answer instead of each deriving its
            // own. Two components that resolve the client independently will eventually disagree,
            // and a security tool whose evidence contradicts what it forwarded is worse than one
            // that resolves the client badly but consistently.
            context.Features.Set(ClientAddressResolver.Resolve(context, trustedProxies));

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

        // The pattern is explicit because the MapFallback default is "{*path:nonfile}", and the
        // nonfile constraint rejects any path whose last segment contains a dot. That default is
        // written for single-page applications, where a request for a real file should 404 rather
        // than be answered with index.html. In a reverse proxy it is catastrophic and silent:
        // /wp-login.php, /wp-admin/async-upload.php, /index.php and every .css, .js and .jpg
        // returned 404 from WPShield instead of reaching WordPress, while extensionless routes such
        // as /wp-admin/ worked — which is exactly why the existing test suite, whose paths are all
        // extensionless, never caught it. Measured on this build before the fix: GET /wp-login.php
        // returned 404 with the backend untouched, GET /wp-login returned 200.
        //
        // It also mattered specifically for M2. WordPress uploads post to
        // /wp-admin/async-upload.php, so with the constrained pattern the inspection step below
        // could never have run on a single real upload no matter how correctly it was wired.
        app.MapFallback("{*path}", ForwardRequestAsync);

        return app;

        async Task ForwardRequestAsync(
            HttpContext context,
            SiteResolver siteResolver,
            IHttpForwarder forwarder,
            HttpMessageInvoker httpClient,
            WPShieldTransformer transformer,
            ILoggerFactory requestLoggerFactory)
        {
            var logger = requestLoggerFactory.CreateLogger("WPShield.Gateway.Request");
            var host = context.Request.Host.Host;
            var site = siteResolver.Resolve(host);

            // The same resolved value the transformer forwards, so an operator comparing a WPShield
            // log line with a WordPress access log entry sees one address, not two.
            var client = context.Features.Get<ResolvedClient>()?.Address?.ToString() ?? "unknown";

            if (site is null)
            {
                logger.LogWarning(
                    "Unknown host rejected. RequestId={RequestId} Client={Client} Host={Host} Method={Method} Path={Path}",
                    context.TraceIdentifier,
                    client,
                    host,
                    context.Request.Method,
                    context.Request.Path.Value);
                await WriteGatewayErrorAsync(context, StatusCodes.Status421MisdirectedRequest, "unknown_host");
                return;
            }

            if (context.Request.ContentLength > gatewayOptions.MaximumRequestBytes)
            {
                logger.LogWarning(
                    "Request rejected because its declared size exceeds the safety limit. RequestId={RequestId} SiteId={SiteId} DeclaredBytes={DeclaredBytes} LimitBytes={LimitBytes}",
                    context.TraceIdentifier,
                    site.Id,
                    context.Request.ContentLength,
                    gatewayOptions.MaximumRequestBytes);
                await WriteRequestTooLargeAsync(context);
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
                "Request forwarding. RequestId={RequestId} SiteId={SiteId} Client={Client} Method={Method} Path={Path}",
                context.TraceIdentifier,
                site.Id,
                client,
                context.Request.Method,
                context.Request.Path.Value);

            ForwarderError error;
            PooledRequestBuffer? buffer = null;
            var originalBody = context.Request.Body;
            try
            {
                // The limit stream is installed here, before the inspection step rather than
                // immediately before the forward as it used to be. That order is the point: the
                // drain into the pooled buffer must itself be bounded, or a chunked body declaring
                // no Content-Length would be buffered without a limit — the exact hole this stream
                // exists to close.
                context.Request.Body = new RequestBodyLimitStream(
                    originalBody,
                    gatewayOptions.MaximumRequestBytes);

                var decision = await inspectionService.EvaluateAsync(
                    context,
                    site,
                    gatewayOptions,
                    multipartOptions,
                    logger,
                    context.RequestAborted);
                buffer = decision.Body;

                if (decision.Rejection is { } rejection)
                {
                    await WriteGatewayErrorAsync(
                        context,
                        rejection.StatusCode,
                        rejection.Error,
                        rejection.Reason,
                        rejection.RuleIds.Count == 0 ? null : rejection.RuleIds);
                    return;
                }

                if (buffer is not null)
                {
                    // The stage rewinds too. Repeated here because this assignment is what decides
                    // what WordPress actually receives, and a buffer forwarded from a non-zero
                    // position is a silently truncated upload.
                    buffer.Position = 0;
                    context.Request.Body = buffer;
                }

                error = await forwarder.SendAsync(
                    context,
                    site.Destination.ToString().TrimEnd('/') + "/",
                    httpClient,
                    requestConfig,
                    transformer);
            }
            catch (RequestBodyTooLargeException)
            {
                // Reached only from the buffered path: the body crossed the limit while being
                // drained, before the forwarder was called. That is strictly better than the
                // streamed case below, where a bounded prefix has already reached the backend by
                // the time the overflow is detected. Here nothing was forwarded at all.
                logger.LogWarning(
                    "Request rejected after its streamed body exceeded the safety limit. RequestId={RequestId} SiteId={SiteId} LimitBytes={LimitBytes}",
                    context.TraceIdentifier,
                    site.Id,
                    gatewayOptions.MaximumRequestBytes);
                await WriteRequestTooLargeAsync(context);
                return;
            }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
            {
                // A deliberate, narrow exception to the rule that cancellation is never swallowed.
                // This is the top of the request pipeline: there is no caller left to observe the
                // exception, and rethrowing turns an entirely ordinary client abort — a visitor who
                // closed the tab mid-upload — into an unhandled-exception Error line in a component
                // whose Error level should mean "the gateway is broken". The filter is what keeps it
                // narrow: a read-deadline cancellation does not match here and is handled as a
                // timeout. Nothing is written, because the connection is already gone.
                logger.LogInformation(
                    "Client disconnected before the request could be forwarded. RequestId={RequestId} SiteId={SiteId} BufferedBytes={BufferedBytes}",
                    context.TraceIdentifier,
                    site.Id,
                    buffer?.Length ?? 0);
                return;
            }
            finally
            {
                context.Request.Body = originalBody;
                buffer?.Dispose();
            }

            if (error == ForwarderError.None)
            {
                return;
            }

            var forwarderException = context.GetForwarderErrorFeature()?.Exception;
            if (IsRequestTooLarge(forwarderException))
            {
                logger.LogWarning(
                    "Request rejected after its streamed body exceeded the safety limit. RequestId={RequestId} SiteId={SiteId} LimitBytes={LimitBytes}",
                    context.TraceIdentifier,
                    site.Id,
                    gatewayOptions.MaximumRequestBytes);
                await WriteRequestTooLargeAsync(context);
                return;
            }

            logger.LogError(
                "Proxy failure. RequestId={RequestId} SiteId={SiteId} Error={Error}",
                context.TraceIdentifier,
                site.Id,
                error);

            await WriteGatewayErrorAsync(context, StatusCodes.Status502BadGateway, "backend_unavailable");
        }

        static bool IsRequestTooLarge(Exception? exception)
        {
            while (exception is not null)
            {
                if (exception is RequestBodyTooLargeException)
                {
                    return true;
                }

                if (exception is BadHttpRequestException
                    {
                        StatusCode: StatusCodes.Status413PayloadTooLarge
                    })
                {
                    return true;
                }

                exception = exception.InnerException;
            }

            return false;
        }

        static Task WriteRequestTooLargeAsync(HttpContext context)
        {
            return WriteGatewayErrorAsync(context, StatusCodes.Status413PayloadTooLarge, "request_too_large");
        }
    }

    /// <summary>
    /// Writes every response WPShield generates itself, so the header set exists in one place.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This also fixes a real bug rather than replicating it.</b> <c>HttpResponse.Clear()</c> is
    /// an extension method that clears the status code, the reason phrase <i>and the headers</i>.
    /// The 413 and 502 writers both called it, which wiped the <c>X-WPShield-Request-ID</c> and
    /// <c>X-Content-Type-Options</c> headers the first middleware had already set — so those two
    /// responses carried neither, contradicting the documented promise that <i>every</i> response,
    /// forwarded or generated, carries both. The 421 path never called <c>Clear()</c> and was
    /// unaffected, which is exactly why the inconsistency survived: the difference was invisible
    /// unless you compared two failure responses side by side.
    /// </para>
    /// <para>
    /// <c>Cache-Control: no-store</c> is new to all of them. A refusal depends on the request body,
    /// and no intermediary should ever serve a cached 403 for a different body. <c>Retry-After</c>
    /// is deliberately absent: it implies the refusal is transient and invites a retry loop against
    /// a decision that will not change.
    /// </para>
    /// <para>
    /// The <c>HasStarted</c> guard replaces the checks the individual call sites used to make. A
    /// response that has already begun cannot be rewritten, and attempting it throws on top of
    /// whatever went wrong first.
    /// </para>
    /// </remarks>
    private static async Task WriteGatewayErrorAsync(
        HttpContext context,
        int statusCode,
        string error,
        string? reason = null,
        IReadOnlyList<string>? ruleIds = null)
    {
        if (context.Response.HasStarted)
        {
            return;
        }

        context.Response.Clear();
        context.Response.StatusCode = statusCode;
        context.Response.Headers["X-WPShield-Request-ID"] = context.TraceIdentifier;
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers.CacheControl = "no-store";
        await context.Response.WriteAsJsonAsync(
            new GatewayErrorResponse(error, context.TraceIdentifier, reason, ruleIds),
            context.RequestAborted);
    }

    /// <summary>
    /// Registers the inspection engine and the complete shipped rule set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every registration here is a singleton, and that is a claim about the code rather than a
    /// performance choice: no shipped rule holds a mutable instance field — the only fields are
    /// <c>const</c> and the extension tables are <c>FrozenSet</c> — so a single instance is safe to
    /// share across concurrent requests. <see cref="InspectionEngine"/> copies its rules into an
    /// array in its constructor and keeps no per-request state, and the reader and the inspection
    /// service keep every piece of state in a local. If a future rule needs per-request state, it
    /// belongs in <see cref="InspectionContext"/>, not in a field.
    /// </para>
    /// <para>
    /// The order of the rule registrations is the order the engine evaluates them, and it does not
    /// affect the outcome: the engine sums every finding rather than stopping at the first, so the
    /// list is grouped for a human reader — WordPress name rules, then IIS rules, then general name
    /// rules, then content rules.
    /// </para>
    /// </remarks>
    private static void RegisterInspection(IServiceCollection services)
    {
        services.AddSingleton<IInspectionRule, ExecutableUploadExtensionRule>();
        services.AddSingleton<IInspectionRule, DisguisedExtensionRule>();
        services.AddSingleton<IInspectionRule, IisExecutableUploadRule>();
        services.AddSingleton<IInspectionRule, IisConfigurationUploadRule>();
        services.AddSingleton<IInspectionRule, UnsafeFileNameRule>();
        services.AddSingleton<IInspectionRule, PhpContentInUploadRule>();
        services.AddSingleton<IInspectionRule, FileTypeMismatchRule>();
        services.AddSingleton<IInspectionRule, PhpPolyglotUploadRule>();
        services.AddSingleton<InspectionEngine>();
        services.AddSingleton<MultipartInspectionReader>();
        services.AddSingleton<UploadInspectionService>();
    }

    /// <summary>
    /// Reports the site table the gateway actually resolved. JSON configuration providers merge
    /// arrays element by element, so an operator overlay that declares fewer sites than the shipped
    /// example leaves the surplus example entries active. Printing the resolved table at startup
    /// makes that mistake visible immediately instead of at the first misrouted request.
    /// Destinations are loopback-validated before this runs, so they carry no sensitive topology.
    /// </summary>
    private static void LogResolvedSites(ILoggerFactory loggerFactory, IReadOnlyList<SiteOptions> sites)
    {
        var logger = loggerFactory.CreateLogger("WPShield.Gateway.Configuration");
        logger.LogInformation("Gateway configuration resolved {SiteCount} site(s).", sites.Count);

        foreach (var site in sites)
        {
            logger.LogInformation(
                "Configured site. SiteId={SiteId} Hosts={Hosts} Destination={Destination} Mode={Mode}",
                site.Id,
                string.Join(", ", site.Hosts),
                site.Destination,
                site.Mode);
        }
    }

    /// <summary>
    /// Reports the inspection bounds the gateway will actually enforce.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The disabled case is logged at Warning on purpose. A gateway with multipart inspection
    /// switched off is a reverse proxy with a size limit — which is a legitimate operator decision
    /// during an incident, and exactly the state nobody should be able to end up in without
    /// noticing.
    /// </para>
    /// <para>
    /// The sample-versus-body-limit line is the one configuration mismatch the validator
    /// deliberately does not throw on. A sample larger than any request the gateway will accept is
    /// harmless — the reader fills what exists and stops — and a deliberately tiny
    /// <c>MaximumRequestBytes</c> is a legitimate configuration, so refusing to start would turn a
    /// no-op over-specification into an outage. Saying so at startup is the honest middle.
    /// </para>
    /// </remarks>
    private static void LogInspectionConfiguration(
        ILoggerFactory loggerFactory,
        GatewayOptions gatewayOptions,
        MultipartInspectionOptions multipartOptions)
    {
        var logger = loggerFactory.CreateLogger("WPShield.Gateway.Configuration");

        if (!multipartOptions.Enabled)
        {
            logger.LogWarning(
                "Multipart upload inspection is DISABLED by configuration. No upload rule will run on live traffic.");
            return;
        }

        logger.LogInformation(
            "Multipart upload inspection enabled. MaximumRequestBytes={MaximumRequestBytes} MaximumFileCount={MaximumFileCount} MaximumFieldCount={MaximumFieldCount} MaximumPartHeaderBytes={MaximumPartHeaderBytes} SampleBytes={SampleBytes} ReadTimeoutSeconds={ReadTimeoutSeconds}",
            gatewayOptions.MaximumRequestBytes,
            multipartOptions.MaximumFileCount,
            multipartOptions.MaximumFieldCount,
            multipartOptions.MaximumPartHeaderBytes,
            multipartOptions.SampleBytes,
            multipartOptions.ReadTimeoutSeconds);

        if (multipartOptions.SampleBytes > gatewayOptions.MaximumRequestBytes)
        {
            logger.LogWarning(
                "Gateway:Multipart:SampleBytes ({SampleBytes}) exceeds Gateway:MaximumRequestBytes ({MaximumRequestBytes}), so the configured sample size can never be reached.",
                multipartOptions.SampleBytes,
                gatewayOptions.MaximumRequestBytes);
        }
    }

    /// <summary>
    /// Reports where the log is being written, or that it is not being written anywhere.
    /// </summary>
    /// <remarks>
    /// The absent case is a Warning, and it is the reason this method exists. Monitor mode produces
    /// exactly one artefact - the log - so a gateway running in Monitor with no file destination is
    /// observing traffic and telling nobody. Under a Windows service there is no console either, so
    /// the only remaining channel is the Windows Event Log at Warning and above. Saying so on the way
    /// up is cheaper than an operator discovering it a week into a rollout with nothing to review.
    /// </remarks>
    private static void LogLogDestination(ILoggerFactory loggerFactory, string? logDirectory)
    {
        var logger = loggerFactory.CreateLogger("WPShield.Gateway.Configuration");

        if (logDirectory is null)
        {
            logger.LogWarning(
                "File logging is disabled. Nothing the gateway observes is recorded to disk; under a Windows service the only remaining destination is the Windows Event Log. Set Logging:File:Enabled to true.");
            return;
        }

        logger.LogInformation("Writing JSON Lines log files. Directory={Directory}", logDirectory);
    }

    /// <summary>
    /// Reports whose forwarding headers the gateway will honor.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both states are printed, because both are wrong somewhere. An empty list is correct for the
    /// loopback laboratory and wrong behind IIS, where it attributes every visitor to the proxy and
    /// tells WordPress the request arrived over HTTP; a populated list is correct behind IIS and
    /// over-trusting anywhere the named peer is not actually a proxy. An operator cannot tell which
    /// state they are in from behavior alone until traffic is already flowing, so the gateway says so
    /// at startup next to the resolved site table.
    /// </para>
    /// <para>
    /// A non-loopback entry is reported at Warning rather than refused. It is provably dead
    /// configuration - <c>ValidateListeners</c> permits loopback listeners only, so no other peer can
    /// ever connect - and dead configuration is exactly the kind of thing that gets copied forward
    /// into the deployment where it would matter. Refusing to start would follow the wrong precedent:
    /// this is an over-specification with no effect, like a sample larger than the request limit, not
    /// a safety ceiling being lifted.
    /// </para>
    /// </remarks>
    private static void LogTrustedProxies(ILoggerFactory loggerFactory, IReadOnlySet<IPAddress> trustedProxies)
    {
        var logger = loggerFactory.CreateLogger("WPShield.Gateway.Configuration");

        if (trustedProxies.Count == 0)
        {
            logger.LogInformation(
                "No trusted proxies configured. Every inbound forwarding header is stripped and each request is attributed to the address that connected. Behind IIS this reports the proxy rather than the visitor; see Gateway:TrustedProxies.");
            return;
        }

        logger.LogInformation(
            "Trusted proxies configured. X-Forwarded-For and X-Forwarded-Proto are honored from these peers only. TrustedProxies={TrustedProxies}",
            string.Join(", ", trustedProxies.Select(address => address.ToString())));

        foreach (var address in trustedProxies.Where(address => !IPAddress.IsLoopback(address)))
        {
            logger.LogWarning(
                "Gateway:TrustedProxies contains a non-loopback address that can never match, because the gateway accepts loopback connections only. TrustedProxy={TrustedProxy}",
                address);
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

/// <summary>
/// The body of every response WPShield generates itself.
/// </summary>
/// <remarks>
/// <para>
/// What is absent matters more than what is present. No raw file name — attacker-controlled bytes
/// must never be reflected into a body a browser dev tool, a log viewer or a future dashboard will
/// render. No normalized name either: safer, but still derived from attacker input and worth
/// nothing to whoever sent the request. No sample, no evidence, no field name, no site identifier,
/// no destination.
/// </para>
/// <para>
/// And above all, <b>no score and no thresholds</b>. That is the real oracle. A binary allow/deny
/// forces an attacker to search blind, while a numeric score turns evasion into hill-climbing
/// because every mutation reports how much closer it got. <see cref="RuleIds"/> is disclosed for
/// the opposite reason: the complete rule catalogue, with identifiers, scores and matching logic,
/// is already published in this repository, so withholding the identifiers protects nothing an
/// attacker cannot read — while the cost of withholding falls entirely on a site owner staring at
/// an opaque refusal, which is how a security tool gets switched off. Disclose what is published;
/// withhold what is derived. Should WPShield ever gain non-public rules, that trade must be
/// revisited for those rules specifically.
/// </para>
/// </remarks>
internal sealed record GatewayErrorResponse(
    string Error,
    string RequestId,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Reason,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<string>? RuleIds);

internal static class HealthAccess
{
    public static bool IsAllowed(HttpContext context, GatewayOptions options)
    {
        return options.AllowRemoteHealthChecks ||
               (context.Connection.RemoteIpAddress is { } ip && IPAddress.IsLoopback(ip));
    }
}

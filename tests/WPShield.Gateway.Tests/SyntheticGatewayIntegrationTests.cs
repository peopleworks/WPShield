using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace WPShield.Gateway.Tests;

public sealed class SyntheticGatewayIntegrationTests
{
    [Fact]
    public async Task ConfiguredHosts_ReachOnlyTheirAssignedBackends()
    {
        await using var harness = await SyntheticGatewayHarness.StartAsync();

        using var siteOneResponse = await harness.SendAsync("site-one.test", HttpMethod.Get, "/one");
        using var siteTwoResponse = await harness.SendAsync("site-two.test", HttpMethod.Get, "/two");

        Assert.Equal(HttpStatusCode.OK, siteOneResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, siteTwoResponse.StatusCode);
        var siteOneRequest = Assert.Single(harness.SiteOne.Requests);
        var siteTwoRequest = Assert.Single(harness.SiteTwo.Requests);
        Assert.Equal("site-one", siteOneRequest.Backend);
        Assert.Equal("/one", siteOneRequest.PathAndQuery);
        Assert.Equal("site-two", siteTwoRequest.Backend);
        Assert.Equal("/two", siteTwoRequest.PathAndQuery);
    }

    [Fact]
    public async Task UnknownHost_Returns421AndReachesNoBackend()
    {
        await using var harness = await SyntheticGatewayHarness.StartAsync();

        using var response = await harness.SendAsync("unknown.test", HttpMethod.Get, "/");

        Assert.Equal((HttpStatusCode)421, response.StatusCode);
        Assert.Empty(harness.SiteOne.Requests);
        Assert.Empty(harness.SiteTwo.Requests);
    }

    [Fact]
    public async Task Forwarding_ReplacesSpoofedHeadersAndPreservesRequestData()
    {
        await using var harness = await SyntheticGatewayHarness.StartAsync();
        using var request = harness.CreateRequest(
            "site-one.test",
            HttpMethod.Post,
            "/wp-json/synthetic?mode=safe&item=42");
        request.Headers.Add("X-Forwarded-For", "203.0.113.99");
        request.Headers.Add("X-Forwarded-Proto", "https");
        request.Headers.Add("X-Forwarded-Host", "spoofed.example");
        request.Headers.Add("X-WPShield-Request-ID", "spoofed-request-id");

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var recorded = Assert.Single(harness.SiteOne.Requests);
        Assert.Equal("POST", recorded.Method);
        Assert.Equal("/wp-json/synthetic?mode=safe&item=42", recorded.PathAndQuery);
        Assert.Equal("http", recorded.ForwardedProto);
        Assert.Equal("site-one.test", recorded.ForwardedHost);
        Assert.NotEqual("203.0.113.99", recorded.ForwardedFor);
        Assert.True(IPAddress.TryParse(recorded.ForwardedFor, out var forwardedAddress));
        Assert.True(IPAddress.IsLoopback(forwardedAddress));
        Assert.NotEqual("spoofed-request-id", recorded.RequestId);
        Assert.Equal(response.Headers.GetValues("X-WPShield-Request-ID").Single(), recorded.RequestId);
        Assert.Empty(harness.SiteTwo.Requests);
    }

    /// <summary>
    /// Every header in this list lets a client influence how WordPress, IIS URL Rewrite or a security
    /// plugin perceives the request origin or the effective path. None may survive the gateway.
    /// </summary>
    private static readonly string[] UntrustedClientHeaders =
    [
        "Forwarded",
        "X-Real-IP",
        "X-Client-IP",
        "X-Cluster-Client-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
        "Fastly-Client-IP",
        "X-Azure-ClientIP",
        "X-Azure-SocketIP",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Original-Host",
        "X-Forwarded-Port",
        "X-Forwarded-Server",
        "X-Forwarded-Prefix",
        "X-Forwarded-Scheme",
        "X-Forwarded-Ssl",
        "X-Forwarded-AnythingElse"
    ];

    [Fact]
    public async Task Forwarding_RemovesEveryUntrustedClientHeader()
    {
        const string attackerValue = "attacker-controlled";
        await using var harness = await SyntheticGatewayHarness.StartAsync();
        using var request = harness.CreateRequest("site-one.test", HttpMethod.Get, "/wp-admin/");

        foreach (var header in UntrustedClientHeaders)
        {
            Assert.True(
                request.Headers.TryAddWithoutValidation(header, attackerValue),
                $"Test could not send '{header}'.");
        }

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var recorded = Assert.Single(harness.SiteOne.Requests);

        foreach (var header in UntrustedClientHeaders)
        {
            Assert.False(
                recorded.Headers.ContainsKey(header),
                $"'{header}' reached the backend with the client-supplied value.");
        }
    }

    /// <summary>
    /// <c>X-Original-URL</c> deserves its own assertion. IIS URL Rewrite resolves the effective
    /// request path from it, so a surviving value would let a client reach a route the gateway
    /// believed it had already evaluated.
    /// </summary>
    [Theory]
    [InlineData("X-Original-URL")]
    [InlineData("X-Rewrite-URL")]
    public async Task PathOverrideHeaders_CannotRedirectTheBackendRoute(string header)
    {
        await using var harness = await SyntheticGatewayHarness.StartAsync();
        using var request = harness.CreateRequest("site-one.test", HttpMethod.Get, "/harmless");
        request.Headers.TryAddWithoutValidation(header, "/wp-admin/users.php");

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var recorded = Assert.Single(harness.SiteOne.Requests);
        Assert.Equal("/harmless", recorded.PathAndQuery);
        Assert.False(recorded.Headers.ContainsKey(header));
    }

    [Fact]
    public async Task Forwarding_ReplacesRatherThanRemovesTheTrustedForwardingHeaders()
    {
        await using var harness = await SyntheticGatewayHarness.StartAsync();
        using var request = harness.CreateRequest("site-one.test", HttpMethod.Get, "/");
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", "203.0.113.99");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Host", "spoofed.example");

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var recorded = Assert.Single(harness.SiteOne.Requests);
        Assert.True(IPAddress.TryParse(recorded.ForwardedFor, out var forwarded));
        Assert.True(IPAddress.IsLoopback(forwarded));
        Assert.Equal("http", recorded.ForwardedProto);
        Assert.Equal("site-one.test", recorded.ForwardedHost);
    }

    /// <summary>
    /// The production traffic path, proved on real traffic: the connection is loopback, the peer is a
    /// configured trusted proxy, and what reaches WordPress is the visitor's address and the
    /// visitor's scheme rather than the local hop's.
    /// </summary>
    /// <remarks>
    /// The scheme half is what keeps two live sites working. IIS terminates TLS and speaks plain HTTP
    /// to the gateway over loopback, so without an honored <c>X-Forwarded-Proto</c> WordPress decides
    /// it was reached over HTTP and generates <c>http://</c> canonical URLs, redirects and login
    /// targets behind an HTTPS site — a redirect loop, not a subtle degradation.
    /// </remarks>
    [Fact]
    public async Task TrustedProxy_ForwardsTheClientAddressAndSchemeItSupplied()
    {
        await using var harness = await SyntheticGatewayHarness.StartAsync(
            trustedProxies: ["127.0.0.1", "::1"]);
        using var request = harness.CreateRequest("site-one.test", HttpMethod.Get, "/wp-admin/");
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", "203.0.113.99");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var recorded = Assert.Single(harness.SiteOne.Requests);
        Assert.Equal("203.0.113.99", recorded.ForwardedFor);
        Assert.Equal("https", recorded.ForwardedProto);
        Assert.Equal("site-one.test", recorded.ForwardedHost);
    }

    /// <summary>
    /// The spoof the rightmost-entry rule refuses, proved end to end. A client that appends the
    /// trusted proxy's own address to its chain is trying to make the resolver step over that entry
    /// and believe the one to its left.
    /// </summary>
    [Fact]
    public async Task TrustedProxy_DoesNotBelieveAnEntryLeftOfTheOneTheProxyWrote()
    {
        await using var harness = await SyntheticGatewayHarness.StartAsync(
            trustedProxies: ["127.0.0.1", "::1"]);
        using var request = harness.CreateRequest("site-one.test", HttpMethod.Get, "/");
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", "8.8.8.8, 127.0.0.1");

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var recorded = Assert.Single(harness.SiteOne.Requests);
        Assert.NotEqual("8.8.8.8", recorded.ForwardedFor);
        Assert.True(IPAddress.TryParse(recorded.ForwardedFor, out var forwarded));
        Assert.True(IPAddress.IsLoopback(forwarded));
    }

    /// <summary>
    /// Trust unlocks two headers and no more. Everything an attacker could use to change the
    /// perceived origin or the effective path is still removed, including from a trusted peer.
    /// </summary>
    [Fact]
    public async Task TrustedProxy_StillRemovesEveryOtherUntrustedHeader()
    {
        const string attackerValue = "attacker-controlled";
        await using var harness = await SyntheticGatewayHarness.StartAsync(
            trustedProxies: ["127.0.0.1", "::1"]);
        using var request = harness.CreateRequest("site-one.test", HttpMethod.Get, "/wp-admin/");
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", "203.0.113.99");

        foreach (var header in UntrustedClientHeaders)
        {
            request.Headers.TryAddWithoutValidation(header, attackerValue);
        }

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var recorded = Assert.Single(harness.SiteOne.Requests);
        Assert.Equal("203.0.113.99", recorded.ForwardedFor);

        foreach (var header in UntrustedClientHeaders)
        {
            Assert.False(
                recorded.Headers.ContainsKey(header),
                $"'{header}' reached the backend from a trusted peer.");
        }
    }

    /// <summary>
    /// Configuring a trusted proxy trusts that peer and no other. A gateway listing some other
    /// address must behave exactly as one listing none.
    /// </summary>
    [Fact]
    public async Task UnlistedPeer_KeepsTheStripEverythingBehavior()
    {
        await using var harness = await SyntheticGatewayHarness.StartAsync(
            trustedProxies: ["203.0.113.1"]);
        using var request = harness.CreateRequest("site-one.test", HttpMethod.Get, "/");
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", "203.0.113.99");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var recorded = Assert.Single(harness.SiteOne.Requests);
        Assert.NotEqual("203.0.113.99", recorded.ForwardedFor);
        Assert.True(IPAddress.TryParse(recorded.ForwardedFor, out var forwarded));
        Assert.True(IPAddress.IsLoopback(forwarded));
        Assert.Equal("http", recorded.ForwardedProto);
    }

    // =================================================================================================
    // Request-path inspection, on real traffic
    // =================================================================================================

    /// <summary>
    /// The webshell shapes recovered from a real compromise, refused before anything reads a body.
    /// </summary>
    /// <remarks>
    /// These are ordinary <c>GET</c> requests with no body at all, which is exactly why the upload
    /// rules could never have seen them: a shell already on disk is fetched, not uploaded. Reduced to
    /// their directory structure — no hostname, no client address, no payload.
    /// </remarks>
    [Theory]
    [InlineData("/wp-content/uploads/2021/02/tuto1.php", "WP-PATH-001")]
    [InlineData("/wp-content/plugins/exampleslider/static/codemirror/addon/display/index.php", "WP-PATH-002")]
    [InlineData("/wp-content/plugins/exampleslider/static/exampleslider/skins/lightskin/terms.php", "WP-PATH-002")]
    public async Task BlockMode_RefusesAWebshellRequestAndReachesNoBackend(string path, string expectedRuleId)
    {
        await using var harness = await SyntheticGatewayHarness.StartAsync(siteMode: "Block");

        using var response = await harness.SendAsync("site-one.test", HttpMethod.Get, path);
        var content = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("\"error\":\"request_blocked\"", content, StringComparison.Ordinal);
        Assert.Contains(expectedRuleId, content, StringComparison.Ordinal);

        // The whole point of deciding from the request line: WordPress never saw it.
        Assert.Empty(harness.SiteOne.Requests);
        Assert.Empty(harness.SiteTwo.Requests);
    }

    /// <summary>
    /// Monitor is the default and it forwards. The finding is recorded; the request is not refused.
    /// </summary>
    [Fact]
    public async Task MonitorMode_ForwardsAWebshellRequestRatherThanRefusingIt()
    {
        await using var harness = await SyntheticGatewayHarness.StartAsync();

        using var response = await harness.SendAsync(
            "site-one.test", HttpMethod.Get, "/wp-content/uploads/2021/02/tuto1.php");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var recorded = Assert.Single(harness.SiteOne.Requests);
        Assert.Equal("/wp-content/uploads/2021/02/tuto1.php", recorded.PathAndQuery);
    }

    /// <summary>
    /// The refusal discloses the rule identifiers and nothing else. The complete catalogue is
    /// published in this repository, so withholding the identifiers protects nothing an attacker
    /// cannot read — while the score and the thresholds stay hidden, because a number turns evasion
    /// into hill-climbing.
    /// </summary>
    [Fact]
    public async Task BlockedRequest_DisclosesRuleIdsButNeitherScoreNorThresholds()
    {
        await using var harness = await SyntheticGatewayHarness.StartAsync(siteMode: "Block");

        using var response = await harness.SendAsync(
            "site-one.test", HttpMethod.Get, "/wp-content/uploads/shell.php");
        var content = await response.Content.ReadAsStringAsync();

        Assert.Contains("WP-PATH-001", content, StringComparison.Ordinal);
        Assert.DoesNotContain("score", content, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("threshold", content, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.True(response.Headers.Contains("X-WPShield-Request-ID"));
    }

    /// <summary>
    /// Ordinary WordPress traffic is untouched in Block mode, which is the assertion that decides
    /// whether this rule family can be switched on at all.
    /// </summary>
    [Theory]
    [InlineData("/")]
    [InlineData("/wp-login.php")]
    [InlineData("/wp-admin/admin-ajax.php")]
    [InlineData("/wp-json/wp/v2/posts")]
    [InlineData("/wp-content/uploads/2026/09/photo.jpg")]
    [InlineData("/wp-content/plugins/elementor/assets/js/frontend.min.js")]
    [InlineData("/wp-content/themes/example/style.css")]
    public async Task BlockMode_LeavesOrdinaryTrafficAlone(string path)
    {
        await using var harness = await SyntheticGatewayHarness.StartAsync(siteMode: "Block");

        using var response = await harness.SendAsync("site-one.test", HttpMethod.Get, path);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(harness.SiteOne.Requests);
    }

    /// <summary>
    /// A site an operator has switched off is forwarded untouched, path rules included. Disabled has
    /// to mean disabled, or the escape hatch is not one.
    /// </summary>
    [Fact]
    public async Task DisabledSite_ForwardsEvenAWebshellRequest()
    {
        await using var harness = await SyntheticGatewayHarness.StartAsync(siteMode: "Disabled");

        using var response = await harness.SendAsync(
            "site-one.test", HttpMethod.Get, "/wp-content/uploads/shell.php");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(harness.SiteOne.Requests);
    }

    [Fact]
    public async Task SlowBackend_ReturnsPrivacySafe502AfterConfiguredTimeout()
    {
        await using var harness = await SyntheticGatewayHarness.StartAsync(activityTimeoutSeconds: 1);
        var stopwatch = Stopwatch.StartNew();

        using var response = await harness.SendAsync("site-one.test", HttpMethod.Get, "/slow");
        var content = await response.Content.ReadAsStringAsync();

        stopwatch.Stop();
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.Contains("\"error\":\"backend_unavailable\"", content, StringComparison.Ordinal);
        Assert.DoesNotContain(harness.SiteOne.Address.ToString(), content, StringComparison.Ordinal);
        Assert.DoesNotContain("TaskCanceledException", content, StringComparison.Ordinal);
        Assert.InRange(stopwatch.Elapsed, TimeSpan.FromMilliseconds(500), TimeSpan.FromSeconds(4));
    }

    [Fact]
    public async Task HealthEndpoints_RemainLocalAndReachNoBackend()
    {
        await using var harness = await SyntheticGatewayHarness.StartAsync();

        using var live = await harness.SendAsync("site-one.test", HttpMethod.Get, "/_wpshield/health/live");
        using var ready = await harness.SendAsync("site-two.test", HttpMethod.Get, "/_wpshield/health/ready");
        using var unknown = await harness.SendAsync("site-one.test", HttpMethod.Get, "/_wpshield/health/unknown");

        Assert.Equal(HttpStatusCode.OK, live.StatusCode);
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Empty(harness.SiteOne.Requests);
        Assert.Empty(harness.SiteTwo.Requests);
    }

    private sealed class SyntheticGatewayHarness : IAsyncDisposable
    {
        private readonly WebApplication _gateway;

        private SyntheticGatewayHarness(
            WebApplication gateway,
            HttpClient client,
            SyntheticBackend siteOne,
            SyntheticBackend siteTwo)
        {
            _gateway = gateway;
            Client = client;
            SiteOne = siteOne;
            SiteTwo = siteTwo;
        }

        public HttpClient Client { get; }
        public SyntheticBackend SiteOne { get; }
        public SyntheticBackend SiteTwo { get; }

        public static async Task<SyntheticGatewayHarness> StartAsync(
            int activityTimeoutSeconds = 10,
            string[]? trustedProxies = null,
            string siteMode = "Monitor")
        {
            var siteOne = await SyntheticBackend.StartAsync("site-one");
            SyntheticBackend? siteTwo = null;
            WebApplication? gateway = null;

            try
            {
                siteTwo = await SyntheticBackend.StartAsync("site-two");
                var builder = WebApplication.CreateBuilder(new WebApplicationOptions
                {
                    EnvironmentName = "Testing"
                });
                builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
                builder.Configuration.Sources.Clear();
                var settings = new Dictionary<string, string?>
                {
                    ["Gateway:Urls:0"] = "http://127.0.0.1:0",
                    ["Gateway:AllowRemoteHealthChecks"] = "false",
                    ["Gateway:ActivityTimeoutSeconds"] = activityTimeoutSeconds.ToString(),
                    ["Sites:0:Id"] = "site-one",
                    ["Sites:0:Hosts:0"] = "site-one.test",
                    ["Sites:0:Destination"] = siteOne.Address.ToString(),
                    ["Sites:0:Mode"] = siteMode,
                    ["Sites:0:ObserveThreshold"] = "30",
                    ["Sites:0:BlockThreshold"] = "80",
                    ["Sites:1:Id"] = "site-two",
                    ["Sites:1:Hosts:0"] = "site-two.test",
                    ["Sites:1:Destination"] = siteTwo.Address.ToString(),
                    ["Sites:1:Mode"] = siteMode,
                    ["Sites:1:ObserveThreshold"] = "30",
                    ["Sites:1:BlockThreshold"] = "80"
                };

                for (var index = 0; index < (trustedProxies?.Length ?? 0); index++)
                {
                    settings[$"Gateway:TrustedProxies:{index}"] = trustedProxies![index];
                }

                builder.Configuration.AddInMemoryCollection(settings);

                gateway = GatewayApplication.Build(builder);
                await gateway.StartAsync();
                var address = GetBoundAddress(gateway);
                var client = new HttpClient { BaseAddress = address };
                return new SyntheticGatewayHarness(gateway, client, siteOne, siteTwo);
            }
            catch
            {
                if (gateway is not null)
                {
                    await gateway.DisposeAsync();
                }

                if (siteTwo is not null)
                {
                    await siteTwo.DisposeAsync();
                }

                await siteOne.DisposeAsync();
                throw;
            }
        }

        public HttpRequestMessage CreateRequest(string host, HttpMethod method, string pathAndQuery)
        {
            var request = new HttpRequestMessage(method, pathAndQuery);
            request.Headers.Host = host;
            return request;
        }

        public Task<HttpResponseMessage> SendAsync(string host, HttpMethod method, string pathAndQuery)
        {
            return Client.SendAsync(CreateRequest(host, method, pathAndQuery));
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await _gateway.DisposeAsync();
            await SiteTwo.DisposeAsync();
            await SiteOne.DisposeAsync();
        }
    }

    private sealed class SyntheticBackend : IAsyncDisposable
    {
        private readonly WebApplication _application;
        private readonly ConcurrentQueue<SyntheticRequest> _requests = new();

        private SyntheticBackend(WebApplication application, string name, Uri address)
        {
            _application = application;
            Name = name;
            Address = address;
        }

        public string Name { get; }
        public Uri Address { get; }
        public IReadOnlyCollection<SyntheticRequest> Requests => _requests;

        public static async Task<SyntheticBackend> StartAsync(string name)
        {
            var builder = WebApplication.CreateSlimBuilder();
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
            var application = builder.Build();
            SyntheticBackend? backend = null;

            // The pattern is explicit for the same reason it is explicit in GatewayApplication, and
            // this is the second place the same default caused the same blind spot. MapFallback's
            // default is "{**path:nonfile}", whose nonfile constraint rejects any path whose last
            // segment contains a dot — so this synthetic backend answered 404 to /wp-login.php,
            // /style.css and every image, while extensionless routes worked. Every path in the suite
            // was extensionless, so nothing noticed: the harness could not have exercised a dotted
            // path even after the gateway itself was fixed.
            application.MapFallback("{*path}", async context =>
            {
                var request = new SyntheticRequest(
                    name,
                    context.Request.Method,
                    context.Request.Path + context.Request.QueryString,
                    context.Request.Headers["X-Forwarded-For"].ToString(),
                    context.Request.Headers["X-Forwarded-Proto"].ToString(),
                    context.Request.Headers["X-Forwarded-Host"].ToString(),
                    context.Request.Headers["X-WPShield-Request-ID"].ToString(),
                    context.Request.Headers.ToDictionary(
                        header => header.Key,
                        header => header.Value.ToString(),
                        StringComparer.OrdinalIgnoreCase));
                backend!._requests.Enqueue(request);

                if (context.Request.Path == "/slow")
                {
                    await Task.Delay(TimeSpan.FromSeconds(10), context.RequestAborted);
                    return;
                }

                await context.Response.WriteAsJsonAsync(new
                {
                    backend = name,
                    request.Method,
                    request.PathAndQuery,
                    request.RequestId
                }, context.RequestAborted);
            });

            await application.StartAsync();
            var address = GetBoundAddress(application);
            backend = new SyntheticBackend(application, name, address);
            return backend;
        }

        public ValueTask DisposeAsync()
        {
            return _application.DisposeAsync();
        }
    }

    private sealed record SyntheticRequest(
        string Backend,
        string Method,
        string PathAndQuery,
        string ForwardedFor,
        string ForwardedProto,
        string ForwardedHost,
        string RequestId,
        IReadOnlyDictionary<string, string> Headers);

    private static Uri GetBoundAddress(WebApplication application)
    {
        var addresses = application.Services
            .GetRequiredService<IServer>()
            .Features
            .Get<IServerAddressesFeature>()?
            .Addresses;
        var address = Assert.Single(addresses ?? []);
        var uri = new Uri(address);
        Assert.DoesNotContain(uri.Port, new[] { 80, 443, 8081, 8082, 10000 });
        Assert.True(IPAddress.TryParse(uri.Host, out var ipAddress));
        Assert.True(IPAddress.IsLoopback(ipAddress));
        return uri;
    }
}

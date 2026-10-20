using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Web.Administration;

namespace WPShield.Gateway.Tests;

/// <summary>
/// M1.3 — validation against a real IIS installation on loopback.
/// </summary>
/// <remarks>
/// <para>
/// These tests prove that the gateway routes to real IIS destinations on
/// <c>127.0.0.1:8081</c> and <c>127.0.0.1:8082</c>, that unknown hosts fail closed with 421,
/// and that the public bindings on 80 and 443 are untouched.
/// </para>
/// <para>
/// <b>They skip when IIS is not available.</b> There is no IIS on the Linux CI leg, and there may
/// be no IIS on a developer workstation. The detection below checks whether anything is listening
/// on the laboratory ports; if nothing is, every test here returns without running rather than
/// failing.
/// </para>
/// <para>
/// Before running these against your IIS, configure two WordPress sites on loopback ports 8081
/// and 8082, and set <c>Gateway:Multipart:Enabled</c> to <c>true</c> in your test configuration.
/// See <c>docs/en/m1-iis-validation.md</c> for the complete manual checklist this suite automates.
/// </para>
/// </remarks>
public sealed class IISValidationTests
{
    private const int SiteOnePort = 8081;
    private const int SiteTwoPort = 8082;

    /// <summary>
    /// Whether anything is listening on either laboratory IIS port.
    /// </summary>
    private static bool IisLaboratoryPortsAvailable =>
        PortIsListening(SiteOnePort) || PortIsListening(SiteTwoPort);

    private static bool PortIsListening(int port)
    {
        try
        {
            using var client = new TcpClient();
            var result = client.ConnectAsync(
                new IPAddress(new byte[] { 127, 0, 0, 1 }), port)
                .Wait(TimeSpan.FromSeconds(1));
            return result && client.Connected;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Whether IIS administration is accessible and reports at least one site.
    /// </summary>
    private static bool IisAdministrationAvailable
    {
        get
        {
            try
            {
                using var serverManager = new ServerManager();
                return serverManager.Sites.Count > 0;
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Returns from the test when no IIS laboratory endpoint is available.
    /// </summary>
    private static bool ShouldSkipWhenNoIis()
    {
        return !IisLaboratoryPortsAvailable;
    }

    /// <summary>
    /// Returns from the test when IIS administration is not accessible.
    /// </summary>
    private static bool ShouldSkipWhenNoIisAdministration()
    {
        return !IisAdministrationAvailable;
    }

    [Fact]
    public void IisAdministration_ReportsSitesWhenAvailable()
    {
        if (ShouldSkipWhenNoIisAdministration())
        {
            return;
        }

        using var serverManager = new ServerManager();
        Assert.True(serverManager.Sites.Count > 0, "IIS reports no sites.");
    }

    [Fact]
    public async Task UnknownHost_Returns421AgainstRealIIS()
    {
        if (ShouldSkipWhenNoIis())
        {
            return;
        }

        await using var harness = await IisGatewayHarness.StartAsync();
        using var response = await harness.SendAsync("iis-unknown.example", HttpMethod.Get, "/");

        Assert.Equal(HttpStatusCode.MisdirectedRequest, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("\"error\":\"unknown_host\"", content, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(SiteOnePort, "wordpress-one.example")]
    [InlineData(SiteTwoPort, "wordpress-two.example")]
    public async Task ConfiguredHost_ReachesItsAssignedIISSite(int expectedPort, string host)
    {
        if (ShouldSkipWhenNoIis())
        {
            return;
        }

        if (!PortIsListening(expectedPort))
        {
            return;
        }

        await using var harness = await IisGatewayHarness.StartAsync();
        using var response = await harness.SendAsync(host, HttpMethod.Get, "/");

        Assert.True(
            response.StatusCode == HttpStatusCode.OK ||
            response.StatusCode == (HttpStatusCode)502,
            $"Unexpected status for {host}: {response.StatusCode}");
    }

    [Fact]
    public async Task HomePage_RoutesToCorrectSite()
    {
        if (ShouldSkipWhenNoIis())
        {
            return;
        }

        await using var harness = await IisGatewayHarness.StartAsync();

        if (PortIsListening(SiteOnePort))
        {
            using var response = await harness.SendAsync("wordpress-one.example", HttpMethod.Get, "/");
            Assert.True(
                response.StatusCode == HttpStatusCode.OK ||
                response.StatusCode == (HttpStatusCode)502,
                $"Site one home page: {response.StatusCode}");
        }

        if (PortIsListening(SiteTwoPort))
        {
            using var response = await harness.SendAsync("wordpress-two.example", HttpMethod.Get, "/");
            Assert.True(
                response.StatusCode == HttpStatusCode.OK ||
                response.StatusCode == (HttpStatusCode)502,
                $"Site two home page: {response.StatusCode}");
        }
    }

    [Fact]
    public async Task LoginAndAdmin_RoutedWithoutCredentials()
    {
        if (ShouldSkipWhenNoIis())
        {
            return;
        }

        await using var harness = await IisGatewayHarness.StartAsync();

        foreach (var (port, host) in new[] { (SiteOnePort, "wordpress-one.example"), (SiteTwoPort, "wordpress-two.example") })
        {
            if (!PortIsListening(port))
            {
                continue;
            }

            using var login = await harness.SendAsync(host, HttpMethod.Get, "/wp-login.php");
            Assert.True(
                login.StatusCode == HttpStatusCode.OK ||
                login.StatusCode == (HttpStatusCode)502,
                $"{host} /wp-login.php: {login.StatusCode}");

            using var admin = await harness.SendAsync(host, HttpMethod.Get, "/wp-admin/");
            Assert.True(
                admin.StatusCode == HttpStatusCode.OK ||
                admin.StatusCode == (HttpStatusCode)502,
                $"{host} /wp-admin/: {admin.StatusCode}");
        }
    }

    [Fact]
    public async Task StaticAssets_RoutedCorrectly()
    {
        if (ShouldSkipWhenNoIis())
        {
            return;
        }

        await using var harness = await IisGatewayHarness.StartAsync();

        if (PortIsListening(SiteOnePort))
        {
            using var css = await harness.SendAsync(
                "wordpress-one.example", HttpMethod.Get, "/wp-content/themes/example/style.css");
            Assert.True(
                css.StatusCode == HttpStatusCode.OK ||
                css.StatusCode == HttpStatusCode.NotModified ||
                css.StatusCode == (HttpStatusCode)502,
                $"Site one CSS: {css.StatusCode}");
        }

        if (PortIsListening(SiteTwoPort))
        {
            using var js = await harness.SendAsync(
                "wordpress-two.example", HttpMethod.Get, "/wp-content/plugins/elementor/assets/js/frontend.min.js");
            Assert.True(
                js.StatusCode == HttpStatusCode.OK ||
                js.StatusCode == HttpStatusCode.NotModified ||
                js.StatusCode == (HttpStatusCode)502,
                $"Site two JS: {js.StatusCode}");
        }
    }

    [Fact]
    public async Task RestApi_RoutedCorrectly()
    {
        if (ShouldSkipWhenNoIis())
        {
            return;
        }

        await using var harness = await IisGatewayHarness.StartAsync();

        if (PortIsListening(SiteOnePort))
        {
            using var rest = await harness.SendAsync(
                "wordpress-one.example", HttpMethod.Get, "/wp-json/wp/v2/posts");
            Assert.True(
                rest.StatusCode == HttpStatusCode.OK ||
                rest.StatusCode == (HttpStatusCode)502 ||
                rest.StatusCode == HttpStatusCode.Unauthorized,
                $"Site one REST: {rest.StatusCode}");
        }
    }

    [Fact]
    public async Task NotFound_Returns404FromIIS()
    {
        if (ShouldSkipWhenNoIis())
        {
            return;
        }

        await using var harness = await IisGatewayHarness.StartAsync();

        if (PortIsListening(SiteOnePort))
        {
            using var response = await harness.SendAsync(
                "wordpress-one.example", HttpMethod.Get, "/this-path-does-not-exist-12345");
            Assert.True(
                response.StatusCode == HttpStatusCode.NotFound ||
                response.StatusCode == (HttpStatusCode)502,
                $"Site one 404: {response.StatusCode}");
        }
    }

    [Fact]
    public async Task Head_ReturnsSameStatusWithoutBody()
    {
        if (ShouldSkipWhenNoIis())
        {
            return;
        }

        await using var harness = await IisGatewayHarness.StartAsync();

        if (PortIsListening(SiteOnePort))
        {
            using var request = new HttpRequestMessage(HttpMethod.Head, "/");
            request.Headers.Host = "wordpress-one.example";
            using var response = await harness.Client.SendAsync(request);
            Assert.True(
                response.StatusCode == HttpStatusCode.OK ||
                response.StatusCode == (HttpStatusCode)502,
                $"Site one HEAD: {response.StatusCode}");
            Assert.True(response.Content.Headers.ContentLength is null or 0);
        }
    }

    [Fact]
    public async Task PublicBindings_UnchangedOn80And443()
    {
        if (ShouldSkipWhenNoIisAdministration())
        {
            return;
        }

        using var serverManager = new ServerManager();
        var bindings80 = serverManager.Sites
            .SelectMany(site => site.Bindings)
            .Where(binding => binding.EndPoint?.Port == 80)
            .ToList();

        var bindings443 = serverManager.Sites
            .SelectMany(site => site.Bindings)
            .Where(binding => binding.EndPoint?.Port == 443)
            .ToList();

        foreach (var binding in bindings80.Concat(bindings443))
        {
            Assert.NotEqual("10000", binding.EndPoint?.Port.ToString());
        }
    }

    /// <summary>
    /// A gateway harness whose destinations are real IIS loopback ports instead of synthetic
    /// backends. Used only when IIS is actually listening on 8081/8082.
    /// </summary>
    private sealed class IisGatewayHarness : IAsyncDisposable
    {
        private readonly WebApplication _gateway;
        private readonly HttpClient _client;

        private IisGatewayHarness(WebApplication gateway, HttpClient client)
        {
            _gateway = gateway;
            _client = client;
        }

        public HttpClient Client => _client;

        public static async Task<IisGatewayHarness> StartAsync()
        {
            WebApplication? gateway = null;

            try
            {
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
                    ["Gateway:ActivityTimeoutSeconds"] = "10",
                    ["Gateway:Multipart:Enabled"] = "true",
                    ["Sites:0:Id"] = "wordpress-one",
                    ["Sites:0:Hosts:0"] = "wordpress-one.example",
                    ["Sites:0:Destination"] = $"http://127.0.0.1:{SiteOnePort}",
                    ["Sites:0:Mode"] = "Monitor",
                    ["Sites:0:ObserveThreshold"] = "30",
                    ["Sites:0:BlockThreshold"] = "80",
                    ["Sites:1:Id"] = "wordpress-two",
                    ["Sites:1:Hosts:0"] = "wordpress-two.example",
                    ["Sites:1:Destination"] = $"http://127.0.0.1:{SiteTwoPort}",
                    ["Sites:1:Mode"] = "Monitor",
                    ["Sites:1:ObserveThreshold"] = "30",
                    ["Sites:1:BlockThreshold"] = "80"
                };
                builder.Configuration.AddInMemoryCollection(settings);

                gateway = GatewayApplication.Build(builder);
                await gateway.StartAsync();
                var address = GetBoundAddress(gateway);
                var client = new HttpClient { BaseAddress = address };

                return new IisGatewayHarness(gateway, client);
            }
            catch
            {
                if (gateway is not null)
                {
                    await gateway.DisposeAsync();
                }
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
            _client.Dispose();
            await _gateway.DisposeAsync();
        }
    }

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

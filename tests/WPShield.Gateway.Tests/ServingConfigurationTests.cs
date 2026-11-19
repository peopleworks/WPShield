using System.Text.Json;
using WPShield.Core;

namespace WPShield.Gateway.Tests;

public sealed class ServingConfigurationTests
{
    [Fact]
    public void ChangingBindingInputs_CannotAlterServingCollections()
    {
        string[] urls = ["http://127.0.0.1:0"];
        string[] proxies = ["192.0.2.1"];
        string[] paths = ["/budget"];
        string[] hosts = ["one.example"];
        RateLimitRuleOptions[] rules = [new() { Id = "budget", Paths = paths }];
        var gateway = new GatewayOptions { Urls = urls, TrustedProxies = proxies, RateLimit = new() { Rules = rules } };
        var site = new SiteOptions { Id = "one", Hosts = hosts, Destination = new Uri("http://127.0.0.1:0") };

        urls[0] = proxies[0] = paths[0] = hosts[0] = "candidate";
        rules[0] = new RateLimitRuleOptions();

        Assert.Equal("http://127.0.0.1:0", Assert.Single(gateway.Urls));
        Assert.Equal("192.0.2.1", Assert.Single(gateway.TrustedProxies));
        Assert.Equal("/budget", Assert.Single(Assert.Single(gateway.RateLimit.Rules).Paths));
        Assert.Equal("one.example", Assert.Single(site.Hosts));
    }

    [Fact]
    public void GatewayRuntimeManifest_ExcludesTheOfflineCliAndPdfRenderer()
    {
        // Inspect the gateway's transitive runtime dependencies, not the test host's graph.
        var manifest = Path.ChangeExtension(typeof(GatewayApplication).Assembly.Location, ".deps.json");
        using var stream = File.OpenRead(manifest);
        using var json = JsonDocument.Parse(stream);
        var libraries = json.RootElement.GetProperty("libraries").EnumerateObject()
            .Select(lib => lib.Name.Split('/')[0]).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Contains("WPShield.Gateway", libraries);
        Assert.Contains("WPShield.Core", libraries);
        Assert.DoesNotContain("wpshield", libraries); // The CLI's assembly name.
        Assert.DoesNotContain("QuestPDF", libraries);
    }
}

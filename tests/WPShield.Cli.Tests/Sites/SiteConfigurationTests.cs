using System.Text.Json;
using WPShield.Cli.Sites;

namespace WPShield.Cli.Tests.Sites;

/// <summary>
/// The site table, written the way the gateway reads it.
/// </summary>
/// <remarks>
/// The gateway refuses to start when real hostnames appear beside the shipped <c>.example</c>
/// placeholders, because JSON configuration merges arrays element by element and an overlay with
/// fewer entries leaves the surplus shipped ones live. So "writes the overlay" is not enough to be
/// correct here, and most of what is asserted below is about the shipped file rather than the new one.
/// </remarks>
public sealed class SiteConfigurationTests : IDisposable
{
    private readonly string _dir;

    public SiteConfigurationTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "wpshield-site-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private SiteConfiguration Configuration => new(_dir);

    private void WriteShipped(string json) =>
        File.WriteAllText(Path.Combine(_dir, SiteConfiguration.ShippedFileName), json);

    private JsonDocument ReadJson(string name) =>
        JsonDocument.Parse(File.ReadAllText(Path.Combine(_dir, name)));

    private static SiteEntry Site(string id, params string[] hosts) => new()
    {
        Id = id,
        Hosts = hosts,
        DestinationPort = 8081
    };

    [Fact]
    public void An_absent_overlay_reads_as_no_sites()
    {
        Assert.Empty(Configuration.Read());
    }

    [Fact]
    public void A_saved_site_round_trips()
    {
        var configuration = Configuration;
        configuration.Save([Site("peopleworks.com.do", "peopleworks.com.do", "www.peopleworks.com.do")]);

        var site = Assert.Single(configuration.Read());
        Assert.Equal("peopleworks.com.do", site.Id);
        Assert.Equal(["peopleworks.com.do", "www.peopleworks.com.do"], site.Hosts);
        Assert.Equal(8081, site.DestinationPort);
        Assert.Equal("http://127.0.0.1:8081", site.Destination);
        Assert.Equal("Monitor", site.Mode);
    }

    /// <summary>
    /// The reason this class exists. Leaving the shipped placeholders in place produces a gateway
    /// that refuses to start, which is worse than the problem being solved.
    /// </summary>
    [Fact]
    public void Saving_empties_the_shipped_placeholder_sites()
    {
        WriteShipped("""
            {
              "Gateway": { "Urls": [ "http://127.0.0.1:10000" ] },
              "Sites": [
                { "Id": "wordpress-one", "Hosts": [ "wordpress-one.example" ], "Destination": "http://127.0.0.1:8081" },
                { "Id": "wordpress-two", "Hosts": [ "wordpress-two.example" ], "Destination": "http://127.0.0.1:8082" }
              ],
              "Logging": { "File": { "Enabled": true } }
            }
            """);

        var changed = Configuration.Save([Site("real.example.test", "real.example.test")]);

        Assert.True(changed);

        using var shipped = ReadJson(SiteConfiguration.ShippedFileName);
        Assert.Empty(shipped.RootElement.GetProperty("Sites").EnumerateArray());

        // Everything else in the shipped file is left exactly alone.
        Assert.True(shipped.RootElement.TryGetProperty("Gateway", out _));
        Assert.True(shipped.RootElement.TryGetProperty("Logging", out _));
    }

    [Fact]
    public void The_shipped_file_is_backed_up_before_it_is_rewritten()
    {
        WriteShipped("""{ "Sites": [ { "Id": "a", "Hosts": [ "a.example" ], "Destination": "http://127.0.0.1:8081" } ] }""");

        Configuration.Save([Site("real.example.test", "real.example.test")]);

        var backup = Path.Combine(_dir, SiteConfiguration.ShippedFileName + ".bak");
        Assert.True(File.Exists(backup));
        Assert.Contains("a.example", File.ReadAllText(backup));
    }

    [Fact]
    public void Saving_reports_no_change_when_the_shipped_file_has_no_sites()
    {
        WriteShipped("""{ "Sites": [], "Gateway": {} }""");

        Assert.False(Configuration.Save([Site("real.example.test", "real.example.test")]));
    }

    [Fact]
    public void Other_overlay_sections_survive_a_save()
    {
        File.WriteAllText(
            Path.Combine(_dir, SiteConfiguration.OverlayFileName),
            """{ "Sites": [], "Logging": { "File": { "Directory": "D:\\logs" } } }""");

        Configuration.Save([Site("real.example.test", "real.example.test")]);

        using var overlay = ReadJson(SiteConfiguration.OverlayFileName);
        Assert.Equal(
            "D:\\logs",
            overlay.RootElement.GetProperty("Logging").GetProperty("File").GetProperty("Directory").GetString());
    }

    [Fact]
    public void A_malformed_overlay_is_reported_rather_than_silently_replaced()
    {
        File.WriteAllText(Path.Combine(_dir, SiteConfiguration.OverlayFileName), "{ not json");

        var failure = Assert.Throws<CliArgumentException>(() => Configuration.Read());

        Assert.Contains("could not be read as JSON", failure.Message);
    }

    [Fact]
    public void The_written_overlay_uses_the_field_names_the_gateway_binds()
    {
        Configuration.Save([Site("id", "host.example.test")]);

        using var overlay = ReadJson(SiteConfiguration.OverlayFileName);
        var site = overlay.RootElement.GetProperty("Sites").EnumerateArray().Single();

        // These names are the contract with WPShield.Core's SiteOptions. A rename there without one
        // here produces a gateway that silently resolves nothing.
        foreach (var field in new[] { "Id", "Hosts", "Destination", "Mode", "ObserveThreshold", "BlockThreshold" })
        {
            Assert.True(site.TryGetProperty(field, out _), $"the overlay is missing '{field}'");
        }
    }
}

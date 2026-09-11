using WPShield.Cli.Sites;

namespace WPShield.Cli.Tests.Sites;

/// <summary>
/// The argument refusals, which are the reason this verb can be trusted to write a live gateway's
/// configuration. Every one of them fires before a file is touched.
/// </summary>
public sealed class SiteCommandTests : IDisposable
{
    private readonly string _dir;

    public SiteCommandTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "wpshield-sitecmd-" + Guid.NewGuid().ToString("N"));
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

    private string Run(string action, params string[] args)
    {
        var output = new StringWriter();
        var arguments = CliOptions.Parse([.. args, "--install-path", _dir, "--no-restart"]);
        SiteCommand.Run(arguments, output, action);
        return output.ToString();
    }

    private CliArgumentException Refused(string action, params string[] args) =>
        Assert.Throws<CliArgumentException>(() => Run(action, args));

    private bool OverlayExists => File.Exists(Path.Combine(_dir, SiteConfiguration.OverlayFileName));

    [Fact]
    public void Add_writes_the_site_and_reports_what_it_wrote()
    {
        var output = Run("add", "--id", "peopleworks.com.do", "--hosts", "peopleworks.com.do,www.peopleworks.com.do",
            "--destination-port", "8081");

        Assert.Contains("Added", output);
        Assert.Contains("peopleworks.com.do", output);
        Assert.Contains("http://127.0.0.1:8081", output);
        Assert.True(OverlayExists);
    }

    [Fact]
    public void Add_without_hosts_is_refused_and_writes_nothing()
    {
        var failure = Refused("add", "--id", "x", "--destination-port", "8081");

        Assert.Contains("--hosts is required", failure.Message);
        Assert.False(OverlayExists);
    }

    [Fact]
    public void Add_without_a_destination_port_is_refused()
    {
        var failure = Refused("add", "--id", "x", "--hosts", "x.example.test");

        Assert.Contains("--destination-port is required", failure.Message);
        Assert.False(OverlayExists);
    }

    /// <summary>
    /// Forwarding back to IIS's public port would send the request round through IIS's public face
    /// instead of to the site, which is a loop rather than a protected path.
    /// </summary>
    [Theory]
    [InlineData(80)]
    [InlineData(443)]
    public void Add_refuses_iis_public_ports_as_a_destination(int port)
    {
        var failure = Refused("add", "--id", "x", "--hosts", "x.example.test", "--destination-port", port.ToString());

        Assert.Contains("public port", failure.Message);
        Assert.Contains("PRIVATE loopback", failure.Message);
        Assert.False(OverlayExists);
    }

    [Fact]
    public void Add_refuses_an_unknown_mode()
    {
        var failure = Refused("add", "--id", "x", "--hosts", "x.example.test", "--destination-port", "8081",
            "--mode", "Paranoid");

        Assert.Contains("--mode must be one of", failure.Message);
        Assert.False(OverlayExists);
    }

    [Fact]
    public void Add_refuses_thresholds_that_block_before_they_observe()
    {
        var failure = Refused("add", "--id", "x", "--hosts", "x.example.test", "--destination-port", "8081",
            "--observe-threshold", "90", "--block-threshold", "50");

        Assert.Contains("blocked before it was ever observed", failure.Message);
        Assert.False(OverlayExists);
    }

    /// <summary>The gateway refuses to start on a host claimed twice; here is a better place to say so.</summary>
    [Fact]
    public void Add_refuses_a_host_already_claimed_by_another_site()
    {
        Run("add", "--id", "first", "--hosts", "shared.example.test", "--destination-port", "8081");

        var failure = Refused("add", "--id", "second", "--hosts", "shared.example.test", "--destination-port", "8082");

        Assert.Contains("already claimed by site 'first'", failure.Message);
        Assert.Contains("Nothing was changed", failure.Message);
    }

    [Fact]
    public void Adding_the_same_id_twice_updates_rather_than_duplicating()
    {
        Run("add", "--id", "same", "--hosts", "a.example.test", "--destination-port", "8081");
        var output = Run("add", "--id", "same", "--hosts", "b.example.test", "--destination-port", "8082");

        Assert.Contains("Updated", output);

        var site = Assert.Single(new SiteConfiguration(_dir).Read());
        Assert.Equal(["b.example.test"], site.Hosts);
        Assert.Equal(8082, site.DestinationPort);
    }

    [Fact]
    public void List_says_plainly_when_there_is_nothing_configured()
    {
        Assert.Contains("No sites configured", Run("list"));
    }

    [Fact]
    public void Remove_takes_the_site_out_and_warns_when_none_remain()
    {
        Run("add", "--id", "only", "--hosts", "only.example.test", "--destination-port", "8081");

        var output = Run("remove", "--id", "only");

        Assert.Contains("Removed", output);
        Assert.Contains("no sites remain", output);
        Assert.Empty(new SiteConfiguration(_dir).Read());
    }

    [Fact]
    public void Remove_of_an_unknown_id_changes_nothing()
    {
        Run("add", "--id", "kept", "--hosts", "kept.example.test", "--destination-port", "8081");

        var output = Run("remove", "--id", "nope");

        Assert.Contains("Nothing was changed", output);
        Assert.Single(new SiteConfiguration(_dir).Read());
    }

    [Fact]
    public void An_unknown_action_is_refused_with_the_list_of_actions()
    {
        var failure = Refused("frobnicate", "--id", "x");

        Assert.Contains("list, add, remove", failure.Message);
    }

    [Fact]
    public void No_restart_says_the_change_is_not_live_yet()
    {
        var output = Run("add", "--id", "x", "--hosts", "x.example.test", "--destination-port", "8081");

        Assert.Contains("not live yet", output);
        Assert.Contains("sc stop WPShield", output);
    }
}

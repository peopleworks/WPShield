using WPShield.Cli.Enable;
using WPShield.Cli.Preflight;
using WPShield.Cli.Setup;
using WPShield.Cli.Sites;

namespace WPShield.Cli.Tests.Setup;

/// <summary>
/// The chain, and the promise that it stops at the first thing that needs a person.
/// </summary>
/// <remarks>
/// The value of this verb is entirely in the ordering and the stopping, so that is what is asserted:
/// a blocked step must prevent every later step from running at all, and the run must be safe to
/// repeat.
/// </remarks>
public sealed class SetupRunnerTests : IDisposable
{
    private const string SiteName = "example-site";
    private const string PublicHost = "example.test";

    private readonly string _dir;
    private readonly string _webRoot;

    public SetupRunnerTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "wpshield-setup-" + Guid.NewGuid().ToString("N"));
        _webRoot = Path.Combine(_dir, "web");
        Directory.CreateDirectory(_dir);
        Directory.CreateDirectory(_webRoot);
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

    private sealed record RunResult(int Exit, string Output, int EnableCalls);

    private RunResult Run(
        IHostFacts? host = null,
        IIisFacts? iis = null,
        int enableExit = Enabler.ExitEnabled,
        Func<SetupOptions, SetupOptions>? adjust = null,
        PreflightReport? preflight = null,
        InstallationReport? installation = null)
    {
        var output = new StringWriter();
        var enableCalls = 0;

        var options = new SetupOptions { SiteName = SiteName, GatewayPort = 10000 };
        options = adjust is null ? options : adjust(options);

        var exit = new SetupRunner(
            host ?? Host(),
            iis ?? Iis(),
            options,
            new SiteConfiguration(_dir),
            _ => preflight ?? Ready(),
            () => installation ?? Installed(),
            _ => { enableCalls++; return enableExit; },
            output).Run();

        return new RunResult(exit, output.ToString(), enableCalls);
    }

    /// <summary>A preflight that found nothing wrong, which is the uninteresting case for this class.</summary>
    private static PreflightReport Ready() => new();

    private static PreflightReport Blocked(string id, string title)
    {
        var report = new PreflightReport();
        report.Add(id, PreflightStatus.Blocker, title);
        return report;
    }

    private static InstallationReport Installed(bool installed = true, string state = "Running") =>
        new() { ServiceInstalled = installed, ServiceState = state };

    private FakeHost Host(bool elevated = true, IReadOnlyList<int>? listening = null) =>
        new() { IsElevated = elevated, Ports = listening ?? [80, 443, 10000] };

    private FakeIis Iis(IReadOnlyList<IisBinding>? bindings = null) => new()
    {
        Readable = true,
        ArrProxyEnabled = true,
        ArrPreserveHostHeader = true,
        Sites =
        [
            new IisSite(SiteName, "Started", _webRoot,
                bindings ??
                [
                    new IisBinding("https", $"*:443:{PublicHost}"),
                    new IisBinding("http", "127.0.0.1:8081:")
                ],
                [])
        ]
    };

    private void WriteWpConfig(string content) =>
        File.WriteAllText(Path.Combine(_webRoot, "wp-config.php"), content);

    private static string Translating =>
        "<?php if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) { $_SERVER['HTTPS'] = 'on'; }";

    // =============================================================================================
    //  Stopping.
    // =============================================================================================

    /// <summary>
    /// The whole promise. A blocked step must stop the chain, and nothing after it may run - most of
    /// all step 5, which changes IIS.
    /// </summary>
    [Fact]
    public void A_missing_scheme_translation_stops_before_anything_touches_iis()
    {
        WriteWpConfig("<?php define('DB_NAME','x'); require_once ABSPATH . 'wp-settings.php';");

        var result = Run();

        Assert.Equal(SetupRunner.ExitBlocked, result.Exit);
        Assert.Equal(0, result.EnableCalls);
        Assert.Contains("[4/5]", result.Output);
        Assert.Contains("MISSING the X-Forwarded-Proto translation", result.Output);
        Assert.Contains("Stopped at step 4 of 5", result.Output);
        Assert.Contains("$_SERVER['HTTPS'] = 'on';", result.Output);

        // Step 5 was never announced.
        Assert.DoesNotContain("[5/5]", result.Output);
    }

    /// <summary>Step 1 blocking must stop everything, including the steps that write.</summary>
    [Fact]
    public void A_preflight_blocker_stops_at_step_one()
    {
        var result = Run(preflight: Blocked("PRE-003", "URL Rewrite is not installed"));

        Assert.Equal(SetupRunner.ExitBlocked, result.Exit);
        Assert.Equal(0, result.EnableCalls);
        Assert.Contains("[1/5]", result.Output);
        Assert.Contains("PRE-003", result.Output);
        Assert.Contains("Stopped at step 1 of 5", result.Output);
        Assert.DoesNotContain("[2/5]", result.Output);
        Assert.Empty(new SiteConfiguration(_dir).Read());
    }

    [Fact]
    public void An_uninstalled_gateway_stops_at_step_two_and_names_the_install_command()
    {
        var result = Run(installation: Installed(installed: false));

        Assert.Equal(SetupRunner.ExitBlocked, result.Exit);
        Assert.Contains("not installed", result.Output);
        Assert.Contains("wpshield install --path", result.Output);
        Assert.DoesNotContain("[3/5]", result.Output);
    }

    [Fact]
    public void Nothing_listening_on_the_gateway_port_stops_at_step_two()
    {
        var result = Run(host: Host(listening: [80, 443]));

        Assert.Equal(SetupRunner.ExitBlocked, result.Exit);
        Assert.Equal(0, result.EnableCalls);
        Assert.Contains("[2/5]", result.Output);
        Assert.Contains("nothing answers on 127.0.0.1:10000", result.Output);
        Assert.DoesNotContain("[3/5]", result.Output);
    }

    [Fact]
    public void A_site_with_no_private_loopback_binding_stops_at_step_three()
    {
        var result = Run(iis: Iis(bindings: [new IisBinding("https", $"*:443:{PublicHost}")]));

        Assert.Equal(SetupRunner.ExitBlocked, result.Exit);
        Assert.Equal(0, result.EnableCalls);
        Assert.Contains("no private loopback binding", result.Output);
    }

    [Fact]
    public void A_site_with_no_host_header_stops_at_step_three()
    {
        var result = Run(iis: Iis(bindings: [new IisBinding("http", "127.0.0.1:8081:")]));

        Assert.Equal(SetupRunner.ExitBlocked, result.Exit);
        Assert.Contains("no host header to route by", result.Output);
    }

    [Fact]
    public void A_refusal_from_enable_is_reported_as_a_blocked_final_step()
    {
        WriteWpConfig(Translating);

        var result = Run(enableExit: Enabler.ExitRefused);

        Assert.Equal(SetupRunner.ExitBlocked, result.Exit);
        Assert.Equal(1, result.EnableCalls);
        Assert.Contains("[5/5]", result.Output);
        Assert.Contains("Stopped at step 5 of 5", result.Output);
    }

    [Fact]
    public void A_revert_after_a_failed_probe_is_reported_as_such()
    {
        WriteWpConfig(Translating);

        var result = Run(enableExit: Enabler.ExitRevertedAfterFailure);

        Assert.Equal(SetupRunner.ExitBlocked, result.Exit);
        Assert.Contains("everything was reverted", result.Output);
    }

    // =============================================================================================
    //  Completing.
    // =============================================================================================

    [Fact]
    public void A_translating_wordpress_site_goes_all_the_way_through()
    {
        WriteWpConfig(Translating);

        var result = Run();

        Assert.Equal(SetupRunner.ExitComplete, result.Exit);
        Assert.Equal(1, result.EnableCalls);
        Assert.Contains("[5/5]", result.Output);
        Assert.Contains("Setup complete", result.Output);
        Assert.Contains($"wpshield watch --host \"{PublicHost}\"", result.Output);
    }

    /// <summary>A site that is not WordPress has nothing to translate, and must not be stopped for it.</summary>
    [Fact]
    public void A_site_with_no_wp_config_passes_step_four()
    {
        var result = Run();

        Assert.Equal(SetupRunner.ExitComplete, result.Exit);
        Assert.Contains("not a WordPress site", result.Output);
    }

    [Fact]
    public void It_writes_the_site_table_from_the_iis_bindings_alone()
    {
        WriteWpConfig(Translating);

        Run();

        var site = Assert.Single(new SiteConfiguration(_dir).Read());
        Assert.Equal(PublicHost, site.Id);
        Assert.Equal([PublicHost], site.Hosts);
        Assert.Equal(8081, site.DestinationPort);
        Assert.Equal("Monitor", site.Mode);
    }

    [Fact]
    public void Explicit_flags_win_over_what_iis_says()
    {
        WriteWpConfig(Translating);

        Run(adjust: options => options with
        {
            SiteId = "custom-id",
            Hosts = ["a.example.test", "b.example.test"],
            DestinationPort = 9090,
            Mode = "Block"
        });

        var site = Assert.Single(new SiteConfiguration(_dir).Read());
        Assert.Equal("custom-id", site.Id);
        Assert.Equal(["a.example.test", "b.example.test"], site.Hosts);
        Assert.Equal(9090, site.DestinationPort);
        Assert.Equal("Block", site.Mode);
    }

    /// <summary>Running twice must not duplicate the site or fail on work already done.</summary>
    [Fact]
    public void A_second_run_reports_the_site_as_already_configured()
    {
        WriteWpConfig(Translating);

        Run();
        var second = Run();

        Assert.Equal(SetupRunner.ExitComplete, second.Exit);
        Assert.Contains("already configured", second.Output);
        Assert.Single(new SiteConfiguration(_dir).Read());
    }

    // =============================================================================================
    //  The dry run.
    // =============================================================================================

    [Fact]
    public void A_dry_run_changes_nothing_and_never_calls_enable()
    {
        WriteWpConfig(Translating);

        var result = Run(adjust: options => options with { DryRun = true });

        Assert.Equal(SetupRunner.ExitComplete, result.Exit);
        Assert.Equal(0, result.EnableCalls);
        Assert.Contains("DRY RUN", result.Output);
        Assert.Contains("would write", result.Output);
        Assert.Empty(new SiteConfiguration(_dir).Read());
    }

    [Fact]
    public void An_unknown_site_is_refused_before_any_step_runs()
    {
        var failure = Assert.Throws<CliArgumentException>(() =>
            Run(adjust: options => options with { SiteName = "not-a-site" }));

        Assert.Contains("No IIS site named", failure.Message);
    }

    // =============================================================================================
    //  Doubles.
    // =============================================================================================

    private sealed class FakeHost : IHostFacts
    {
        public bool IsElevated { get; init; } = true;
        public IReadOnlyList<int> Ports { get; init; } = [];

        public string OperatingSystem => "Windows Server 2022";
        public string RuntimeDescription => ".NET 10.0.0";
        public IReadOnlyList<string> AspNetCoreRuntimes => ["10.0.0"];
        public bool UrlRewriteInstalled => true;
        public bool ApplicationRequestRoutingInstalled => true;
        public string? WebServerServiceState => "Running";
        public InstalledService? WPShieldService => new("Running", @"NT SERVICE\WPShield", null);
        public IReadOnlyList<int> ListeningPorts => Ports;
        public IReadOnlyList<string> PortOwners(int port) => [];
        public DirectoryFacts DescribeDirectory(string path) => new(Directory.Exists(path), []);
        public bool FileExists(string path) => File.Exists(path);
        public IReadOnlyList<string> ChildDirectories(string path) => [];
    }

    private sealed class FakeIis : IIisFacts
    {
        public bool Readable { get; init; }
        public string? UnreadableReason { get; init; }
        public bool? ArrProxyEnabled { get; init; }
        public bool? ArrPreserveHostHeader { get; init; }
        public IReadOnlyList<IisSite> Sites { get; init; } = [];
    }
}

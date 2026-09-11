using WPShield.Cli.Enable;
using WPShield.Cli.Preflight;

namespace WPShield.Cli.Tests;

/// <summary>
/// The one verb permitted to change IIS, and every refusal that is the reason it is permitted.
/// </summary>
/// <remarks>
/// ADR 0005 allows this only for a single named site, only for individually reversible changes, and
/// only when it verifies the result and reverts on failure. Those are not aspirations in a document;
/// each one is a test below.
/// </remarks>
public sealed class EnablerTests : IDisposable
{
    private const string SiteName = "example-site";
    private const string PublicHost = "example.test";

    private readonly string _root = Path.Combine(
        AppContext.BaseDirectory, "enable-tests", Guid.NewGuid().ToString("N"));

    // =============================================================================================
    //  The refusals.
    // =============================================================================================

    /// <summary>
    /// The hole this class did not cover, and the outage it allowed.
    /// </summary>
    /// <remarks>
    /// The gateway answers 421 for a Host it has no site for. Enabling the rule against a gateway
    /// that does not know the site pointed every visitor at that 421 — and the probe read a 421 as
    /// "the site answered", so the verb applied the change, verified nothing, reverted nothing and
    /// printed success. Two tests now close it: this one refuses before anything is written, and
    /// <see cref="A_421_is_a_failure_because_it_is_the_gateway_refusing_to_own_the_host"/> makes the
    /// probe catch it if it ever gets that far.
    /// </remarks>
    [Fact]
    public void It_refuses_when_the_gateway_does_not_know_the_sites_host()
    {
        WriteWpConfig("<?php if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) { $_SERVER['HTTPS'] = 'on'; }");

        var failure = Assert.Throws<CliArgumentException>(() =>
            Run(gateway: GatewayFacts.ForHosts(["wordpress-one.example", "wordpress-two.example"])));

        Assert.Contains("does not resolve", failure.Message);
        Assert.Contains(PublicHost, failure.Message);
        Assert.Contains("421", failure.Message);
        Assert.Contains("Nothing was changed.", failure.Message);

        // The refusal must happen before the first write, not after a revert.
        Assert.Empty(LastWriter.Calls);
    }

    [Fact]
    public void It_says_so_plainly_when_the_gateway_has_no_sites_at_all()
    {
        WriteWpConfig("<?php if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) { $_SERVER['HTTPS'] = 'on'; }");

        var failure = Assert.Throws<CliArgumentException>(() =>
            Run(gateway: GatewayFacts.ForHosts([])));

        Assert.Contains("no sites configured at all", failure.Message);
        Assert.Empty(LastWriter.Calls);
    }

    [Fact]
    public void The_hosts_check_is_case_insensitive()
    {
        WriteWpConfig("<?php if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) { $_SERVER['HTTPS'] = 'on'; }");

        // A host is a host regardless of case; refusing on casing would be a false alarm that teaches
        // an operator to distrust the guard.
        var result = Run(gateway: GatewayFacts.ForHosts([PublicHost.ToUpperInvariant()]));

        Assert.Equal(Enabler.ExitEnabled, result.Exit);
    }

    /// <summary>
    /// The refusal that makes this verb unable to create the redirect loop it exists to prevent.
    /// <c>wp-config.php</c> is the site's own source and the verb never writes it.
    /// </summary>
    [Fact]
    public void WithoutTheSchemeTranslationInWpConfig_ItRefusesAndPrintsTheCode()
    {
        WriteWpConfig("<?php define('DB_NAME', 'x'); require_once ABSPATH . 'wp-settings.php';");

        var exception = Assert.Throws<CliArgumentException>(() => Run());

        Assert.Contains("ERR_TOO_MANY_REDIRECTS", exception.Message, StringComparison.Ordinal);
        Assert.Contains("$_SERVER['HTTPS'] = 'on'", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Nothing was changed", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void WithTheTranslationPresent_ItProceeds()
    {
        WriteWpConfig("<?php if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) { $_SERVER['HTTPS'] = 'on'; }");

        Assert.Contains("AddRuleFirst", Run().Writer.Calls);
    }

    /// <summary>
    /// A site that is not WordPress has nothing to translate, and the rule works regardless.
    /// </summary>
    [Fact]
    public void ASiteWithNoWpConfig_IsNotAskedForATranslation()
    {
        Assert.Contains("AddRuleFirst", Run().Writer.Calls);
    }

    /// <summary>
    /// Server-wide, no per-site override, and it changes what every ARR proxy on the machine sends
    /// downstream. A tool must not make that change for an operator who asked about one site.
    /// </summary>
    [Fact]
    public void WithPreserveHostHeaderOff_ItRefusesRatherThanTurningItOn()
    {
        var exception = Assert.Throws<CliArgumentException>(
            () => Run(iis: Iis(preserveHostHeader: false)));

        Assert.Contains("server-wide", exception.Message, StringComparison.Ordinal);
        Assert.Contains("yourself", exception.Message, StringComparison.Ordinal);
        Assert.Contains("421", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void WithTheArrProxyDisabled_ItRefuses()
    {
        var exception = Assert.Throws<CliArgumentException>(
            () => Run(iis: Iis(arrProxyEnabled: false)));

        Assert.Contains("404 for every request", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Enabling the rule while nothing answers on the loopback port takes the site down instantly:
    /// IIS would forward every request to a closed port.
    /// </summary>
    [Fact]
    public void WithNothingListeningOnTheGatewayPort_ItRefuses()
    {
        var exception = Assert.Throws<CliArgumentException>(
            () => Run(host: Host(listening: [80, 443])));

        Assert.Contains("closed port", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Nothing was changed", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnknownSite_IsRefused()
    {
        var exception = Assert.Throws<CliArgumentException>(
            () => Run(adjust: o => o with { SiteName = "not-a-site" }));

        Assert.Contains("No IIS site named", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ARealRunWithoutElevation_IsRefusedBeforeAnythingIsTouched()
    {
        Assert.Throws<CliArgumentException>(() => Run(host: Host(elevated: false)));
        Assert.Empty(LastWriter.Calls);
    }

    [Fact]
    public void ASiteWithNoHostHeaderBinding_IsRefusedBecauseThereIsNoNameToVerifyBy()
    {
        var site = new IisSite(SiteName, "Started", _root, [new IisBinding("http", "127.0.0.1:8081:")], []);

        var exception = Assert.Throws<CliArgumentException>(() => Run(iis: Iis(sites: [site])));

        Assert.Contains("no binding with a host header", exception.Message, StringComparison.Ordinal);
    }

    // =============================================================================================
    //  The dry run.
    // =============================================================================================

    [Fact]
    public void ADryRunChangesNothingAndDoesNotRequireElevation()
    {
        var result = Run(host: Host(elevated: false), adjust: o => o with { DryRun = true });

        Assert.Equal(Enabler.ExitEnabled, result.Exit);
        Assert.Empty(result.Writer.Calls);
    }

    [Fact]
    public void ADryRunNamesTheRollback()
    {
        Assert.Contains("wpshield disable", Run(adjust: o => o with { DryRun = true }).Output, StringComparison.Ordinal);
    }

    // =============================================================================================
    //  The order, and the revert. This is the deliverable.
    // =============================================================================================

    /// <summary>
    /// A rule that sets a variable which is not on the allowed list returns HTTP 500 for the whole
    /// site, so the variable is allowed first. Always.
    /// </summary>
    [Fact]
    public void TheServerVariableIsAllowedBeforeTheRuleIsAdded()
    {
        var calls = Run().Writer.Calls;

        Assert.True(
            calls.IndexOf("AllowServerVariable") < calls.IndexOf("AddRuleFirst"),
            string.Join(", ", calls));
    }

    [Fact]
    public void WebConfigIsBackedUpBeforeAnythingIsChanged()
    {
        Assert.Equal("BackupWebConfig", Run().Writer.Calls[0]);
    }

    /// <summary>
    /// The whole case for this verb. A person types the rule, saves, and has to notice, diagnose and
    /// undo it themselves; this reverts before the command returns.
    /// </summary>
    [Fact]
    public void WhenTheSiteStopsAnswering_EverythingIsRevertedBeforeTheCommandReturns()
    {
        var result = Run(probe: new FakeProbe(new SiteHealth(false, "the site redirected 5 times without settling")));

        Assert.Equal(Enabler.ExitRevertedAfterFailure, result.Exit);
        Assert.Contains("RemoveRule", result.Writer.Calls);
        Assert.Contains("DisallowServerVariable", result.Writer.Calls);
        Assert.Contains("REVERTING", result.Output, StringComparison.Ordinal);
    }

    /// <summary>Newest first, so a partly applied change comes apart in the order it went together.</summary>
    [Fact]
    public void TheRevertRunsInReverse()
    {
        var calls = Run(probe: new FakeProbe(new SiteHealth(false, "HTTP 500"))).Writer.Calls;

        Assert.True(calls.IndexOf("RemoveRule") < calls.IndexOf("DisallowServerVariable"));
    }

    /// <summary>
    /// A reversal that throws must not stop the ones behind it. Leaving a site half-reverted because
    /// the first undo failed is worse than leaving it half-applied.
    /// </summary>
    [Fact]
    public void AFailingRevertDoesNotStopTheRest()
    {
        var writer = new FakeWriter { ThrowOnRemoveRule = true };

        var result = Run(probe: new FakeProbe(new SiteHealth(false, "HTTP 500")), writer: writer);

        Assert.Contains("COULD NOT REVERT", result.Output, StringComparison.Ordinal);
        Assert.Contains("DisallowServerVariable", writer.Calls);
    }

    [Fact]
    public void WhenTheSiteAnswers_NothingIsReverted()
    {
        var result = Run();

        Assert.Equal(Enabler.ExitEnabled, result.Exit);
        Assert.DoesNotContain("RemoveRule", result.Writer.Calls);
        Assert.Contains("wpshield disable", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public void AMissingLoopbackBindingIsAddedAndRevertedWithTheRest()
    {
        var site = new IisSite(SiteName, "Started", _root, [new IisBinding("https", "*:443:example.test")], []);

        var calls = Run(
            iis: Iis(sites: [site]),
            probe: new FakeProbe(new SiteHealth(false, "HTTP 500")),
            adjust: o => o with { DestinationPort = 8081 }).Writer.Calls;

        Assert.Contains("AddLoopbackBinding", calls);
        Assert.Contains("RemoveLoopbackBinding", calls);
    }

    // =============================================================================================
    //  Helpers.
    // =============================================================================================

    private sealed record RunResult(int Exit, FakeWriter Writer, string Output);

    private RunResult Run(
        IIisFacts? iis = null,
        IHostFacts? host = null,
        ISiteProbe? probe = null,
        Func<EnableOptions, EnableOptions>? adjust = null,
        FakeWriter? writer = null,
        IGatewayFacts? gateway = null)
    {
        var recorder = writer ?? new FakeWriter();
        var text = new StringWriter();

        try
        {
            var exit = new Enabler(
                recorder,
                probe ?? new FakeProbe(new SiteHealth(true, "HTTP 200 after 1 request(s)")),
                iis ?? Iis(),
                host ?? Host(),
                // By default the gateway knows the site, so the existing tests keep testing what they
                // were written to test rather than all tripping the new guard.
                gateway ?? GatewayFacts.ForHosts([PublicHost]),
                Options(adjust),
                text).Run();

            return new RunResult(exit, recorder, text.ToString());
        }
        catch (CliArgumentException)
        {
            LastOutput = text.ToString();
            LastWriter = recorder;
            throw;
        }
    }

    private string LastOutput { get; set; } = string.Empty;
    private FakeWriter LastWriter { get; set; } = new();

    private EnableOptions Options(Func<EnableOptions, EnableOptions>? adjust)
    {
        var options = new EnableOptions
        {
            SiteName = SiteName,
            GatewayPort = 10000,
            BackupDirectory = _root
        };

        return adjust is null ? options : adjust(options);
    }

    private FakeIis Iis(bool? arrProxyEnabled = true, bool? preserveHostHeader = true, IReadOnlyList<IisSite>? sites = null)
    {
        Directory.CreateDirectory(_root);

        return new FakeIis
        {
            Readable = true,
            ArrProxyEnabled = arrProxyEnabled,
            ArrPreserveHostHeader = preserveHostHeader,
            Sites = sites ??
            [
                new IisSite(SiteName, "Started", _root,
                    [new IisBinding("https", $"*:443:{PublicHost}"), new IisBinding("http", "127.0.0.1:8081:")],
                    [])
            ]
        };
    }

    private static FakeHost Host(bool elevated = true, IReadOnlyList<int>? listening = null) =>
        new() { IsElevated = elevated, Ports = listening ?? [80, 443, 10000] };

    private void WriteWpConfig(string content)
    {
        Directory.CreateDirectory(_root);
        File.WriteAllText(Path.Combine(_root, "wp-config.php"), content);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private sealed class FakeWriter : IIisSiteWriter
    {
        public List<string> Calls { get; } = [];
        public bool ThrowOnRemoveRule { get; init; }

        public void BackupWebConfig(string sitePhysicalPath, string backupPath) => Calls.Add("BackupWebConfig");
        public void AddLoopbackBinding(string siteName, int port) => Calls.Add("AddLoopbackBinding");
        public void RemoveLoopbackBinding(string siteName, int port) => Calls.Add("RemoveLoopbackBinding");
        public void AllowServerVariable(string siteName) => Calls.Add("AllowServerVariable");
        public void DisallowServerVariable(string siteName) => Calls.Add("DisallowServerVariable");
        public void AddRuleFirst(string siteName, int gatewayPort) => Calls.Add("AddRuleFirst");

        public void RemoveRule(string siteName)
        {
            Calls.Add("RemoveRule");
            if (ThrowOnRemoveRule)
            {
                throw new InvalidOperationException("the configuration is locked");
            }
        }

        public bool SetRuleEnabled(string siteName, bool enabled)
        {
            Calls.Add($"SetRuleEnabled:{enabled}");
            return true;
        }
    }

    private sealed class FakeProbe(SiteHealth health) : ISiteProbe
    {
        public SiteHealth Check(string publicHost) => health;
    }

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
        public InstalledService? WPShieldService => null;
        public IReadOnlyList<int> ListeningPorts => Ports;
        public IReadOnlyList<string> PortOwners(int port) => [];
        public DirectoryFacts DescribeDirectory(string path) => new(false, []);
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

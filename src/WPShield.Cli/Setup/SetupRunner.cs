using WPShield.Cli.Enable;
using WPShield.Cli.Preflight;
using WPShield.Cli.Sites;

namespace WPShield.Cli.Setup;

/// <summary>How one step of the chain came out.</summary>
internal enum StepResult
{
    /// <summary>It was already true, or this run made it true. Continue.</summary>
    Ok,

    /// <summary>This run changed something to make it true. Continue.</summary>
    Done,

    /// <summary>Something the operator has to fix. Stop here and say what.</summary>
    Blocked
}

/// <summary>What a step decided, and what to tell the operator about it.</summary>
internal sealed record SetupStep(int Number, string Title, StepResult Result, string Summary)
{
    public IReadOnlyList<string> Detail { get; init; } = [];
}

/// <summary>Everything a setup run needs, after flags and answers have been resolved.</summary>
internal sealed record SetupOptions
{
    public required string SiteName { get; init; }
    public string? SiteId { get; init; }
    public IReadOnlyList<string> Hosts { get; init; } = [];
    public int DestinationPort { get; init; }
    public int GatewayPort { get; init; } = 10000;
    public string Mode { get; init; } = "Monitor";
    public bool DryRun { get; init; }
}

/// <summary>
/// Asks the five questions that stand between an unpacked artifact and a first finding, in order,
/// and refuses to skip one.
/// </summary>
/// <remarks>
/// <para>
/// <b>This verb exists because the pieces were each defensible and the assembly was not.</b> An
/// operator took the artifact to a real server, ran <c>watch</c>, and got a blank console — because
/// seeing anything required the host to be ready, the service installed, the site configured,
/// <c>wp-config.php</c> translating the scheme, and IIS actually forwarding. Five things, each with
/// its own verb or none at all, and nothing that said which one was missing.
/// </para>
/// <para>
/// <b>It orchestrates; it does not reimplement.</b> Every step delegates to the piece that already
/// owns that question — the preflight checks, <see cref="InstallationReport"/>,
/// <see cref="SiteConfiguration"/>, <see cref="WordPressSchemeTranslation"/> and
/// <see cref="Enabler"/>. A second copy of any of those rules is how <c>setup</c> would start
/// reporting a site ready that <c>enable</c> refuses.
/// </para>
/// <para>
/// <b>It stops at the first blocker and is safe to re-run.</b> Each step checks before it acts, so a
/// run after a fix continues from where the last one stopped rather than repeating work or failing
/// on something already done.
/// </para>
/// </remarks>
internal sealed class SetupRunner(
    IHostFacts host,
    IIisFacts iis,
    SetupOptions options,
    SiteConfiguration configuration,
    Func<IisSite, PreflightReport> preflight,
    Func<InstallationReport> installation,
    Func<IisSite, int> enable,
    TextWriter output)
{
    private readonly IHostFacts _host = host ?? throw new ArgumentNullException(nameof(host));
    private readonly IIisFacts _iis = iis ?? throw new ArgumentNullException(nameof(iis));
    private readonly Func<IisSite, PreflightReport> _preflight = preflight ?? throw new ArgumentNullException(nameof(preflight));
    private readonly Func<InstallationReport> _installation = installation ?? throw new ArgumentNullException(nameof(installation));
    private readonly SetupOptions _options = options ?? throw new ArgumentNullException(nameof(options));
    private readonly SiteConfiguration _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    private readonly Func<IisSite, int> _enable = enable ?? throw new ArgumentNullException(nameof(enable));
    private readonly TextWriter _output = output ?? throw new ArgumentNullException(nameof(output));

    private const int TotalSteps = 5;

    public const int ExitComplete = 0;
    public const int ExitBlocked = 1;

    public int Run()
    {
        var site = ResolveSite();

        _output.WriteLine();
        _output.WriteLine($"WPShield setup - {site.Name}{(_options.DryRun ? "   DRY RUN, nothing will be changed" : string.Empty)}");
        _output.WriteLine();

        var steps = new List<SetupStep>();

        foreach (var step in new Func<IisSite, SetupStep>[]
        {
            CheckHost, CheckGatewayInstalled, ConfigureSite, CheckSchemeTranslation, PutInPath
        })
        {
            var result = step(site);
            steps.Add(result);
            Report(result);

            if (result.Result == StepResult.Blocked)
            {
                return Stop(result);
            }
        }

        _output.WriteLine();
        _output.WriteLine(_options.DryRun
            ? "  Dry run complete. Every step above would have been attempted in that order."
            : "  Setup complete. WPShield is in the path for this site.");

        if (!_options.DryRun)
        {
            _output.WriteLine();
            _output.WriteLine($"  Watch it:  wpshield watch --host \"{SiteId(site)}\"");
            _output.WriteLine($"  Roll back: wpshield disable --site \"{site.Name}\"");
        }

        _output.WriteLine();
        return ExitComplete;
    }

    // =============================================================================================
    //  The five steps.
    // =============================================================================================

    /// <summary>Step 1 — is this host able to run WPShield at all?</summary>
    private SetupStep CheckHost(IisSite site)
    {
        var report = _preflight(site);

        if (report.Ready)
        {
            var warnings = report.Warnings.Count;
            return new SetupStep(1, "preflight", StepResult.Ok,
                warnings == 0 ? "ok" : $"ok, {warnings} warning(s) - see 'wpshield preflight'");
        }

        return new SetupStep(1, "preflight", StepResult.Blocked,
            $"{report.Blockers.Count} blocker(s)")
        {
            Detail = [.. report.Blockers.Select(blocker => $"{blocker.Id}  {blocker.Title}"),
                      string.Empty,
                      "Run 'wpshield preflight' for the full detail and the remedy for each."]
        };
    }

    /// <summary>Step 2 — is the gateway installed, and is it answering?</summary>
    private SetupStep CheckGatewayInstalled(IisSite site)
    {
        _ = site;
        var report = _installation();

        if (!report.ServiceInstalled)
        {
            return new SetupStep(2, "gateway installed", StepResult.Blocked, "not installed")
            {
                Detail =
                [
                    "Install it from the published artifact, then run this again:",
                    string.Empty,
                    "    wpshield install --path <the copied artifact directory> --start"
                ]
            };
        }

        if (!_host.ListeningPorts.Contains(_options.GatewayPort))
        {
            return new SetupStep(2, "gateway installed", StepResult.Blocked,
                $"installed, but nothing answers on 127.0.0.1:{_options.GatewayPort}")
            {
                Detail =
                [
                    $"The service is {report.ServiceState ?? "in an unknown state"}. Putting IIS in front of a",
                    "closed port would take the site down instantly, so this stops here.",
                    string.Empty,
                    "    sc start WPShield",
                    "    wpshield status"
                ]
            };
        }

        return new SetupStep(2, "gateway installed", StepResult.Ok,
            $"{report.ServiceState}, answering on 127.0.0.1:{_options.GatewayPort}");
    }

    /// <summary>Step 3 — does the gateway know this site?</summary>
    private SetupStep ConfigureSite(IisSite site)
    {
        var id = SiteId(site);
        var hosts = Hosts(site);
        var port = DestinationPort(site);

        if (hosts.Count == 0)
        {
            return new SetupStep(3, "site configuration", StepResult.Blocked, "no host header to route by")
            {
                Detail =
                [
                    $"IIS site '{site.Name}' has no binding with a host header, so there is no Host value",
                    "for the gateway to resolve. Give it one, or pass --hosts explicitly."
                ]
            };
        }

        if (port == 0)
        {
            return new SetupStep(3, "site configuration", StepResult.Blocked, "no private loopback binding")
            {
                Detail =
                [
                    $"IIS site '{site.Name}' has no 127.0.0.1 binding, so there is no private port for",
                    "WPShield to forward back to. Add one in IIS, or pass --destination-port."
                ]
            };
        }

        var existing = _configuration.Read();
        var already = existing.FirstOrDefault(entry =>
            string.Equals(entry.Id, id, StringComparison.OrdinalIgnoreCase));

        if (already is not null &&
            already.DestinationPort == port &&
            hosts.All(value => already.Hosts.Contains(value, StringComparer.OrdinalIgnoreCase)))
        {
            return new SetupStep(3, "site configuration", StepResult.Ok,
                $"{id} -> 127.0.0.1:{port}, already configured");
        }

        if (_options.DryRun)
        {
            return new SetupStep(3, "site configuration", StepResult.Ok,
                $"would write {id} -> 127.0.0.1:{port}  hosts: {string.Join(", ", hosts)}");
        }

        var entry = new SiteEntry
        {
            Id = id,
            Hosts = hosts,
            DestinationPort = port,
            Mode = _options.Mode
        };

        var sites = existing.Where(candidate =>
            !string.Equals(candidate.Id, id, StringComparison.OrdinalIgnoreCase)).ToList();
        sites.Add(entry);

        var shippedChanged = _configuration.Save(sites);

        return new SetupStep(3, "site configuration", StepResult.Done,
            $"{id} -> 127.0.0.1:{port}")
        {
            Detail = shippedChanged
                ? [$"wrote {_configuration.OverlayPath}",
                   $"emptied the shipped Sites array in {_configuration.ShippedPath}",
                   "RESTART the service so the gateway reads it:  sc stop WPShield && sc start WPShield"]
                : [$"wrote {_configuration.OverlayPath}",
                   "RESTART the service so the gateway reads it:  sc stop WPShield && sc start WPShield"]
        };
    }

    /// <summary>Step 4 — has WordPress been told the original request was HTTPS?</summary>
    private SetupStep CheckSchemeTranslation(IisSite site)
    {
        var status = WordPressSchemeTranslation.Check(_host, site.PhysicalPath);

        return status switch
        {
            SchemeTranslation.NotWordPress => new SetupStep(4, "wp-config.php", StepResult.Ok,
                "not a WordPress site, nothing to translate"),

            SchemeTranslation.Present => new SetupStep(4, "wp-config.php", StepResult.Ok,
                "translates X-Forwarded-Proto"),

            _ => new SetupStep(4, "wp-config.php", StepResult.Blocked,
                "MISSING the X-Forwarded-Proto translation")
            {
                Detail =
                [
                    $"{WordPressSchemeTranslation.PathFor(site.PhysicalPath)} does not read the forwarded",
                    "scheme. Behind the gateway WordPress would see plain HTTP on an HTTPS site and",
                    "redirect to itself forever - ERR_TOO_MANY_REDIRECTS.",
                    string.Empty,
                    "WPShield will not write that file: it is the site's own source. Add this before",
                    "require_once ABSPATH . 'wp-settings.php'; and run setup again:",
                    string.Empty,
                    .. WordPressSchemeTranslation.Snippet.Split(Environment.NewLine)
                ]
            }
        };
    }

    /// <summary>Step 5 — put IIS in front of the gateway, verified, revertible.</summary>
    private SetupStep PutInPath(IisSite site)
    {
        if (_options.DryRun)
        {
            return new SetupStep(5, "in the traffic path", StepResult.Ok,
                "would run 'wpshield enable' for this site");
        }

        var exit = _enable(site);

        return exit switch
        {
            Enabler.ExitEnabled => new SetupStep(5, "in the traffic path", StepResult.Done,
                "enabled and verified"),

            Enabler.ExitRevertedAfterFailure => new SetupStep(5, "in the traffic path", StepResult.Blocked,
                "applied, the site did not answer, everything was reverted")
            {
                Detail = ["The detail is printed above by 'enable'. The site is back as it was."]
            },

            _ => new SetupStep(5, "in the traffic path", StepResult.Blocked, "refused")
            {
                Detail = ["The refusal is printed above by 'enable'."]
            }
        };
    }

    // =============================================================================================
    //  Resolution and reporting.
    // =============================================================================================

    private IisSite ResolveSite()
    {
        if (!_iis.Readable)
        {
            throw new CliArgumentException(
                $"IIS could not be read: {_iis.UnreadableReason}. Run from an elevated prompt.");
        }

        return _iis.Sites.FirstOrDefault(candidate =>
            string.Equals(candidate.Name, _options.SiteName, StringComparison.OrdinalIgnoreCase))
            ?? throw new CliArgumentException(
                $"No IIS site named '{_options.SiteName}'. Run 'wpshield preflight' to list them.");
    }

    /// <summary>The gateway's SiteId, which is also what <c>watch --host</c> filters on.</summary>
    private string SiteId(IisSite site) =>
        !string.IsNullOrWhiteSpace(_options.SiteId) ? _options.SiteId!.Trim() : PublicHost(site) ?? site.Name;

    private IReadOnlyList<string> Hosts(IisSite site)
    {
        if (_options.Hosts.Count > 0)
        {
            return _options.Hosts;
        }

        // Every public binding that names a host. A site answering both the bare domain and its www
        // form has two, and the gateway must resolve both or one of them gets a 421.
        return
        [
            .. site.Bindings
                .Where(binding => !binding.IsLoopback && !string.IsNullOrWhiteSpace(binding.HostHeader))
                .Select(binding => binding.HostHeader)
                .Distinct(StringComparer.OrdinalIgnoreCase)
        ];
    }

    private static string? PublicHost(IisSite site) =>
        site.Bindings
            .Where(binding => !binding.IsLoopback && !string.IsNullOrWhiteSpace(binding.HostHeader))
            .Select(binding => binding.HostHeader)
            .FirstOrDefault();

    private int DestinationPort(IisSite site) =>
        _options.DestinationPort > 0
            ? _options.DestinationPort
            : site.Bindings.FirstOrDefault(binding => binding.IsLoopback)?.Port ?? 0;

    private void Report(SetupStep step)
    {
        var marker = step.Result switch
        {
            StepResult.Ok => "ok",
            StepResult.Done => "done",
            _ => "STOP"
        };

        _output.WriteLine($"  [{step.Number}/{TotalSteps}] {step.Title.PadRight(20)} {marker,-5} {step.Summary}");

        foreach (var line in step.Detail)
        {
            _output.WriteLine(line.Length == 0 ? string.Empty : $"        {line}");
        }

        if (step.Detail.Count > 0)
        {
            _output.WriteLine();
        }
    }

    private int Stop(SetupStep step)
    {
        _output.WriteLine();
        _output.WriteLine($"  Stopped at step {step.Number} of {TotalSteps}. Nothing after it was attempted.");
        _output.WriteLine("  Fix the above and run 'wpshield setup' again - it continues from here.");
        _output.WriteLine();
        return ExitBlocked;
    }
}

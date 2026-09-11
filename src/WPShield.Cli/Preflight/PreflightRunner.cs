using System.Globalization;

namespace WPShield.Cli.Preflight;

/// <summary>
/// What the operator asked to be checked.
/// </summary>
internal sealed record PreflightOptions
{
    public int GatewayPort { get; init; } = 10000;
    public IReadOnlyList<int> PrivatePorts { get; init; } = [8081, 8082];
    public IReadOnlyList<string> SiteNames { get; init; } = [];
    public string InstallPath { get; init; } = @"C:\Program Files\WPShield";
    public string LogPath { get; init; } = @"C:\ProgramData\WPShield\logs";
}

/// <summary>
/// The readiness check, as a pure function of facts.
/// </summary>
/// <remarks>
/// <para>
/// Every rule here was in <c>Invoke-WPShieldPreflight.ps1</c> first, and each one exists because the
/// production traffic path has several ways to fail <b>on the live site</b>, at the moment the
/// rewrite rule is enabled, with an error that does not say what is wrong.
/// </para>
/// <para>
/// <b>Nothing here touches the machine.</b> It receives facts and returns findings. That is also why
/// it can be tested: the PowerShell version could only be exercised by running it on a server with
/// IIS, ARR and the right failure conditions, which is how <c>PRE-018</c> shipped unable to match the
/// one rule it was written to find.
/// </para>
/// </remarks>
internal sealed class PreflightRunner(IHostFacts host, IIisFacts iis, PreflightOptions options)
{
    private readonly IHostFacts _host = host ?? throw new ArgumentNullException(nameof(host));
    private readonly IIisFacts _iis = iis ?? throw new ArgumentNullException(nameof(iis));
    private readonly PreflightOptions _options = options ?? throw new ArgumentNullException(nameof(options));

    public PreflightReport Run()
    {
        var report = new PreflightReport();

        CheckHost(report);
        CheckIis(report);
        CheckPorts(report);
        var planned = CheckSites(report);
        CheckInstallationTarget(report, planned);

        return report;
    }

    /// <summary>The sites that look like WordPress, for the configuration the command prints.</summary>
    public IReadOnlyList<IisSite> PlannedSites { get; private set; } = [];

    // =============================================================================================
    //  Host
    // =============================================================================================

    private void CheckHost(PreflightReport report)
    {
        if (_host.IsElevated)
        {
            report.Add(
                "PRE-001", PreflightStatus.Pass, "Running elevated",
                "The IIS configuration, listening ports and directory permissions are all readable.",
                data: PreflightReport.Fields(("elevated", true)));
        }
        else
        {
            // A blocker rather than a warning, and the reason is the direction of the error: without
            // elevation the IIS configuration and the ACLs are unreadable, so every answer below
            // comes out optimistic, and optimistic is the worst direction for a readiness check.
            report.Add(
                "PRE-001", PreflightStatus.Blocker, "Not running as administrator",
                "IIS configuration, listening ports and directory permissions are all partly or wholly unreadable, and the answers below will be wrong in the optimistic direction.",
                "Run this from an elevated prompt.",
                PreflightReport.Fields(("elevated", false)));
        }

        report.Add(
            "PRE-002", PreflightStatus.Info, "Windows and .NET",
            $"{_host.OperatingSystem}  |  {_host.RuntimeDescription}",
            data: PreflightReport.Fields(
                ("operatingSystem", _host.OperatingSystem),
                ("runtime", _host.RuntimeDescription)));

        var ten = _host.AspNetCoreRuntimes.Where(version => version.StartsWith("10.", StringComparison.Ordinal)).ToArray();

        if (ten.Length > 0)
        {
            report.Add(
                "PRE-003", PreflightStatus.Pass, "ASP.NET Core 10 runtime present",
                $"Microsoft.AspNetCore.App {string.Join(", ", ten)}",
                data: PreflightReport.Fields(("aspNetCoreRuntimes", ten)));
        }
        else
        {
            report.Add(
                "PRE-003", PreflightStatus.Warn, "No ASP.NET Core 10 runtime found",
                _host.AspNetCoreRuntimes.Count == 0
                    ? "No shared ASP.NET Core runtime is installed on this host."
                    : $"Found {string.Join(", ", _host.AspNetCoreRuntimes)}, none of them 10.x.",
                "Not a blocker: WPShield publishes self-contained and carries its own runtime. It matters only if you intend a framework-dependent deployment.",
                PreflightReport.Fields(("aspNetCoreRuntimes", _host.AspNetCoreRuntimes)));
        }
    }

    // =============================================================================================
    //  IIS
    // =============================================================================================

    private void CheckIis(PreflightReport report)
    {
        if (!_iis.Readable)
        {
            report.Add(
                "PRE-004", PreflightStatus.Blocker, "The IIS configuration could not be read",
                _iis.UnreadableReason ?? "No reason was reported.",
                "Run elevated, and confirm IIS is installed. Nothing below says anything about IIS until this passes.",
                PreflightReport.Fields(("iisReadable", false)));
            return;
        }

        if (_host.WebServerServiceState is null)
        {
            report.Add(
                "PRE-004", PreflightStatus.Blocker, "IIS is not installed",
                remedy: "This traffic path assumes IIS owns ports 80 and 443. Without IIS there is nothing to put WPShield behind.",
                data: PreflightReport.Fields(("iisInstalled", false)));
        }
        else
        {
            report.Add(
                "PRE-004",
                _host.WebServerServiceState == "Running" ? PreflightStatus.Pass : PreflightStatus.Warn,
                "IIS is installed",
                $"W3SVC is {_host.WebServerServiceState}",
                data: PreflightReport.Fields(("w3svcStatus", _host.WebServerServiceState)));
        }

        if (_host.UrlRewriteInstalled)
        {
            report.Add("PRE-005", PreflightStatus.Pass, "URL Rewrite is installed",
                data: PreflightReport.Fields(("urlRewrite", true)));
        }
        else
        {
            report.Add(
                "PRE-005", PreflightStatus.Blocker, "URL Rewrite is not installed",
                @"rewrite.dll was not found under System32\inetsrv.",
                "Install the IIS URL Rewrite module. It is what sends traffic to WPShield; without it there is no way in.",
                PreflightReport.Fields(("urlRewrite", false)));
        }

        if (_host.ApplicationRequestRoutingInstalled)
        {
            report.Add("PRE-006", PreflightStatus.Pass, "Application Request Routing is installed",
                data: PreflightReport.Fields(("arr", true)));
        }
        else
        {
            report.Add(
                "PRE-006", PreflightStatus.Blocker, "Application Request Routing is not installed",
                "ARR is what actually performs the proxy hop to WPShield. URL Rewrite alone can rewrite a URL but cannot forward the request to another process.",
                "Install Application Request Routing 3.0.",
                PreflightReport.Fields(("arr", false)));
        }

        CheckArrSwitches(report);
    }

    /// <summary>
    /// The two settings this whole check exists for. Both default to the value that breaks, both
    /// live in a server-level section with no per-site override, and both fail on the live site at
    /// the moment the rewrite rule is enabled.
    /// </summary>
    private void CheckArrSwitches(PreflightReport report)
    {
        switch (_iis.ArrProxyEnabled)
        {
            case null:
                report.Add(
                    "PRE-007", PreflightStatus.Warn, "The ARR proxy setting could not be read",
                    "system.webServer/proxy was not present or not readable.",
                    "Confirm ARR is installed, then read it again. An unreadable setting is not a disabled one, and this check will not guess.");
                break;

            case true:
                report.Add("PRE-007", PreflightStatus.Pass, "ARR server-level proxy is enabled",
                    data: PreflightReport.Fields(("proxyEnabled", true)));
                break;

            default:
                report.Add(
                    "PRE-007", PreflightStatus.Blocker, "ARR server-level proxy is disabled",
                    "With it off, a rewrite rule pointing at the gateway does not proxy - it returns 404 for every request, and nothing in the log explains why.",
                    "Enable the proxy in IIS Manager: server node, Application Request Routing Cache, Server Proxy Settings, Enable proxy.",
                    PreflightReport.Fields(("proxyEnabled", false)));
                break;
        }

        switch (_iis.ArrPreserveHostHeader)
        {
            case null:
                report.Add(
                    "PRE-008", PreflightStatus.Warn, "The ARR host header setting could not be read",
                    "system.webServer/proxy was not present or not readable.");
                break;

            case true:
                report.Add(
                    "PRE-008", PreflightStatus.Pass, "ARR preserves the client Host header",
                    "WPShield resolves the site from this header, so this setting is load-bearing.",
                    data: PreflightReport.Fields(("preserveHostHeader", true)));
                break;

            default:
                report.Add(
                    "PRE-008", PreflightStatus.Blocker, "ARR does not preserve the client Host header",
                    "WPShield resolves the site from the Host header and fails closed with HTTP 421 when it matches no configured site. With this off, the whole site answers 421 the moment the rule goes live.",
                    "Turn on Preserve client Host header in Server Proxy Settings. It is a SERVER-LEVEL setting with no per-site override - see PRE-017 for which other applications it changes.",
                    PreflightReport.Fields(("preserveHostHeader", false)));
                break;
        }
    }

    // =============================================================================================
    //  Ports
    // =============================================================================================

    private void CheckPorts(PreflightReport report)
    {
        var listening = _host.ListeningPorts.ToHashSet();

        if (!listening.Contains(_options.GatewayPort))
        {
            report.Add(
                "PRE-009", PreflightStatus.Pass, $"Gateway port {_options.GatewayPort} is free",
                data: PreflightReport.Fields(("gatewayPort", _options.GatewayPort), ("free", true)));
        }
        else
        {
            report.Add(
                "PRE-009", PreflightStatus.Blocker, $"Gateway port {_options.GatewayPort} is already in use",
                "Something is listening there. WPShield binds this port and will fail to start.",
                "Choose another port with --gateway-port, and use the same one in the rewrite rule.",
                PreflightReport.Fields(("gatewayPort", _options.GatewayPort), ("free", false)));
        }

        foreach (var port in _options.PrivatePorts)
        {
            var id = FormattableString.Invariant($"PRE-010.{port}");

            if (!listening.Contains(port))
            {
                report.Add(id, PreflightStatus.Pass, $"Private port {port} is free",
                    data: PreflightReport.Fields(("port", port), ("free", true)));
            }
            else
            {
                report.Add(
                    id, PreflightStatus.Warn, $"Private port {port} is in use",
                    "This is also how an existing IIS binding appears, so check whether it is already the private binding for one of the sites below.",
                    data: PreflightReport.Fields(("port", port), ("free", false)));
            }
        }

        foreach (var publicPort in new[] { 80, 443 })
        {
            var id = FormattableString.Invariant($"PRE-011.{publicPort}");

            if (listening.Contains(publicPort))
            {
                report.Add(
                    id, PreflightStatus.Info, $"Port {publicPort} is in use",
                    "WPShield never binds a public port. It listens on loopback only, which is why it needs no elevated binding rights.",
                    data: PreflightReport.Fields(("port", publicPort), ("inUse", true)));
            }
            else
            {
                report.Add(
                    id, PreflightStatus.Warn, $"Nothing is listening on port {publicPort}",
                    "Under this traffic path IIS owns the public ports. If nothing holds them, confirm what is actually serving these sites.",
                    data: PreflightReport.Fields(("port", publicPort), ("inUse", false)));
            }
        }
    }

    // =============================================================================================
    //  Sites
    // =============================================================================================

    private IReadOnlyList<IisSite> CheckSites(PreflightReport report)
    {
        if (!_iis.Readable)
        {
            // Without this the section would be empty, and an empty section reads as "there are no
            // sites" rather than "nobody could look". On a readiness check those must never look
            // alike.
            report.Add(
                "PRE-012", PreflightStatus.Blocker, "The sites could not be inventoried",
                "IIS was unreadable, so this run says nothing about what is being served, which bindings exist, or which rewrite rules are already in place.",
                "Fix the blockers above and run again. Do not read the absence of site findings as an absence of sites.",
                PreflightReport.Fields(("sitesReadable", false)));
            return [];
        }

        if (_iis.Sites.Count == 0)
        {
            report.Add("PRE-012", PreflightStatus.Warn, "No IIS sites could be read");
            return [];
        }

        var planned = new List<IisSite>();
        var proxyingRules = new List<string>();
        var catchAllRules = new List<string>();
        var catchAllStops = false;

        foreach (var site in _iis.Sites)
        {
            if (_options.SiteNames.Count > 0 &&
                !_options.SiteNames.Contains(site.Name, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            var looksLikeWordPress =
                _host.FileExists(Path.Combine(site.PhysicalPath, "wp-config.php")) ||
                _host.FileExists(Path.Combine(site.PhysicalPath, "wp-includes", "version.php"));

            if (looksLikeWordPress)
            {
                planned.Add(site);
            }

            var bindings = string.Join(" | ", site.Bindings.Select(b => $"{b.Protocol} {b.BindingInformation}"));

            report.Add(
                $"PRE-012.{site.Name}",
                PreflightStatus.Info,
                $"Site: {site.Name}  ({(looksLikeWordPress ? "WordPress" : "not WordPress")}, {site.State})",
                $"bindings: {bindings}   path: {site.PhysicalPath}",
                data: PreflightReport.Fields(
                    ("site", site.Name),
                    ("state", site.State),
                    ("wordPress", looksLikeWordPress),
                    ("physicalPath", site.PhysicalPath)));

            if (site.RewriteRules.Count == 0)
            {
                continue;
            }

            var names = site.RewriteRules.Select(rule => rule.Name).ToArray();
            var hasWPShield = names.Any(name => name.Contains("WPShield", StringComparison.OrdinalIgnoreCase));

            report.Add(
                $"PRE-013.{site.Name}",
                hasWPShield ? PreflightStatus.Warn : PreflightStatus.Info,
                hasWPShield
                    ? $"A WPShield rewrite rule already exists on {site.Name}"
                    : $"{site.Name} has {site.RewriteRules.Count} existing rewrite rule(s)",
                $"rules: {string.Join(", ", names)}. The WPShield rule must be ordered so these still behave as intended.",
                data: PreflightReport.Fields(("site", site.Name), ("rules", names)));

            foreach (var rule in site.RewriteRules)
            {
                if (rule.ActionType.Equals("Rewrite", StringComparison.OrdinalIgnoreCase) &&
                    (rule.ActionUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                     rule.ActionUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
                {
                    proxyingRules.Add($"{site.Name}/{rule.Name}");
                }

                if (rule.ActionType.Equals("Rewrite", StringComparison.OrdinalIgnoreCase) &&
                    CatchAllPatterns.Contains(rule.MatchUrl, StringComparer.Ordinal))
                {
                    catchAllRules.Add(
                        $"{site.Name}/{rule.Name} (match \"{rule.MatchUrl}\" -> \"{rule.ActionUrl}\"" +
                        (rule.StopProcessing ? ", stopProcessing)" : ")"));

                    catchAllStops |= rule.StopProcessing;
                }
            }
        }

        ReportProxyingRules(report, proxyingRules);
        ReportCatchAllRules(report, catchAllRules, catchAllStops);

        PlannedSites = planned;
        return planned;
    }

    /// <summary>
    /// Regex catch-alls and the <c>Wildcard</c> <c>*</c> the WordPress permalink rule actually uses.
    /// </summary>
    /// <remarks>
    /// The PowerShell version required <c>stopProcessing</c> together with a regex catch-all, and a
    /// comment claimed the WordPress rule "has exactly this shape". It does not: WordPress writes
    /// <c>patternSyntax="Wildcard"</c> with <c>match url="*"</c> and no <c>stopProcessing</c>. Run
    /// against a server with three WordPress sites, that check reported nothing.
    /// </remarks>
    private static readonly string[] CatchAllPatterns = [".*", "^(.*)$", "^.*$", "(.*)", ".", "*"];

    private static void ReportProxyingRules(PreflightReport report, List<string> proxyingRules)
    {
        if (proxyingRules.Count == 0)
        {
            return;
        }

        report.Add(
            "PRE-017", PreflightStatus.Warn,
            "Other applications on this server are proxied through ARR",
            $"These rules proxy to another host, so they are the ones the server-wide preserveHostHeader setting affects: {string.Join(", ", proxyingRules)}.",
            "Re-test those applications after changing preserveHostHeader. Most reverse-proxied applications want the original Host and improve when they get it; some are configured around not getting it.",
            PreflightReport.Fields(("proxyingRules", proxyingRules)));
    }

    private static void ReportCatchAllRules(PreflightReport report, List<string> catchAllRules, bool anyStops)
    {
        if (catchAllRules.Count == 0)
        {
            return;
        }

        var consequence = anyStops
            ? "Where stopProcessing is set, a WPShield rule placed after it is never evaluated at all. Where it is not set, the WPShield rule still runs but against the already-rewritten URL, so every request reaches the gateway as the rewrite target and the original path is lost before it can be inspected."
            : "None of these sets stopProcessing, so a WPShield rule placed after one still runs - but against the already-rewritten URL. Every request would reach the gateway as the rewrite target, the request-path rules would see one path forever, and the log would fill with plausible entries describing traffic that never happened that way.";

        report.Add(
            "PRE-018", PreflightStatus.Warn,
            "Catch-all rewrite rules exist that the WPShield rule must be ordered before",
            $"The WPShield rule has to be ordered BEFORE these: {string.Join(", ", catchAllRules)}. {consequence}",
            "In IIS Manager, open URL Rewrite on the site, select the WPShield rule and use Move Up until it is first. Confirm with a request to a distinctive path and check that the path appears in the WPShield log rather than the rewrite target.",
            PreflightReport.Fields(("catchAllRules", catchAllRules)));
    }

    // =============================================================================================
    //  Installation target
    // =============================================================================================

    private void CheckInstallationTarget(PreflightReport report, IReadOnlyList<IisSite> planned)
    {
        _ = planned;

        if (_host.WPShieldService is { } service)
        {
            report.Add(
                "PRE-014", PreflightStatus.Warn,
                $"A WPShield service already exists and is {service.State}",
                $"identity: {service.Account ?? "unreadable"}. This is an upgrade rather than a first install.",
                "Stop it before installing over it.",
                PreflightReport.Fields(
                    ("serviceInstalled", true),
                    ("state", service.State),
                    ("account", service.Account)));
        }
        else
        {
            report.Add("PRE-014", PreflightStatus.Pass, "No WPShield service is installed yet",
                data: PreflightReport.Fields(("serviceInstalled", false)));
        }

        CheckDirectory(report, "PRE-015", _options.InstallPath, "Installation directory", blocker: false);
        CheckDirectory(report, "PRE-016", _options.LogPath, "Log directory", blocker: true);

        CheckNothingUnderAWebRoot(report);
    }

    private void CheckDirectory(PreflightReport report, string id, string path, string what, bool blocker)
    {
        var facts = _host.DescribeDirectory(path);

        if (!facts.Exists)
        {
            report.Add(
                id, PreflightStatus.Info, $"{what} does not exist yet",
                $"{path} - the install step will create it with a restricted ACL.",
                data: PreflightReport.Fields(("path", path), ("exists", false)));
            return;
        }

        if (facts.Problem is not null)
        {
            report.Add(
                id, PreflightStatus.Warn, $"{what} permissions could not be read",
                $"{path}: {facts.Problem}",
                data: PreflightReport.Fields(("path", path), ("exists", true)));
            return;
        }

        if (facts.BroadAccess.Count == 0)
        {
            report.Add(
                id, PreflightStatus.Pass, $"{what} exists and is not readable by unprivileged accounts",
                path,
                data: PreflightReport.Fields(("path", path), ("exists", true)));
            return;
        }

        report.Add(
            id,
            blocker ? PreflightStatus.Blocker : PreflightStatus.Warn,
            $"{what} is readable by unprivileged accounts",
            $"{path} grants: {string.Join(", ", facts.BroadAccess)}",
            blocker
                ? "A WPShield log carries request paths, rule hits and client addresses, so this stays a " +
                  "blocker. 'wpshield install' replaces the permissions on this directory and clears it - " +
                  "which is usually the whole fix, because a loose directory here is normally left over " +
                  "from an earlier run. Only do it by hand if you are not installing: remove inheritance " +
                  "and grant the service account and administrators alone."
                : string.Empty,
            PreflightReport.Fields(("path", path), ("exists", true), ("broadAccess", facts.BroadAccess)));
    }

    /// <summary>
    /// <c>PRE-019</c>. WPShield is not an IIS application, and none of it belongs under a web root.
    /// </summary>
    /// <remarks>
    /// The first version compared only the install path, the log path and a registered service's
    /// directory — and passed on the very server it was written for, while an unpacked copy of the
    /// gateway sat in <c>C:\inetpub\wwwroot\WPShield</c> writing its log there. All three inputs were
    /// correct; none described what was on disk. So the executable is looked for directly.
    /// </remarks>
    private void CheckNothingUnderAWebRoot(PreflightReport report)
    {
        var served = new List<string>();

        var systemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        if (!string.IsNullOrWhiteSpace(systemDrive))
        {
            // Listed whether or not IIS was readable. An unelevated run cannot enumerate the sites,
            // and the common version of this mistake lands in exactly this directory.
            served.Add(Path.Combine(systemDrive, "inetpub"));
        }

        // Every site, including ones --site filtered out. A site nobody asked about serves its
        // directory just as effectively.
        served.AddRange(_iis.Sites
            .Select(site => site.PhysicalPath)
            .Where(path => !string.IsNullOrWhiteSpace(path)));

        var roots = served.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var exposed = new List<string>();

        void Consider(string what, string? candidate)
        {
            if (string.IsNullOrWhiteSpace(candidate))
            {
                return;
            }

            foreach (var root in roots)
            {
                if (PathIsInside(candidate, root))
                {
                    exposed.Add($"{what}: {candidate} is inside {root}");
                    return;
                }
            }
        }

        Consider("Installation directory", _options.InstallPath);
        Consider("Log directory", _options.LogPath);

        if (_host.WPShieldService?.ImagePath is { } imagePath)
        {
            Consider("The WPShield service is already installed at", DirectoryOf(Unquote(imagePath)));
        }

        foreach (var root in roots)
        {
            foreach (var directory in Enumerable.Repeat(root, 1).Concat(_host.ChildDirectories(root)))
            {
                if (_host.FileExists(Path.Combine(directory, "WPShield.Gateway.exe")))
                {
                    exposed.Add($"An unpacked copy of the gateway: {directory}");
                }
            }
        }

        if (exposed.Count == 0)
        {
            report.Add(
                "PRE-019", PreflightStatus.Pass, "Nothing of WPShield sits inside a directory IIS serves",
                $"{roots.Length} served director(ies) checked.",
                data: PreflightReport.Fields(("servedDirectoryCount", roots.Length)));
            return;
        }

        report.Add(
            "PRE-019", PreflightStatus.Blocker, "WPShield is inside a directory IIS serves",
            string.Join("; ", exposed),
            @"Move it outside every web root. appsettings.Local.json is fetchable over HTTP from there - .json is in the default IIS MIME map - and it names every host this gateway protects. The defaults are C:\Program Files\WPShield with the log in C:\ProgramData\WPShield\logs, which are outside both.",
            PreflightReport.Fields(("exposed", exposed), ("servedDirectories", roots)));
    }

    internal static bool PathIsInside(string candidate, string container)
    {
        if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(container))
        {
            return false;
        }

        var left = Normalize(candidate);
        var right = Normalize(container);

        return left.Equals(right, StringComparison.OrdinalIgnoreCase) ||
               left.StartsWith(right + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string Normalize(string path)
    {
        try
        {
            return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
    }

    private static string Unquote(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.StartsWith('"'))
        {
            var end = trimmed.IndexOf('"', 1);
            return end > 1 ? trimmed[1..end] : trimmed;
        }

        var space = trimmed.IndexOf(' ');
        return space > 0 ? trimmed[..space] : trimmed;
    }

    private static string? DirectoryOf(string path)
    {
        try
        {
            return Path.GetDirectoryName(path);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}

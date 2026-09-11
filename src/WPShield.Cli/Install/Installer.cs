using System.Security.AccessControl;
using WPShield.Cli.Preflight;

namespace WPShield.Cli.Install;

internal sealed record InstallOptions
{
    public required string SourcePath { get; init; }
    public string InstallPath { get; init; } = Installer.DefaultInstallPath;
    public string LogPath { get; init; } = @"C:\ProgramData\WPShield\logs";
    public string? ConfigurationPath { get; init; }
    public bool AllowWebRootPaths { get; init; }
    public bool Start { get; init; }
    public bool DryRun { get; init; }
}

/// <summary>
/// Installs the gateway as a Windows service with a least-privilege identity and restricted
/// directories. <b>Touches nothing in IIS.</b>
/// </summary>
/// <remarks>
/// <para>
/// The order below is load-bearing and is asserted by tests rather than left to be read. The
/// per-service SID has to exist before it can be named in an ACL, which is why the directories are
/// restricted <i>after</i> the service is registered — and that ordering is exactly what made a
/// failure between the two steps leave the gateway running as <c>LocalSystem</c> with an evidence log
/// readable by every account on the machine.
/// </para>
/// <para>
/// Every step is announced before it happens. A dry run performs none of them and does not require
/// elevation: the point of a preview is that an operator can read what a tool intends before deciding
/// to let it, and requiring administrator rights to read that makes the preview harder to reach than
/// the thing it previews.
/// </para>
/// </remarks>
internal sealed class Installer(IInstallEnvironment environment, InstallOptions options)
{
    /// <summary>Where an install lands unless told otherwise, and what a preview assumes.</summary>
    public const string DefaultInstallPath = @"C:\Program Files\WPShield";

    public const string ServiceName = "WPShield";
    public const string ServiceDisplayName = "WPShield gateway";
    public const string VirtualAccount = @"NT SERVICE\WPShield";
    public const string ExecutableName = "WPShield.Gateway.exe";
    public const string SettingsFileName = "appsettings.json";
    public const string OverlayFileName = "appsettings.Local.json";

    private const string ServiceDescription =
        "WPShield defensive security gateway for WordPress on IIS. Research preview: not approved for production traffic.";

    private readonly IInstallEnvironment _environment = environment ?? throw new ArgumentNullException(nameof(environment));
    private readonly InstallOptions _options = options ?? throw new ArgumentNullException(nameof(options));

    public int Run()
    {
        Validate();

        var existing = _environment.QueryService(ServiceName);

        Say($"Source      : {_options.SourcePath}");
        Say($"Install to  : {_options.InstallPath}");
        Say($"Logs to     : {_options.LogPath}  (written into {SettingsFileName}, not just created)");
        Say($"Service     : {ServiceName}{(existing is null ? " (new)" : $" (upgrade, currently {existing.State})")}");
        Say($"Identity    : {VirtualAccount}");

        Step("1. Stop the service if it is already running");
        if (existing is not null && existing.State != "Stopped")
        {
            Do($"stop {ServiceName}", () => _environment.StopService(ServiceName));
        }
        else
        {
            Say("nothing to stop");
        }

        Step("2. Create the directories");
        foreach (var directory in new[] { _options.InstallPath, _options.LogPath })
        {
            if (_environment.DirectoryExists(directory))
            {
                Say($"exists: {directory}");
            }
            else
            {
                Do($"create {directory}", () => _environment.CreateDirectory(directory));
            }
        }

        Step("3. Copy the build");
        Do($"copy the published build into {_options.InstallPath}", () =>
        {
            _environment.CopyTree(_options.SourcePath, _options.InstallPath);
            Say($"{_environment.CountFiles(_options.InstallPath)} files in place");

            // Immediately after the copy, because the copy just replaced the file being edited.
            _environment.SetLogDirectory(Path.Combine(_options.InstallPath, SettingsFileName), _options.LogPath);
            Say($"Logging:File:Directory set to {_options.LogPath}");
        });

        if (!string.IsNullOrWhiteSpace(_options.ConfigurationPath))
        {
            var destination = Path.Combine(_options.InstallPath, OverlayFileName);
            Do($"install the operator configuration at {destination}",
                () => _environment.CopyFile(_options.ConfigurationPath!, destination));
        }

        Step("4. Register the service");
        var executable = Path.Combine(_options.InstallPath, ExecutableName);

        if (existing is null)
        {
            Do($"create the Windows service {ServiceName}",
                () => _environment.CreateService(ServiceName, executable, ServiceDisplayName, ServiceDescription));
        }
        else
        {
            Do($"update the binary path of {ServiceName}",
                () => _environment.SetServiceBinaryPath(ServiceName, executable));
        }

        // The service SID has to be in the token before NT SERVICE\WPShield means anything as an
        // identity, and it has to exist before it can be granted anything in an ACL. That is why
        // step 5 comes after this one rather than before.
        Do("enable the per-service SID", () => _environment.EnableServiceSid(ServiceName));
        Do($"set the service identity to {VirtualAccount}",
            () => _environment.SetServiceIdentity(ServiceName, VirtualAccount));
        Do("configure restart-on-failure: 5s, 15s, 60s",
            () => _environment.ConfigureServiceRecovery(ServiceName));

        Step("5. Lock down the directories");
        Do($"replace the permissions on {_options.InstallPath} and {_options.LogPath}", () =>
        {
            var sid = _environment.ResolveServiceSid(ServiceName);

            // Read and execute on the program files. The service runs the binaries; it has no
            // business rewriting them, and a gateway that can overwrite its own executable is a
            // persistence mechanism waiting for a bug.
            _environment.HardenDirectory(_options.InstallPath, FileSystemRights.ReadAndExecute, sid);
            Say($"{_options.InstallPath}: SYSTEM and Administrators full, service read+execute");

            // Modify on the logs, because writing is the point.
            _environment.HardenDirectory(_options.LogPath, FileSystemRights.Modify, sid);
            Say($"{_options.LogPath}: SYSTEM and Administrators full, service modify");

            var broad = _environment.BroadAccess(_options.InstallPath)
                .Concat(_environment.BroadAccess(_options.LogPath))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            Say(broad.Length == 0
                ? "no unprivileged account can read either directory"
                : $"WARNING: a broad group still has access: {string.Join(", ", broad)}");
        });

        Step("6. Start");
        var configurationInstalled =
            !string.IsNullOrWhiteSpace(_options.ConfigurationPath) ||
            _environment.FileExists(Path.Combine(_options.InstallPath, OverlayFileName));

        if (!_options.Start)
        {
            Say($"not started: pass --start, or use Start-Service, once the configuration is in place");
        }
        else if (!configurationInstalled)
        {
            Say($"not started: there is no {OverlayFileName}, so the gateway has no real site to resolve.");
        }
        else
        {
            Do($"start {ServiceName}", () => _environment.StartService(ServiceName));
        }

        WriteClosingNotes(configurationInstalled);
        return 0;
    }

    /// <summary>
    /// Everything that can refuse, before anything is created, copied or registered.
    /// </summary>
    private void Validate()
    {
        if (!_environment.DirectoryExists(_options.SourcePath))
        {
            throw new CliArgumentException($"The published build was not found at {_options.SourcePath}. Nothing was changed.");
        }

        if (!_environment.FileExists(Path.Combine(_options.SourcePath, ExecutableName)))
        {
            throw new CliArgumentException(
                $"{_options.SourcePath} does not look like a WPShield build: it has no {ExecutableName}. Nothing was changed.");
        }

        // A published build must not carry operator topology. The publish verb refuses to produce
        // one that does, but this build may have arrived by some other route.
        if (_environment.FileExists(Path.Combine(_options.SourcePath, OverlayFileName)))
        {
            Say($"WARNING: the build directory contains {OverlayFileName}. That file carries real hostnames and topology and should not travel inside a build.");
        }

        if (!string.IsNullOrWhiteSpace(_options.ConfigurationPath) &&
            !_environment.FileExists(_options.ConfigurationPath!))
        {
            throw new CliArgumentException($"The configuration file was not found at {_options.ConfigurationPath}. Nothing was changed.");
        }

        AssertNotUnderWebRoot();

        // A real run requires elevation; a dry run does not, and refusing it there would be the
        // wrong trade.
        if (!_options.DryRun && !_environment.IsElevated)
        {
            throw new CliArgumentException("This must run from an elevated prompt. Nothing was changed.");
        }
    }

    /// <summary>
    /// WPShield is not an IIS application and must not live inside one.
    /// </summary>
    /// <remarks>
    /// Installed under a served directory the evidence log sits in the tree IIS hands out, and
    /// <c>.json</c> is in the default IIS MIME map — so <c>appsettings.Local.json</c>, which names
    /// every host this gateway protects and the private port behind each, is fetchable over HTTP. A
    /// webshell on any neighbouring site reads all of it without an HTTP request at all. WPShield was
    /// unpacked into <c>C:\inetpub\wwwroot\WPShield</c> on the server this was written for.
    /// </remarks>
    private void AssertNotUnderWebRoot()
    {
        var roots = _environment.ServedDirectories();
        var offences = new List<string>();

        foreach (var candidate in new[] { _options.InstallPath, _options.LogPath })
        {
            foreach (var root in roots)
            {
                if (PreflightRunner.PathIsInside(candidate, root))
                {
                    offences.Add($"{candidate} is inside {root}");
                    break;
                }
            }
        }

        if (offences.Count == 0)
        {
            return;
        }

        if (_options.AllowWebRootPaths)
        {
            Say("WARNING: installing inside a directory IIS serves.");
            foreach (var offence in offences)
            {
                Say($"  {offence}");
            }

            Say("Continuing because --allow-web-root-paths was given.");
            return;
        }

        throw new CliArgumentException(
            "WPShield would be installed inside a directory IIS serves, and it refuses to be. " +
            string.Join("; ", offences) +
            ". WPShield is not an IIS application: it is a separate process on a loopback port that IIS " +
            "forwards to, so nothing of it belongs under a web root. There, appsettings.Local.json is " +
            "fetchable over HTTP - .json is in the default IIS MIME map - and it names every host this " +
            "gateway protects. Use the defaults, or pass --install-path and --log-path outside every " +
            "served directory. Nothing was changed.");
    }

    private void WriteClosingNotes(bool configurationInstalled)
    {
        _environment.Report(string.Empty);
        _environment.Report(_options.DryRun
            ? "--dry-run: nothing above was actually done."
            : "Installed. IIS was not touched.");
        _environment.Report(string.Empty);
        _environment.Report("Still to do, by hand, in this order:");

        // The notes must not tell an operator to do what this tool just did.
        _environment.Report(configurationInstalled
            ? $"  1. Read back the site table the gateway resolves at startup. The configuration is in place:"
            : $"  1. Put {OverlayFileName} in place. 'wpshield preflight' prints one.");
        _environment.Report($"     {Path.Combine(_options.InstallPath, OverlayFileName)}");
        _environment.Report("  2. Start the service and confirm it listens, before any IIS change.");
        _environment.Report("  3. Add the private loopback binding to each site.");
        _environment.Report("  4. Add the rewrite rule, ordered BEFORE any catch-all the site already has,");
        _environment.Report("     with its serverVariables block, and translate the header in wp-config.php.");
        _environment.Report("     'wpshield preflight' prints all three.");
        _environment.Report("  5. Watch the log with the sites in Monitor mode before changing anything to Block.");
        _environment.Report(string.Empty);
        _environment.Report("Know the bypass before you enable the rule: once IIS forwards to the gateway,");
        _environment.Report("stopping this service DOES NOT bypass WPShield - it takes the site down, because");
        _environment.Report("IIS keeps forwarding to a port with nothing behind it. The bypass is disabling");
        _environment.Report("the rewrite rule.");
    }

    private void Step(string title)
    {
        _environment.Report(string.Empty);
        _environment.Report(title);
    }

    private void Say(string line) => _environment.Report(line);

    /// <summary>Announces a change, then makes it — unless this is a dry run.</summary>
    private void Do(string description, Action action)
    {
        if (_options.DryRun)
        {
            _environment.Report($"would {description}");
            return;
        }

        action();
    }
}

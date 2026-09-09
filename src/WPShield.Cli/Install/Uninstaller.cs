namespace WPShield.Cli.Install;

internal sealed record UninstallOptions
{
    public string InstallPath { get; init; } = @"C:\Program Files\WPShield";
    public string LogPath { get; init; } = @"C:\ProgramData\WPShield\logs";
    public bool RemoveFiles { get; init; }
    public bool RemoveLogs { get; init; }
    public bool Force { get; init; }
    public bool DryRun { get; init; }
}

/// <summary>
/// Removes the service and, optionally, its files. Touches nothing in IIS.
/// </summary>
/// <remarks>
/// <para>
/// <b>Uninstalling is not a rollback, and this is the mistake it cannot undo.</b> If the IIS rewrite
/// rule is still enabled, removing this service takes the site down: IIS keeps forwarding every
/// request to a loopback port with nothing behind it. The rollback is the rewrite rule — disable it,
/// confirm the site serves normally, and only then remove the service.
/// </para>
/// <para>
/// So this refuses to run while it can still see a WPShield rewrite rule anywhere in IIS, <b>and it
/// refuses just as hard when it cannot read IIS at all.</b> Not finding a reason to stop is not the
/// same as confirming there is none, and getting that order wrong happens during an incident, which
/// is exactly when nobody is reading carefully.
/// </para>
/// </remarks>
internal sealed class Uninstaller(IInstallEnvironment environment, UninstallOptions options)
{
    private readonly IInstallEnvironment _environment = environment ?? throw new ArgumentNullException(nameof(environment));
    private readonly UninstallOptions _options = options ?? throw new ArgumentNullException(nameof(options));

    public int Run()
    {
        if (!_options.DryRun && !_environment.IsElevated)
        {
            throw new CliArgumentException("This must run from an elevated prompt. Nothing was changed.");
        }

        AssertIisNoLongerForwards();

        var service = _environment.QueryService(Installer.ServiceName);

        Step("1. Stop and remove the service");
        if (service is null)
        {
            Say($"no service named {Installer.ServiceName} is registered");
        }
        else
        {
            if (service.State != "Stopped")
            {
                Do($"stop {Installer.ServiceName}", () => _environment.StopService(Installer.ServiceName));
            }

            Do($"delete the service {Installer.ServiceName}",
                () => _environment.DeleteService(Installer.ServiceName));
        }

        Step("2. The installation directory");
        if (!_options.RemoveFiles)
        {
            Say($"kept: {_options.InstallPath}  (pass --remove-files to delete it)");
        }
        else if (!_environment.DirectoryExists(_options.InstallPath))
        {
            Say($"nothing at {_options.InstallPath}");
        }
        else if (!_environment.FileExists(Path.Combine(_options.InstallPath, Installer.ExecutableName)))
        {
            // Refuses to delete a directory that is not a WPShield installation. --install-path takes
            // an arbitrary path, and a recursive delete pointed at the wrong one is unrecoverable.
            throw new CliArgumentException(
                $"{_options.InstallPath} does not contain {Installer.ExecutableName}. Refusing to delete a directory that is not a WPShield installation. Nothing was changed.");
        }
        else
        {
            Do($"delete {_options.InstallPath}", () => _environment.DeleteDirectory(_options.InstallPath));
        }

        Step("3. The log directory");
        if (!_options.RemoveLogs)
        {
            // Kept by default, and deliberately. The log is the record of what the gateway saw, and
            // an uninstall during an incident is the worst moment to delete evidence.
            Say($"kept: {_options.LogPath}  (pass --remove-logs to delete it)");
        }
        else if (!_environment.DirectoryExists(_options.LogPath))
        {
            Say($"nothing at {_options.LogPath}");
        }
        else
        {
            Do($"delete {_options.LogPath}", () => _environment.DeleteDirectory(_options.LogPath));
        }

        Say(string.Empty);
        Say(_options.DryRun ? "--dry-run: nothing above was actually done." : "Removed. IIS was not touched.");
        Say(string.Empty);
        Say("If a WPShield rewrite rule is still in IIS, the site is now forwarding to a port with");
        Say("nothing behind it. Disable the rule.");

        return 0;
    }

    private void AssertIisNoLongerForwards()
    {
        var (readable, rules) = _environment.WPShieldRewriteRules();

        if (!readable)
        {
            Say("IIS could not be read, so this cannot confirm that nothing still forwards to the gateway.");

            if (!_options.Force)
            {
                throw new CliArgumentException(
                    "Refusing to uninstall without being able to confirm that IIS no longer forwards to the gateway. " +
                    "Not finding a rule is not the same as there being none. Disable the rewrite rule, confirm the " +
                    "site serves normally, and re-run with --force. Nothing was changed.");
            }

            Say("Continuing anyway because --force was given.");
            return;
        }

        if (rules.Count == 0)
        {
            return;
        }

        if (!_options.Force)
        {
            throw new CliArgumentException(
                $"IIS still has a WPShield rewrite rule: {string.Join(", ", rules)}. Removing the service now takes " +
                "the site down, because IIS keeps forwarding to a loopback port with nothing behind it. Disable the " +
                "rule first, confirm the site serves normally, and only then uninstall. Nothing was changed.");
        }

        Say($"WARNING: a WPShield rewrite rule is still present: {string.Join(", ", rules)}");
        Say("Continuing anyway because --force was given.");
    }

    private void Step(string title)
    {
        _environment.Report(string.Empty);
        _environment.Report(title);
    }

    private void Say(string line) => _environment.Report(line);

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

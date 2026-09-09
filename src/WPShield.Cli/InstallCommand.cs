using WPShield.Cli.Install;

namespace WPShield.Cli;

internal static class InstallCommand
{
    public const string Help = """
        wpshield install - install the gateway as a Windows service with a least-privilege identity
        and restricted directories. TOUCHES NOTHING IN IIS.

        Usage: wpshield install --path <published build> [options]

          --path <dir>            The published build to install. Required.
          --install-path <dir>    Where to install. Default C:\Program Files\WPShield.
          --log-path <dir>        Where the gateway writes its log. Default
                                  C:\ProgramData\WPShield\logs. This path is WRITTEN INTO the
                                  installed appsettings.json, not merely created.
          --config <file>         An appsettings.Local.json to copy into the installation.
          --start                 Start the service when the install finishes. Off by default.
          --dry-run               Print every step without doing any of it. Does not require
                                  elevation.
          --allow-web-root-paths  Install even though a path is inside a directory IIS serves.
                                  Warns instead of refusing. There is no good reason to do this.

        WHAT IT DELIBERATELY DOES NOT DO:
          It does not touch IIS. No binding, no rewrite rule, no application pool, no proxy setting.
          Those are the changes that take a live site down, they need somebody looking at the site,
          and on a shared host they affect applications that have nothing to do with WPShield.

          It does not touch any service other than WPShield.

          It does not write appsettings.Local.json. That file carries real hostnames and topology; it
          belongs to the operator, and 'wpshield preflight' prints its contents to be pasted.

        ABOUT ROLLING BACK, WHICH IS THE PART WORTH READING TWICE:
          Once the IIS rewrite rule is live, stopping this service DOES NOT bypass WPShield - it
          takes the site down, because IIS keeps forwarding every request to a port with nothing
          behind it. The bypass is the rewrite rule, not the service.

        Exit codes:
          0   installed
          1   an argument was wrong, or a guard refused
        """;

    private static readonly string[] KnownOptions =
    [
        "--path", "--install-path", "--log-path", "--config", "--start", "--dry-run", "--allow-web-root-paths"
    ];

    public static int Run(CliOptions arguments, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);

        arguments.RejectUnknown(KnownOptions);

        var source = arguments.Get("--path");
        if (string.IsNullOrWhiteSpace(source))
        {
            throw new CliArgumentException("--path is required: the published build to install.");
        }

        var options = new InstallOptions
        {
            SourcePath = source,
            InstallPath = arguments.Get("--install-path", @"C:\Program Files\WPShield"),
            LogPath = arguments.Get("--log-path", @"C:\ProgramData\WPShield\logs"),
            ConfigurationPath = arguments.Get("--config"),
            AllowWebRootPaths = arguments.Flag("--allow-web-root-paths"),
            Start = arguments.Flag("--start"),
            DryRun = arguments.Flag("--dry-run")
        };

        output.WriteLine();
        output.WriteLine($"WPShield install{(options.DryRun ? " - DRY RUN. Nothing will be changed." : string.Empty)}");
        output.WriteLine($"Host: {Environment.MachineName}");

        return new Installer(new InstallEnvironment(output), options).Run();
    }
}

internal static class UninstallCommand
{
    public const string Help = """
        wpshield uninstall - remove the service and, optionally, its files. Touches nothing in IIS.

        Usage: wpshield uninstall [options]

          --install-path <dir>  The installation directory. Default C:\Program Files\WPShield.
          --log-path <dir>      The log directory. Default C:\ProgramData\WPShield\logs.
          --remove-files        Also delete the installation directory.
          --remove-logs         Also delete the log directory. OFF BY DEFAULT, deliberately: the log
                                is the record of what the gateway saw, and an uninstall during an
                                incident is the worst moment to delete evidence.
          --force               Proceed even though a WPShield rewrite rule is still present, or
                                even though IIS could not be read at all.
          --dry-run             Print every step without doing any of it.

        READ THIS FIRST, BECAUSE IT IS THE MISTAKE THIS CANNOT UNDO:
          If the IIS rewrite rule is still enabled, removing this service TAKES THE SITE DOWN. IIS
          keeps forwarding every request to a loopback port with nothing behind it, and every visitor
          gets an error. UNINSTALLING IS NOT A ROLLBACK.

          The rollback is the rewrite rule. Disable it, confirm the site serves normally again, and
          only then remove the service. This refuses to run without --force while it can still see a
          WPShield rewrite rule - and refuses just as hard when it cannot read IIS at all, because
          not finding a rule is not the same as there being none.

        Exit codes:
          0   removed
          1   an argument was wrong, or a guard refused
        """;

    private static readonly string[] KnownOptions =
    [
        "--install-path", "--log-path", "--remove-files", "--remove-logs", "--force", "--dry-run"
    ];

    public static int Run(CliOptions arguments, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);

        arguments.RejectUnknown(KnownOptions);

        var options = new UninstallOptions
        {
            InstallPath = arguments.Get("--install-path", @"C:\Program Files\WPShield"),
            LogPath = arguments.Get("--log-path", @"C:\ProgramData\WPShield\logs"),
            RemoveFiles = arguments.Flag("--remove-files"),
            RemoveLogs = arguments.Flag("--remove-logs"),
            Force = arguments.Flag("--force"),
            DryRun = arguments.Flag("--dry-run")
        };

        output.WriteLine();
        output.WriteLine($"WPShield uninstall{(options.DryRun ? " - DRY RUN. Nothing will be changed." : string.Empty)}");

        return new Uninstaller(new InstallEnvironment(output), options).Run();
    }
}

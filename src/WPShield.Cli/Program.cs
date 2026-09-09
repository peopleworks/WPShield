using System.Reflection;
using WPShield.Cli;

return ProgramMain.Run(args);

// -------------------------------------------------------------------------------------------------
//  wpshield — the operator tool.
//
//  ADR 0003 moves every operator script except the triage tool here. The triage tool stays in
//  PowerShell on purpose: it runs on a host that has no WPShield installed and may be compromised,
//  where a single ASCII file that can be pasted into an RDP window is the feature.
//
//  The shape of this file follows the operator's other tools - SQLDiff, DBFSync, SyncJob - rather
//  than a framework's. Same verb dispatch, same help forms including /?, same one-line ERROR on
//  stderr, same exit codes. A fourth tool run by the same person at eleven at night should not have
//  its own dialect.
// -------------------------------------------------------------------------------------------------

internal static class ProgramMain
{
    public static int Run(string[] args)
    {
        if (args.Length == 0)
        {
            PrintHelp();
            return 1;
        }

        if (IsHelp(args[0]))
        {
            PrintHelp();
            return 0;
        }

        if (IsVersion(args[0]))
        {
            Console.WriteLine(GetVersion());
            return 0;
        }

        var command = args[0].Trim().ToLowerInvariant();
        var rest = args.Skip(1).ToArray();

        // A verb's own --help, so `wpshield preflight /?` works the way `wpshield /?` does.
        if (rest.Length > 0 && IsHelp(rest[0]))
        {
            return PrintVerbHelp(command);
        }

        try
        {
            var options = CliOptions.Parse(rest);

            return command switch
            {
                "preflight" => PreflightCommand.Run(options, Console.Out),
                "install" => InstallCommand.Run(options, Console.Out),
                "uninstall" => UninstallCommand.Run(options, Console.Out),
                "publish" => PublishCommand.Run(options, Console.Out),
                "status" => StatusCommand.Run(options, Console.Out),
                _ => Fail($"Unknown command: {command}. Run 'wpshield --help' for the command list.")
            };
        }
        catch (CliArgumentException exception)
        {
            return Fail(exception.Message);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return Fail(exception.Message);
        }
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine($"ERROR: {message}");
        return 1;
    }

    private static bool IsHelp(string command) =>
        command is "help" or "--help" or "-h" or "-?" or "/?";

    private static bool IsVersion(string command) =>
        command is "version" or "--version" or "-v";

    private static string GetVersion() =>
        typeof(ProgramMain).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            .Split('+')[0]
        ?? "0.0.0";

    private static int PrintVerbHelp(string command)
    {
        switch (command)
        {
            case "preflight":
                Console.WriteLine(PreflightCommand.Help);
                return 0;

            case "install":
                Console.WriteLine(InstallCommand.Help);
                return 0;

            case "uninstall":
                Console.WriteLine(UninstallCommand.Help);
                return 0;

            case "publish":
                Console.WriteLine(PublishCommand.Help);
                return 0;

            case "status":
                Console.WriteLine(StatusCommand.Help);
                return 0;

            default:
                return Fail($"Unknown command: {command}. Run 'wpshield --help' for the command list.");
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine(
            $"""
            WPShield {GetVersion()} - security gateway for WordPress on Windows Server and IIS (.NET 10)
            RESEARCH PREVIEW. Not approved for production traffic.

            Usage: wpshield <command> [options]

            Commands:
              preflight   Check whether this host is ready. Reads and reports; changes nothing.
                          [--gateway-port 10000] [--private-port 8081,8082] [--site <names>]
                          [--install-path <dir>] [--log-path <dir>] [--output report.jsonl]

              install     Install the gateway as a Windows service with a least-privilege identity
                          and restricted directories. Touches nothing in IIS.
                          --path <build> [--install-path <dir>] [--log-path <dir>]
                          [--config appsettings.Local.json] [--start] [--dry-run]

              uninstall   Remove the service and, optionally, its files. Refuses while an IIS
                          rewrite rule still forwards to the gateway.
                          [--remove-files] [--remove-logs] [--force] [--dry-run]

              status      Report what is installed, which account runs it, and whether it is
                          writing a log. Reads only.

              publish     Build a self-contained win-x64 deployment, with a checksum. Runs on a
                          build machine, not on a server.
                          [--repository <dir>] [--output <dir>] [--skip-archive]

              version     Print the version. --version and -v also work.

            Help:
              wpshield --help             This list. -h, -?, /? and help also work.
              wpshield <command> --help   Everything one command accepts.

            Exit codes:
              0   ready, healthy, or the command did what was asked
              1   an argument was wrong, or the host is not ready
              2   installed, and something about it is wrong
              3   nothing is installed

            Not here on purpose:
              Invoke-WPShieldTriage.ps1 stays a PowerShell script. It runs on hosts that have no
              WPShield installed and are not trusted enough to install one, where being a single
              ASCII file that can be pasted into an RDP window is the point. See ADR 0003.
            """);
    }
}

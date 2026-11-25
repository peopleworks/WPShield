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

        if (command == "network-filter")
        {
            return Fail(NetworkFilterCommand.Unavailable);
        }

        try
        {
            var options = CliOptions.Parse(rest);

            return command switch
            {
                "preflight" => PreflightCommand.Run(options, Console.Out),
                "audit" => AuditCommand.Run(options, Console.Out),
                "install" => InstallCommand.Run(options, Console.Out),
                "uninstall" => UninstallCommand.Run(options, Console.Out),
                "publish" => PublishCommand.Run(options, Console.Out),
                "enable" => EnableCommand.Run(options, Console.Out),
                "disable" => DisableCommand.Run(options, Console.Out),
                "status" => StatusCommand.Run(options, Console.Out),
                // 'site' is the one verb with a sub-action. CliOptions skips tokens that do not start
                // with '--', so the action word passes through the parser harmlessly.
                "setup" => SetupCommand.Run(options, Console.Out),
                "site" => SiteCommand.Run(options, Console.Out, rest.FirstOrDefault() ?? "list"),
                "watch" => WatchCommand.Run(options, Console.Out),
                "report" => ReportCommand.Run(options, Console.Out),
                "preview" => PreviewCommand.Run(options, Console.Out),
                "network-monitor" => NetworkMonitorCommand.Run(options, Console.Out),
                "iis-login" => IisLoginCommand.RunAsync(options, Console.Out).GetAwaiter().GetResult(),
                "audit-reference" => AuditReferenceCommand.RunAsync(options, Console.Out, Console.Error).GetAwaiter().GetResult(),
                "security-monitor" => SecurityMonitorCommand.Run(options, Console.Out),
                "evidence" => EvidenceCommand.Run(options, Console.Out, rest.FirstOrDefault() ?? string.Empty),
                "attacks" => AttacksCommand.Run(options, Console.Out, Console.Error),
                "decisions" => DecisionsCommand.Run(options, Console.Out, Console.Error),
                "web" => WebCommand.Run(options, Console.Out, Console.Error),
                "settings" => SettingsCommand.Run(rest, Console.Out, Console.Error),
                "mcp" => McpCommand.Run(options),
                "analyst" => AnalystCommand.Run(rest, Console.Out, Console.Error),
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

            case "audit":
                Console.WriteLine(AuditCommand.Help);
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

            case "enable":
                Console.WriteLine(EnableCommand.Help);
                return 0;

            case "disable":
                Console.WriteLine(DisableCommand.Help);
                return 0;

            case "status":
                Console.WriteLine(StatusCommand.Help);
                return 0;

            case "setup":
                Console.WriteLine(SetupCommand.Help);
                return 0;

            case "site":
                Console.WriteLine(SiteCommand.Help);
                return 0;

            case "watch":
                Console.WriteLine(WatchCommand.Help);
                return 0;

            case "report":
                Console.WriteLine(ReportCommand.Help);
                return 0;

            case "preview":
                Console.WriteLine(PreviewCommand.Help);
                return 0;

            case "network-monitor":
                Console.WriteLine(NetworkMonitorCommand.Help);
                return 0;

            case "iis-login":
                Console.WriteLine(IisLoginCommand.Help);
                return 0;

            case "audit-reference":
                Console.WriteLine(AuditReferenceCommand.Help);
                return 0;

            case "network-filter":
                Console.WriteLine(NetworkFilterCommand.Help);
                return 0;

            case "security-monitor":
                Console.WriteLine(SecurityMonitorCommand.Help);
                return 0;

            case "evidence":
                Console.WriteLine(EvidenceCommand.Help);
                return 0;

            case "attacks":
                Console.WriteLine(AttacksCommand.Help);
                return 0;

            case "decisions":
                Console.WriteLine(DecisionsCommand.Help);
                return 0;

            case "web":
                Console.WriteLine(WebCommand.Help);
                return 0;

            case "settings":
                Console.WriteLine(SettingsCommand.Help);
                return 0;

            case "mcp":
                Console.WriteLine(McpCommand.Help);
                return 0;

            case "analyst":
                Console.WriteLine(AnalystCommand.Help);
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
              setup       Take ONE site from nothing configured to protected and verified, in five
                          steps, stopping at the first thing that needs you. START HERE.
                          --site <iis-site-name> [--hosts <a,b>] [--destination-port n] [--dry-run]

              preflight   Check whether this host is ready. Reads and reports; changes nothing.
                          [--gateway-port 10000] [--private-port 8081,8082] [--site <names>]
                          [--install-path <dir>] [--log-path <dir>] [--output report.jsonl]

              audit       Audit how this IIS server is put together: pools running as an
                          administrator, PHP mapped for every site, site folders anyone can write,
                          a catch-all site over the others. Reads and reports; changes nothing.
                          [--output report.jsonl]

              install    Install the gateway as a Windows service with a least-privilege identity
                          and restricted directories. Touches nothing in IIS.
                          --path <build> [--install-path <dir>] [--log-path <dir>]
                          [--config appsettings.Local.json] [--start] [--dry-run]

              uninstall   Remove the service and, optionally, its files. Refuses while an IIS
                          rewrite rule still forwards to the gateway.
                          [--remove-files] [--remove-logs] [--force] [--dry-run]

              enable      Put WPShield in the traffic path for ONE site, verify the site still
                          works, and revert everything if it does not.
                          --site <name> [--gateway-port n] [--destination-port n] [--dry-run]

              disable     Take it back out. THIS IS THE ROLLBACK - stopping the service is not.
                          --site <name> [--dry-run]

              site        Tell the gateway which sites to protect. Writes the configuration for
                          you - no hand-written JSON - and restarts the service.
                          site list | site add --id <id> --hosts <a,b> --destination-port <n>
                                     | site remove --id <id>

              status      Report what is installed, which account runs it, and whether it is
                          writing a log. Reads only.

              watch       A live console over the gateway's evidence log: findings and verdicts as
                          they land, with running counts. Reads only.
                          [--log-dir <dir>] [--host <names>] [--from-start] [--plain]

              report      A PDF over a window of the evidence log: executive summary, findings by
                          rule and by site, and a SHA-256 evidence appendix. Reads only.
                          [--log-dir <dir>] [--log-file <file>] [--host <names>] [--since 7d]
                          [--out report.pdf]

              preview     Compare historical inspection scores with a candidate policy. Offline;
                          prints JSON, applies no changes. See 'wpshield preview --help' for limits.
                          --log-file <file.jsonl> --site <id> [--mode Monitor|Block]
                          [--observe-threshold 30] [--block-threshold 80]

              network-monitor
                          Passive HTTP metadata or live TCP/UDP flows (Administrator and Npcap).
                          --listeners [--protocol tcp|udp] [--local-address <IP>] [--ports <numbers>] [--owners] [--port-hints] [--json] reads the local socket tables.
                          --list-interfaces [--json] lists local capture device IDs and IP families.
                          --sql-instance <name> [--json] reads one local Application log snapshot.
                          --flows --interfaces <adapter> (--ports <numbers> | --all-ports) [--json]
                          [--rdp-port <port>] [--sql-instance <name>] [--history]
                          --ports <numbers> [--interfaces <names>] [--output <file>]
                          [--max-events-per-second <n>] [--promiscuous]
                          [--rotation-max-size-bytes <n>] [--rotation-retention-days <n>]

              iis-login   Inspect a copied IIS W3C log for one site's authentication evidence.
                          --log-file <file> --site <s-sitename> [--json]

              audit-reference  Print one source reference from a saved JSON snapshot.
                          --snapshot <report.json> --source <rdp|sql|iis> (--record-id <id> | --line <n>)

              network-filter
                          Unavailable in this preview. No host-wide packet blocking is active.

              security-monitor
                          Read-only Windows Security event log monitor. Detects RDP brute force
                          and failed logons; prints findings as JSON Lines. Requires Administrator
                          elevation. Findings are report-only.
                          --log-name <string> [--event-ids <numbers>]
                          [--max-failed-logons <n>] [--window-minutes <n>] [--allow-list <ips>]
                          [--watch] [--interval-seconds <n>] [--output <file>]

              evidence collect
                          Record failed logons into the evidence store in the foreground, until
                          Ctrl+C. Elevated; refuses while the WPShield service runs. [--store <file>]

              attacks     Failed Windows logons from the WPShield evidence store: totals, top
                          sources with their labels, or one address's history. Reads only;
                          needs an elevated prompt. Says "no data" where nothing was recorded.
                          [--range 1h|6h|24h|7d|30d] [--top N] [--source <ip>] [--store <path>] [--json]

              decisions   What the decision engine decided (Monitor: nothing is blocked), or what is
                          in force now. Reads only; needs an elevated prompt.
                          [--range 1h|6h|24h|7d|30d] [--active] [--target <ip>] [--store <path>] [--json]

              web         What the IIS logs showed (ADR 0011): coverage per site, totals, the
                          addresses rules and observations flagged, recent findings. Reads only;
                          needs an elevated prompt.
                          [--range 1h|6h|24h|7d|30d] [--site <id|name>] [--source <ip>] [--store <path>] [--json]

              settings    The evidence store's settings: retention, labels, the attacks range.
                          list | get <key> | history [<key>] read only; set <key> <value> and
                          reset <key> need elevation and --reason, and are recorded with who and why.

              mcp         A read-only MCP server over the evidence store, for an assistant to start
                          on stdio. Opens no port; changes nothing. Needs elevation. [--store <path>]

              analyst     An optional AI analyst over the evidence store: reads and recommends, never
                          acts. Off by default; your key from the environment, bounded per run and day.
                          status | test | digest [--since 24h] | investigate <ip|net> | ask "<q>"
                          | reports [--last N] | show <id>

              publish    Build a self-contained win-x64 deployment, with a checksum. Runs on a
                          build machine, not on a server.
                          [--repository <dir>] [--output <dir>] [--skip-archive]

              version     Print the version. --version and -v also work.

            Help:
              wpshield --help             This list. -h, -?, /? and help also work.
              wpshield <command> --help   Everything one command accepts.

            Exit codes:
              0   ready, healthy, or the command did what was asked
              1   an argument was wrong, the host is not ready, or a refusal fired
              2   installed, and something about it is wrong; or the audit found a critical weakness
              3   nothing is installed
              4   a change was applied, the site did not answer, everything was reverted

            Not here on purpose:
              Invoke-WPShieldTriage.ps1 stays a PowerShell script. It runs on hosts that have no
              WPShield installed and are not trusted enough to install one, where being a single
              ASCII file that can be pasted into an RDP window is the point. See ADR 0003.
            """);
    }
}

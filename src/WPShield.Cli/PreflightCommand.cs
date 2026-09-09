using System.Globalization;
using System.Text.Json;
using WPShield.Cli.Preflight;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield preflight</c> — read-only readiness check. Reports every blocker, changes nothing.
/// </summary>
internal static class PreflightCommand
{
    public const int ExitReady = 0;
    public const int ExitBlocked = 1;

    public const string Help = """
        wpshield preflight - read-only readiness check for putting WPShield in front of live IIS
        sites. Reports every blocker. Changes nothing.

        Usage: wpshield preflight [options]

          --gateway-port <n>     The loopback port WPShield will listen on. Default 10000.
          --private-port <list>  Candidate loopback ports for the private IIS bindings WPShield
                                 forwards to. Comma-separated. Default 8081,8082.
          --site <names>         IIS site names to plan for. Comma-separated. When omitted, every
                                 site is inventoried and the ones that look like WordPress are
                                 proposed.
          --install-path <dir>   Where WPShield will be installed. Checked for existence and
                                 permissions only. Default C:\Program Files\WPShield.
          --log-path <dir>       Where WPShield will write its log. Checked for whether
                                 unprivileged accounts can read it.
                                 Default C:\ProgramData\WPShield\logs.
          --output <file>        Optional JSON Lines report, in the same envelope the gateway log
                                 and the triage tool use.

        Run it elevated. Without elevation the IIS configuration, the listening ports and the
        directory permissions are all partly or wholly unreadable, and the answer comes out wrong
        in the OPTIMISTIC direction - which is the worst direction for a readiness check. That is
        reported as PRE-001, a blocker, for exactly that reason.

        Exit codes:
          0   ready, no blockers
          1   not ready, or an argument was wrong
        """;

    private static readonly string[] KnownOptions =
    [
        "--gateway-port", "--private-port", "--site", "--install-path", "--log-path", "--output"
    ];

    public static int Run(CliOptions arguments, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);

        arguments.RejectUnknown(KnownOptions);

        var options = new PreflightOptions
        {
            GatewayPort = arguments.Integer("--gateway-port", 10000),
            PrivatePorts = arguments.IntegerList("--private-port", [8081, 8082]),
            SiteNames = arguments.List("--site"),
            InstallPath = arguments.Get("--install-path", @"C:\Program Files\WPShield"),
            LogPath = arguments.Get("--log-path", @"C:\ProgramData\WPShield\logs")
        };

        var runner = new PreflightRunner(new HostFacts(), IisFacts.Read(), options);
        var report = runner.Run();

        Render(report, runner.PlannedSites, options, output);

        var reportPath = arguments.Get("--output");
        if (!string.IsNullOrWhiteSpace(reportPath))
        {
            WriteJsonLines(report, reportPath, output);
        }

        return report.Ready ? ExitReady : ExitBlocked;
    }

    internal static void Render(
        PreflightReport report,
        IReadOnlyList<IisSite> plannedSites,
        PreflightOptions options,
        TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(output);

        output.WriteLine();
        output.WriteLine("WPShield preflight - read-only. No IIS setting, service, binding, ACL or firewall rule is changed.");
        output.WriteLine($"Host: {Environment.MachineName}    {DateTimeOffset.UtcNow.ToString("u", CultureInfo.InvariantCulture)}");
        output.WriteLine();

        foreach (var check in report.Checks)
        {
            output.WriteLine($"  {check.Status.ToString().ToUpperInvariant().PadRight(8)}{check.Id}  {check.Title}");

            if (!string.IsNullOrWhiteSpace(check.Detail))
            {
                // Collapsed to one line. A detail can carry an exception message, and those arrive
                // with embedded newlines that break the column this report is read down.
                output.WriteLine($"           {Collapse(check.Detail)}");
            }
        }

        output.WriteLine();
        output.WriteLine("================================================================================");
        output.WriteLine(report.Ready
            ? $" Ready. {report.Warnings.Count} warning(s), no blockers."
            : $" NOT ready. {report.Blockers.Count} blocker(s), {report.Warnings.Count} warning(s).");
        output.WriteLine("================================================================================");

        // Every blocker carries a remedy. A readiness check that reports a problem without saying
        // what to do about it has moved the problem rather than solved it.
        foreach (var blocker in report.Blockers)
        {
            output.WriteLine($"  {blocker.Id}  {blocker.Title}");
            if (!string.IsNullOrWhiteSpace(blocker.Remedy))
            {
                output.WriteLine($"        {blocker.Remedy}");
            }
        }

        if (plannedSites.Count > 0)
        {
            SuggestedConfiguration.Write(plannedSites, options, output);
        }

        output.WriteLine();
        output.WriteLine("Nothing on this server was changed.");
    }

    /// <summary>
    /// Folds a multi-line detail onto one line.
    /// </summary>
    /// <remarks>
    /// A detail can carry an exception message, and those arrive with embedded newlines that break
    /// the column this report is read down. <c>ReplaceLineEndings</c> rather than a split on
    /// character literals: every escape written by hand in this project has been wrong at least once.
    /// </remarks>
    private static string Collapse(string text)
    {
        return string.Join(
            ' ',
            text.ReplaceLineEndings(" ").Split(' ', StringSplitOptions.RemoveEmptyEntries));
    }

    /// <summary>
    /// The JSON Lines report, in the envelope the gateway log and the triage tool share.
    /// </summary>
    /// <remarks>
    /// Serialised by <c>System.Text.Json</c> rather than by a hand-written escaper. The PowerShell
    /// tools carry three copies of one, and a defect in it corrupted every Windows path in a triage
    /// report — the file looked fine to a human and no parser would read it.
    /// </remarks>
    internal static void WriteJsonLines(PreflightReport report, string path, TextWriter console)
    {
        try
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(path));
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            using var writer = new StreamWriter(path, append: false);
            var timestamp = DateTimeOffset.UtcNow;

            foreach (var check in report.Checks)
            {
                var state = new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["CheckId"] = check.Id,
                    ["Status"] = check.Status.ToString(),
                    ["Title"] = check.Title
                };

                if (!string.IsNullOrWhiteSpace(check.Detail)) { state["Detail"] = check.Detail; }
                if (!string.IsNullOrWhiteSpace(check.Remedy)) { state["Remedy"] = check.Remedy; }

                if (check.Data is not null)
                {
                    foreach (var pair in check.Data)
                    {
                        state[pair.Key] = pair.Value;
                    }
                }

                var entry = new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["timestamp"] = timestamp,
                    ["level"] = check.Status switch
                    {
                        PreflightStatus.Blocker => "Error",
                        PreflightStatus.Warn => "Warning",
                        _ => "Information"
                    },
                    ["category"] = "WPShield.Preflight",
                    ["message"] = $"{check.Id} {check.Title}",
                    ["state"] = state
                };

                writer.WriteLine(JsonSerializer.Serialize(entry));
            }

            console.WriteLine();
            console.WriteLine($"Report written: {Path.GetFullPath(path)}");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            console.WriteLine();
            console.WriteLine($"The report could not be written to {path}: {exception.Message}");
        }
    }
}

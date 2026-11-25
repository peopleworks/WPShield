using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using WPShield.Cli.Audit;
using WPShield.Evidence;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield audit</c> - a read-only posture audit of the IIS host: the configuration that decides
/// whether one compromised site stays one compromised site.
/// </summary>
internal static class AuditCommand
{
    public const int ExitClean = 0;
    public const int ExitIncomplete = 1;
    public const int ExitCritical = 2;

    public const string Help = """
        wpshield audit - read-only posture audit of this IIS server. Reports the configuration that
        lets one compromised site take over the rest. Changes nothing.

        Usage: wpshield audit [--output report.jsonl] [--store <file>]

          --output <file>   Optional JSON Lines report, in the same envelope the gateway log, the
                            preflight and the triage tool use.
          --store <file>    The evidence store the summary is recorded in. Default
                            %ProgramData%\WPShield\evidence\wpshield-evidence.db.

        What it checks:
          AUDIT-001   It could look: running elevated, and IIS readable. When it could not, it says
                      so rather than printing a clean report.
          AUDIT-002   Application pools that run as LocalSystem, or as an account in the local
                      Administrators group. A web shell in any of their sites runs as an
                      administrator of the server.
          AUDIT-003   Pools that share NetworkService or LocalService, so no permission can keep
                      one of their sites out of another's files.
          AUDIT-004   PHP mappings at server and site level, including the WordPress sites that
                      need to keep PHP.
          AUDIT-005   Site folders that Everyone, Users, Authenticated Users or IIS_IUSRS can write
                      into - checked by SID, so it works on a Spanish Windows too.
          AUDIT-006   A site that answers any host name while its folder contains other sites'
                      folders: stopping one of those sites does not take its files offline.
          AUDIT-007   Web roots that share a folder with FTP, contain an FTP folder, or sit inside one.

        It never repairs. Every remedy it prints is a change you make by hand, one pool or one site
        at a time, looking at the site while it happens. It reads the account a pool runs as, never
        the password stored beside it.

        Its one write is to WPShield itself: a summary of the run (finding IDs, severities and counts,
        never names) is recorded in WPShield's evidence store as a posture snapshot (ADR 0013), so
        'wpshield host posture' and the command center can show the progress. That is not a change
        to this server. When the store cannot be opened, the audit still runs and says the summary
        was not recorded.

        Run it elevated. Without elevation the answers come out optimistic, and that is reported as
        AUDIT-001 rather than hidden.

        Exit codes:
          0   no critical finding
          1   it could not look: not elevated, IIS unreadable, or an argument was wrong
          2   at least one critical finding
        """;

    private static readonly string[] KnownOptions = ["--output", "--store"];

    public static int Run(CliOptions arguments, TextWriter output) =>
        Run(arguments, output, AuditFactsReader.Read,
            (report, facts, path) => RecordPosture(report, facts, path, EvidenceAccess.IsElevated()), EvidenceStore.DefaultPath);

    /// <param name="record">Records the posture summary; returns <see langword="null"/> when it was recorded, or why not.</param>
    internal static int Run(CliOptions arguments, TextWriter output, Func<AuditFacts> read,
        Func<AuditReport, AuditFacts, string, string?> record, string defaultStore)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);

        arguments.RejectUnknown(KnownOptions);
        var store = AttacksCommand.StorePath(arguments, defaultStore);

        var facts = read();
        var report = new AuditRunner(facts).Run();

        Render(report, output, record(report, facts, store) is { } notRecorded ? new PostureRecord(false, notRecorded) : new PostureRecord(true, null));

        var reportPath = arguments.Get("--output");
        if (!string.IsNullOrWhiteSpace(reportPath))
        {
            WriteJsonLines(report, reportPath, output);
        }

        return ExitCode(report);
    }

    internal static int ExitCode(AuditReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        if (!report.Complete)
        {
            return ExitIncomplete;
        }

        return report.Criticals.Count > 0 ? ExitCritical : ExitClean;
    }

    /// <summary>Whether the posture summary reached WPShield's evidence store, and why not.</summary>
    internal sealed record PostureRecord(bool Recorded, string? Reason);

    /// <summary>
    /// Records one posture snapshot (ADR 0013) in WPShield's own evidence store: finding IDs, severities and counts,
    /// never names. The store is opened the way a settings change opens it - never created, never migrated.
    /// </summary>
    internal static string? RecordPosture(AuditReport report, AuditFacts facts, string path, bool elevated)
    {
        // An incomplete run must not become the latest posture: it would replace a real reading with "nobody could look".
        if (!report.Complete) return "the audit could not look at everything, so its summary is not a posture reading.";
        try
        {
            using var store = EvidenceAccess.OpenForSettings(path, elevated);
            new HostFactsWriter(store).Write(Host.HostIisFacts.Posture(report, facts, "audit", DateTimeOffset.UtcNow));
            return null;
        }
        catch (EvidenceAccessException exception)
        {
            return exception.Message;
        }
        catch (Exception exception) when (exception is SqliteException or IOException or UnauthorizedAccessException)
        {
            return $"{exception.GetType().Name}: {NetworkMonitorCommand.ConsoleLabel(exception.Message)}";
        }
    }

    internal static void Render(AuditReport report, TextWriter output, PostureRecord? recorded = null)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(output);

        output.WriteLine();
        output.WriteLine("WPShield audit - read-only. No IIS setting, pool, permission, service or firewall rule is changed.");
        output.WriteLine($"Host: {Environment.MachineName}    {DateTimeOffset.UtcNow.ToString("u", CultureInfo.InvariantCulture)}");
        output.WriteLine();

        foreach (var finding in report.Findings)
        {
            output.WriteLine($"  {Label(finding.Severity).PadRight(9)}{finding.Id}  {Printable(finding.Title)}");

            if (!string.IsNullOrWhiteSpace(finding.Detail))
            {
                output.WriteLine($"           {Printable(finding.Detail)}");
            }

            WriteItems(finding.Items, output);
        }

        output.WriteLine();
        output.WriteLine("================================================================================");
        output.WriteLine(Summary(report));
        output.WriteLine("================================================================================");

        // Every warning and critical finding carries a remedy, printed together at the end so that
        // the list of things to do can be read on its own.
        foreach (var finding in report.Findings.Where(finding =>
                     finding.Severity is AuditSeverity.Critical or AuditSeverity.Warn))
        {
            output.WriteLine($"  {finding.Id}  {Printable(finding.Title)}");
            if (!string.IsNullOrWhiteSpace(finding.Remedy))
            {
                output.WriteLine($"        {Printable(finding.Remedy)}");
            }
        }

        output.WriteLine();
        output.WriteLine("Nothing on this server was changed.");
        if (recorded is { Recorded: true })
            output.WriteLine("A summary was recorded in WPShield's evidence store (finding IDs and counts, no names).");
        else if (recorded is { Reason: { } reason })
            output.WriteLine($"The summary was not recorded in WPShield's evidence store: {Printable(reason)}");
    }

    private static string Summary(AuditReport report)
    {
        if (!report.Complete)
        {
            return " INCOMPLETE. The audit could not look at everything; the findings below say what it could not read.";
        }

        return report.Criticals.Count > 0
            ? $" {report.Criticals.Count} critical finding(s), {report.Warnings.Count} warning(s)."
            : $" No critical finding. {report.Warnings.Count} warning(s).";
    }

    private static string Label(AuditSeverity severity) => severity switch
    {
        AuditSeverity.Critical => "CRITICAL",
        AuditSeverity.Warn => "WARN",
        AuditSeverity.Info => "INFO",
        _ => "PASS"
    };

    private static void WriteItems(IReadOnlyList<string>? items, TextWriter output)
    {
        if (items is null || items.Count == 0)
        {
            return;
        }

        foreach (var item in items.Take(AuditRunner.ListLimit))
        {
            output.WriteLine($"             - {Printable(item)}");
        }

        if (items.Count > AuditRunner.ListLimit)
        {
            output.WriteLine($"             ... and {items.Count - AuditRunner.ListLimit} more (all of them are in the --output report).");
        }
    }

    /// <summary>
    /// One line, with nothing a terminal would interpret.
    /// </summary>
    /// <remarks>
    /// Site names, paths and exception messages come from a server that may be compromised, and a
    /// control character or an escape sequence in one of them would reach the terminal intact. The
    /// same rule as the gateway's evidence and the triage report. Line breaks become spaces rather than
    /// question marks, because an exception message is the usual source of those.
    /// </remarks>
    internal static string Printable(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var builder = new StringBuilder(text.Length);

        foreach (var character in text.ReplaceLineEndings(" "))
        {
            builder.Append(char.IsControl(character) ? '?' : character);
        }

        return builder.ToString().Trim();
    }

    /// <summary>
    /// The JSON Lines report, in the envelope the gateway log, the preflight and the triage tool share.
    /// </summary>
    internal static void WriteJsonLines(AuditReport report, string path, TextWriter console)
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

            foreach (var finding in report.Findings)
            {
                var state = new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["CheckId"] = finding.Id,
                    ["Severity"] = finding.Severity.ToString(),
                    ["Title"] = finding.Title
                };

                if (!string.IsNullOrWhiteSpace(finding.Detail)) { state["Detail"] = finding.Detail; }
                if (!string.IsNullOrWhiteSpace(finding.Remedy)) { state["Remedy"] = finding.Remedy; }
                if (finding.Items is { Count: > 0 }) { state["Items"] = finding.Items; }

                if (finding.Data is not null)
                {
                    foreach (var pair in finding.Data)
                    {
                        state[pair.Key] = pair.Value;
                    }
                }

                var entry = new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["timestamp"] = timestamp,
                    ["level"] = finding.Severity switch
                    {
                        AuditSeverity.Critical => "Error",
                        AuditSeverity.Warn => "Warning",
                        _ => "Information"
                    },
                    ["category"] = "WPShield.Audit",
                    ["message"] = $"{finding.Id} {finding.Title}",
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

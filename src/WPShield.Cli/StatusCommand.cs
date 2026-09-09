using System.CommandLine;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield status</c> — what is installed, under which account, and whether it is writing
/// anything down.
/// </summary>
/// <remarks>
/// <para>
/// This verb exists because its four questions had to be answered by hand, from four separate
/// commands, during the first real deployment — and the one that mattered most was the one nobody
/// thought to ask. An install that threw partway through left the gateway running as
/// <c>LocalSystem</c> with both directories still inheriting their parents, and every summary the
/// installer had printed still said otherwise.
/// </para>
/// <para>
/// It reports and returns a verdict. It never starts, stops, writes or changes anything.
/// </para>
/// </remarks>
internal static class StatusCommand
{
    /// <summary>Everything is as an install should leave it.</summary>
    public const int ExitHealthy = 0;

    /// <summary>Something is installed, and something about it is wrong.</summary>
    public const int ExitDegraded = 2;

    /// <summary>Nothing is installed. Not a failure; there is simply nothing to report on.</summary>
    public const int ExitNotInstalled = 3;

    public static Command Create()
    {
        var command = new Command(
            "status",
            "Report what is installed, which account runs it, and whether it is writing a log.");

        command.SetAction(_ => Run(InstallationReport.Gather(), Console.Out));
        return command;
    }

    internal static int Run(InstallationReport report, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(output);

        output.WriteLine();
        output.WriteLine("WPShield status - read-only. Nothing on this machine was changed.");
        output.WriteLine();

        if (!report.ServiceInstalled)
        {
            output.WriteLine("  service            not installed");
            output.WriteLine();
            output.WriteLine("Nothing to report. Install with 'wpshield install', or run");
            output.WriteLine("Invoke-WPShieldPreflight.ps1 first to check this host is ready.");
            return ExitNotInstalled;
        }

        var findings = new List<string>();

        output.WriteLine($"  service            {report.ServiceState}");
        Write(output, "identity", report.ServiceAccount ?? "unreadable");

        // The single most valuable line here. LocalSystem is the most privileged account on the
        // machine, and a gateway that faces hostile traffic has no business holding it.
        if (!string.Equals(report.ServiceAccount, InstallationReport.ExpectedAccount, StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(
                $"The service runs as '{report.ServiceAccount ?? "unknown"}' rather than " +
                $"'{InstallationReport.ExpectedAccount}'. Re-run the install; it sets the identity " +
                "at step 4 of 6, and an install that threw after that step leaves exactly this.");
        }

        Write(output, "installed at", report.InstallDirectory ?? "unreadable");
        Write(output, "listens on", report.ConfiguredUrls ?? "not configured");
        Write(output, "configuration", report.OperatorConfigurationPresent
            ? "appsettings.Local.json present"
            : "appsettings.Local.json MISSING");

        if (!report.OperatorConfigurationPresent)
        {
            findings.Add(
                "There is no appsettings.Local.json, so the gateway resolves no real site. The " +
                "shipped configuration carries .example placeholders only.");
        }

        Write(output, "log directory", report.ConfiguredLogDirectory ?? "not configured");

        if (report.NewestLogFile is null)
        {
            Write(output, "newest log", "none");
            findings.Add(
                "The log directory holds no .jsonl file. In Monitor mode the log is the only " +
                "artefact WPShield produces, so an empty one is a finding rather than a quiet night.");
        }
        else
        {
            Write(
                output,
                "newest log",
                $"{report.NewestLogFile}  ({InstallationReport.FormatTimestamp(report.NewestLogWritten!.Value)})");
        }

        if (report.LogDirectoryBroadAccess.Count > 0)
        {
            Write(output, "log readable by", string.Join(", ", report.LogDirectoryBroadAccess));
            findings.Add(
                "The log directory is readable by an unprivileged group. A WPShield log carries " +
                "request paths, rule hits and client addresses, so on a shared host that is the " +
                "condition PRE-016 refuses.");
        }
        else
        {
            Write(output, "log readable by", "administrators and the service account only");
        }

        foreach (var problem in report.Problems)
        {
            findings.Add(problem);
        }

        output.WriteLine();

        if (findings.Count == 0)
        {
            output.WriteLine("Healthy. The install is complete and the evidence log is restricted.");
            return ExitHealthy;
        }

        output.WriteLine(findings.Count == 1 ? "1 finding:" : $"{findings.Count} findings:");
        foreach (var finding in findings)
        {
            output.WriteLine();
            output.WriteLine($"  - {finding}");
        }

        return ExitDegraded;
    }

    private static void Write(TextWriter output, string label, string value)
    {
        output.WriteLine($"  {label.PadRight(18)} {value}");
    }
}

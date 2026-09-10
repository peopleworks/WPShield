using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using QuestPDF.Fluent;
using QuestPDF.Infrastructure;
using WPShield.Cli.Report;
using WPShield.Cli.Watch;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield report</c> — a PDF over a window of the gateway's evidence log.
/// </summary>
/// <remarks>
/// <para>
/// The durable companion to <c>watch</c>. Where <c>watch</c> is the live view, this reads the same
/// JSON Lines files and produces the report an operator files or forwards: an executive summary, the
/// findings broken down by rule and by site, and a SHA-256 evidence appendix that ties the report to
/// the exact log it was built from.
/// </para>
/// <para>
/// It reads only. It opens each log for shared reading, hashes it, and writes one PDF where it was
/// told to. It never touches the gateway, IIS, or the service.
/// </para>
/// </remarks>
internal static class ReportCommand
{
    public const string Help = """
        wpshield report - a PDF over a window of the gateway's evidence log. Reads only.

        Usage: wpshield report [options]

          --log-dir <dir>   The gateway's log directory. Default: the directory the installed
                            service is configured to use, else C:\ProgramData\WPShield\logs.
          --log-file <file> A single log file to report on instead of a directory - for a log
                            pulled off a server.
          --host <name>     Report only on this site (the gateway's SiteId). Comma-separate for
                            several: --host a.example,b.example.
          --since <window>  Only events newer than this: 24h, 7d, 90m, 1d. Default: everything in
                            the files.
          --out <file>      Where to write the PDF. Default: wpshield-report-<timestamp>.pdf in the
                            current directory.

        The report counts what the gateway wrote down - findings, verdicts, and inspected uploads -
        not total traffic, because a clean non-upload request is never logged. The evidence appendix
        hashes every source file with SHA-256, so the report can be tied to the exact log it
        summarised.

        Exit codes:
          0   a report was written
          1   an argument was wrong, or no log file could be read
        """;

    private static readonly string[] KnownOptions =
    [
        "--log-dir", "--log-file", "--host", "--since", "--out"
    ];

    public static int Run(CliOptions arguments, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);

        arguments.RejectUnknown(KnownOptions);

        var hosts = arguments.List("--host");
        var since = ParseSince(arguments.Get("--since"));
        var files = ResolveFiles(arguments.Get("--log-file"), arguments.Get("--log-dir"));
        var outputPath = ResolveOutputPath(arguments.Get("--out"));

        var generatedAt = DateTimeOffset.Now;
        var cutoff = since is { } window ? generatedAt - window : (DateTimeOffset?)null;

        var events = new List<EvidenceEvent>();
        var sources = new List<EvidenceSource>();

        foreach (var file in files)
        {
            var (source, fileEvents) = ReadSource(file, hosts, cutoff);
            sources.Add(source);
            events.AddRange(fileEvents);
        }

        var model = ReportAggregator.Build(events, sources, hosts, generatedAt);

        // Community licence: an MIT research preview by a company well under the revenue threshold the
        // licence names. Set once, before anything is rendered.
        QuestPDF.Settings.License = LicenseType.Community;
        new ReportPdf(model).GeneratePdf(outputPath);

        output.WriteLine();
        output.WriteLine($"  wrote     {outputPath}");
        output.WriteLine($"  window    {WindowText(model)}");
        output.WriteLine($"  events    {model.TotalEvents} ({model.Findings} findings, {model.Blocked} blocked, {model.Observed} observed)");
        output.WriteLine($"  sources   {sources.Count} file(s), hashed in the appendix");
        output.WriteLine();

        return 0;
    }

    /// <summary>Reads one file: its fixity, and the events it contributes after the host and window filters.</summary>
    private static (EvidenceSource Source, List<EvidenceEvent> Events) ReadSource(
        string path,
        IReadOnlyList<string> hosts,
        DateTimeOffset? cutoff)
    {
        var events = new List<EvidenceEvent>();
        var totalLines = 0;
        long size = 0;
        var hash = "unreadable";

        try
        {
            size = new FileInfo(path).Length;
            hash = HashFile(path);

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Encoding.UTF8);

            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                totalLines++;
                var evidence = EvidenceParser.Parse(line);
                if (evidence is null || evidence.Kind == EvidenceKind.Other)
                {
                    continue;
                }

                if (cutoff is { } floor && evidence.Timestamp < floor)
                {
                    continue;
                }

                if (hosts.Count > 0 &&
                    (evidence.Host is null ||
                     !hosts.Any(host => string.Equals(host, evidence.Host, StringComparison.OrdinalIgnoreCase))))
                {
                    continue;
                }

                events.Add(evidence);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A file that cannot be read is still recorded in the appendix, marked unreadable, rather
            // than dropped: a report that silently omits a source it could not open is a report that
            // hides its own gap.
        }

        var source = new EvidenceSource
        {
            FileName = Path.GetFileName(path),
            SizeBytes = size,
            Sha256 = hash,
            TotalLines = totalLines,
            ParsedEvents = events.Count
        };

        return (source, events);
    }

    private static string HashFile(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexStringLower(hash);
    }

    /// <summary>
    /// The files to read: an explicit single file, or every log file in the resolved directory.
    /// </summary>
    private static IReadOnlyList<string> ResolveFiles(string? explicitFile, string? explicitDirectory)
    {
        if (!string.IsNullOrWhiteSpace(explicitFile))
        {
            if (!File.Exists(explicitFile))
            {
                throw new CliArgumentException($"--log-file '{explicitFile}' does not exist.");
            }

            return [explicitFile];
        }

        var directory = EvidenceLog.ResolveDirectory(explicitDirectory);
        var files = new DirectoryInfo(directory)
            .GetFiles(EvidenceLog.SearchPattern)
            .OrderBy(file => file.Name, StringComparer.OrdinalIgnoreCase)
            .Select(file => file.FullName)
            .ToArray();

        if (files.Length == 0)
        {
            throw new CliArgumentException(
                $"No {EvidenceLog.SearchPattern} files in '{directory}'. There is nothing to report on yet.");
        }

        return files;
    }

    private static string ResolveOutputPath(string? explicitOut)
    {
        if (!string.IsNullOrWhiteSpace(explicitOut))
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(explicitOut));
            if (directory is not null && !Directory.Exists(directory))
            {
                throw new CliArgumentException($"The output directory '{directory}' does not exist.");
            }

            return Path.GetFullPath(explicitOut);
        }

        var name = FormattableString.Invariant(
            $"wpshield-report-{DateTime.Now:yyyyMMdd-HHmmss}.pdf");
        return Path.GetFullPath(name);
    }

    /// <summary>Parses <c>24h</c>, <c>7d</c>, <c>90m</c> into a span. Null input means no window.</summary>
    private static TimeSpan? ParseSince(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var text = value.Trim();
        var unit = text[^1];
        var numberPart = text[..^1];

        if (!int.TryParse(numberPart, NumberStyles.Integer, CultureInfo.InvariantCulture, out var amount) || amount <= 0)
        {
            throw new CliArgumentException(
                $"--since must be a positive number followed by m, h or d, for example 24h or 7d. It was '{value}'.");
        }

        return char.ToLowerInvariant(unit) switch
        {
            'm' => TimeSpan.FromMinutes(amount),
            'h' => TimeSpan.FromHours(amount),
            'd' => TimeSpan.FromDays(amount),
            _ => throw new CliArgumentException(
                $"--since unit must be m, h or d, for example 24h or 7d. It was '{value}'.")
        };
    }

    private static string WindowText(ReportModel model)
    {
        if (model.WindowStart is not { } start || model.WindowEnd is not { } end)
        {
            return "no events in range";
        }

        return $"{start.ToUniversalTime():yyyy-MM-dd HH:mm} to {end.ToUniversalTime():yyyy-MM-dd HH:mm} UTC";
    }
}

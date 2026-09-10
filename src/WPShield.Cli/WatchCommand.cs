using WPShield.Cli.Watch;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield watch</c> — a live console over the gateway's evidence log.
/// </summary>
/// <remarks>
/// <para>
/// This is the first verb that is for watching rather than changing. It tails the JSON Lines file the
/// gateway already writes and shows findings and verdicts as they land, with running counts of what
/// WPShield saw and did. It reads only: it opens the log for shared reading and never writes, never
/// touches IIS, and never starts or stops the service.
/// </para>
/// <para>
/// <b>The counts are honest about what the log contains.</b> A clean request that is not a multipart
/// upload is not written to the log at all, so there is no total request rate to show and the console
/// does not pretend to one. What it shows — findings, observed, blocked, and the events-per-second of
/// those — are all lines the gateway actually recorded.
/// </para>
/// </remarks>
internal static class WatchCommand
{
    public const string Help = """
        wpshield watch - a live console over the gateway's evidence log. Reads only.

        Usage: wpshield watch [options]

          --log-dir <dir>   The gateway's log directory. Default: the directory the installed
                            service is configured to use, else C:\ProgramData\WPShield\logs.
          --host <name>     Show only lines for this site (the gateway's SiteId). Repeat by
                            comma-separating: --host a.example,b.example.
          --from-start      Read the current log file from its top before following. Default is
                            to start at the end and show what happens next.
          --plain           Line-by-line output with no live redraw. Chosen automatically when
                            output is redirected, so 'wpshield watch --plain > feed.txt' works.
          --interval <ms>   How often to poll the file. Default 500. Minimum 100.

        What it shows: one row per finding and per request verdict - time, site, rule, score, and
        the action the gateway took (Observe, Block, or Allow for a clean upload). A footer keeps
        the running totals and an events-per-second sparkline.

        What it does NOT show: clean traffic. The gateway does not log a request that produced no
        finding, and only a multipart upload records an Allow, so there is no total request rate
        here - only what WPShield saw and did.

        Stop it with Ctrl+C. Nothing on this machine is changed by running it.

        Exit codes:
          0   stopped cleanly
          1   an argument was wrong, or no log directory could be found
        """;

    private static readonly string[] KnownOptions =
    [
        "--log-dir", "--host", "--from-start", "--plain", "--interval"
    ];

    public static int Run(CliOptions arguments, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);

        arguments.RejectUnknown(KnownOptions);

        var interval = arguments.Integer("--interval", 500);
        if (interval < 100)
        {
            throw new CliArgumentException("--interval is in milliseconds and must be at least 100.");
        }

        var hosts = arguments.List("--host");
        var fromStart = arguments.Flag("--from-start");
        var logDirectory = EvidenceLog.ResolveDirectory(arguments.Get("--log-dir"));

        var settings = new WatchSettings
        {
            LogDirectory = logDirectory,
            Hosts = hosts,
            FromStart = fromStart,
            PollInterval = TimeSpan.FromMilliseconds(interval)
        };

        var plain = arguments.Flag("--plain") || Console.IsOutputRedirected;

        var session = new WatchSession(settings);
        return plain
            ? session.RunPlain(output)
            : session.RunLive();
    }
}

/// <summary>The resolved inputs to a watch session.</summary>
internal sealed record WatchSettings
{
    public required string LogDirectory { get; init; }

    public IReadOnlyList<string> Hosts { get; init; } = [];

    public bool FromStart { get; init; }

    public TimeSpan PollInterval { get; init; } = TimeSpan.FromMilliseconds(500);

    /// <summary>Whether a line's site passes the host filter. No filter means everything passes.</summary>
    public bool Includes(EvidenceEvent evidence)
    {
        if (Hosts.Count == 0)
        {
            return true;
        }

        return evidence.Host is not null &&
            Hosts.Any(host => string.Equals(host, evidence.Host, StringComparison.OrdinalIgnoreCase));
    }
}

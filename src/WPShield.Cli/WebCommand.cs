using System.Globalization;
using System.Net;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using WPShield.Evidence;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield web</c> - what the IIS logs showed (ADR 0011), from the evidence store, read-only. The same
/// store access, exit codes and cleaning as <c>wpshield attacks</c> and <c>decisions</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Coverage comes first.</b> A site whose log nobody could read and a quiet site must never look alike,
/// so the answer starts with which sites were read and which were not, and why, before any count.
/// </para>
/// <para>
/// <b>Paths and user agents are attacker-chosen.</b> They were normalized, cleaned and bounded before
/// they were stored; they are cleaned again for the console and labelled as untrusted.
/// </para>
/// </remarks>
internal static class WebCommand
{
    public const string Help = """
        wpshield web - what the IIS logs of this host showed, from the evidence store (ADR 0011). Reads only.

        Usage: wpshield web [--range 1h|6h|24h|7d|30d] [--site <id|name>] [--source <ip>] [--store PATH] [--json]

          --range <r>     How far back. Default: 24h. Ranges from 24h up start on a whole hour.
          --site <s>      One IIS site, by ID (the number in its W3SVC log folder) or by name.
          --source <ip>   One address: its counts on every site, and its findings.
          --store <path>  The evidence store.
                          Default: %ProgramData%\WPShield\evidence\wpshield-evidence.db
          --json          One JSON document on stdout. Errors go to stderr.

        EVIDENCE ONLY. Nothing is decided from web evidence in this version and nothing is blocked.

        What is recorded ('wpshield evidence collect' or the service reads each site's W3C log):
          findings       requests a request-path rule flagged, the same rules the gateway runs
                         (WP-PATH-001 ...), with the normalized path - never the logged one
          WEB-OBS-001    a 2xx answer to a .php file that is not a WordPress entry point: how a
                         webshell answers. An observation: evidence only, never a score
          WEB-OBS-002    a POST to wp-login.php, counted per address and hour
          WEB-OBS-003    a POST to xmlrpc.php, counted per address and hour
        Requests are counted per site and hour, so totals cover the whole hours that overlap the
        range. Addresses are kept per hour only when they were flagged or sent more than 50 client
        errors. The query string, the referer and the user name of a request are never read.

        Exit codes:
          0   answered
          1   an argument was wrong, or the store could not be opened (not elevated, access denied)
          2   the store cannot be read by this build, or the sensor recorded nothing for the range
          3   there is no evidence store
        """;

    internal const int TopShown = 20;
    internal const int FindingsShown = 25;
    private static readonly string[] Known = ["--range", "--site", "--source", "--store", "--json"];

    public static int Run(CliOptions arguments, TextWriter output, TextWriter error) =>
        Run(arguments, output, error, EvidenceStore.DefaultPath, EvidenceAccess.IsElevated, () => DateTimeOffset.UtcNow);

    internal static int Run(CliOptions arguments, TextWriter output, TextWriter error, string defaultStore,
        Func<bool> elevated, Func<DateTimeOffset> now)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        arguments.RejectUnknown(Known);
        arguments.RejectRepeated();
        if (arguments.Get("--json") is not null) throw new CliArgumentException("--json takes no value.");
        var range = "24h";
        if (arguments.Has("--range"))
        {
            range = arguments.Get("--range")?.Trim().ToLowerInvariant() ?? "";
            if (!EvidenceRanges.IsName(range)) throw new CliArgumentException("--range must be one of 1h, 6h, 24h, 7d or 30d.");
        }
        string? siteText = null;
        if (arguments.Has("--site"))
        {
            siteText = arguments.Get("--site")?.Trim();
            if (string.IsNullOrEmpty(siteText) || siteText.Length > WebEvidenceWriter.MaxSiteNameLength || siteText.Any(char.IsControl))
                throw new CliArgumentException("--site requires a site ID or an IIS site name.");
        }
        string? source = null;
        if (arguments.Has("--source"))
        {
            source = IPAddress.TryParse(arguments.Get("--source")?.Trim(), out var address)
                ? (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString()
                : throw new CliArgumentException("--source must be one IP address, for example 203.0.113.7.");
        }
        var path = AttacksCommand.StorePath(arguments, defaultStore);
        var json = arguments.Has("--json");

        EvidenceStore store;
        try
        {
            store = EvidenceAccess.OpenReadOnly(path, elevated());
        }
        catch (EvidenceAccessException ex)
        {
            error.WriteLine("ERROR: " + ex.Message);
            return ex.ExitCode;
        }

        using (store)
        {
            try
            {
                var queries = new WebEvidenceQueries(store);
                var sites = queries.Sites();
                WebSiteCoverage? site = null;
                if (siteText is not null)
                {
                    site = long.TryParse(siteText, NumberStyles.None, CultureInfo.InvariantCulture, out var id)
                        ? sites.FirstOrDefault(s => s.SiteId == id)
                        : sites.FirstOrDefault(s => string.Equals(s.Name, siteText, StringComparison.OrdinalIgnoreCase));
                    if (site is null)
                    {
                        error.WriteLine($"ERROR: the sensor knows no site '{NetworkMonitorCommand.ConsoleLabel(siteText)}'. " +
                            "Run without --site to list the sites it knows.");
                        return 1;
                    }
                }
                return Answer(output, path, queries, sites, site, source, EvidenceRanges.Window(range, now()), json);
            }
            catch (Exception ex) when (ex is SqliteException or InvalidOperationException or InvalidCastException or FormatException)
            {
                error.WriteLine("ERROR: the evidence store could not be read: " + NetworkMonitorCommand.ConsoleLabel(ex.Message));
                return 2;
            }
        }
    }

    private static int Answer(TextWriter output, string path, WebEvidenceQueries queries, IReadOnlyList<WebSiteCoverage> sites,
        WebSiteCoverage? site, string? source, EvidenceWindow window, bool json)
    {
        var siteId = site?.SiteId;
        var sourceName = siteId is null ? WebEvidenceWriter.SensorSource : WebEvidenceWriter.SiteSource(siteId.Value);
        var coverage = CoverageReport.Analyse(queries.Coverage(window.From, window.To), window.From, window.To, sourceName);
        var summary = queries.Summary(window.From, window.To, siteId);
        var rules = queries.RuleCounts(window.From, window.To, siteId, source);
        var top = source is null ? queries.TopSources(window.From, window.To, siteId, TopShown + 1) : [];
        var one = source is null ? null
            : queries.TopSources(window.From, window.To, siteId, WebEvidenceQueries.MaxSources, includeProtected: true)
                .FirstOrDefault(s => s.Address == source);
        var findings = queries.Findings(window.From, window.To, siteId, source, FindingsShown + 1);
        var noData = coverage.State == CoverageReport.None && summary.Requests == 0 && findings.Count == 0;

        if (json)
        {
            output.WriteLine(JsonSerializer.Serialize(new Document(path, window.Name, window.From, window.To, summary.HoursFrom, summary.HoursTo,
                "evidence-only", siteId, source,
                sites.Select(s => new SiteDto(s.SiteId, s.Name, s.Status, s.Reason, s.Remedy, s.Proxied, s.UpdatedAt)).ToArray(),
                new CoverageDto(coverage.State, coverage.Gaps.Select(g => new GapDto(g.From, g.To, g.Status, g.Reason)).ToArray(), coverage.Omitted),
                noData ? null : summary, noData ? null : rules, noData ? null : (one is null ? top.Take(TopShown).ToArray() : [one]),
                noData ? null : findings.Take(FindingsShown).Select(FindingDto.From).ToArray(), findings.Count > FindingsShown), AttacksCommand.JsonOptions));
            return noData ? 2 : 0;
        }

        output.WriteLine($"Evidence store   {NetworkMonitorCommand.ConsoleLabel(path)} (read-only)");
        output.WriteLine($"Range            {window.Describe()}: {AttacksCommand.Minute(window.From)} to {AttacksCommand.Minute(window.To)} UTC");
        output.WriteLine($"Counted hours    {AttacksCommand.Minute(summary.HoursFrom)} to {AttacksCommand.Minute(summary.HoursTo)} UTC " +
            "(requests are counted per site and hour)");
        output.WriteLine("Mode             evidence only - nothing is decided from web evidence and nothing is blocked");
        WriteSites(output, sites, site);
        WriteCoverage(output, coverage, site is null ? "Sensor coverage" : "Site coverage");
        output.WriteLine();

        if (noData)
        {
            output.WriteLine("Requests         no data");
            output.WriteLine();
            output.WriteLine("No data: the IIS log sensor recorded nothing for this range - which is not the same as no requests.");
            output.WriteLine("Run 'wpshield evidence collect' (or the service) on the IIS host, elevated, and look again.");
            return 2;
        }

        if (source is not null)
        {
            output.WriteLine($"Source           {source}  (network {EvidenceQueries.Network(source)})");
            if (one is null)
                output.WriteLine("                 no hourly counts kept: it was not flagged and sent at most 50 client errors in any hour");
            else
            {
                output.WriteLine($"                 requests {AttacksCommand.Number(one.Requests)}, 4xx {AttacksCommand.Number(one.ClientErrors)}, " +
                    $"findings {AttacksCommand.Number(one.Findings)}, observations {AttacksCommand.Number(one.Observations)}, " +
                    $"wp-login POSTs {AttacksCommand.Number(one.LoginPosts)}, xmlrpc POSTs {AttacksCommand.Number(one.XmlrpcPosts)}, " +
                    $"sites {one.Sites}");
                output.WriteLine($"                 first {AttacksCommand.Minute(one.First)}, last {AttacksCommand.Minute(one.Last)} UTC" +
                    (one.Protection is null ? "" : $"; never counted against it: {NetworkMonitorCommand.ConsoleLabel(one.Protection)}"));
            }
        }
        else
        {
            output.WriteLine($"Requests         {AttacksCommand.Number(summary.Requests)}  (4xx {AttacksCommand.Number(summary.ClientErrors)}, " +
                $"5xx {AttacksCommand.Number(summary.ServerErrors)})");
            output.WriteLine($"Flagged          findings {AttacksCommand.Number(summary.Findings)}, observations {AttacksCommand.Number(summary.Observations)} " +
                $"(WEB-OBS-001), wp-login POSTs {AttacksCommand.Number(summary.LoginPosts)}, xmlrpc POSTs {AttacksCommand.Number(summary.XmlrpcPosts)}");
            output.WriteLine($"Addresses        {AttacksCommand.Number(summary.Sources)} kept" +
                (summary.ProtectedSources > 0
                    ? $", and {AttacksCommand.Number(summary.ProtectedSources)} the evidence never counts against (this host, the allow-list, private ranges, proxied sites)"
                    : ""));
        }
        if (summary.FindingsFrom is { } pruned)
            output.WriteLine($"                 findings before {AttacksCommand.Minute(pruned)} UTC were pruned; the hourly counts remain");
        output.WriteLine();

        if (rules.Count > 0)
        {
            output.WriteLine("Rules and observations");
            AttacksCommand.WriteTable(output, ["ID", "REQUESTS", "KIND"], rules.Select(r => new[]
            {
                NetworkMonitorCommand.ConsoleLabel(r.Id), AttacksCommand.Number(r.Requests), r.Observation ? "observation (evidence only)" : "rule"
            }).ToArray(), rightAligned: [1]);
            output.WriteLine();
        }

        if (source is null)
        {
            if (top.Count == 0)
                output.WriteLine("No address was flagged or sent more than 50 client errors in an hour" +
                    (coverage.State == CoverageReport.Full ? "." : " in the part of this range that was recorded."));
            else
            {
                output.WriteLine("Addresses (kept per hour when flagged, or with more than 50 client errors)");
                AttacksCommand.WriteTable(output, ["ADDRESS", "REQUESTS", "4XX", "FINDINGS", "OBS", "LOGIN", "XMLRPC", "SITES", "NETWORK", "NEIGHBORS", "LAST (UTC)"],
                    top.Take(TopShown).Select(s => new[]
                    {
                        s.Address, AttacksCommand.Number(s.Requests), AttacksCommand.Number(s.ClientErrors), AttacksCommand.Number(s.Findings),
                        AttacksCommand.Number(s.Observations), AttacksCommand.Number(s.LoginPosts), AttacksCommand.Number(s.XmlrpcPosts),
                        s.Sites.ToString(CultureInfo.InvariantCulture), s.Network, AttacksCommand.Number(s.Neighbors), AttacksCommand.Minute(s.Last)
                    }).ToArray(), rightAligned: [1, 2, 3, 4, 5, 6, 7, 9]);
                if (top.Count > TopShown) output.WriteLine($"Showing the top {TopShown}; name a --source or a --site to narrow.");
            }
            output.WriteLine();
        }

        if (findings.Count == 0)
        {
            output.WriteLine("No finding was stored in this range.");
            return 0;
        }
        output.WriteLine("Recent findings - the paths and agents were chosen by whoever sent the request: untrusted text, cleaned");
        AttacksCommand.WriteTable(output, ["TIME (UTC)", "SITE", "ADDRESS", "METHOD", "STATUS", "RULES", "PATH"],
            findings.Take(FindingsShown).Select(f => new[]
            {
                AttacksCommand.Minute(f.Timestamp), f.SiteId.ToString(CultureInfo.InvariantCulture), f.Address,
                NetworkMonitorCommand.ConsoleLabel(f.Method), f.Status.ToString(CultureInfo.InvariantCulture),
                NetworkMonitorCommand.ConsoleLabel(string.Join(',', f.Hits.Select(h => h.Id))) + (f.Live ? "" : " (history)"),
                NetworkMonitorCommand.ConsoleLabel(Bound(f.Path, 120))
            }).ToArray(), rightAligned: [4]);
        if (findings.Count > FindingsShown) output.WriteLine($"Showing the newest {FindingsShown}; narrow with --site or --source, or use --json.");
        return 0;
    }

    private static void WriteSites(TextWriter output, IReadOnlyList<WebSiteCoverage> sites, WebSiteCoverage? site)
    {
        if (sites.Count == 0)
        {
            output.WriteLine("Sites            none known: the IIS log sensor has not run against this store");
            return;
        }
        if (site is not null)
        {
            output.WriteLine($"Site             {site.SiteId} {NetworkMonitorCommand.ConsoleLabel(site.Name)}: {Describe(site)}");
            if (site.Remedy is not null) output.WriteLine($"                 remedy: {NetworkMonitorCommand.ConsoleLabel(site.Remedy)}");
            return;
        }
        var read = sites.Count(s => s.Status == "collected");
        var ignored = sites.Count(s => s.Status == "ignored");
        var notRead = sites.Count - read - ignored;
        output.WriteLine($"Sites            {sites.Count} known: {read} read, {notRead} not read" +
            (ignored > 0 ? $", {ignored} ignored (no HTTP binding)" : ""));
        foreach (var problem in sites.Where(s => s.Status is not "collected" and not "ignored").Take(20))
        {
            output.WriteLine($"                   {problem.SiteId} {NetworkMonitorCommand.ConsoleLabel(Bound(problem.Name, 40))}: {Describe(problem)}");
            if (problem.Remedy is not null) output.WriteLine($"                     remedy: {NetworkMonitorCommand.ConsoleLabel(problem.Remedy)}");
        }
        if (notRead > 20) output.WriteLine($"                   and {notRead - 20} more ('--json' lists them all)");
    }

    private static string Describe(WebSiteCoverage site) =>
        (site.Status == "collected" ? "read" : site.Status == "ignored" ? "ignored" : "not read") +
        (site.Reason is null ? "" : $" ({NetworkMonitorCommand.ConsoleLabel(site.Reason)})") +
        (site.Proxied ? ", behind a proxy (http.proxied_sites)" : "");

    private static void WriteCoverage(TextWriter output, CoverageReport coverage, string label)
    {
        var head = label.PadRight(17);
        switch (coverage.State)
        {
            case CoverageReport.Full:
                output.WriteLine($"{head}recorded for the whole range");
                break;
            case CoverageReport.None:
                output.WriteLine($"{head}none: the sensor recorded no interval in this range" + AttacksCommand.Why(coverage.Gaps[0]));
                break;
            default:
                output.WriteLine($"{head}gaps - these times were not read, which is no data, never zero:");
                foreach (var gap in coverage.Gaps)
                    output.WriteLine($"                   {AttacksCommand.Minute(gap.From)} to {AttacksCommand.Minute(gap.To)} UTC{AttacksCommand.Why(gap)}");
                if (coverage.Omitted > 0) output.WriteLine($"                   and {AttacksCommand.Number(coverage.Omitted)} more gap(s)");
                break;
        }
    }

    private static string Bound(string text, int max) => text.Length <= max ? text : text[..(max - 1)] + "…";

    private sealed record Document(string Store, string Range, DateTimeOffset From, DateTimeOffset To, DateTimeOffset CountedFrom,
        DateTimeOffset CountedTo, string Mode, long? Site, string? Source, IReadOnlyList<SiteDto> Sites, CoverageDto Coverage,
        WebSummary? Summary, IReadOnlyList<WebRuleCount>? Rules, IReadOnlyList<WebSource>? Addresses, IReadOnlyList<FindingDto>? Findings,
        bool FindingsTruncated);

    private sealed record SiteDto(long Id, string Name, string Status, string? Reason, string? Remedy, bool Proxied, DateTimeOffset UpdatedAt);

    private sealed record CoverageDto(string State, IReadOnlyList<GapDto> Gaps, int Omitted);

    private sealed record GapDto(DateTimeOffset From, DateTimeOffset To, string? Status, string? Reason);

    /// <summary>A finding as JSON. The path and the agent are wrapped as untrusted: the attacker chose them.</summary>
    private sealed record FindingDto(DateTimeOffset Time, long Site, string Address, string Method, int Status, IReadOnlyList<string> Rules,
        int Score, Untrusted Path, Untrusted UserAgent, bool Live, bool Proxied, string? Protection)
    {
        public static FindingDto From(WebFindingRecord f) => new(f.Timestamp, f.SiteId, f.Address, f.Method, f.Status,
            f.Hits.Select(h => h.Id).ToArray(), f.Score, new(f.Path), new(f.UserAgent), f.Live, f.Proxied, f.Protection);
    }

    private sealed record Untrusted(string Value);
}

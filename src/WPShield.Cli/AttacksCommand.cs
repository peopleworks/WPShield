using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using WPShield.Evidence;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield attacks</c> - failed Windows logons from the evidence store (ADR 0007), read-only.
/// </summary>
/// <remarks>
/// <para>
/// Every answer says what it is made of. A period older than the detailed records is answered from
/// hourly aggregates and says so; time the collector did not record is listed as "no data" and never
/// added up as zero; a store that cannot be opened is an error with its reason, never an empty table.
/// </para>
/// <para>
/// Account names and labels are attacker- or operator-written text. They are printed through
/// <see cref="NetworkMonitorCommand.ConsoleLabel"/> and, with <c>--json</c>, escaped by the serializer.
/// </para>
/// </remarks>
internal static class AttacksCommand
{
    public const string Help = """
        wpshield attacks - failed Windows logons from the WPShield evidence store. Reads only.

        Usage: wpshield attacks [--range 1h|6h|24h|7d|30d] [--top N] [--source IP] [--store PATH] [--json]

          --range <r>     How far back. Default: the attacks.default_range setting (24h when unset).
                          24h and 7d start on a whole hour and 30d on a whole UTC day, so hourly
                          totals add up exactly; a range is never shorter than its name.
          --top <n>       Source addresses to list, 1..1000. Default: 20.
          --source <ip>   One address's history instead of the top sources.
          --store <path>  The evidence store.
                          Default: %ProgramData%\WPShield\evidence\wpshield-evidence.db
          --json          One JSON document on stdout. Errors go to stderr.

        The WPShield service writes the store; this command opens it read-only. Its folder admits only
        administrators and the service, so run this from an elevated prompt.

        What every answer says about itself:
          - Periods older than the detailed records are answered from hourly aggregates. The counts
            are exact; account names, logon types and single attempts are no longer kept.
          - Time the collector did not record is listed as "no data", never counted as zero.
          - Account names were chosen by the attacker. Control and format characters are replaced.
          - Labels (the labels.addresses setting) name an address. They never allow or block it.

        Exit codes:
          0   answered
          1   an argument was wrong, or the store could not be opened (not elevated, access denied)
          2   the store cannot be read by this build, or it recorded nothing for the range
          3   there is no evidence store
        """;

    internal const int DefaultTop = 20;
    private const int RecentAttempts = 20;
    private const int AccountsShown = 10;
    private static readonly string[] Known = ["--range", "--top", "--source", "--store", "--json"];

    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

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
        string? range = null;
        if (arguments.Has("--range"))
        {
            range = arguments.Get("--range")?.Trim().ToLowerInvariant();
            if (!EvidenceRanges.IsName(range)) throw new CliArgumentException("--range must be one of 1h, 6h, 24h, 7d or 30d.");
        }
        var top = arguments.Integer("--top", DefaultTop);
        if (top < 1 || top > EvidenceQueries.MaxSources)
            throw new CliArgumentException($"--top must be a number from 1 to {EvidenceQueries.MaxSources}.");
        IPAddress? source = null;
        if (arguments.Has("--source") && !IPAddress.TryParse(arguments.Get("--source")?.Trim(), out source))
            throw new CliArgumentException("--source must be one IP address, for example 203.0.113.7.");
        var path = StorePath(arguments, defaultStore);
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
                var settings = new EvidenceSettings(store);
                var window = EvidenceRanges.Window(range ?? DefaultRange(settings), now());
                var context = new Context(path, window, new EvidenceQueries(store), AddressLabels.Read(store), RawDays(settings), json);
                var coverage = CoverageReport.Analyse(context.Queries.Coverage(window.From, window.To), window.From, window.To);
                return source is null
                    ? Sources(output, context, coverage, top)
                    : History(output, context, coverage, source);
            }
            catch (Exception ex) when (ex is SqliteException or InvalidOperationException or InvalidCastException or FormatException
                                           or JsonException or KeyNotFoundException)
            {
                error.WriteLine("ERROR: the evidence store could not be read: " + NetworkMonitorCommand.ConsoleLabel(ex.Message));
                return 2;
            }
        }
    }

    /// <summary><c>--store</c>, refusing the option without a path rather than falling back silently.</summary>
    internal static string StorePath(CliOptions arguments, string fallback)
    {
        if (!arguments.Has("--store")) return fallback;
        var value = arguments.Get("--store");
        if (string.IsNullOrWhiteSpace(value)) throw new CliArgumentException("--store requires the path of the evidence store.");
        return value.Trim();
    }

    /// <summary>The <c>attacks.default_range</c> setting, or 24h when it is unset or unreadable.</summary>
    internal static string DefaultRange(EvidenceSettings settings) =>
        settings.Get("attacks.default_range") is JsonValue value && value.TryGetValue<string>(out var text) && EvidenceRanges.IsName(text)
            ? text
            : "24h";

    private static int? RawDays(EvidenceSettings settings) =>
        settings.Get("retention.raw_days") is JsonValue value && value.TryGetValue<int>(out var days) ? days : null;

    private sealed record Context(string Path, EvidenceWindow Window, EvidenceQueries Queries, AddressLabels Labels, int? RawDays, bool Json);

    private static int Sources(TextWriter output, Context context, CoverageReport coverage, int top)
    {
        var window = context.Window;
        var summary = context.Queries.Summary(window.From, window.To);
        var rows = context.Queries.TopSources(window.From, window.To, top);
        // Nothing recorded and nothing counted is "no data", not a quiet host.
        var noData = coverage.State == CoverageReport.None && summary.Attempts == 0;

        if (context.Json)
        {
            output.WriteLine(JsonSerializer.Serialize(new SourcesDocument(context.Path, window.Name, window.From, window.To,
                summary.Detailed, Coverage(coverage),
                noData
                    ? new SummaryDto(null, null, null, null, null, null)
                    : new SummaryDto(summary.Attempts, summary.Sources, summary.WithoutAddress, summary.UnknownAccount,
                        Share(summary.UnknownAccount, summary.Attempts), summary.Detailed ? summary.TopAccount : null),
                noData ? null : rows.Select(r => new SourceDto(r.Address, context.Labels.For(r.Address), r.Attempts, r.UnknownAccount,
                    Share(r.UnknownAccount, r.Attempts) ?? 0, r.Accounts, r.Network, r.Neighbors, r.First, r.Last)).ToArray()), JsonOptions));
            return noData ? 2 : 0;
        }

        Header(output, context, summary.Detailed, coverage);
        if (noData)
        {
            output.WriteLine("Failed attempts       no data");
            output.WriteLine("Source addresses      no data");
            output.WriteLine();
            output.WriteLine("No data: the collector recorded nothing for this range, so there is nothing to count - which is not");
            output.WriteLine("the same as no attacks. Check that the WPShield service is running and can read the Security log.");
            return 2;
        }

        var withoutAddress = summary.WithoutAddress > 0 ? $"  ({Number(summary.WithoutAddress)} without a source address)" : "";
        output.WriteLine($"Failed attempts       {Number(summary.Attempts)}{withoutAddress}");
        output.WriteLine($"Source addresses      {Number(summary.Sources)}");
        output.WriteLine($"Nonexistent accounts  {Percent(summary.UnknownAccount, summary.Attempts)} of attempts");
        output.WriteLine("Most tried account    " + (!summary.Detailed ? "not kept for this period"
            : summary.TopAccount is { Length: > 0 } account ? NetworkMonitorCommand.ConsoleLabel(account) : "no record names one"));
        if (coverage.State == CoverageReport.None)
            output.WriteLine("Note: no recorded interval covers this range, so these counts are a floor and quiet time cannot be told from unrecorded time.");
        output.WriteLine();

        if (rows.Count == 0)
        {
            output.WriteLine(coverage.State == CoverageReport.Full
                ? "No failed logon with a source address was recorded in this range."
                : "No failed logon with a source address was recorded in the part of this range that was covered.");
            return 0;
        }

        output.WriteLine($"Top {Number(rows.Count)} of {Number(summary.Sources)} source addresses");
        var labelled = rows.Any(r => context.Labels.For(r.Address) is not null);
        string[] headers = labelled
            ? ["ADDRESS", "ATTEMPTS", "NONEXISTENT", "ACCOUNTS", "NETWORK", "NEIGHBOURS", "FIRST (UTC)", "LAST (UTC)", "LABEL"]
            : ["ADDRESS", "ATTEMPTS", "NONEXISTENT", "ACCOUNTS", "NETWORK", "NEIGHBOURS", "FIRST (UTC)", "LAST (UTC)"];
        var table = rows.Select(r =>
        {
            string[] cells = [r.Address, Number(r.Attempts), Percent(r.UnknownAccount, r.Attempts),
                r.Accounts is long accounts ? Number(accounts) : "-", r.Network, Number(r.Neighbors), Minute(r.First), Minute(r.Last)];
            return labelled ? [.. cells, Label(context.Labels.For(r.Address))] : cells;
        }).ToArray();
        WriteTable(output, headers, table, rightAligned: [1, 2, 3, 5]);
        if (!summary.Detailed)
            output.WriteLine("ACCOUNTS is '-' because account names are no longer kept for this period.");
        return 0;
    }

    private static int History(TextWriter output, Context context, CoverageReport coverage, IPAddress address)
    {
        var window = context.Window;
        var canonical = (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();
        var history = context.Queries.SourceHistory(canonical, window.From, window.To, RecentAttempts);
        var attempts = history.Timeline.Sum(b => b.Attempts);
        var unknown = history.Timeline.Sum(b => b.UnknownAccount);
        var noData = coverage.State == CoverageReport.None && attempts == 0;
        var label = context.Labels.For(history.Address);
        var network = EvidenceQueries.Network(history.Address);

        if (context.Json)
        {
            output.WriteLine(JsonSerializer.Serialize(new HistoryDocument(context.Path, window.Name, window.From, window.To,
                history.Detailed, Coverage(coverage), new HistoryDto(history.Address, label, network, history.FirstSeen, history.DaysSeen,
                    noData ? null : attempts, noData ? null : unknown,
                    history.Detailed ? history.Accounts.Select(a => new AccountDto(a.Account, a.Count)).ToArray() : null,
                    history.Detailed ? history.Recent.Select(f => new AttemptDto(f.Timestamp, f.Account, f.Reason, f.LogonType, f.Port, f.Channel)).ToArray() : null,
                    history.Timeline.Select(b => new BucketDto(b.Start, b.End, b.Attempts, b.UnknownAccount, b.Covered)).ToArray())), JsonOptions));
            return noData ? 2 : 0;
        }

        Header(output, context, history.Detailed, coverage);
        output.WriteLine($"Source           {history.Address}{(label is null ? "" : "  [" + Label(label) + "]")}");
        output.WriteLine($"Network          {network}");
        output.WriteLine(history.FirstSeen is { } first
            ? $"First seen       {Minute(first)} UTC, on {Number(history.DaysSeen)} different day(s) in the whole store"
            : "First seen       never: the store holds no failed logon from this address");
        if (noData)
        {
            output.WriteLine("In this range    no data");
            output.WriteLine();
            output.WriteLine("No data: the collector recorded nothing for this range, so there is nothing to count.");
            return 2;
        }
        output.WriteLine($"In this range    {Number(attempts)} attempt(s), {Percent(unknown, attempts)} on nonexistent accounts");
        output.WriteLine("Accounts tried   " + (!history.Detailed ? "not kept for this period (hourly aggregates)"
            : history.Accounts.Count == 0 ? "no record names one"
            : string.Join(", ", history.Accounts.Take(AccountsShown).Select(a => $"{NetworkMonitorCommand.ConsoleLabel(a.Account)} ({Number(a.Count)})")) +
              (history.Accounts.Count > AccountsShown ? $", and {Number(history.Accounts.Count - AccountsShown)} more" : "")));
        output.WriteLine();

        var size = history.Timeline.Count > 0 ? history.Timeline[0].End - history.Timeline[0].Start : TimeSpan.Zero;
        output.WriteLine($"Attempts per {(size >= TimeSpan.FromDays(1) ? "day" : size >= TimeSpan.FromHours(1) ? "hour" : "5 minutes")} (UTC)");
        WriteTimeline(output, history.Timeline, size >= TimeSpan.FromDays(1));

        if (history.Detailed && history.Recent.Count > 0)
        {
            output.WriteLine();
            output.WriteLine("Latest attempts (UTC)");
            foreach (var attempt in history.Recent)
                output.WriteLine($"  {attempt.Timestamp.ToUniversalTime():yyyy-MM-dd HH:mm:ss}  " +
                    $"{(attempt.Account.Length > 0 ? NetworkMonitorCommand.ConsoleLabel(attempt.Account) : "-")}  " +
                    $"{NetworkMonitorCommand.ConsoleLabel(attempt.Reason)}" +
                    (attempt.LogonType is int type ? $"  logon type {type.ToString(CultureInfo.InvariantCulture)}" : ""));
        }
        else if (!history.Detailed)
        {
            output.WriteLine();
            output.WriteLine("Single attempts are no longer kept for this period.");
        }
        return 0;
    }

    private static void Header(TextWriter output, Context context, bool detailed, CoverageReport coverage)
    {
        var window = context.Window;
        output.WriteLine($"Evidence store   {NetworkMonitorCommand.ConsoleLabel(context.Path)} (read-only)");
        output.WriteLine($"Range            {window.Describe()}: {Minute(window.From)} to {Minute(window.To)} UTC");
        output.WriteLine(detailed
            ? "Records          detailed: every attempt and the account it named"
            : "Records          hourly aggregates: the counts are exact, but account names, logon types and single attempts");
        if (!detailed)
            output.WriteLine("                 are no longer kept for this period" +
                (context.RawDays is int days ? $" (detailed records are kept {days.ToString(CultureInfo.InvariantCulture)} days)" : ""));
        switch (coverage.State)
        {
            case CoverageReport.Full:
                output.WriteLine("Coverage         recorded for the whole range");
                break;
            case CoverageReport.None:
                output.WriteLine("Coverage         none: the collector recorded no interval in this range" + Why(coverage.Gaps[0]));
                break;
            default:
                output.WriteLine("Coverage         gaps - these times were not recorded and read as no data, never as zero:");
                foreach (var gap in coverage.Gaps)
                    output.WriteLine($"                   {Minute(gap.From)} to {Minute(gap.To)} UTC{Why(gap)}");
                if (coverage.Omitted > 0) output.WriteLine($"                   and {Number(coverage.Omitted)} more gap(s)");
                break;
        }
        output.WriteLine();
    }

    private static string Why(CoverageGap gap) => gap.Status is null ? ""
        : "  (" + NetworkMonitorCommand.ConsoleLabel(gap.Status) + (gap.Reason is null ? "" : ": " + NetworkMonitorCommand.ConsoleLabel(gap.Reason)) + ")";

    /// <summary>
    /// The timeline with runs of empty buckets folded into one line, so a 30-day answer is readable. A
    /// run of recorded empty buckets says 0; a run of unrecorded ones says "no data".
    /// </summary>
    private static void WriteTimeline(TextWriter output, IReadOnlyList<EvidenceBucket> buckets, bool days)
    {
        string Time(DateTimeOffset t) => t.ToUniversalTime().ToString(days ? "yyyy-MM-dd" : "yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
        for (var i = 0; i < buckets.Count;)
        {
            var bucket = buckets[i];
            if (bucket.Attempts > 0)
            {
                output.WriteLine($"  {Time(bucket.Start)}  {Number(bucket.Attempts)}" +
                    (bucket.UnknownAccount > 0 ? $"  ({Number(bucket.UnknownAccount)} nonexistent)" : "") +
                    (bucket.Covered ? "" : "  (not all of this interval was recorded)"));
                i++;
                continue;
            }
            var run = i;
            while (run + 1 < buckets.Count && buckets[run + 1].Attempts == 0 && buckets[run + 1].Covered == bucket.Covered) run++;
            var what = bucket.Covered ? "0" : "no data";
            output.WriteLine(run == i
                ? $"  {Time(bucket.Start)}  {what}"
                : $"  {Time(bucket.Start)} to {Time(buckets[run].End)}  {what}");
            i = run + 1;
        }
    }

    private static void WriteTable(TextWriter output, string[] headers, string[][] rows, int[] rightAligned)
    {
        var widths = headers.Select((h, c) => Math.Max(h.Length, rows.Max(r => r[c].Length))).ToArray();
        string Line(string[] cells) => string.Join("  ", cells.Select((cell, c) =>
            rightAligned.Contains(c) ? cell.PadLeft(widths[c]) : c == cells.Length - 1 ? cell : cell.PadRight(widths[c]))).TrimEnd();
        output.WriteLine(Line(headers));
        foreach (var row in rows) output.WriteLine(Line(row));
    }

    private static string Label(string? label) => label is null ? "" : NetworkMonitorCommand.ConsoleLabel(label);

    private static string Number(long value) => value.ToString("N0", CultureInfo.InvariantCulture);

    private static double? Share(long part, long whole) => whole == 0 ? null : (double)part / whole;

    private static string Percent(long part, long whole) =>
        whole == 0 ? "-" : Math.Round(100.0 * part / whole).ToString("0", CultureInfo.InvariantCulture) + "%";

    private static string Minute(DateTimeOffset time) => time.ToUniversalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);

    private static CoverageDto Coverage(CoverageReport report) =>
        new(report.State, report.Gaps.Select(g => new GapDto(g.From, g.To, g.Status, g.Reason)).ToArray(), report.Omitted);

    // The JSON shapes. Projected rather than serialising the query records: those carry value-tuple
    // lists and IPAddress values, which System.Text.Json writes as {} or worse.
    private sealed record CoverageDto(string State, IReadOnlyList<GapDto> Gaps, int GapsOmitted);

    private sealed record GapDto(DateTimeOffset From, DateTimeOffset To, string? Status, string? Reason);

    private sealed record SummaryDto(long? Attempts, long? Sources, long? WithoutAddress, long? UnknownAccount, double? UnknownShare, string? TopAccount);

    private sealed record SourceDto(string Address, string? Label, long Attempts, long UnknownAccount, double UnknownShare, long? Accounts,
        string Network, long Neighbors, DateTimeOffset First, DateTimeOffset Last);

    private sealed record SourcesDocument(string Store, string Range, DateTimeOffset From, DateTimeOffset To, bool Detailed,
        CoverageDto Coverage, SummaryDto Summary, IReadOnlyList<SourceDto>? Sources);

    private sealed record AccountDto(string Account, long Count);

    private sealed record AttemptDto(DateTimeOffset Time, string Account, string Reason, int? LogonType, int? Port, string Channel);

    private sealed record BucketDto(DateTimeOffset Start, DateTimeOffset End, long Attempts, long UnknownAccount, bool Covered);

    private sealed record HistoryDto(string Address, string? Label, string Network, DateTimeOffset? FirstSeen, int DaysSeen,
        long? Attempts, long? UnknownAccount, IReadOnlyList<AccountDto>? Accounts, IReadOnlyList<AttemptDto>? Recent,
        IReadOnlyList<BucketDto> Timeline);

    private sealed record HistoryDocument(string Store, string Range, DateTimeOffset From, DateTimeOffset To, bool Detailed,
        CoverageDto Coverage, HistoryDto Source);
}

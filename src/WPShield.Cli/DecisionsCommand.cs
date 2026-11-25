using System.Net;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield decisions</c> - what the decision engine (ADR 0009) decided, from the evidence store,
/// read-only. The same store access, exit codes and cleaning as <c>wpshield attacks</c>.
/// </summary>
/// <remarks>
/// <para>
/// This version decides in Monitor only, and every answer says so: a <c>would-block</c> is what Block
/// mode would have done, never something that was done.
/// </para>
/// <para>
/// "In force" is the store's one definition (<see cref="EvidenceQueries.ActiveDecisions"/>): made by the
/// engine run that started last, unexpired, and only while the collector is recording, because a decision
/// never outlives the process that made it and a restart writes no <c>expire</c> for what it forgot.
/// </para>
/// </remarks>
internal static class DecisionsCommand
{
    public const string Help = """
        wpshield decisions - what the WPShield decision engine decided, from the evidence store. Reads only.

        Usage: wpshield decisions [--range 1h|6h|24h|7d|30d] [--active] [--target IP] [--store PATH] [--json]

          --range <r>     How far back. Default: 24h. Ranges from 24h up start on a whole hour.
          --active        The decisions in force now instead of a range. Takes no --range.
          --target <ip>   One address - its own decisions and its /24 or /64's - or one network
                          exactly as a decision names it, for example 203.0.113.0/24.
          --store <path>  The evidence store.
                          Default: %ProgramData%\WPShield\evidence\wpshield-evidence.db
          --json          One JSON document on stdout. Errors go to stderr.

        MONITOR ONLY. Nothing is blocked. 'would-block' is what Block mode would have done; Block mode
        does not exist yet (ADR 0009, ADR 0006).

        Actions:
          would-block   a rule fired; the target would be blocked until the expiry shown
          protected     a rule fired on an address the engine never decides against (the allow-list,
                        this host, a private range, a Remote Desktop session); shown until the
                        would-be block would have ended
          refused       a rule fired and the engine could not check what it must check, or too many
                        decisions were active; nothing was decided
          report        HOST-AUTH-004: one existing account failing from many addresses. Never blocks,
                        and the account is not named; 'wpshield attacks --source' shows it
          expire        a would-block ended, at its expiry or when the process that made it stopped

        In force (--active) means made by the engine run that started last, unexpired, while the
        service is recording. A decision never outlives the process that made it.

        Exit codes:
          0   answered
          1   an argument was wrong, or the store could not be opened (not elevated, access denied)
          2   the store cannot be read by this build, or it recorded nothing for the range
          3   there is no evidence store
        """;

    internal const int Shown = 200;
    private static readonly string[] Known = ["--range", "--active", "--target", "--store", "--json"];

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
        if (arguments.Get("--active") is not null) throw new CliArgumentException("--active takes no value.");
        var active = arguments.Has("--active");
        var range = "24h";
        if (arguments.Has("--range"))
        {
            if (active) throw new CliArgumentException("--active shows what is in force now; it takes no --range.");
            range = arguments.Get("--range")?.Trim().ToLowerInvariant() ?? "";
            if (!EvidenceRanges.IsName(range)) throw new CliArgumentException("--range must be one of 1h, 6h, 24h, 7d or 30d.");
        }
        var target = arguments.Has("--target") ? Target(arguments.Get("--target")) : null;
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
                var queries = new EvidenceQueries(store);
                return active
                    ? Active(output, path, queries.ActiveDecisions(now()), target, json)
                    : Recent(output, path, queries, EvidenceRanges.Window(range, now()), target, json);
            }
            catch (Exception ex) when (ex is SqliteException or InvalidOperationException or InvalidCastException or FormatException)
            {
                error.WriteLine("ERROR: the evidence store could not be read: " + NetworkMonitorCommand.ConsoleLabel(ex.Message));
                return 2;
            }
        }
    }

    /// <summary>An address, made canonical, or a network written exactly as a decision names one.</summary>
    private static string Target(string? text)
    {
        text = text?.Trim();
        if (text is not null && text.Contains('/', StringComparison.Ordinal))
            return AddressRanges.TryParseCanonical(text, out var network)
                ? AddressRanges.Text(network)
                : throw new CliArgumentException("--target: a network must be written with no bit set after the prefix, for example 203.0.113.0/24.");
        return IPAddress.TryParse(text, out var address)
            ? AddressRanges.Canonical(address).ToString()
            : throw new CliArgumentException("--target must be one IP address or network, for example 203.0.113.7 or 203.0.113.0/24.");
    }

    private static int Recent(TextWriter output, string path, EvidenceQueries queries, EvidenceWindow window, string? target, bool json)
    {
        var coverage = CoverageReport.Analyse(queries.Coverage(window.From, window.To), window.From, window.To);
        var rows = target is null ? queries.Decisions(window.From, window.To, Shown + 1)
            : target.Contains('/', StringComparison.Ordinal) ? queries.Decisions(window.From, window.To, Shown + 1, target)
            : queries.DecisionsAbout(target, window.From, window.To, Shown + 1);
        var shown = rows.Take(Shown).ToArray();
        var truncated = rows.Count > Shown;
        // No decision where nothing was recorded is "no data": the engine only decides while the collector runs.
        var noData = coverage.State == CoverageReport.None && rows.Count == 0;

        if (json)
        {
            output.WriteLine(JsonSerializer.Serialize(new RecentDocument(path, window.Name, window.From, window.To, DecisionActions.MonitorMode,
                target, new CoverageDto(coverage.State, coverage.Gaps.Select(g => new GapDto(g.From, g.To, g.Status, g.Reason)).ToArray(), coverage.Omitted),
                noData ? null : Counts(shown), noData ? null : shown.Select(Dto).ToArray(), truncated), AttacksCommand.JsonOptions));
            return noData ? 2 : 0;
        }

        output.WriteLine($"Evidence store   {NetworkMonitorCommand.ConsoleLabel(path)} (read-only)");
        output.WriteLine($"Range            {window.Describe()}: {AttacksCommand.Minute(window.From)} to {AttacksCommand.Minute(window.To)} UTC");
        if (target is not null)
            output.WriteLine($"Target           {target}" + (target.Contains('/', StringComparison.Ordinal) ? "" : $" and its network {EvidenceQueries.Network(target)}"));
        output.WriteLine("Mode             monitor - nothing is blocked; would-block is what Block mode would have done");
        switch (coverage.State)
        {
            case CoverageReport.Full:
                output.WriteLine("Coverage         recorded for the whole range");
                break;
            case CoverageReport.None:
                output.WriteLine("Coverage         none: the collector recorded no interval in this range" + AttacksCommand.Why(coverage.Gaps[0]));
                break;
            default:
                output.WriteLine("Coverage         gaps - nothing was decided in these times, because nothing was recorded:");
                foreach (var gap in coverage.Gaps)
                    output.WriteLine($"                   {AttacksCommand.Minute(gap.From)} to {AttacksCommand.Minute(gap.To)} UTC{AttacksCommand.Why(gap)}");
                if (coverage.Omitted > 0) output.WriteLine($"                   and {AttacksCommand.Number(coverage.Omitted)} more gap(s)");
                break;
        }
        output.WriteLine();

        if (noData)
        {
            output.WriteLine("Decisions        no data");
            output.WriteLine();
            output.WriteLine("No data: the collector recorded nothing for this range, and the engine decides only on what it records -");
            output.WriteLine("which is not the same as nothing to decide. Check that the WPShield service is running.");
            return 2;
        }

        var counts = Counts(shown);
        output.WriteLine($"Decisions        {AttacksCommand.Number(rows.Count > Shown ? Shown : rows.Count)}{(truncated ? "+" : "")}" +
            $"  (would-block {counts.WouldBlock}, protected {counts.Protected}, refused {counts.Refused}, report {counts.Report}, expire {counts.Expire})");
        output.WriteLine();
        if (shown.Length == 0)
        {
            output.WriteLine(coverage.State == CoverageReport.Full
                ? "No decision was made in this range."
                : "No decision was made in the part of this range that was recorded.");
            return 0;
        }
        AttacksCommand.WriteTable(output, ["TIME (UTC)", "ACTION", "TARGET", "RULE", "EXPIRES (UTC)", "REASON"],
            shown.Select(d => new[]
            {
                AttacksCommand.Minute(d.Timestamp), Clean(d.Action, 16), Clean(d.Target, 64), Clean(d.RuleId, 32),
                d.ExpiresAt is { } expires ? AttacksCommand.Minute(expires) : "-", Clean(d.Reason, 200)
            }).ToArray(), rightAligned: []);
        if (truncated) output.WriteLine($"Showing the newest {Shown}; narrow the range or name a --target to see the rest.");
        return 0;
    }

    private static int Active(TextWriter output, string path, ActiveDecisions active, string? target, bool json)
    {
        IReadOnlyList<DecisionRecord> rows = target is null ? active.Decisions
            : target.Contains('/', StringComparison.Ordinal) ? active.Decisions.Where(d => d.Target == target).ToArray()
            : active.For(target) is { } one ? [one] : [];
        var why = active.EngineStarted is null
            ? "the decision engine has never run on this store"
            : !active.CollectorCurrent
                ? active.CollectedUntil is { } until
                    ? $"the collector has not recorded since {AttacksCommand.Minute(until)} UTC, so the process that made the decisions is not running"
                    : "the collector has never recorded on this store"
                : null;

        if (json)
        {
            output.WriteLine(JsonSerializer.Serialize(new ActiveDocument(path, active.At, DecisionActions.MonitorMode, target, active.EngineStarted,
                active.CollectedUntil, active.CollectorCurrent, rows.Select(Dto).ToArray(), active.Truncated,
                why is null
                    ? "Monitor: nothing is blocked. These are what Block mode would be enforcing now. A decision never outlives the process that made it."
                    : "No decision is in force: " + why + ". A decision never outlives the process that made it."), AttacksCommand.JsonOptions));
            return 0;
        }

        output.WriteLine($"Evidence store   {NetworkMonitorCommand.ConsoleLabel(path)} (read-only)");
        output.WriteLine($"At               {AttacksCommand.Minute(active.At)} UTC");
        if (target is not null)
            output.WriteLine($"Target           {target}" + (target.Contains('/', StringComparison.Ordinal) ? "" : $" and its network {EvidenceQueries.Network(target)}"));
        output.WriteLine("Mode             monitor - nothing is blocked; these are what Block mode would be enforcing now");
        output.WriteLine(active.EngineStarted is { } started
            ? $"Engine           started {AttacksCommand.Minute(started)} UTC; only decisions made since then can be in force"
            : "Engine           never started on this store");
        output.WriteLine(active.CollectorCurrent
            ? $"Collector        recording (coverage reaches {AttacksCommand.Minute(active.CollectedUntil!.Value)} UTC)"
            : active.CollectedUntil is { } last ? $"Collector        not recording since {AttacksCommand.Minute(last)} UTC" : "Collector        never recorded");
        output.WriteLine();
        if (why is not null)
        {
            output.WriteLine($"No decision is in force: {why}. A decision never outlives the process that made it.");
            return 0;
        }
        var counts = Counts(rows);
        output.WriteLine($"In force now     {AttacksCommand.Number(rows.Count)}  (would-block {counts.WouldBlock}, protected {counts.Protected})");
        output.WriteLine();
        if (rows.Count == 0)
        {
            output.WriteLine(target is null ? "No decision is in force." : "No decision about this target is in force.");
            return 0;
        }
        AttacksCommand.WriteTable(output, ["TARGET", "ACTION", "RULE", "SINCE (UTC)", "UNTIL (UTC)", "REASON"],
            rows.Select(d => new[]
            {
                Clean(d.Target, 64), Clean(d.Action, 16), Clean(d.RuleId, 32), AttacksCommand.Minute(d.Timestamp),
                d.ExpiresAt is { } until ? AttacksCommand.Minute(until) : "-", Clean(d.Reason, 200)
            }).ToArray(), rightAligned: []);
        if (active.Truncated) output.WriteLine($"The newest {EvidenceQueries.MaxDecisionScan:N0} records were read; older ones in force may be missing.");
        return 0;
    }

    /// <summary>Stored text is cleaned when written; it is cleaned again for the terminal, as every reader does.</summary>
    private static string Clean(string text, int max) => NetworkMonitorCommand.ConsoleLabel(EvidenceText.Clean(text, max));

    private static CountsDto Counts(IReadOnlyCollection<DecisionRecord> decisions)
    {
        int Of(string action) => decisions.Count(d => d.Action == action);
        return new(Of(DecisionActions.WouldBlock), Of(DecisionActions.Protected), Of(DecisionActions.Refused), Of(DecisionActions.Report),
            Of(DecisionActions.Expire));
    }

    private static DecisionDto Dto(DecisionRecord d) => new(d.Timestamp, EvidenceText.Clean(d.Action, 16), EvidenceText.Clean(d.Target, 64),
        EvidenceText.Clean(d.RuleId, 32), EvidenceText.Clean(d.Mode, 16), EvidenceText.Clean(d.Reason, 200),
        d.RequestedBy is null ? null : EvidenceText.Clean(d.RequestedBy, 64), d.ExpiresAt);

    private sealed record DecisionDto(DateTimeOffset Time, string Action, string Target, string RuleId, string Mode, string Reason,
        string? RequestedBy, DateTimeOffset? Expires);

    private sealed record CountsDto(int WouldBlock, int Protected, int Refused, int Report, int Expire);

    private sealed record CoverageDto(string State, IReadOnlyList<GapDto> Gaps, int GapsOmitted);

    private sealed record GapDto(DateTimeOffset From, DateTimeOffset To, string? Status, string? Reason);

    private sealed record RecentDocument(string Store, string Range, DateTimeOffset From, DateTimeOffset To, string Mode, string? Target,
        CoverageDto Coverage, CountsDto? Counts, IReadOnlyList<DecisionDto>? Decisions, bool Truncated);

    private sealed record ActiveDocument(string Store, DateTimeOffset At, string Mode, string? Target, DateTimeOffset? EngineStarted,
        DateTimeOffset? CollectedUntil, bool CollectorCurrent, IReadOnlyList<DecisionDto> Active, bool Truncated, string Note);
}

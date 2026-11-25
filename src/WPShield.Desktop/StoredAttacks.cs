using WPShield.Cli;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;

namespace WPShield.Desktop;

/// <summary>What opening the store told the window: the labels, the range to open with, and the decisions in force.</summary>
internal sealed record AttackStoreStatus(AddressLabels Labels, string DefaultRange, ActiveDecisions Decisions);

/// <summary>One read of the evidence store for a 7-day or 30-day range, kept until the next refresh.</summary>
/// <param name="LastHour">Attempts in the last hour, or <see langword="null"/> when the service recorded none of it.</param>
internal sealed record StoredAttacks(AttackRange Range, EvidenceWindow Window, EvidenceSummary Summary,
    IReadOnlyList<EvidenceSource> Sources, IReadOnlyList<EvidenceBucket> Timeline, long? LastHour, CoverageReport Coverage,
    AddressLabels Labels);

/// <summary>
/// The evidence store, as the attacks view asks it. Every call opens the store read-only, asks through
/// <see cref="EvidenceQueries"/> and closes it again, so no connection is ever shared between threads
/// and a closed window holds no file open. A store that cannot be opened throws
/// <see cref="EvidenceAccessException"/>, which says why.
/// </summary>
internal interface IAttackStore
{
    AttackStoreStatus Probe(DateTimeOffset now);

    /// <summary>Decisions about one address and its /24 or /64, newest first.</summary>
    IReadOnlyList<DecisionRecord> Decisions(string address, DateTimeOffset from, DateTimeOffset to);

    StoredAttacks Read(AttackRange range, DateTimeOffset now);

    EvidenceSourceHistory History(string address, EvidenceWindow window);
}

internal sealed class EvidenceAttackStore(string path, Func<bool> elevated) : IAttackStore
{
    public AttackStoreStatus Probe(DateTimeOffset now)
    {
        using var store = EvidenceAccess.OpenReadOnly(path, elevated());
        return new(AddressLabels.Read(store), AttacksCommand.DefaultRange(new EvidenceSettings(store)),
            new EvidenceQueries(store).ActiveDecisions(now));
    }

    public IReadOnlyList<DecisionRecord> Decisions(string address, DateTimeOffset from, DateTimeOffset to)
    {
        using var store = EvidenceAccess.OpenReadOnly(path, elevated());
        return new EvidenceQueries(store).DecisionsAbout(address, from, to, AttackDecisions.DetailRows);
    }

    public StoredAttacks Read(AttackRange range, DateTimeOffset now)
    {
        using var store = EvidenceAccess.OpenReadOnly(path, elevated());
        var window = EvidenceRanges.Window(StoredAttackBoard.Name(range), now);
        var queries = new EvidenceQueries(store);
        var hourAgo = window.To - TimeSpan.FromHours(1);
        var lastHour = queries.Summary(hourAgo, window.To).Attempts;
        var lastHourRecorded = CoverageReport.Analyse(queries.Coverage(hourAgo, window.To), hourAgo, window.To).State != CoverageReport.None;
        return new(range, window, queries.Summary(window.From, window.To),
            queries.TopSources(window.From, window.To, EvidenceQueries.MaxSources),
            queries.Timeline(window.From, window.To, window.Bucket),
            lastHour == 0 && !lastHourRecorded ? null : lastHour,
            CoverageReport.Analyse(queries.Coverage(window.From, window.To), window.From, window.To),
            AddressLabels.Read(store));
    }

    public EvidenceSourceHistory History(string address, EvidenceWindow window)
    {
        using var store = EvidenceAccess.OpenReadOnly(path, elevated());
        return new EvidenceQueries(store).SourceHistory(address, window.From, window.To);
    }
}

/// <summary>
/// Turns a read of the evidence store into what the attacks view shows - the same records the live
/// board produces, so the window draws both one way.
/// </summary>
/// <remarks>
/// The store's top-sources question returns counts, not the accounts or logon types of each row, so
/// those columns say "—" rather than pretending to be empty; a source's detail asks for its accounts.
/// From hourly aggregates the account count is unknown, not zero.
/// </remarks>
internal static class StoredAttackBoard
{
    internal const string NotAsked = "—";

    internal static bool IsStored(AttackRange range) => range is AttackRange.Week or AttackRange.Month;

    internal static string Name(AttackRange range) => range switch
    {
        AttackRange.Hour => "1h",
        AttackRange.SixHours => "6h",
        AttackRange.Day => "24h",
        AttackRange.Week => "7d",
        _ => "30d"
    };

    internal static AttackRange Parse(string? name) => name switch
    {
        "1h" => AttackRange.Hour,
        "6h" => AttackRange.SixHours,
        "7d" => AttackRange.Week,
        "30d" => AttackRange.Month,
        _ => AttackRange.Day
    };

    internal static AttackView View(StoredAttacks stored, string query, int maxRows = 500)
    {
        var summary = stored.Summary;
        var rows = stored.Sources.Select(s => Source(s, stored.Labels)).ToArray();
        var matching = rows.Where(r => r.Matches(query)).ToArray();
        var noData = stored.Coverage.State == CoverageReport.None && summary.Attempts == 0;
        return new(Int(summary.Attempts), Int(summary.Sources), Int(summary.WithoutAddress),
            summary.Attempts == 0 ? 0 : (double)summary.UnknownAccount / summary.Attempts, Int(stored.LastHour ?? 0),
            summary.TopAccount ?? "", stored.Timeline.Select(Bucket).ToArray(), matching.Take(maxRows).ToArray(), matching.Length,
            summary.CoveredFrom, summary.Detailed, noData, LastHourKnown: stored.LastHour is not null);
    }

    /// <summary>The detail of one source; <see langword="null"/> when it is not among the sources read.</summary>
    internal static AttackDetail? Detail(StoredAttacks stored, EvidenceSourceHistory history)
    {
        var row = stored.Sources.FirstOrDefault(s => s.Address == history.Address);
        if (row is null) return null;
        var neighbors = stored.Sources.Where(s => s.Network == row.Network && s.Address != row.Address)
            .OrderByDescending(s => s.Attempts).Take(20).Select(s => (s.Address, Int(s.Attempts))).ToArray();
        return new(Source(row, stored.Labels),
            history.Detailed ? history.Accounts.Take(15).Select(a => (a.Account, Int(a.Count))).ToArray() : [],
            history.Timeline.Select(Bucket).ToArray(),
            history.Detailed ? history.Recent.Take(100).ToArray() : [],
            neighbors, history.Detailed, history.FirstSeen, history.DaysSeen);
    }

    internal static AttackSource Source(EvidenceSource source, AddressLabels labels) =>
        new(source.Address, Int(source.Attempts), source.First, source.Last, source.Accounts is long accounts ? Int(accounts) : null,
            NotAsked, source.Attempts == 0 ? 0 : (double)source.UnknownAccount / source.Attempts, NotAsked, source.Network,
            Int(source.Neighbors), AttackBoard.LabelFor(labels, source.Address));

    internal static AttackBucket Bucket(EvidenceBucket bucket) =>
        new(bucket.Start, bucket.End, Int(bucket.UnknownAccount), Int(bucket.Attempts - bucket.UnknownAccount), bucket.Covered);

    private static int Int(long value) => (int)Math.Clamp(value, 0, int.MaxValue);
}

/// <summary>
/// The decision engine's records as the attacks view shows them (ADR 0009): a mark per source for the
/// decision in force, and the lines of a source's detail. Monitor only - the words say "would", never
/// "blocked".
/// </summary>
/// <remarks>
/// A store that could not be read marks every source "—": nobody could look, which is not the same as
/// no decision. A readable store with nothing in force leaves the cell empty.
/// </remarks>
internal static class AttackDecisions
{
    internal const int DetailRows = 50;
    internal static readonly TimeSpan DetailSpan = TimeSpan.FromDays(30);

    internal static string Mark(ActiveDecisions? decisions, string address, bool spanish) =>
        decisions is null ? StoredAttackBoard.NotAsked
        : decisions.For(address) is { } decision ? Action(decision.Action, spanish)
        : "";

    internal static AttackView Apply(AttackView view, ActiveDecisions? decisions, bool spanish) =>
        view with { Rows = view.Rows.Select(r => r with { Decision = Mark(decisions, r.Address, spanish) }).ToArray() };

    internal static string Action(string action, bool spanish) => action switch
    {
        DecisionActions.WouldBlock => spanish ? "bloquearía" : "would block",
        DecisionActions.Protected => spanish ? "protegida" : "protected",
        DecisionActions.Refused => spanish ? "rechazada" : "refused",
        DecisionActions.Report => spanish ? "informe" : "report",
        DecisionActions.Expire => spanish ? "terminó" : "ended",
        _ => DisplayText.Clean(action, 16)
    };

    /// <summary>One line of a source's detail. The reason is the engine's stored English text, cleaned.</summary>
    internal static string Line(DecisionRecord decision, bool spanish)
    {
        var time = decision.Timestamp.ToUniversalTime().ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture);
        var until = decision.ExpiresAt is { } expires && decision.Action != DecisionActions.Expire
            ? (spanish ? " hasta " : " until ") + expires.ToUniversalTime().ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture)
            : "";
        return $"{time}  {Action(decision.Action, spanish)}{until}  ·  {DisplayText.Clean(decision.RuleId, 16)}  ·  " +
            $"{DisplayText.Clean(decision.Target, 64)}  ·  {DisplayText.Clean(decision.Reason, 200)}";
    }

    /// <summary>What the footer says about decisions, so an empty column is never read as "the engine looked and found nothing".</summary>
    internal static string Status(ActiveDecisions? decisions, bool spanish)
    {
        if (decisions is null)
            return spanish ? "decisiones: sin lectura (almacén de evidencia no disponible)" : "decisions: not read (evidence store unavailable)";
        if (decisions.EngineStarted is null)
            return spanish ? "decisiones: el motor de decisiones nunca se ejecutó" : "decisions: the decision engine has never run";
        if (!decisions.CollectorCurrent)
            return spanish ? "decisiones: ninguna vigente, el servicio no está registrando" : "decisions: none in force, the service is not recording";
        return spanish
            ? $"decisiones vigentes: {decisions.Decisions.Count:N0} (Monitor: no se bloquea nada)"
            : $"decisions in force: {decisions.Decisions.Count:N0} (Monitor: nothing is blocked)";
    }
}

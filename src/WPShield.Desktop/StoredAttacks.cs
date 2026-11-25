using WPShield.Cli;
using WPShield.Evidence;

namespace WPShield.Desktop;

/// <summary>What opening the store told the window: the labels, and the range to open with.</summary>
internal sealed record AttackStoreStatus(AddressLabels Labels, string DefaultRange);

/// <summary>One read of the evidence store for a 7-day or 30-day range, kept until the next refresh.</summary>
internal sealed record StoredAttacks(AttackRange Range, EvidenceWindow Window, EvidenceSummary Summary,
    IReadOnlyList<EvidenceSource> Sources, IReadOnlyList<EvidenceBucket> Timeline, long LastHour, CoverageReport Coverage,
    AddressLabels Labels);

/// <summary>
/// The evidence store, as the attacks view asks it. Every call opens the store read-only, asks through
/// <see cref="EvidenceQueries"/> and closes it again, so no connection is ever shared between threads
/// and a closed window holds no file open. A store that cannot be opened throws
/// <see cref="EvidenceAccessException"/>, which says why.
/// </summary>
internal interface IAttackStore
{
    AttackStoreStatus Probe();

    StoredAttacks Read(AttackRange range, DateTimeOffset now);

    EvidenceSourceHistory History(string address, EvidenceWindow window);
}

internal sealed class EvidenceAttackStore(string path, Func<bool> elevated) : IAttackStore
{
    public AttackStoreStatus Probe()
    {
        using var store = EvidenceAccess.OpenReadOnly(path, elevated());
        return new(AddressLabels.Read(store), AttacksCommand.DefaultRange(new EvidenceSettings(store)));
    }

    public StoredAttacks Read(AttackRange range, DateTimeOffset now)
    {
        using var store = EvidenceAccess.OpenReadOnly(path, elevated());
        var window = EvidenceRanges.Window(StoredAttackBoard.Name(range), now);
        var queries = new EvidenceQueries(store);
        return new(range, window, queries.Summary(window.From, window.To),
            queries.TopSources(window.From, window.To, EvidenceQueries.MaxSources),
            queries.Timeline(window.From, window.To, window.Bucket),
            queries.Summary(window.To - TimeSpan.FromHours(1), window.To).Attempts,
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
            summary.Attempts == 0 ? 0 : (double)summary.UnknownAccount / summary.Attempts, Int(stored.LastHour),
            summary.TopAccount ?? "", stored.Timeline.Select(Bucket).ToArray(), matching.Take(maxRows).ToArray(), matching.Length,
            summary.CoveredFrom, summary.Detailed, noData);
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

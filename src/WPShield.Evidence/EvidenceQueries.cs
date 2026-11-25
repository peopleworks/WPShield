using System.Globalization;
using System.Net;
using System.Net.Sockets;
using WPShield.Evidence.Decisions;

namespace WPShield.Evidence;

public sealed record EvidenceSummary(DateTimeOffset From, DateTimeOffset To, long Attempts, long Sources, long WithoutAddress,
    long UnknownAccount, string? TopAccount, bool Detailed, DateTimeOffset? CoveredFrom);

public sealed record EvidenceSource(string Address, long Attempts, long UnknownAccount, DateTimeOffset First, DateTimeOffset Last,
    long? Accounts, string Network, long Neighbors);

public sealed record EvidenceBucket(DateTimeOffset Start, DateTimeOffset End, long Attempts, long UnknownAccount, bool Covered);

public sealed record EvidenceSourceHistory(string Address, DateTimeOffset? FirstSeen, int DaysSeen,
    IReadOnlyList<EvidenceBucket> Timeline, IReadOnlyList<(string Account, long Count)> Accounts,
    IReadOnlyList<AuthFailure> Recent, bool Detailed);

public sealed record EvidenceCoverage(string Source, DateTimeOffset From, DateTimeOffset To, string Status, string? Reason);

/// <summary>The decisions in force at <paramref name="At"/>, and what that answer rests on.</summary>
/// <param name="EngineStarted">When a decision engine last started on this store; none means it never ran.</param>
/// <param name="CollectedUntil">How far the collector's recorded coverage reaches.</param>
/// <param name="CollectorCurrent">Whether the collector is recording now. If not, nothing is in force.</param>
/// <param name="Truncated">More rows than a reader scans: the list may be missing older decisions.</param>
public sealed record ActiveDecisions(DateTimeOffset At, DateTimeOffset? EngineStarted, DateTimeOffset? CollectedUntil,
    bool CollectorCurrent, IReadOnlyList<DecisionRecord> Decisions, bool Truncated)
{
    /// <summary>The decision in force about an address: its own, or its /24 or /64's.</summary>
    public DecisionRecord? For(string address)
    {
        var network = EvidenceQueries.Network(address);
        return Decisions.FirstOrDefault(d => d.Target == address) ?? Decisions.FirstOrDefault(d => d.Target == network);
    }
}

/// <summary>
/// Every question a reader may ask the store. Fixed, parameterised SQL with bounded results: no
/// reader - the desktop, the CLI or an MCP server - can send its own SQL (ADR 0007, section 6).
/// </summary>
/// <remarks>
/// Detailed rows are kept for a short time and hourly aggregates for a long one. A question about a
/// period older than the detailed rows answers from the aggregates and says so with
/// <c>Detailed = false</c>: the counts are exact, but account names and single attempts are gone.
/// </remarks>
public sealed class EvidenceQueries
{
    public const int MaxSources = 1000;
    public const int MaxRecent = 500;
    public const int MaxBuckets = 2000;
    private const int MaxNetworkScan = 200_000;

    /// <summary>Rows <see cref="ActiveDecisions"/> reads at most.</summary>
    public const int MaxDecisionScan = 100_000;

    internal const string EngineStartedKey = "decision_engine_started";

    /// <summary>How far behind 'now' a collected interval may end and still vouch for the present.</summary>
    public static readonly TimeSpan CurrentAllowance = TimeSpan.FromMinutes(2);
    private readonly EvidenceStore store;

    public EvidenceQueries(EvidenceStore store) => this.store = store;

    public EvidenceSummary Summary(DateTimeOffset from, DateTimeOffset to)
    {
        var (f, t) = Range(from, to);
        var covered = CoveredFrom(from, to);
        if (Detailed(from))
        {
            using var command = store.Command("""
                SELECT COUNT(*), COUNT(DISTINCT address), COALESCE(SUM(address IS NULL), 0), COALESCE(SUM(reason = 'unknown-account'), 0)
                FROM auth_failures WHERE ts >= $f AND ts < $t;
                """, null, ("$f", f), ("$t", t));
            using var reader = command.ExecuteReader();
            reader.Read();
            var top = store.Scalar<string?>("""
                SELECT account FROM auth_failures WHERE ts >= $f AND ts < $t AND account <> ''
                GROUP BY account COLLATE NOCASE ORDER BY COUNT(*) DESC LIMIT 1;
                """, null, ("$f", f), ("$t", t));
            return new(from, to, reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3), top, true, covered);
        }
        using var hourly = store.Command("""
            SELECT COALESCE(SUM(attempts), 0), COUNT(DISTINCT NULLIF(address, '')),
                   COALESCE(SUM(CASE WHEN address = '' THEN attempts ELSE 0 END), 0), COALESCE(SUM(unknown_account), 0)
            FROM hourly_sources WHERE hour >= $f AND hour < $t;
            """, null, ("$f", f / 3_600_000), ("$t", CeilHour(t)));
        using var r = hourly.ExecuteReader();
        r.Read();
        return new(from, to, r.GetInt64(0), r.GetInt64(1), r.GetInt64(2), r.GetInt64(3), null, false, covered);
    }

    public IReadOnlyList<EvidenceSource> TopSources(DateTimeOffset from, DateTimeOffset to, int limit = 100)
    {
        var (f, t) = Range(from, to);
        limit = Math.Clamp(limit, 1, MaxSources);
        var detailed = Detailed(from);
        using var command = detailed
            ? store.Command("""
                SELECT address, COUNT(*), SUM(reason = 'unknown-account'), MIN(ts), MAX(ts), COUNT(DISTINCT account)
                FROM auth_failures WHERE ts >= $f AND ts < $t AND address IS NOT NULL
                GROUP BY address ORDER BY COUNT(*) DESC, MAX(ts) DESC LIMIT $n;
                """, null, ("$f", f), ("$t", t), ("$n", limit))
            : store.Command("""
                SELECT address, SUM(attempts), SUM(unknown_account), MIN(first_ts), MAX(last_ts), NULL
                FROM hourly_sources WHERE hour >= $f AND hour < $t AND address <> ''
                GROUP BY address ORDER BY SUM(attempts) DESC, MAX(last_ts) DESC LIMIT $n;
                """, null, ("$f", f / 3_600_000), ("$t", CeilHour(t)), ("$n", limit));
        var rows = new List<(string Address, long Attempts, long Unknown, long First, long Last, long? Accounts)>();
        using (var reader = command.ExecuteReader())
            while (reader.Read())
                rows.Add((reader.GetString(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3), reader.GetInt64(4),
                    reader.IsDBNull(5) ? null : reader.GetInt64(5)));
        var networks = NetworkCounts(f, t, detailed);
        return rows.Select(r =>
        {
            var network = Network(r.Address);
            return new EvidenceSource(r.Address, r.Attempts, r.Unknown, EvidenceStore.FromMs(r.First), EvidenceStore.FromMs(r.Last),
                r.Accounts, network, Math.Max(0, networks.GetValueOrDefault(network) - 1));
        }).ToArray();
    }

    public EvidenceSourceHistory SourceHistory(string address, DateTimeOffset from, DateTimeOffset to, int recent = 100)
    {
        address = Canonical(address) ?? throw new ArgumentException("Not an IP address.", nameof(address));
        var (f, t) = Range(from, to);
        recent = Math.Clamp(recent, 0, MaxRecent);
        var firstSeen = store.Scalar<long?>("SELECT MIN(first_ts) FROM hourly_sources WHERE address = $a;", null, ("$a", address));
        var days = store.Scalar<long>("SELECT COUNT(DISTINCT hour / 24) FROM hourly_sources WHERE address = $a;", null, ("$a", address));
        var detailed = Detailed(from);
        var accounts = new List<(string, long)>();
        var events = new List<AuthFailure>();
        if (detailed)
        {
            using (var command = store.Command("""
                SELECT account, COUNT(*) FROM auth_failures WHERE address = $a AND ts >= $f AND ts < $t AND account <> ''
                GROUP BY account COLLATE NOCASE ORDER BY COUNT(*) DESC LIMIT 50;
                """, null, ("$a", address), ("$f", f), ("$t", t)))
            using (var reader = command.ExecuteReader())
                while (reader.Read()) accounts.Add((reader.GetString(0), reader.GetInt64(1)));
            using (var command = store.Command("""
                SELECT ts, channel, address, port, account, reason, logon_type, record_id FROM auth_failures
                WHERE address = $a AND ts >= $f AND ts < $t ORDER BY ts DESC LIMIT $n;
                """, null, ("$a", address), ("$f", f), ("$t", t), ("$n", recent)))
            using (var reader = command.ExecuteReader())
                while (reader.Read()) events.Add(Read(reader));
        }
        var span = to - from;
        var size = span <= TimeSpan.FromHours(6) ? TimeSpan.FromMinutes(5) : span <= TimeSpan.FromDays(2) ? TimeSpan.FromHours(1) : TimeSpan.FromDays(1);
        return new(address, firstSeen is null ? null : EvidenceStore.FromMs(firstSeen.Value), (int)days,
            Timeline(from, to, size, address), accounts, events, detailed);
    }

    /// <summary>
    /// Attempts per bucket. Buckets smaller than an hour need the detailed rows; an hour or more reads
    /// the aggregates. A bucket the collector did not cover entirely is marked, never shown as zero.
    /// </summary>
    public IReadOnlyList<EvidenceBucket> Timeline(DateTimeOffset from, DateTimeOffset to, TimeSpan bucket, string? address = null)
    {
        if (bucket <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(bucket));
        var count = (int)Math.Ceiling((to - from) / bucket);
        if (count <= 0) return [];
        if (count > MaxBuckets) throw new ArgumentOutOfRangeException(nameof(bucket), $"At most {MaxBuckets} buckets.");
        var (f, t) = Range(from, to);
        var attempts = new long[count];
        var unknown = new long[count];
        var useRaw = bucket < TimeSpan.FromHours(1);
        var filter = address is null ? "" : " AND address = $a";
        using var command = useRaw
            ? store.Command($"""
                SELECT (ts - $f) / $size, COUNT(*), SUM(reason = 'unknown-account') FROM auth_failures
                WHERE ts >= $f AND ts < $t{filter} GROUP BY 1;
                """, null, ("$f", f), ("$t", t), ("$size", (long)bucket.TotalMilliseconds), ("$a", address))
            : store.Command($"""
                SELECT (hour * 3600000 - $f) / $size, SUM(attempts), SUM(unknown_account) FROM hourly_sources
                WHERE hour >= $fh AND hour < $th{filter} GROUP BY 1;
                """, null, ("$f", f), ("$fh", f / 3_600_000), ("$th", CeilHour(t)), ("$size", (long)bucket.TotalMilliseconds), ("$a", address));
        using (var reader = command.ExecuteReader())
            while (reader.Read())
            {
                var index = reader.GetInt64(0);
                if (index < 0 || index >= count) continue;
                attempts[index] += reader.GetInt64(1);
                unknown[index] += reader.GetInt64(2);
            }
        var intervals = Collected(from, to);
        var rawFrom = useRaw ? RawPrunedBefore(store) : null;
        return Enumerable.Range(0, count).Select(i =>
        {
            var start = from + bucket * i;
            var end = start + bucket < to ? start + bucket : to;
            // The collector extends its interval as it goes, so the newest bucket is vouched for when the
            // interval reaches the last moments before 'to' - the same allowance CoveredFrom makes.
            var needed = end < to ? end : to - CurrentAllowance > start ? to - CurrentAllowance : start;
            var covered = intervals.Any(c => c.From <= start && c.To >= needed) && (rawFrom is null || start >= rawFrom);
            return new EvidenceBucket(start, end, attempts[i], unknown[i], covered);
        }).ToArray();
    }

    public IReadOnlyList<EvidenceCoverage> Coverage(DateTimeOffset from, DateTimeOffset to)
    {
        var (f, t) = Range(from, to);
        using var command = store.Command("""
            SELECT source, from_ts, to_ts, status, reason FROM coverage WHERE to_ts >= $f AND from_ts <= $t
            ORDER BY from_ts LIMIT 5000;
            """, null, ("$f", f), ("$t", t));
        using var reader = command.ExecuteReader();
        var result = new List<EvidenceCoverage>();
        while (reader.Read())
            result.Add(new(reader.GetString(0), EvidenceStore.FromMs(reader.GetInt64(1)), EvidenceStore.FromMs(reader.GetInt64(2)),
                reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4)));
        return result;
    }

    public IReadOnlyList<DecisionRecord> Decisions(DateTimeOffset from, DateTimeOffset to, int limit = 100, string? target = null)
    {
        var (f, t) = Range(from, to);
        using var command = store.Command($"""
            SELECT ts, action, target, rule_id, mode, reason, requested_by, expires_ts FROM decisions
            WHERE ts >= $f AND ts < $t{(target is null ? "" : " AND target = $target")} ORDER BY ts DESC LIMIT $n;
            """, null, ("$f", f), ("$t", t), ("$n", Math.Clamp(limit, 1, MaxSources)), ("$target", target));
        return ReadDecisions(command);
    }

    private static List<DecisionRecord> ReadDecisions(Microsoft.Data.Sqlite.SqliteCommand command)
    {
        using var reader = command.ExecuteReader();
        var result = new List<DecisionRecord>();
        while (reader.Read())
            result.Add(new(EvidenceStore.FromMs(reader.GetInt64(0)), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                reader.GetString(4), reader.GetString(5), reader.IsDBNull(6) ? null : reader.GetString(6),
                reader.IsDBNull(7) ? null : EvidenceStore.FromMs(reader.GetInt64(7))));
        return result;
    }

    /// <summary>
    /// Decisions about one address and about its /24 or /64 - a network decision covers the address too -
    /// newest first.
    /// </summary>
    public IReadOnlyList<DecisionRecord> DecisionsAbout(string address, DateTimeOffset from, DateTimeOffset to, int limit = 100)
    {
        address = Canonical(address) ?? throw new ArgumentException("Not an IP address.", nameof(address));
        var (f, t) = Range(from, to);
        using var command = store.Command("""
            SELECT ts, action, target, rule_id, mode, reason, requested_by, expires_ts FROM decisions
            WHERE ts >= $f AND ts < $t AND target IN ($a, $n) ORDER BY ts DESC, id DESC LIMIT $limit;
            """, null, ("$f", f), ("$t", t), ("$a", address), ("$n", Network(address)), ("$limit", Math.Clamp(limit, 1, MaxSources)));
        return ReadDecisions(command);
    }

    /// <summary>
    /// The decisions in force now, as the audit trail shows them: the newest <c>would-block</c> or
    /// <c>protected</c> record of each target, unexpired, with no later <c>expire</c>, made by the engine
    /// run that started last, while the collector is still recording.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A decision lives only as long as the process that made it, and a process that stops or crashes
    /// writes no <c>expire</c> for what it forgot. So a record counts only if it is newer than the last
    /// engine start, and nothing counts while the collector has not extended its coverage within
    /// <see cref="CurrentAllowance"/>: a service that is not running has nothing in force.
    /// </para>
    /// <para>
    /// No decision lasts more than seven days, so only the last seven days are read, at most
    /// <see cref="MaxDecisionScan"/> rows of them.
    /// </para>
    /// </remarks>
    public ActiveDecisions ActiveDecisions(DateTimeOffset now)
    {
        var engine = store.Scalar<string?>("SELECT value FROM meta WHERE key = $k;", null, ("$k", EngineStartedKey));
        DateTimeOffset? started = long.TryParse(engine, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ms) ? EvidenceStore.FromMs(ms) : null;
        var collectedUntil = store.Scalar<long?>("SELECT MAX(to_ts) FROM coverage WHERE source = $s AND status = 'collected';", null,
            ("$s", EvidenceWriter.RawSource));
        DateTimeOffset? until = collectedUntil is null ? null : EvidenceStore.FromMs(collectedUntil.Value);
        var current = until is not null && until >= now - CurrentAllowance;
        if (started is null || !current) return new(now, started, until, current, [], false);

        var since = started.Value > now - DecisionEngine.MaxDuration ? started.Value : now - DecisionEngine.MaxDuration;
        using var command = store.Command("""
            SELECT ts, action, target, rule_id, mode, reason, requested_by, expires_ts FROM decisions
            WHERE ts >= $f AND ts <= $t AND action IN ('would-block', 'protected', 'expire') ORDER BY ts DESC, id DESC LIMIT $n;
            """, null, ("$f", EvidenceStore.ToMs(since)), ("$t", EvidenceStore.ToMs(now)), ("$n", MaxDecisionScan + 1));
        var rows = ReadDecisions(command);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var active = new List<DecisionRecord>();
        foreach (var row in rows.Take(MaxDecisionScan))
        {
            if (!seen.Add(row.Target)) continue;
            if (row.Action != DecisionActions.Expire && row.ExpiresAt > now) active.Add(row);
        }
        return new(now, started, until, current, active, rows.Count > MaxDecisionScan);
    }

    /// <summary>The /24 of an IPv4 address or the /64 of an IPv6 one, as text.</summary>
    public static string Network(string address)
    {
        if (!IPAddress.TryParse(address, out var ip)) return address;
        var bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            bytes[3] = 0;
            return new IPAddress(bytes) + "/24";
        }
        for (var i = 8; i < bytes.Length; i++) bytes[i] = 0;
        return new IPAddress(bytes) + "/64";
    }

    internal static DateTimeOffset? RawPrunedBefore(EvidenceStore store)
    {
        var value = store.Scalar<string?>("SELECT value FROM meta WHERE key = 'raw_pruned_before';");
        return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ms) ? EvidenceStore.FromMs(ms) : null;
    }

    /// <summary>The earliest moment from which every part of the range was collected, if any.</summary>
    private DateTimeOffset? CoveredFrom(DateTimeOffset from, DateTimeOffset to)
    {
        var intervals = Collected(from, to);
        var covering = intervals.Where(c => c.To >= to - CurrentAllowance).OrderBy(c => c.From).FirstOrDefault();
        if (covering is null) return null;
        return covering.From > from ? covering.From : from;
    }

    /// <summary>
    /// Intervals the failed-logon collector vouches for (source auth-failures only: a future HTTP or SQL
    /// collector's coverage must not make a failed-logon bucket look covered), with intervals that
    /// overlap or touch joined into one: a service restart that resumes where it stopped leaves no gap,
    /// so it must not draw one. Intervals with any time between them stay apart - that time was not
    /// recorded.
    /// </summary>
    private List<EvidenceCoverage> Collected(DateTimeOffset from, DateTimeOffset to)
    {
        var merged = new List<EvidenceCoverage>();
        EvidenceCoverage? current = null;
        foreach (var interval in Coverage(from, to)
                     .Where(c => c.Status == "collected" && c.Source == EvidenceWriter.RawSource)
                     .OrderBy(c => c.From))
        {
            if (current is not null && interval.From <= current.To)
            {
                if (interval.To > current.To) current = current with { To = interval.To };
                continue;
            }
            if (current is not null) merged.Add(current);
            current = interval;
        }
        if (current is not null) merged.Add(current);
        return merged;
    }

    private bool Detailed(DateTimeOffset from)
    {
        var pruned = RawPrunedBefore(store);
        return pruned is null || from >= pruned.Value;
    }

    private Dictionary<string, long> NetworkCounts(long f, long t, bool detailed)
    {
        using var command = detailed
            ? store.Command("SELECT DISTINCT address FROM auth_failures WHERE ts >= $f AND ts < $t AND address IS NOT NULL LIMIT $n;",
                null, ("$f", f), ("$t", t), ("$n", MaxNetworkScan))
            : store.Command("SELECT DISTINCT address FROM hourly_sources WHERE hour >= $f AND hour < $t AND address <> '' LIMIT $n;",
                null, ("$f", f / 3_600_000), ("$t", CeilHour(t)), ("$n", MaxNetworkScan));
        var counts = new Dictionary<string, long>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var network = Network(reader.GetString(0));
            counts[network] = counts.GetValueOrDefault(network) + 1;
        }
        return counts;
    }

    private static AuthFailure Read(Microsoft.Data.Sqlite.SqliteDataReader reader) =>
        new(EvidenceStore.FromMs(reader.GetInt64(0)), reader.GetString(1),
            reader.IsDBNull(2) ? null : IPAddress.Parse(reader.GetString(2)), reader.IsDBNull(3) ? null : reader.GetInt32(3),
            reader.GetString(4), reader.GetString(5), reader.IsDBNull(6) ? null : reader.GetInt32(6), reader.GetInt64(7));

    private static string? Canonical(string address) =>
        IPAddress.TryParse(address.Trim(), out var ip) ? (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString() : null;

    private static (long From, long To) Range(DateTimeOffset from, DateTimeOffset to)
    {
        if (to <= from) throw new ArgumentException("The range must end after it starts.");
        return (EvidenceStore.ToMs(from), EvidenceStore.ToMs(to));
    }

    private static long CeilHour(long ms) => (ms + 3_599_999) / 3_600_000;
}

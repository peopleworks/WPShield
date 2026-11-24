using System.Globalization;
using System.Net;
using System.Net.Sockets;

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
            var covered = intervals.Any(c => c.From <= start && c.To >= end) && (rawFrom is null || start >= rawFrom);
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
        using var reader = command.ExecuteReader();
        var result = new List<DecisionRecord>();
        while (reader.Read())
            result.Add(new(EvidenceStore.FromMs(reader.GetInt64(0)), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                reader.GetString(4), reader.GetString(5), reader.IsDBNull(6) ? null : reader.GetString(6),
                reader.IsDBNull(7) ? null : EvidenceStore.FromMs(reader.GetInt64(7))));
        return result;
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
        var covering = intervals.Where(c => c.To >= to - TimeSpan.FromMinutes(2)).OrderBy(c => c.From).FirstOrDefault();
        if (covering is null) return null;
        return covering.From > from ? covering.From : from;
    }

    private List<EvidenceCoverage> Collected(DateTimeOffset from, DateTimeOffset to) =>
        Coverage(from, to).Where(c => c.Status == "collected").ToList();

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

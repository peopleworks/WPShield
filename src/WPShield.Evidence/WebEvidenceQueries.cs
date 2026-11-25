using System.Globalization;
using System.Net;

namespace WPShield.Evidence;

/// <summary>What the IIS logs of a range add up to, over the whole hours that overlap it.</summary>
/// <param name="HoursFrom">The start of the first whole hour counted. Requests are kept per hour, not per request.</param>
/// <param name="HoursTo">The end of the last whole hour counted.</param>
/// <param name="Sources">Addresses with a finding or an observation, or many client errors, that the evidence counts against.</param>
/// <param name="ProtectedSources">Such addresses the evidence never counts against: this host, the allow-list, private ranges.</param>
/// <param name="FindingsFrom">Where the kept findings start, when older ones were pruned; <see langword="null"/> when none were.</param>
public sealed record WebSummary(DateTimeOffset From, DateTimeOffset To, DateTimeOffset HoursFrom, DateTimeOffset HoursTo,
    long Requests, long ClientErrors, long ServerErrors, long Findings, long Observations, long LoginPosts, long XmlrpcPosts,
    long BytesReceived, long Sources, long ProtectedSources, DateTimeOffset? FindingsFrom);

/// <summary>One address across the sites it reached, over the whole hours that overlap a range.</summary>
/// <param name="Network">Its /24 or /64.</param>
/// <param name="Neighbors">Other addresses of that network among the addresses kept for the range.</param>
/// <param name="Protection">Why the evidence never counts against it, or <see langword="null"/>.</param>
public sealed record WebSource(string Address, long Requests, long ClientErrors, long Findings, long Observations, long LoginPosts,
    long XmlrpcPosts, int Sites, DateTimeOffset First, DateTimeOffset Last, string Network, long Neighbors, string? Protection);

/// <summary>How many requests one rule or observation flagged.</summary>
/// <param name="Observation">An observation (<c>WEB-OBS-*</c>): evidence only, never a score.</param>
public sealed record WebRuleCount(string Id, long Requests, bool Observation);

/// <summary>A stored finding, as a reader sees it. The path and the user agent are attacker-chosen text.</summary>
public sealed record WebFindingRecord(DateTimeOffset Timestamp, long SiteId, string Address, string Method, string Path, int Status,
    IReadOnlyList<WebHit> Hits, int Score, string UserAgent, bool Live, bool Proxied, string? Protection);

/// <summary>A site the sensor knows, and whether its log is read.</summary>
public sealed record WebSiteCoverage(long SiteId, string Name, string Status, string? Reason, string? Remedy, bool Proxied,
    DateTimeOffset UpdatedAt);

/// <summary>One bucket of a web timeline. <see cref="Requests"/> is known only for buckets of an hour or more.</summary>
public sealed record WebBucket(DateTimeOffset Start, DateTimeOffset End, long? Requests, long Findings, long Observations, bool Covered);

/// <summary>
/// Every question a reader may ask about the IIS log evidence (ADR 0011): fixed, parameterised SQL with
/// bounded results, like <see cref="EvidenceQueries"/>. The desktop's Web tab, <c>wpshield web</c> and the
/// MCP tools all read through here.
/// </summary>
/// <remarks>
/// <para>
/// Requests are counted per site and hour, never stored one by one, so totals cover the whole hours that
/// overlap a range and say which hours those are. Findings are stored per request and counted exactly.
/// </para>
/// <para>
/// Paths and user agents in the answers were chosen by whoever sent the request. They were cleaned and
/// bounded before they were stored; a reader that shows them must still present them as untrusted text.
/// </para>
/// </remarks>
public sealed class WebEvidenceQueries
{
    public const int MaxSources = 1000;
    public const int MaxFindings = 500;
    public const int MaxBuckets = 2000;
    public const string ObservationPrefix = "WEB-OBS-";
    internal const string WebPrunedBeforeKey = "web_pruned_before";
    private const int MaxRuleScan = 10_000;
    private const int MaxNetworkScan = 200_000;
    private readonly EvidenceStore store;

    public WebEvidenceQueries(EvidenceStore store) => this.store = store ?? throw new ArgumentNullException(nameof(store));

    public WebSummary Summary(DateTimeOffset from, DateTimeOffset to, long? siteId = null)
    {
        var (fh, th) = Hours(from, to);
        var site = siteId is null ? "" : " AND site_id = $site";
        using var command = store.Command($"""
            SELECT COALESCE(SUM(requests), 0), COALESCE(SUM(client_errors), 0), COALESCE(SUM(server_errors), 0),
                   COALESCE(SUM(findings), 0), COALESCE(SUM(observations), 0), COALESCE(SUM(login_posts), 0),
                   COALESCE(SUM(xmlrpc_posts), 0), COALESCE(SUM(bytes_received), 0)
            FROM web_hourly_sites WHERE hour >= $f AND hour < $t{site};
            """, null, ("$f", fh), ("$t", th), ("$site", siteId));
        using var reader = command.ExecuteReader();
        reader.Read();
        var sources = store.Scalar<long>($"""
            SELECT COUNT(*) FROM (SELECT address FROM web_hourly_sources WHERE hour >= $f AND hour < $t{site}
            GROUP BY address HAVING MAX(protection IS NOT NULL) = 0);
            """, null, ("$f", fh), ("$t", th), ("$site", siteId));
        var protectedSources = store.Scalar<long>($"""
            SELECT COUNT(*) FROM (SELECT address FROM web_hourly_sources WHERE hour >= $f AND hour < $t{site}
            GROUP BY address HAVING MAX(protection IS NOT NULL) = 1);
            """, null, ("$f", fh), ("$t", th), ("$site", siteId));
        return new(from, to, FromHour(fh), FromHour(th), reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3),
            reader.GetInt64(4), reader.GetInt64(5), reader.GetInt64(6), reader.GetInt64(7), sources, protectedSources, FindingsFrom(from));
    }

    /// <summary>
    /// The addresses kept for a range, most flagged first: findings and observations, then login and XML-RPC
    /// posts, then client errors. Protected addresses are left out unless asked for.
    /// </summary>
    public IReadOnlyList<WebSource> TopSources(DateTimeOffset from, DateTimeOffset to, long? siteId = null, int limit = 100,
        bool includeProtected = false)
    {
        var (fh, th) = Hours(from, to);
        limit = Math.Clamp(limit, 1, MaxSources);
        var site = siteId is null ? "" : " AND site_id = $site";
        var protection = includeProtected ? "" : " HAVING MAX(protection IS NOT NULL) = 0";
        using var command = store.Command($"""
            SELECT address, SUM(requests), SUM(client_errors), SUM(findings), SUM(observations), SUM(login_posts), SUM(xmlrpc_posts),
                   COUNT(DISTINCT site_id), MIN(first_ts), MAX(last_ts), MAX(protection)
            FROM web_hourly_sources WHERE hour >= $f AND hour < $t{site}
            GROUP BY address{protection}
            ORDER BY SUM(findings) + SUM(observations) DESC, SUM(login_posts) + SUM(xmlrpc_posts) DESC, SUM(client_errors) DESC,
                     MAX(last_ts) DESC
            LIMIT $n;
            """, null, ("$f", fh), ("$t", th), ("$site", siteId), ("$n", limit));
        var rows = new List<(string Address, long Requests, long Client, long Findings, long Observations, long Login, long Xmlrpc, int Sites,
            long First, long Last, string? Protection)>();
        using (var reader = command.ExecuteReader())
            while (reader.Read())
                rows.Add((reader.GetString(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3), reader.GetInt64(4),
                    reader.GetInt64(5), reader.GetInt64(6), reader.GetInt32(7), reader.GetInt64(8), reader.GetInt64(9),
                    reader.IsDBNull(10) ? null : reader.GetString(10)));
        var networks = NetworkCounts(fh, th, siteId);
        return rows.Select(r =>
        {
            var network = EvidenceQueries.Network(r.Address);
            return new WebSource(r.Address, r.Requests, r.Client, r.Findings, r.Observations, r.Login, r.Xmlrpc, r.Sites,
                EvidenceStore.FromMs(r.First), EvidenceStore.FromMs(r.Last), network, Math.Max(0, networks.GetValueOrDefault(network) - 1),
                r.Protection);
        }).ToArray();
    }

    /// <summary>
    /// Requests per rule and per observation in a range. Rules and <c>WEB-OBS-001</c> come from the stored
    /// findings (exact); <c>WEB-OBS-002</c> and <c>-003</c>, which are counted rather than stored, from the
    /// hourly counts (whole hours).
    /// </summary>
    public IReadOnlyList<WebRuleCount> RuleCounts(DateTimeOffset from, DateTimeOffset to, long? siteId = null, string? address = null)
    {
        var (f, t) = Range(from, to);
        address = address is null ? null : Canonical(address) ?? throw new ArgumentException("Not an IP address.", nameof(address));
        var filter = (siteId is null ? "" : " AND site_id = $site") + (address is null ? "" : " AND address = $address");
        var counts = new Dictionary<string, long>(StringComparer.Ordinal);
        using (var command = store.Command($"""
            SELECT rules, COUNT(*) FROM web_findings WHERE ts >= $f AND ts < $t{filter} GROUP BY rules LIMIT $n;
            """, null, ("$f", f), ("$t", t), ("$site", siteId), ("$address", address), ("$n", MaxRuleScan)))
        using (var reader = command.ExecuteReader())
            while (reader.Read())
                foreach (var hit in ParseRules(reader.GetString(0)))
                    counts[hit.Id] = counts.GetValueOrDefault(hit.Id) + reader.GetInt64(1);

        var (fh, th) = Hours(from, to);
        var table = address is null ? "web_hourly_sites" : "web_hourly_sources";
        using (var command = store.Command($"""
            SELECT COALESCE(SUM(login_posts), 0), COALESCE(SUM(xmlrpc_posts), 0) FROM {table} WHERE hour >= $f AND hour < $t{filter};
            """, null, ("$f", fh), ("$t", th), ("$site", siteId), ("$address", address)))
        using (var reader = command.ExecuteReader())
        {
            reader.Read();
            if (reader.GetInt64(0) > 0) counts[WebObservationIds.LoginPost] = reader.GetInt64(0);
            if (reader.GetInt64(1) > 0) counts[WebObservationIds.XmlrpcPost] = reader.GetInt64(1);
        }

        return counts.Select(pair => new WebRuleCount(pair.Key, pair.Value, pair.Key.StartsWith(ObservationPrefix, StringComparison.Ordinal)))
            .OrderByDescending(c => c.Requests).ThenBy(c => c.Id, StringComparer.Ordinal).ToArray();
    }

    /// <summary>Stored findings, newest first.</summary>
    public IReadOnlyList<WebFindingRecord> Findings(DateTimeOffset from, DateTimeOffset to, long? siteId = null, string? address = null,
        int limit = 100)
    {
        var (f, t) = Range(from, to);
        address = address is null ? null : Canonical(address) ?? throw new ArgumentException("Not an IP address.", nameof(address));
        var filter = (siteId is null ? "" : " AND site_id = $site") + (address is null ? "" : " AND address = $address");
        using var command = store.Command($"""
            SELECT ts, site_id, address, method, path, status, rules, score, user_agent, live, proxied, protection
            FROM web_findings WHERE ts >= $f AND ts < $t{filter} ORDER BY ts DESC, id DESC LIMIT $n;
            """, null, ("$f", f), ("$t", t), ("$site", siteId), ("$address", address), ("$n", Math.Clamp(limit, 1, MaxFindings)));
        using var reader = command.ExecuteReader();
        var result = new List<WebFindingRecord>();
        while (reader.Read())
            result.Add(new(EvidenceStore.FromMs(reader.GetInt64(0)), reader.GetInt64(1), reader.GetString(2), reader.GetString(3),
                reader.GetString(4), reader.GetInt32(5), ParseRules(reader.GetString(6)), reader.GetInt32(7), reader.GetString(8),
                reader.GetInt64(9) == 1, reader.GetInt64(10) == 1, reader.IsDBNull(11) ? null : reader.GetString(11)));
        return result;
    }

    /// <summary>Every site the sensor knows, by site ID, with the state of its log.</summary>
    public IReadOnlyList<WebSiteCoverage> Sites()
    {
        using var command = store.Command("""
            SELECT site_id, name, status, reason, remedy, proxied, updated_ts FROM web_sites ORDER BY site_id LIMIT 5000;
            """, null);
        using var reader = command.ExecuteReader();
        var result = new List<WebSiteCoverage>();
        while (reader.Read())
            result.Add(new(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4), reader.GetInt64(5) == 1, EvidenceStore.FromMs(reader.GetInt64(6))));
        return result;
    }

    /// <summary>
    /// The sensor's coverage intervals in a range: <see cref="WebEvidenceWriter.SensorSource"/> for the sensor
    /// as a whole and one source per site log.
    /// </summary>
    public IReadOnlyList<EvidenceCoverage> Coverage(DateTimeOffset from, DateTimeOffset to) =>
        new EvidenceQueries(store).Coverage(from, to)
            .Where(c => c.Source == WebEvidenceWriter.SensorSource || c.Source.StartsWith("iis-w3svc", StringComparison.Ordinal))
            .ToArray();

    /// <summary>
    /// Findings and observations per bucket. Buckets of an hour or more read the hourly counts and know the
    /// request total too; smaller ones count stored findings. A bucket the sensor did not cover entirely is
    /// marked, never shown as zero.
    /// </summary>
    public IReadOnlyList<WebBucket> Timeline(DateTimeOffset from, DateTimeOffset to, TimeSpan bucket, long? siteId = null,
        string? address = null)
    {
        if (bucket <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(bucket));
        var count = (int)Math.Ceiling((to - from) / bucket);
        if (count <= 0) return [];
        if (count > MaxBuckets) throw new ArgumentOutOfRangeException(nameof(bucket), $"At most {MaxBuckets} buckets.");
        var (f, t) = Range(from, to);
        address = address is null ? null : Canonical(address) ?? throw new ArgumentException("Not an IP address.", nameof(address));
        var filter = (siteId is null ? "" : " AND site_id = $site") + (address is null ? "" : " AND address = $address");
        var hourly = bucket >= TimeSpan.FromHours(1);
        var requests = hourly ? new long[count] : null;
        var findings = new long[count];
        var observations = new long[count];
        var size = (long)bucket.TotalMilliseconds;
        if (hourly)
        {
            var table = address is null ? "web_hourly_sites" : "web_hourly_sources";
            using var command = store.Command($"""
                SELECT (hour * 3600000 - $f) / $size, SUM(requests), SUM(findings), SUM(observations) FROM {table}
                WHERE hour >= $fh AND hour < $th{filter} GROUP BY 1;
                """, null, ("$f", f), ("$fh", f / 3_600_000), ("$th", CeilHour(t)), ("$size", size), ("$site", siteId), ("$address", address));
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var index = reader.GetInt64(0);
                if (index < 0 || index >= count) continue;
                requests![index] += reader.GetInt64(1);
                findings[index] += reader.GetInt64(2);
                observations[index] += reader.GetInt64(3);
            }
        }
        else
        {
            using var command = store.Command($"""
                SELECT (ts - $f) / $size, SUM(score > 0), SUM(rules LIKE '%{ObservationPrefix}%') FROM web_findings
                WHERE ts >= $f AND ts < $t{filter} GROUP BY 1;
                """, null, ("$f", f), ("$t", t), ("$size", size), ("$site", siteId), ("$address", address));
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var index = reader.GetInt64(0);
                if (index < 0 || index >= count) continue;
                findings[index] += reader.GetInt64(1);
                observations[index] += reader.GetInt64(2);
            }
        }

        var source = siteId is null ? WebEvidenceWriter.SensorSource : WebEvidenceWriter.SiteSource(siteId.Value);
        var intervals = Collected(from, to, source);
        return Enumerable.Range(0, count).Select(i =>
        {
            var start = from + bucket * i;
            var end = start + bucket < to ? start + bucket : to;
            var needed = end < to ? end : to - EvidenceQueries.CurrentAllowance > start ? to - EvidenceQueries.CurrentAllowance : start;
            var covered = intervals.Any(c => c.From <= start && c.To >= needed);
            return new WebBucket(start, end, requests?[i], findings[i], observations[i], covered);
        }).ToArray();
    }

    /// <summary>The hits a stored <c>rules</c> column names: <c>ID:score</c> for a rule, <c>ID</c> for an observation.</summary>
    public static IReadOnlyList<WebHit> ParseRules(string text)
    {
        if (string.IsNullOrEmpty(text)) return [];
        return text.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(part =>
        {
            var colon = part.IndexOf(':', StringComparison.Ordinal);
            return colon < 0
                ? new WebHit(part, 0)
                : new WebHit(part[..colon], int.TryParse(part[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var score) ? score : 0);
        }).ToArray();
    }

    private DateTimeOffset? FindingsFrom(DateTimeOffset from)
    {
        var value = store.Scalar<string?>("SELECT value FROM meta WHERE key = $k;", null, ("$k", WebPrunedBeforeKey));
        if (!long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ms)) return null;
        var pruned = EvidenceStore.FromMs(ms);
        return pruned > from ? pruned : null;
    }

    private List<EvidenceCoverage> Collected(DateTimeOffset from, DateTimeOffset to, string source)
    {
        var merged = new List<EvidenceCoverage>();
        EvidenceCoverage? current = null;
        foreach (var interval in new EvidenceQueries(store).Coverage(from, to)
                     .Where(c => c.Status == "collected" && c.Source == source).OrderBy(c => c.From))
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

    private Dictionary<string, long> NetworkCounts(long fh, long th, long? siteId)
    {
        using var command = store.Command($"""
            SELECT DISTINCT address FROM web_hourly_sources WHERE hour >= $f AND hour < $t{(siteId is null ? "" : " AND site_id = $site")} LIMIT $n;
            """, null, ("$f", fh), ("$t", th), ("$site", siteId), ("$n", MaxNetworkScan));
        var counts = new Dictionary<string, long>(StringComparer.Ordinal);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var network = EvidenceQueries.Network(reader.GetString(0));
            counts[network] = counts.GetValueOrDefault(network) + 1;
        }
        return counts;
    }

    private static string? Canonical(string address) =>
        IPAddress.TryParse(address.Trim(), out var ip) ? (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString() : null;

    private static (long From, long To) Range(DateTimeOffset from, DateTimeOffset to)
    {
        if (to <= from) throw new ArgumentException("The range must end after it starts.");
        return (EvidenceStore.ToMs(from), EvidenceStore.ToMs(to));
    }

    private static (long FromHour, long ToHour) Hours(DateTimeOffset from, DateTimeOffset to)
    {
        var (f, t) = Range(from, to);
        return (f / 3_600_000, CeilHour(t));
    }

    private static DateTimeOffset FromHour(long hour) => EvidenceStore.FromMs(hour * 3_600_000);

    private static long CeilHour(long ms) => (ms + 3_599_999) / 3_600_000;
}

/// <summary>
/// The stable, untranslated IDs of the sensor's observations (ADR 0011, amendment 1). An observation is
/// evidence only: it carries no score, is never a rule, and is never enough to decide anything alone.
/// </summary>
public static class WebObservationIds
{
    /// <summary>A 2xx answer to a <c>.php</c> path that is not a WordPress entry point. Stored per request.</summary>
    public const string PhpOutsideEntryPoints = "WEB-OBS-001";

    /// <summary>A POST to <c>wp-login.php</c>. Counted per address and hour, not stored per request.</summary>
    public const string LoginPost = "WEB-OBS-002";

    /// <summary>A POST to <c>xmlrpc.php</c>. Counted per address and hour, not stored per request.</summary>
    public const string XmlrpcPost = "WEB-OBS-003";
}

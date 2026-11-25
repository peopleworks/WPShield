using System.Globalization;
using System.Text.Json.Nodes;

namespace WPShield.Evidence;

/// <summary>
/// One rule finding or one sensor observation on a request read from an IIS log (ADR 0011). A rule
/// carries its score; an observation scores 0, because an observation is evidence only and never
/// decides anything by itself.
/// </summary>
public sealed record WebHit(string Id, int Score);

/// <summary>A request read from an IIS log that a rule or an observation flagged.</summary>
/// <param name="SiteId">The IIS site ID, the number in its <c>W3SVC</c> log folder.</param>
/// <param name="Path">
/// The normalized path (ADR 0011, section 4): rebuilt from normalized segments, cleaned and bounded at
/// <see cref="WebEvidenceWriter.MaxPathLength"/> characters. Never the logged stem.
/// </param>
/// <param name="UserAgent">Cleaned and bounded at <see cref="WebEvidenceWriter.MaxUserAgentLength"/> characters.</param>
/// <param name="Live">
/// <see langword="false"/> for a line read by the catch-up at start: history, which nothing that decides
/// ever reads.
/// </param>
/// <param name="Proxied">The site is listed in <c>http.proxied_sites</c>: its client address is a proxy's.</param>
/// <param name="Protection">
/// Why this address is one the evidence never counts against (the allow-list, this host, loopback,
/// link-local, a private range), or <see langword="null"/>.
/// </param>
public sealed record WebFinding(DateTimeOffset Timestamp, long SiteId, string Address, string Method, string Path, int Status,
    IReadOnlyList<WebHit> Hits, string UserAgent, bool Live, bool Proxied, string? Protection)
{
    /// <summary>The rules' scores summed and capped at 100, as the gateway's path engine does. Observations add nothing.</summary>
    public int Score => Math.Min(100, Hits.Sum(hit => Math.Max(0, hit.Score)));
}

/// <summary>What one site served in one hour, added to what is already stored for that hour.</summary>
/// <param name="Findings">Requests at least one rule flagged.</param>
/// <param name="Observations">Requests an observation flagged that wrote a finding row (<c>WEB-OBS-001</c>).</param>
/// <param name="LoginPosts">POST requests to <c>wp-login.php</c> (<c>WEB-OBS-002</c>).</param>
/// <param name="XmlrpcPosts">POST requests to <c>xmlrpc.php</c> (<c>WEB-OBS-003</c>).</param>
public sealed record WebSiteCounts(long SiteId, DateTimeOffset Hour, long Requests, long ClientErrors, long ServerErrors,
    long Findings, long Observations, long LoginPosts, long XmlrpcPosts, long BytesReceived);

/// <summary>
/// What one address sent one site in one hour, added to what is already stored. Written only for an
/// address with a finding or an observation, or more than <see cref="WebEvidenceWriter.ClientErrorThreshold"/>
/// client errors, in that hour: the scanners that fire no rule are kept, the ordinary visitors are not.
/// </summary>
public sealed record WebSourceCounts(long SiteId, DateTimeOffset Hour, string Address, long Requests, long ClientErrors,
    long Findings, long Observations, long LoginPosts, long XmlrpcPosts, DateTimeOffset First, DateTimeOffset Last, string? Protection);

/// <summary>How far one site's log file has been read: the byte offset after the last whole line.</summary>
public sealed record WebLogPosition(long SiteId, string File, long Offset, DateTimeOffset LastLine);

/// <summary>Everything one read of one or more site logs produced. Written in one transaction.</summary>
public sealed record WebBatch(IReadOnlyList<WebFinding> Findings, IReadOnlyList<WebSiteCounts> Sites,
    IReadOnlyList<WebSourceCounts> Sources, IReadOnlyList<WebLogPosition> Positions);

/// <summary>
/// A site as the sensor last saw it in the IIS configuration, and whether its log is being read.
/// </summary>
/// <param name="Status"><c>collected</c>, <c>unavailable</c> or <c>limited</c>, as coverage intervals say.</param>
/// <param name="Reason">A stable reason code, for example <c>access-denied</c> or <c>missing-field: c-ip</c>.</param>
/// <param name="Remedy">What the operator can do about it, done by hand, or <see langword="null"/>.</param>
public sealed record WebSiteState(long SiteId, string Name, string Status, string? Reason, string? Remedy, bool Proxied,
    DateTimeOffset UpdatedAt);

/// <summary>
/// Writes the IIS log evidence of ADR 0011. Like <see cref="EvidenceWriter"/>, it accepts typed records
/// and nothing else: there is no method a query string, a referer or a user name could be passed to.
/// </summary>
public sealed class WebEvidenceWriter
{
    /// <summary>The coverage source of the sensor as a whole: it ran, and read what it could.</summary>
    public const string SensorSource = "iis";

    public const int MaxPathLength = 512;
    public const int MaxUserAgentLength = 256;
    public const int MaxSiteNameLength = 128;

    /// <summary>Client errors from one address to one site in one hour that keep its counts without a finding.</summary>
    public const int ClientErrorThreshold = 50;

    private const string PositionPrefix = "iis-w3svc";
    private readonly EvidenceStore store;

    public WebEvidenceWriter(EvidenceStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (store.ReadOnly) throw new InvalidOperationException("A read-only evidence store cannot be written.");
        this.store = store;
    }

    /// <summary>The coverage source for one site's log: <c>iis-w3svc</c> and the site ID.</summary>
    public static string SiteSource(long siteId) => PositionPrefix + siteId.ToString(CultureInfo.InvariantCulture);

    /// <summary>
    /// Writes a batch: findings, the hourly counts added to what is stored, and the read positions, all or
    /// nothing. A position is written in the same transaction as what was read up to it, so a crash can
    /// never count a line twice or skip one.
    /// </summary>
    public void Write(WebBatch batch)
    {
        ArgumentNullException.ThrowIfNull(batch);
        if (batch.Findings.Count + batch.Sites.Count + batch.Sources.Count + batch.Positions.Count == 0) return;
        using var transaction = store.Connection.BeginTransaction();
        using (var insert = store.Command("""
            INSERT INTO web_findings(ts, site_id, address, method, path, status, rules, score, user_agent, live, proxied, protection)
            VALUES ($ts, $site, $address, $method, $path, $status, $rules, $score, $agent, $live, $proxied, $protection);
            """, transaction, ("$ts", 0L), ("$site", 0L), ("$address", ""), ("$method", ""), ("$path", ""), ("$status", 0),
            ("$rules", ""), ("$score", 0), ("$agent", ""), ("$live", 0), ("$proxied", 0), ("$protection", null)))
        {
            foreach (var finding in batch.Findings)
            {
                insert.Parameters["$ts"].Value = EvidenceStore.ToMs(finding.Timestamp);
                insert.Parameters["$site"].Value = finding.SiteId;
                insert.Parameters["$address"].Value = EvidenceText.Clean(finding.Address, 64);
                insert.Parameters["$method"].Value = EvidenceText.Clean(finding.Method, 16);
                insert.Parameters["$path"].Value = EvidenceText.Clean(finding.Path, MaxPathLength);
                insert.Parameters["$status"].Value = finding.Status;
                insert.Parameters["$rules"].Value = Rules(finding.Hits);
                insert.Parameters["$score"].Value = finding.Score;
                insert.Parameters["$agent"].Value = EvidenceText.Clean(finding.UserAgent, MaxUserAgentLength);
                insert.Parameters["$live"].Value = finding.Live ? 1 : 0;
                insert.Parameters["$proxied"].Value = finding.Proxied ? 1 : 0;
                insert.Parameters["$protection"].Value = finding.Protection is null ? DBNull.Value : EvidenceText.Clean(finding.Protection, 64);
                insert.ExecuteNonQuery();
            }
        }

        using (var sites = store.Command("""
            INSERT INTO web_hourly_sites(hour, site_id, requests, client_errors, server_errors, findings, observations, login_posts,
                xmlrpc_posts, bytes_received)
            VALUES ($hour, $site, $requests, $client, $server, $findings, $observations, $login, $xmlrpc, $bytes)
            ON CONFLICT(hour, site_id) DO UPDATE SET
                requests = requests + excluded.requests, client_errors = client_errors + excluded.client_errors,
                server_errors = server_errors + excluded.server_errors, findings = findings + excluded.findings,
                observations = observations + excluded.observations, login_posts = login_posts + excluded.login_posts,
                xmlrpc_posts = xmlrpc_posts + excluded.xmlrpc_posts, bytes_received = bytes_received + excluded.bytes_received;
            """, transaction, ("$hour", 0L), ("$site", 0L), ("$requests", 0L), ("$client", 0L), ("$server", 0L), ("$findings", 0L),
            ("$observations", 0L), ("$login", 0L), ("$xmlrpc", 0L), ("$bytes", 0L)))
        {
            foreach (var counts in batch.Sites)
            {
                sites.Parameters["$hour"].Value = Hour(counts.Hour);
                sites.Parameters["$site"].Value = counts.SiteId;
                sites.Parameters["$requests"].Value = counts.Requests;
                sites.Parameters["$client"].Value = counts.ClientErrors;
                sites.Parameters["$server"].Value = counts.ServerErrors;
                sites.Parameters["$findings"].Value = counts.Findings;
                sites.Parameters["$observations"].Value = counts.Observations;
                sites.Parameters["$login"].Value = counts.LoginPosts;
                sites.Parameters["$xmlrpc"].Value = counts.XmlrpcPosts;
                sites.Parameters["$bytes"].Value = counts.BytesReceived;
                sites.ExecuteNonQuery();
            }
        }

        using (var sources = store.Command("""
            INSERT INTO web_hourly_sources(hour, site_id, address, requests, client_errors, findings, observations, login_posts,
                xmlrpc_posts, first_ts, last_ts, protection)
            VALUES ($hour, $site, $address, $requests, $client, $findings, $observations, $login, $xmlrpc, $first, $last, $protection)
            ON CONFLICT(hour, site_id, address) DO UPDATE SET
                requests = requests + excluded.requests, client_errors = client_errors + excluded.client_errors,
                findings = findings + excluded.findings, observations = observations + excluded.observations,
                login_posts = login_posts + excluded.login_posts, xmlrpc_posts = xmlrpc_posts + excluded.xmlrpc_posts,
                first_ts = MIN(first_ts, excluded.first_ts), last_ts = MAX(last_ts, excluded.last_ts),
                protection = excluded.protection;
            """, transaction, ("$hour", 0L), ("$site", 0L), ("$address", ""), ("$requests", 0L), ("$client", 0L), ("$findings", 0L),
            ("$observations", 0L), ("$login", 0L), ("$xmlrpc", 0L), ("$first", 0L), ("$last", 0L), ("$protection", null)))
        {
            foreach (var counts in batch.Sources)
            {
                sources.Parameters["$hour"].Value = Hour(counts.Hour);
                sources.Parameters["$site"].Value = counts.SiteId;
                sources.Parameters["$address"].Value = EvidenceText.Clean(counts.Address, 64);
                sources.Parameters["$requests"].Value = counts.Requests;
                sources.Parameters["$client"].Value = counts.ClientErrors;
                sources.Parameters["$findings"].Value = counts.Findings;
                sources.Parameters["$observations"].Value = counts.Observations;
                sources.Parameters["$login"].Value = counts.LoginPosts;
                sources.Parameters["$xmlrpc"].Value = counts.XmlrpcPosts;
                sources.Parameters["$first"].Value = EvidenceStore.ToMs(counts.First);
                sources.Parameters["$last"].Value = EvidenceStore.ToMs(counts.Last);
                sources.Parameters["$protection"].Value = counts.Protection is null ? DBNull.Value : EvidenceText.Clean(counts.Protection, 64);
                sources.ExecuteNonQuery();
            }
        }

        using (var positions = store.Command("""
            INSERT INTO collector_state(channel, last_record_id, last_ts) VALUES ($channel, $offset, $ts)
            ON CONFLICT(channel) DO UPDATE SET last_record_id = excluded.last_record_id, last_ts = excluded.last_ts;
            """, transaction, ("$channel", ""), ("$offset", 0L), ("$ts", 0L)))
        {
            foreach (var position in batch.Positions)
            {
                positions.Parameters["$channel"].Value = PositionChannel(position.SiteId, position.File);
                positions.Parameters["$offset"].Value = position.Offset;
                positions.Parameters["$ts"].Value = EvidenceStore.ToMs(position.LastLine);
                positions.ExecuteNonQuery();
            }
        }

        transaction.Commit();
    }

    /// <summary>Where the last read of one site's log file stopped, if this file was read before.</summary>
    public WebLogPosition? Position(long siteId, string file)
    {
        using var command = store.Command("SELECT last_record_id, last_ts FROM collector_state WHERE channel = $c;", null,
            ("$c", PositionChannel(siteId, file)));
        using var reader = command.ExecuteReader();
        return reader.Read() ? new WebLogPosition(siteId, file, reader.GetInt64(0), EvidenceStore.FromMs(reader.GetInt64(1))) : null;
    }

    /// <summary>
    /// Records the sites the sensor knows and whether each log is read. A site no longer in the IIS
    /// configuration keeps its row, marked so, because its evidence is still in the store.
    /// </summary>
    public void RecordSites(IReadOnlyList<WebSiteState> sites, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(sites);
        using var transaction = store.Connection.BeginTransaction();
        store.Execute("UPDATE web_sites SET status = 'unavailable', reason = 'not-in-configuration', remedy = NULL, updated_ts = $ts;", transaction,
            ("$ts", EvidenceStore.ToMs(now)));
        foreach (var site in sites)
            store.Execute("""
                INSERT INTO web_sites(site_id, name, status, reason, remedy, proxied, updated_ts)
                VALUES ($id, $name, $status, $reason, $remedy, $proxied, $ts)
                ON CONFLICT(site_id) DO UPDATE SET name = excluded.name, status = excluded.status, reason = excluded.reason,
                    remedy = excluded.remedy, proxied = excluded.proxied, updated_ts = excluded.updated_ts;
                """, transaction, ("$id", site.SiteId), ("$name", EvidenceText.Clean(site.Name, MaxSiteNameLength)),
                ("$status", EvidenceText.Clean(site.Status, 16)),
                ("$reason", site.Reason is null ? null : EvidenceText.Clean(site.Reason, 200)),
                ("$remedy", site.Remedy is null ? null : EvidenceText.Clean(site.Remedy, 300)),
                ("$proxied", site.Proxied ? 1 : 0), ("$ts", EvidenceStore.ToMs(site.UpdatedAt)));
        transaction.Commit();
    }

    /// <summary>
    /// Marks every known site as not read, for a reason that covers them all - the IIS configuration could not
    /// be read, or it logs centrally - so no site's last state keeps saying "read" while nothing is.
    /// </summary>
    public void MarkAllSites(string status, string reason, DateTimeOffset now) =>
        store.Execute("UPDATE web_sites SET status = $status, reason = $reason, remedy = NULL, updated_ts = $ts;", null,
            ("$status", EvidenceText.Clean(status, 16)), ("$reason", EvidenceText.Clean(reason, 200)), ("$ts", EvidenceStore.ToMs(now)));

    /// <summary>The read positions kept for files no longer read: removed once older than the detailed rows.</summary>
    internal static long PrunePositions(EvidenceStore store, long cutoffMs)
    {
        using var command = store.Command("DELETE FROM collector_state WHERE channel LIKE 'iis-w3svc%' AND last_ts < $c;", null, ("$c", cutoffMs));
        return command.ExecuteNonQuery();
    }

    private static string PositionChannel(long siteId, string file) =>
        SiteSource(siteId) + ":" + EvidenceText.Clean(file, 128).ToLowerInvariant();

    private static string Rules(IReadOnlyList<WebHit> hits) =>
        string.Join(',', hits.Select(hit => EvidenceText.Clean(hit.Id, 32) +
            (hit.Score > 0 ? ":" + hit.Score.ToString(CultureInfo.InvariantCulture) : "")));

    private static long Hour(DateTimeOffset hour) => EvidenceStore.ToMs(hour) / 3_600_000;
}

/// <summary>The <c>http.*</c> settings (ADR 0011, section 5).</summary>
public static class WebSettings
{
    public const string ProxiedSites = "http.proxied_sites";
    public const int MaxProxiedSites = 500;

    internal static IEnumerable<SettingDefinition> Definitions() =>
    [
        new(ProxiedSites,
            "IIS sites that sit behind a proxy, by name. Their client address is the proxy's, so their requests are recorded, " +
            "marked proxied, and never counted against an address. Read again within 15 minutes.",
            new JsonArray(), SettingEffect.NextUse, ValidateSites),
    ];

    /// <summary>The site names in a stored value, compared without regard to case as IIS does.</summary>
    public static IReadOnlySet<string> Read(EvidenceSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var value = settings.Get(ProxiedSites);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (ValidateSites(value) is not null) return names;
        foreach (var entry in value.AsArray())
            if (entry is JsonValue v && v.TryGetValue<string>(out var name)) names.Add(name);
        return names;
    }

    private static string? ValidateSites(JsonNode node)
    {
        const string Expected = "a list of IIS site names, for example [\"shop.example\"]";
        if (node is not JsonArray list) return Expected;
        if (list.Count > MaxProxiedSites) return $"at most {MaxProxiedSites} sites";
        foreach (var entry in list)
            if (entry is not JsonValue value || !value.TryGetValue<string>(out var name) || name.Length is 0 or > WebEvidenceWriter.MaxSiteNameLength
                || name.Any(char.IsControl))
                return $"{Expected}; each name 1 to {WebEvidenceWriter.MaxSiteNameLength} characters";
        return null;
    }
}

using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;

namespace WPShield.Cli.Mcp;

/// <summary>
/// The web evidence of ADR 0011 (<c>web_summary</c>, <c>web_top_sources</c>, <c>web_findings</c>) and the
/// one answer that joins every source for one address (<c>address_report</c>).
/// </summary>
/// <remarks>
/// <para>
/// <b>Read through <see cref="WebEvidenceQueries"/> only,</b> the API <c>wpshield web</c> and the desktop
/// read, so the three answer the same question the same way: coverage first, "no data" never shown as
/// zero, requests counted over whole hours.
/// </para>
/// <para>
/// <b>Site names, paths and user agents leave the host only with <c>mcp.detailed_records</c>,</b> the
/// gate that already withholds account names. Without it an answer carries site IDs, counts and rule and
/// observation IDs, and says what was withheld and which setting controls it. With it, every such string
/// is wrapped as untrusted: a path and a user agent were chosen by whoever sent the request, and a site
/// name and a remedy are text written into the store.
/// </para>
/// </remarks>
internal sealed partial class EvidenceTools
{
    private static readonly string[] WebRangeNames = ["1h", "6h", "24h", "7d", "30d"];

    private const string WebEvidenceOnly =
        "Web evidence is evidence only (ADR 0011): nothing is decided or blocked from it.";

    private const string WebHours =
        "Requests are counted per site and whole hour, so request totals cover counted_hours, which can start before the range and end after it. Findings are stored per request and counted exactly.";

    private const string WebObservations =
        "observations counts WEB-OBS-001: a .php file that answered 2xx and is not a WordPress entry point, which is how a webshell answers. wp_login_posts is WEB-OBS-002 and xmlrpc_posts WEB-OBS-003. Observations are evidence only and carry no score.";

    private const string SiteDetailWithheld =
        "Site names, request paths, user agents and remedies are withheld: the operator has not enabled mcp.detailed_records. Site IDs, counts and rule and observation IDs are complete.";

    private const string NoSiteKnown =
        "The IIS log sensor has not run against this store: it knows no site. That is no data, not zero requests.";

    private const string KeptAddresses =
        "An address is kept per hour only when a rule or an observation flagged it, or it sent more than 50 client errors to one site; an ordinary visitor leaves only counts, so an address missing here may still have sent requests.";

    public ToolAnswer WebSummary(string? range = null, int? site = null) => Guard("web_summary", () =>
    {
        var period = ParseWebRange(range, Now);
        CheckSite(site);
        return Answer("web_summary", period, (store, body, notes) =>
        {
            var web = new WebEvidenceQueries(store);
            var sites = web.Sites();
            var siteId = KnownSite(sites, site);
            body["coverage"] = WebCoverage(web, sites, period, siteId);
            var summary = web.Summary(period.From, period.To, siteId);
            var rules = web.RuleCounts(period.From, period.To, siteId);
            body["detail"] = DetailStatement(summary.FindingsFrom is null);
            body["result"] = new JsonObject
            {
                ["site_id"] = siteId,
                ["counted_hours"] = new JsonObject { ["from"] = Iso(summary.HoursFrom), ["to"] = Iso(summary.HoursTo) },
                ["requests"] = summary.Requests,
                ["client_errors"] = summary.ClientErrors,
                ["server_errors"] = summary.ServerErrors,
                ["bytes_received"] = summary.BytesReceived,
                ["findings"] = summary.Findings,
                ["observations"] = summary.Observations,
                ["wp_login_posts"] = summary.LoginPosts,
                ["xmlrpc_posts"] = summary.XmlrpcPosts,
                ["addresses_kept"] = summary.Sources,
                ["addresses_never_counted_against"] = summary.ProtectedSources,
                ["findings_pruned_before"] = summary.FindingsFrom is { } pruned ? Iso(pruned) : null,
                ["rules_and_observations"] = RulesNode(rules),
                ["truncated"] = rules.Count > MaxLimit
            };
            WebNotes(notes, sites);
            notes.Add(WebObservations);
            if (summary.FindingsFrom is not null)
                notes.Add("Findings before findings_pruned_before were pruned from the store; the hourly counts remain.");
        });
    });

    public ToolAnswer WebTopSources(string? range = null, int? site = null, int limit = DefaultLimit) =>
        Guard("web_top_sources", () =>
        {
            var period = ParseWebRange(range, Now);
            CheckSite(site);
            CheckLimit(limit);
            return Answer("web_top_sources", period, (store, body, notes) =>
            {
                var web = new WebEvidenceQueries(store);
                var sites = web.Sites();
                var siteId = KnownSite(sites, site);
                body["coverage"] = WebCoverage(web, sites, period, siteId);
                var summary = web.Summary(period.From, period.To, siteId);
                var sources = web.TopSources(period.From, period.To, siteId, limit + 1);
                var labels = Labels(store);
                body["result"] = new JsonObject
                {
                    ["site_id"] = siteId,
                    ["counted_hours"] = new JsonObject { ["from"] = Iso(summary.HoursFrom), ["to"] = Iso(summary.HoursTo) },
                    ["total_addresses_kept"] = summary.Sources,
                    ["addresses_never_counted_against"] = summary.ProtectedSources,
                    ["sources"] = new JsonArray(sources.Take(limit).Select(s => (JsonNode)new JsonObject
                    {
                        ["address"] = Address(s.Address),
                        ["label"] = labels.Find(s.Address),
                        ["requests"] = s.Requests,
                        ["client_errors"] = s.ClientErrors,
                        ["findings"] = s.Findings,
                        ["observations"] = s.Observations,
                        ["wp_login_posts"] = s.LoginPosts,
                        ["xmlrpc_posts"] = s.XmlrpcPosts,
                        ["sites"] = s.Sites,
                        ["first"] = Iso(s.First),
                        ["last"] = Iso(s.Last),
                        ["network"] = Address(s.Network),
                        ["other_sources_in_network"] = s.Neighbors
                    }).ToArray()),
                    ["truncated"] = sources.Count > limit
                };
                WebNotes(notes, sites);
                notes.Add(KeptAddresses);
                notes.Add("Addresses the evidence never counts against (this host, the allow-list, private ranges, proxied sites) are not listed; addresses_never_counted_against counts them.");
            });
        });

    public ToolAnswer WebFindings(string? range = null, int? site = null, string? address = null, int limit = DefaultLimit) =>
        Guard("web_findings", () =>
        {
            var period = ParseWebRange(range, Now);
            CheckSite(site);
            CheckLimit(limit);
            var canonical = address is null ? null : ParseAddress("address", address);
            return Answer("web_findings", period, (store, body, notes) =>
            {
                var web = new WebEvidenceQueries(store);
                var sites = web.Sites();
                var siteId = KnownSite(sites, site);
                body["coverage"] = WebCoverage(web, sites, period, siteId);
                var found = web.Findings(period.From, period.To, siteId, canonical, limit + 1);
                var pruned = web.Summary(period.From, period.To, siteId).FindingsFrom;
                body["detail"] = DetailStatement(pruned is null);
                body["result"] = new JsonObject
                {
                    ["site_id"] = siteId,
                    ["address"] = canonical,
                    ["findings"] = new JsonArray(found.Take(limit).Select(f => (JsonNode)FindingNode(f, sites)).ToArray()),
                    ["truncated"] = found.Count > limit,
                    ["paths_withheld"] = !access.DetailedRecords
                };
                WebNotes(notes, sites);
                notes.Add("Newest first. live=false marks a line read by the catch-up when the sensor started: history, which nothing that decides ever reads.");
                notes.Add("WEB-OBS-002 and WEB-OBS-003 (POSTs to wp-login.php and xmlrpc.php) are counted, not stored per request: web_summary and web_top_sources have them.");
                if (pruned is { } before)
                    notes.Add($"Findings before {Iso(before)} were pruned from the store; only their hourly counts remain.");
            });
        });

    public ToolAnswer AddressReport(string address, string? range = null) => Guard("address_report", () =>
    {
        var canonical = ParseAddress("address", address);
        var period = ParseWebRange(range, Now, defaultRange: "7d");
        return Answer("address_report", period, (store, body, notes) =>
        {
            var queries = new EvidenceQueries(store);
            var web = new WebEvidenceQueries(store);
            var allowed = access.DetailedRecords;
            body["coverage"] = CoverageStatement(queries.Coverage(period.From, period.To), period,
                [EvidenceWriter.RawSource, WebEvidenceWriter.SensorSource]);

            var history = queries.SourceHistory(canonical, period.From, period.To, recent: 0);
            var attempts = history.Timeline.Sum(b => b.Attempts);
            var logons = new JsonObject
            {
                ["in_range"] = attempts,
                ["on_nonexistent_accounts"] = history.Timeline.Sum(b => b.UnknownAccount),
                ["first_seen_ever"] = history.FirstSeen is { } first ? Iso(first) : null,
                ["days_seen_ever"] = history.DaysSeen
            };
            if (history.Detailed) logons["distinct_accounts_tried"] = history.Accounts.Count;
            if (allowed && history.Detailed)
                logons["accounts_tried"] = new JsonArray(history.Accounts.Take(DefaultLimit).Select(a => (JsonNode)new JsonObject
                {
                    ["account"] = Untrusted(a.Account, EvidenceText.MaxAccountLength),
                    ["failed_logons"] = a.Count
                }).ToArray());

            var sites = web.Sites();
            var kept = web.TopSources(period.From, period.To, null, WebEvidenceQueries.MaxSources, includeProtected: true)
                .FirstOrDefault(s => s.Address == canonical);
            var findings = web.Findings(period.From, period.To, null, canonical, DefaultLimit + 1);
            var webNode = new JsonObject
            {
                ["kept"] = kept is not null,
                ["requests"] = kept?.Requests ?? 0,
                ["client_errors"] = kept?.ClientErrors ?? 0,
                ["findings"] = kept?.Findings ?? 0,
                ["observations"] = kept?.Observations ?? 0,
                ["wp_login_posts"] = kept?.LoginPosts ?? 0,
                ["xmlrpc_posts"] = kept?.XmlrpcPosts ?? 0,
                ["sites"] = kept?.Sites ?? 0,
                ["first"] = kept is null ? null : Iso(kept.First),
                ["last"] = kept is null ? null : Iso(kept.Last),
                ["never_counted_against"] = ProtectionNode(kept?.Protection),
                ["rules_and_observations"] = RulesNode(web.RuleCounts(period.From, period.To, null, canonical)),
                ["recent_findings"] = new JsonArray(findings.Take(DefaultLimit).Select(f => (JsonNode)FindingNode(f, sites)).ToArray()),
                ["truncated"] = findings.Count > DefaultLimit
            };

            var decisions = queries.DecisionsAbout(canonical, period.From, period.To, DefaultLimit + 1);
            var active = queries.ActiveDecisions(Now);
            var inForce = active.For(canonical);
            var options = DefenseOptions.Read(new EvidenceSettings(store));
            var single = AddressRanges.Single(IPAddress.Parse(canonical));
            var allowEntry = options.Allow.Where(n => AddressRanges.Overlaps(n, single)).Select(n => (IPNetwork?)n).FirstOrDefault();
            var privateRange = AddressRanges.PrivateRangeOf(single);

            body["result"] = new JsonObject
            {
                ["address"] = canonical,
                ["network"] = EvidenceQueries.Network(canonical),
                ["label"] = Labels(store).Find(canonical),
                ["seen_in_range"] = new JsonObject
                {
                    ["failed_logons"] = attempts > 0,
                    ["web"] = kept is not null || findings.Count > 0,
                    ["decisions"] = decisions.Count > 0
                },
                ["engine_protection"] = new JsonObject
                {
                    ["allow_list_entry"] = allowEntry is { } entry ? AddressRanges.Text(entry) : null,
                    ["special_address"] = AddressRanges.SpecialKind(single),
                    ["private_range"] = privateRange is { } privateNetwork ? AddressRanges.Text(privateNetwork) : null,
                    ["private_ranges_decided_against"] = options.IncludePrivate
                },
                ["decision_in_force"] = inForce is null ? null : DecisionNode(inForce),
                ["decisions_in_force_known"] = active.CollectorCurrent,
                ["decisions"] = new JsonArray(decisions.Take(DefaultLimit).Select(d => (JsonNode)DecisionNode(d)).ToArray()),
                ["decisions_truncated"] = decisions.Count > DefaultLimit,
                ["failed_logons"] = logons,
                ["web"] = webNode
            };
            body["detail"] = DetailStatement(history.Detailed);

            notes.Add("One address across every source in the store. A source the coverage section shows as a gap proves nothing about this address in that time.");
            notes.Add("decisions is an audit trail about the address and its /24 or /64, not the current state. decision_in_force is what the engine holds now, and is null whenever decisions_in_force_known is false because the collector is not recording.");
            notes.Add("engine_protection is what the decision engine reads from the store (ADR 0009, section 4). Whether the address is one of this host's own is decided by the collector, and web evidence records it under never_counted_against.");
            notes.Add(WebEvidenceOnly);
            if (!allowed) notes.Add(WithheldBySetting);
            if (!allowed) notes.Add(SiteDetailWithheld);
            if (!history.Detailed) notes.Add(PrunedFromStore);
            notes.Add("first_seen_ever and days_seen_ever cover everything the store still holds for this address's failed logons, not only this range.");
        });
    });

    // ---------------------------------------------------------------------------------------------
    //  Web helpers
    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// The ranges <c>wpshield web</c> takes. Web evidence keeps findings for a shorter time than 90 days
    /// and counts requests per hour, so a 90-day answer would be mostly pruned history.
    /// </summary>
    internal static TimeRange ParseWebRange(string? range, DateTimeOffset now, string defaultRange = "24h")
    {
        var name = (range ?? defaultRange).Trim().ToLowerInvariant();
        if (!WebRangeNames.Contains(name, StringComparer.Ordinal))
            throw new ToolArgumentException("range", "range is one of 1h, 6h, 24h, 7d or 30d.", range);
        return ParseRange(name, null, null, now);
    }

    private static void CheckSite(int? site)
    {
        if (site is < 1)
            throw new ToolArgumentException("site", "site is an IIS site ID: a whole number from 1, the number of its W3SVC log folder.",
                site.Value.ToString(CultureInfo.InvariantCulture));
    }

    /// <summary>The site asked about, which the sensor must know: an unknown ID is a mistake to correct, not an empty site.</summary>
    private static long? KnownSite(IReadOnlyList<WebSiteCoverage> sites, int? site)
    {
        if (site is not { } id) return null;
        if (sites.Any(s => s.SiteId == id)) return id;
        throw new ToolArgumentException("site", "The IIS log sensor knows no site with this ID. web_summary lists the IDs it knows.",
            id.ToString(CultureInfo.InvariantCulture));
    }

    /// <summary>Coverage first: the sensor's intervals (or one site's) and every site the sensor knows, with its state.</summary>
    private JsonObject WebCoverage(WebEvidenceQueries web, IReadOnlyList<WebSiteCoverage> sites, TimeRange period, long? siteId)
    {
        var source = siteId is { } id ? WebEvidenceWriter.SiteSource(id) : WebEvidenceWriter.SensorSource;
        var coverage = CoverageStatement(web.Coverage(period.From, period.To), period, [source]);
        var read = sites.Count(s => s.Status == "collected");
        var ignored = sites.Count(s => s.Status == "ignored");
        IReadOnlyList<WebSiteCoverage> listed = siteId is null ? sites : [.. sites.Where(s => s.SiteId == siteId)];
        coverage["sites"] = new JsonObject
        {
            ["known"] = sites.Count,
            ["read"] = read,
            ["not_read"] = sites.Count - read - ignored,
            ["ignored_no_http_binding"] = ignored,
            ["sites"] = new JsonArray(listed.Take(MaxLimit).Select(s => (JsonNode)SiteNode(s)).ToArray()),
            ["truncated"] = listed.Count > MaxLimit
        };
        return coverage;
    }

    private JsonObject SiteNode(WebSiteCoverage site)
    {
        var node = new JsonObject
        {
            ["site_id"] = site.SiteId,
            ["state"] = site.Status == "collected" ? "read" : site.Status == "ignored" ? "ignored" : "not-read",
            ["status"] = Code(site.Status),
            ["reason"] = site.Reason is null ? null : Code(site.Reason),
            ["proxied"] = site.Proxied
        };
        if (access.DetailedRecords)
        {
            node["name"] = Untrusted(site.Name, WebEvidenceWriter.MaxSiteNameLength);
            node["remedy"] = site.Remedy is null ? null : Untrusted(site.Remedy, 300);
        }
        return node;
    }

    private JsonObject FindingNode(WebFindingRecord finding, IReadOnlyList<WebSiteCoverage> sites)
    {
        var node = new JsonObject
        {
            ["time"] = Iso(finding.Timestamp),
            ["site_id"] = finding.SiteId,
            ["address"] = Address(finding.Address),
            ["method"] = Code(finding.Method),
            ["status"] = finding.Status,
            ["rules"] = new JsonArray(finding.Hits.Take(MaxLimit).Select(h => (JsonNode)Code(h.Id)).ToArray()),
            ["score"] = finding.Score,
            ["live"] = finding.Live,
            ["proxied"] = finding.Proxied,
            ["never_counted_against"] = ProtectionNode(finding.Protection)
        };
        if (access.DetailedRecords)
        {
            var name = sites.FirstOrDefault(s => s.SiteId == finding.SiteId)?.Name;
            node["site"] = name is null ? null : Untrusted(name, WebEvidenceWriter.MaxSiteNameLength);
            node["path"] = Untrusted(finding.Path, WebEvidenceWriter.MaxPathLength);
            node["user_agent"] = Untrusted(finding.UserAgent, WebEvidenceWriter.MaxUserAgentLength);
        }
        return node;
    }

    private static JsonArray RulesNode(IReadOnlyList<WebRuleCount> rules) =>
        new(rules.Take(MaxLimit).Select(r => (JsonNode)new JsonObject
        {
            ["id"] = Code(r.Id),
            ["requests"] = r.Requests,
            ["kind"] = r.Observation ? "observation" : "rule"
        }).ToArray());

    /// <summary>
    /// Why the evidence never counts against an address, as a stable code. The sensor stores the reason as
    /// a phrase; a phrase it does not write is returned wrapped, like any other unexpected stored text.
    /// </summary>
    private static JsonNode? ProtectionNode(string? protection) => protection switch
    {
        null => null,
        "on the allow-list" => "allow-list",
        "a private range" => "private-range",
        "an address of this host" => "this-host",
        "a loopback address" => "loopback",
        "a link-local address" => "link-local",
        "the unspecified address" => "unspecified",
        _ => Untrusted(protection, 64)
    };

    private void WebNotes(List<string> notes, IReadOnlyList<WebSiteCoverage> sites)
    {
        notes.Add(WebEvidenceOnly);
        notes.Add(WebHours);
        if (sites.Count == 0) notes.Add(NoSiteKnown);
        if (!access.DetailedRecords) notes.Add(SiteDetailWithheld);
    }
}

using WPShield.Cli.Watch;

namespace WPShield.Cli.Report;

/// <summary>
/// Folds a window of evidence into a <see cref="ReportModel"/>. Pure and deterministic, so what the
/// report says can be tested without rendering a page.
/// </summary>
/// <remarks>
/// It counts the same way <see cref="WatchModel"/> does, for the same reason: a finding is a finding,
/// a verdict is counted by its action, and lines the gateway wrote about its own configuration are
/// ignored. Rules that arrive comma-joined on one line — an upload that matched two — are credited to
/// each rule, because the report is answering "which rules are firing", and both did.
/// </remarks>
internal static class ReportAggregator
{
    public static ReportModel Build(
        IEnumerable<EvidenceEvent> events,
        IReadOnlyList<EvidenceSource> sources,
        IReadOnlyList<string> hostScope,
        DateTimeOffset generatedAt)
    {
        ArgumentNullException.ThrowIfNull(events);
        ArgumentNullException.ThrowIfNull(sources);
        ArgumentNullException.ThrowIfNull(hostScope);

        var totalEvents = 0;
        var findings = 0;
        var blocked = 0;
        var observed = 0;
        var allowedUploads = 0;
        var dropped = 0;

        DateTimeOffset? windowStart = null;
        DateTimeOffset? windowEnd = null;
        var modes = new SortedSet<string>(StringComparer.Ordinal);

        // rule -> (findings, maxScore, distinct sites)
        var ruleFindings = new Dictionary<string, int>(StringComparer.Ordinal);
        var ruleMaxScore = new Dictionary<string, int>(StringComparer.Ordinal);
        var ruleSites = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);

        // site -> counters, plus per-site per-rule tallies to pick a top rule.
        var siteFindings = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var siteBlocked = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var siteObserved = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var siteRuleTallies = new Dictionary<string, Dictionary<string, int>>(StringComparer.OrdinalIgnoreCase);

        var pathCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (var evidence in events)
        {
            if (evidence.Kind == EvidenceKind.Other)
            {
                continue;
            }

            totalEvents++;
            windowStart = Min(windowStart, evidence.Timestamp);
            windowEnd = Max(windowEnd, evidence.Timestamp);

            var host = evidence.Host;

            switch (evidence.Kind)
            {
                case EvidenceKind.Finding:
                    findings++;
                    if (host is not null)
                    {
                        Increment(siteFindings, host);
                    }

                    foreach (var rule in SplitRules(evidence.Rules))
                    {
                        Increment(ruleFindings, rule);
                        ruleMaxScore[rule] = Math.Max(ruleMaxScore.GetValueOrDefault(rule), evidence.Score ?? 0);
                        if (host is not null)
                        {
                            (ruleSites.TryGetValue(rule, out var set) ? set : ruleSites[rule] = new(StringComparer.OrdinalIgnoreCase)).Add(host);
                            var tallies = siteRuleTallies.TryGetValue(host, out var t) ? t : siteRuleTallies[host] = new(StringComparer.Ordinal);
                            Increment(tallies, rule);
                        }
                    }

                    if (evidence.Path is not null)
                    {
                        Increment(pathCounts, evidence.Path);
                    }

                    break;

                case EvidenceKind.Verdict:
                    if (evidence.Mode is not null)
                    {
                        modes.Add(evidence.Mode);
                    }

                    switch (evidence.Action)
                    {
                        case EvidenceAction.Block:
                            blocked++;
                            if (host is not null)
                            {
                                Increment(siteBlocked, host);
                            }

                            break;
                        case EvidenceAction.Observe:
                            observed++;
                            if (host is not null)
                            {
                                Increment(siteObserved, host);
                            }

                            break;
                        case EvidenceAction.Allow:
                            allowedUploads++;
                            break;
                    }

                    break;

                case EvidenceKind.DroppedNotice:
                    dropped++;
                    break;
            }
        }

        return new ReportModel
        {
            GeneratedAt = generatedAt,
            HostScope = hostScope,
            WindowStart = windowStart,
            WindowEnd = windowEnd,
            TotalEvents = totalEvents,
            Findings = findings,
            Blocked = blocked,
            Observed = observed,
            AllowedUploads = allowedUploads,
            Dropped = dropped,
            ModesSeen = modes.ToArray(),
            Rules = BuildRules(ruleFindings, ruleMaxScore, ruleSites),
            Sites = BuildSites(siteFindings, siteBlocked, siteObserved, siteRuleTallies),
            TopPaths = BuildPaths(pathCounts),
            Sources = sources
        };
    }

    private static IReadOnlyList<RuleRollup> BuildRules(
        Dictionary<string, int> findings,
        Dictionary<string, int> maxScore,
        Dictionary<string, HashSet<string>> sites)
    {
        return findings
            .Select(pair => new RuleRollup
            {
                RuleId = pair.Key,
                Findings = pair.Value,
                MaxScore = maxScore.GetValueOrDefault(pair.Key),
                Sites = sites.TryGetValue(pair.Key, out var set) ? set.Count : 0
            })
            .OrderByDescending(rule => rule.Findings)
            .ThenByDescending(rule => rule.MaxScore)
            .ThenBy(rule => rule.RuleId, StringComparer.Ordinal)
            .ToArray();
    }

    private static IReadOnlyList<SiteRollup> BuildSites(
        Dictionary<string, int> findings,
        Dictionary<string, int> blocked,
        Dictionary<string, int> observed,
        Dictionary<string, Dictionary<string, int>> ruleTallies)
    {
        var sites = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        sites.UnionWith(findings.Keys);
        sites.UnionWith(blocked.Keys);
        sites.UnionWith(observed.Keys);

        return sites
            .Select(site => new SiteRollup
            {
                Site = site,
                Findings = findings.GetValueOrDefault(site),
                Blocked = blocked.GetValueOrDefault(site),
                Observed = observed.GetValueOrDefault(site),
                TopRule = TopRuleFor(site, ruleTallies)
            })
            .OrderByDescending(site => site.Blocked)
            .ThenByDescending(site => site.Findings)
            .ThenBy(site => site.Site, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string? TopRuleFor(string site, Dictionary<string, Dictionary<string, int>> ruleTallies)
    {
        if (!ruleTallies.TryGetValue(site, out var tallies) || tallies.Count == 0)
        {
            return null;
        }

        return tallies
            .OrderByDescending(pair => pair.Value)
            .ThenBy(pair => pair.Key, StringComparer.Ordinal)
            .First().Key;
    }

    private static IReadOnlyList<PathRollup> BuildPaths(Dictionary<string, int> paths)
    {
        return paths
            .Select(pair => new PathRollup { Path = pair.Key, Count = pair.Value })
            .OrderByDescending(path => path.Count)
            .ThenBy(path => path.Path, StringComparer.Ordinal)
            .Take(10)
            .ToArray();
    }

    /// <summary>Splits a comma-joined rule list, trimming and dropping empties.</summary>
    private static IEnumerable<string> SplitRules(string? rules)
    {
        if (string.IsNullOrEmpty(rules))
        {
            yield break;
        }

        foreach (var rule in rules.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            yield return rule;
        }
    }

    private static void Increment<TKey>(Dictionary<TKey, int> map, TKey key) where TKey : notnull =>
        map[key] = map.GetValueOrDefault(key) + 1;

    private static DateTimeOffset Min(DateTimeOffset? current, DateTimeOffset candidate) =>
        current is null || candidate < current ? candidate : current.Value;

    private static DateTimeOffset Max(DateTimeOffset? current, DateTimeOffset candidate) =>
        current is null || candidate > current ? candidate : current.Value;
}

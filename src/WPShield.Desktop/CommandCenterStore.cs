using WPShield.Cli;
using WPShield.Evidence;

namespace WPShield.Desktop;

internal sealed record CommandLogons(EvidenceSummary LastHour, CoverageReport HourCoverage,
    IReadOnlyList<EvidenceBucket> Week, string? TopNetwork, ActiveDecisions Active);

internal sealed record CommandWeb(WebSummary Summary, IReadOnlyList<WebSiteCoverage> Sites, int ReadSites,
    bool Complete, bool HasData);

internal sealed record CommandCenterRead(DateTimeOffset At, CollectorReading Collector, DateTimeOffset? NewestRecord,
    IReadOnlyList<HostFactReading> Facts, CommandLogons Logons, CommandWeb Web,
    IReadOnlyList<HostRestart> Restarts, IReadOnlyList<HealthHour> HealthHistory, IReadOnlyList<PosturePoint> PostureHistory,
    bool AnalystConfigured)
{
    internal HostFactReading? Fact(string name, string? kind = null) => Facts.FirstOrDefault(f => f.Fact == name && f.Kind == kind);
}

/// <summary>Reads the command center from the same bounded APIs as the CLI and the detailed views.</summary>
internal sealed class CommandCenterStore(string path, Func<bool> elevated)
{
    internal CommandCenterRead Read(DateTimeOffset now)
    {
        now = now.ToUniversalTime();
        using var store = EvidenceAccess.OpenReadOnly(path, elevated());
        var evidence = new EvidenceQueries(store);
        var web = new WebEvidenceQueries(store);
        var host = new HostFactsQueries(store);
        var hour = TimeSpan.FromHours(1);
        var hourAgo = now - hour;
        var hourStart = new DateTimeOffset(now.UtcTicks - now.UtcTicks % hour.Ticks, TimeSpan.Zero);
        var end = now.AddMilliseconds(1);

        var active = evidence.ActiveDecisions(now);
        var recent = evidence.Coverage(now - ProtectionStatus.RecentSpan, now)
            .Where(c => c.Source == EvidenceWriter.RawSource).ToArray();
        var collector = ProtectionStatus.Collector(now, active, recent);
        var sources = evidence.TopSources(hourAgo, end, EvidenceQueries.MaxSources);
        var topNetwork = sources.GroupBy(s => s.Network, StringComparer.Ordinal)
            .OrderByDescending(group => group.Sum(s => s.Attempts)).ThenBy(group => group.Key, StringComparer.Ordinal)
            .FirstOrDefault()?.Key;
        var logons = new CommandLogons(evidence.Summary(hourAgo, end),
            CoverageReport.Analyse(evidence.Coverage(hourAgo, end), hourAgo, end),
            evidence.Timeline(hourStart.AddDays(-7), hourStart, hour), topNetwork, active);

        // Start on the last whole hour so the summed request counts have a matching denominator.
        var webFrom = hourStart - hour;
        var summary = web.Summary(webFrom, end);
        var sites = web.Sites();
        var intervals = web.Coverage(webFrom, end);
        var bySource = intervals.ToLookup(c => c.Source, StringComparer.Ordinal);
        var readSites = sites.Count(s => s.Status == "collected" && bySource[WebEvidenceWriter.SiteSource(s.SiteId)]
            .Any(c => c.Status == "collected" && c.From <= now && c.To >= now - EvidenceQueries.CurrentAllowance));
        var complete = sites.Count > 0 && readSites == sites.Count &&
            CoverageReport.Analyse(intervals, webFrom, end, WebEvidenceWriter.SensorSource).State == CoverageReport.Full &&
            sites.All(s => CoverageReport.Analyse(bySource[WebEvidenceWriter.SiteSource(s.SiteId)].ToArray(),
                webFrom, end, WebEvidenceWriter.SiteSource(s.SiteId)).State == CoverageReport.Full);
        var hasWebData = summary.Requests > 0 || summary.Findings > 0 || summary.Observations > 0 ||
            summary.LoginPosts > 0 || summary.XmlrpcPosts > 0 ||
            intervals.Any(c => c.Source != WebEvidenceWriter.SensorSource && c.Status == "collected" && c.To > c.From);
        var webRead = new CommandWeb(summary, sites, readSites, complete, hasWebData);

        var facts = host.LatestAll();
        var restarts = host.Restarts(now - HostFacts.RestartWindow, end, HostFactsQueries.MaxRows);
        var newest = facts.Select(f => (DateTimeOffset?)f.TakenAt)
            .Concat(sources.Select(s => (DateTimeOffset?)s.Last))
            .Concat([web.Findings(webFrom, end, limit: 1).FirstOrDefault()?.Timestamp,
                restarts.FirstOrDefault()?.At, evidence.Decisions(now.AddDays(-1), end, limit: 1).FirstOrDefault()?.Timestamp])
            .Max();
        var settings = new EvidenceSettings(store);
        var configured = settings.Get(AnalystSettings.Enabled)?.GetValue<bool>() == true &&
            settings.Get(AnalystSettings.Provider)?.GetValue<string>() is { Length: > 0 };
        return new(now, collector, newest, facts, logons, webRead, restarts, host.HealthHourly(hourStart.AddHours(-23), end),
            host.PostureHistory(now.AddDays(-30), end), configured);
    }
}

using WPShield.Cli;
using WPShield.Evidence;

namespace WPShield.Desktop;

internal sealed record StoredWebEvidence(EvidenceWindow Window, long? SiteId, IReadOnlyList<WebSiteCoverage> Sites,
    CoverageReport Coverage, CoverageReport? SiteCoverage, WebSummary Summary, IReadOnlyList<WebSource> Sources,
    IReadOnlyList<WebBucket> Timeline, AddressLabels Labels, bool HasData);

internal sealed record StoredWebDetail(IReadOnlyList<WebRuleCount> Counts, IReadOnlyList<WebFindingRecord> Findings);

/// <summary>Each read opens and closes its own read-only connection like the Attacks store.</summary>
internal sealed class EvidenceWebStore(string path, Func<bool> elevated, Func<DateTimeOffset> now)
{
    internal const int SourceLimit = 500;
    internal const int DetailLimit = 100;

    internal StoredWebEvidence Read(AttackRange range, long? siteId)
    {
        using var store = EvidenceAccess.OpenReadOnly(path, elevated());
        var window = EvidenceRanges.Window(StoredAttackBoard.Name(range), now());
        var bucket = StoredAttackBoard.IsStored(range) ? window.Bucket : AttackBoard.Layout(range).Size;
        var queries = new WebEvidenceQueries(store);
        var sites = queries.Sites();
        var intervals = queries.Coverage(window.From, window.To);
        var source = siteId is long site ? WebEvidenceWriter.SiteSource(site) : WebEvidenceWriter.SensorSource;
        var coverage = CoverageReport.Analyse(intervals, window.From, window.To, source);

        // In the all-sites view the sensor can be running even though it could not read a single log.
        // Use the union of log coverage as well as sensor coverage for the dashboard and its gaps.
        var logIntervals = siteId is not null ? [] : intervals
            .Where(row => row.Source != WebEvidenceWriter.SensorSource && row.Status == "collected")
            .Select(row => row with { Source = source }).OrderBy(row => row.From).ToArray();
        var logCoverage = siteId is null ? CoverageReport.Analyse(logIntervals, window.From, window.To, source) : null;
        var summary = queries.Summary(window.From, window.To, siteId);
        var hasData = (logCoverage ?? coverage).State != CoverageReport.None || summary.Requests > 0 ||
            summary.Findings > 0 || summary.Observations > 0 ||
            queries.Findings(window.From, window.To, siteId, limit: 1).Count > 0;
        var timeline = queries.Timeline(window.From, window.To, bucket, siteId);
        if (siteId is null)
        {
            var merged = new List<EvidenceCoverage>();
            foreach (var interval in logIntervals)
            {
                if (merged.Count == 0 || interval.From > merged[^1].To) merged.Add(interval);
                else if (interval.To > merged[^1].To) merged[^1] = merged[^1] with { To = interval.To };
            }
            timeline = timeline.Select(b =>
            {
                var end = b.End == window.To ? window.To - EvidenceQueries.CurrentAllowance : b.End;
                if (end < b.Start) end = b.Start;
                return b with { Covered = b.Covered && merged.Any(log => log.From <= b.Start && log.To >= end) };
            }).ToArray();
        }
        return new(window, siteId, sites, coverage, logCoverage, summary,
            queries.TopSources(window.From, window.To, siteId, SourceLimit), timeline, AddressLabels.Read(store), hasData);
    }

    internal StoredWebDetail ReadDetail(StoredWebEvidence snapshot, string address)
    {
        using var store = EvidenceAccess.OpenReadOnly(path, elevated());
        var queries = new WebEvidenceQueries(store);
        var (from, to) = (snapshot.Window.From, snapshot.Window.To);
        return new(queries.RuleCounts(from, to, snapshot.SiteId, address),
            queries.Findings(from, to, snapshot.SiteId, address, DetailLimit + 1));
    }
}

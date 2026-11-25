using WPShield.Cli.Audit;
using WPShield.Evidence;
using WPShield.WebEvidence;

namespace WPShield.Cli.Host;

/// <summary>
/// <c>iis_sites</c> and <c>iis_posture</c> (ADR 0013), from the same read-only IIS reader <c>wpshield audit</c>
/// uses. A pool's identity type is read; its password never is, and nothing here can hold one.
/// </summary>
internal static class HostIisFacts
{
    public static HostFactReading ReadSites(AuditFacts facts, IisLogConfiguration? logs)
    {
        var now = DateTimeOffset.UtcNow;
        if (!facts.IisReadable) return Unreadable(HostFacts.Sites, now, facts);
        var ids = (logs?.Sites ?? []).GroupBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Id, StringComparer.OrdinalIgnoreCase);
        var pools = facts.Pools.GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        var sites = facts.Sites.Take(HostFacts.MaxSites).Select(site =>
        {
            pools.TryGetValue(site.ApplicationPool, out var pool);
            return new HostSite(
                ids.GetValueOrDefault(site.Name),
                HostFacts.Clean(site.Name),
                HostFacts.Clean(site.State),
                [.. site.Bindings.Take(64).Select(b => new HostBinding(HostFacts.Clean(b.Protocol), b.Port == 0 ? null : b.Port,
                    HostFacts.Clean(b.HostHeader), b.IsLoopback))],
                HostFacts.Clean(site.ApplicationPool),
                HostFacts.Clean(pool?.IdentityType ?? "unknown"),
                IsAdministrator(pool));
        }).ToArray();
        var value = new HostSites(sites);
        return facts.Sites.Count > HostFacts.MaxSites || !facts.IsElevated
            ? HostFactReading.Of(HostFacts.Sites, null, now, value, HostFactStatus.Partial,
                facts.IsElevated ? "site-bound" : "not-elevated",
                facts.IsElevated ? "Only the first sites are listed." : "Run the collector elevated: without it IIS answers optimistically.")
            : HostFactReading.Of(HostFacts.Sites, null, now, value);
    }

    /// <summary><c>LocalSystem</c> is more than an administrator; the built-in identities are not one; a named account is what the audit resolved.</summary>
    internal static bool? IsAdministrator(AuditPool? pool) => pool?.IdentityType switch
    {
        null => null,
        "LocalSystem" => true,
        "ApplicationPoolIdentity" or "NetworkService" or "LocalService" => false,
        _ => pool.RunsAsLocalAdministrator
    };

    /// <summary>The posture snapshot of one audit run: finding IDs, severities and counts - never the items' names.</summary>
    public static HostFactReading Posture(AuditReport report, AuditFacts facts, string source, DateTimeOffset at)
    {
        var findings = report.Findings.Select(f => new HostPostureFinding(f.Id, f.Severity.ToString().ToLowerInvariant(),
            HostFacts.Clean(AuditCommand.Printable(f.Title)), f.Items?.Count ?? 0)).Take(100).ToArray();
        int? CountOf(string id, string key)
        {
            var finding = report.Findings.FirstOrDefault(f => f.Id == id);
            if (finding?.Data is null || !finding.Data.TryGetValue(key, out var value)) return null;
            return value switch { int n => n, string[] names => names.Length, _ => null };
        }
        bool? php = report.Findings.FirstOrDefault(f => f.Id == "AUDIT-004")?.Data is { } data && data.TryGetValue("serverLevelPhp", out var p)
            ? p as bool? : null;
        var ftp = report.Findings.FirstOrDefault(f => f.Id == "AUDIT-007");
        var posture = new HostPosture(
            source,
            report.Complete,
            findings,
            facts.IisReadable ? facts.Pools.Count : null,
            facts.IisReadable ? CountOf("AUDIT-002", "privilegedPools") : null,
            facts.IisReadable ? php : null,
            facts.IisReadable ? CountOf("AUDIT-005", "writableSiteFolders") : null,
            !facts.IisReadable || ftp is null ? null : ftp.Severity == AuditSeverity.Warn ? ftp.Items?.Count ?? 0 : 0);
        return report.Complete
            ? HostFactReading.Of(HostFacts.Posture, null, at, posture)
            : HostFactReading.Of(HostFacts.Posture, null, at, posture,
                facts.IsElevated ? HostFactStatus.Unreadable : HostFactStatus.NeedsElevation,
                facts.IsElevated ? "iis-unreadable" : "not-elevated",
                facts.IsElevated ? "IIS could not be read; 'wpshield audit' says why." : "Run 'wpshield audit' or the collector elevated.");
    }

    private static HostFactReading Unreadable(string fact, DateTimeOffset now, AuditFacts facts) =>
        HostFactReading.Failed(fact, null, now, facts.IsElevated ? HostFactStatus.Unreadable : HostFactStatus.NeedsElevation,
            facts.IsElevated ? "iis-unreadable" : "not-elevated",
            facts.IsElevated ? "IIS could not be read; 'wpshield audit' says why." : "Run the collector elevated: IIS is readable by administrators only.");
}

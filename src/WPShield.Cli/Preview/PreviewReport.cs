using System.Reflection;
using WPShield.Core;

namespace WPShield.Cli.Preview;

internal sealed record CandidatePolicy(ProtectionMode Mode, int ObserveThreshold, int BlockThreshold);

internal sealed record PreviewLimits(int MaximumLines = 10_000, int MaximumBytes = 16 * 1024 * 1024, int TimeoutSeconds = 10)
{
    public const int MaximumLineBytes = 32 * 1024;
    public const int MaximumProvenanceGroups = 64;
    public int LineBytesCeiling => MaximumLineBytes;
    public int ProvenanceGroupCeiling => MaximumProvenanceGroups;
    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsValid => MaximumLines is >= 1 and <= 100_000 && MaximumBytes is >= 1 and <= 64 * 1024 * 1024 && TimeoutSeconds is >= 1 and <= 60;
}

internal sealed record SourcePolicy(string ConfigurationRevision, string GatewayVersion, string EngineVersion,
    string WindowsRulesVersion, string WordPressRulesVersion, string Mode);

internal sealed class PolicyComparison(SourcePolicy source)
{
    public SourcePolicy Source { get; } = source;
    public int EligibleRecords { get; set; }
    public int NewlyRefused { get; set; }
    public int NewlyPermitted { get; set; }
    public int ChangedRecommendations { get; set; }
    public int UnchangedRecommendations { get; set; }
    public DateTimeOffset? WindowStart { get; set; }
    public DateTimeOffset? WindowEnd { get; set; }
}

internal sealed class PreviewReport(string siteId, CandidatePolicy candidate, PreviewLimits limits)
{
    public int SchemaVersion => 1;
    public string PreviewEngineVersion { get; } = typeof(InspectionPolicy).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
    public string Scope => "historical_score_policy_comparison";
    public bool AppliesChanges => false;
    public bool ProvesLogCompleteness => false;
    public string SourceCoverage => Status == "unavailable" ? "unavailable"
        : InvalidLines > 0 || EvidenceLossNotices > 0 || StopReason != "end_of_input" ? "partial" : "unknown";
    public string SiteId { get; } = siteId;
    public CandidatePolicy Candidate { get; } = candidate;
    public string CandidatePolicyId => FormattableString.Invariant($"score-policy-v1/{Candidate.Mode}/{Candidate.ObserveThreshold}/{Candidate.BlockThreshold}");
    public PreviewLimits Limits { get; } = limits;
    public string Status { get; set; } = "cannot_evaluate";
    public string StopReason { get; set; } = "end_of_input";
    public long? SourceBytesAtOpen { get; set; }
    public long BytesRead { get; set; }
    public int LinesRead { get; set; }
    public int IgnoredLines { get; set; }
    public int InvalidLines { get; set; }
    public int OtherSiteRecords { get; set; }
    public int SelectedRecords { get; set; }
    public int EligibleRecords { get; set; }
    public int ExcludedRecords { get; set; }
    public int EvidenceLossNotices { get; set; }
    public int? NewlyRefused { get; set; }
    public int? NewlyPermitted { get; set; }
    public int? ChangedRecommendations { get; set; }
    public int? UnchangedRecommendations { get; set; }
    public DateTimeOffset? WindowStart { get; set; }
    public DateTimeOffset? WindowEnd { get; set; }
    public SortedDictionary<string, int> Exclusions { get; } = new(StringComparer.Ordinal);
    public List<PolicyComparison> Comparisons { get; } = [];

    public void Exclude(string reason)
    {
        ExcludedRecords++;
        Exclusions[reason] = Exclusions.GetValueOrDefault(reason) + 1;
    }

    public void Finish()
    {
        if (Status == "unavailable") return;
        Status = EligibleRecords == 0 ? "cannot_evaluate"
            : StopReason != "end_of_input" || ExcludedRecords > 0 || InvalidLines > 0 || EvidenceLossNotices > 0
                ? "partial" : "complete";
    }
}

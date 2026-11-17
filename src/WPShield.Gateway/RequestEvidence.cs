using System.Reflection;
using WPShield.Abstractions;
using WPShield.Core;
using WPShield.Rules.Windows;
using WPShield.Rules.WordPress;

namespace WPShield.Gateway;

/// <summary>Identity of one validated, startup-only configuration activation; never a hash of secrets.</summary>
internal sealed class EvidenceIdentity
{
    public string ConfigurationRevision { get; } = Guid.NewGuid().ToString("N");
    public string GatewayVersion { get; } = VersionOf(typeof(GatewayApplication));
    public string EngineVersion { get; } = VersionOf(typeof(InspectionEngine));
    public string WindowsRulesVersion { get; } = VersionOf(typeof(PhpContentInUploadRule));
    public string WordPressRulesVersion { get; } = VersionOf(typeof(ExecutableUploadExtensionRule));

    private static string VersionOf(Type type) =>
        type.Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
}

/// <summary>
/// Request-local evidence. It records observations, never makes enforcement decisions, and stores
/// no paths, filenames, headers, samples or exception messages. Only the final event claims an outcome.
/// </summary>
internal sealed class RequestEvidence
{
    public InspectionEvidence Path { get; } = new();
    public InspectionEvidence Upload { get; } = new();
    public string? SiteId { get; set; }
    public ProtectionMode? Mode { get; set; }
    public string? RateLimitRuleId { get; set; }
    public int? FilesRead { get; set; }
    public int FilesInspected { get; set; }
    public long SampleBytesInspected { get; set; }
    public bool ForwardingAttempted { get; set; }
    public string Disposition { get; set; } = "failed";
    public string Reason { get; set; } = "pipeline_failure";

    public void Refuse(string reason)
    {
        // Streaming can send a prefix before a limit or transport failure is discovered.
        Disposition = ForwardingAttempted ? "forwarding_failed" : "rejected";
        Reason = reason;
    }

    public void Cancel()
    {
        Disposition = "cancelled";
        Reason = "request_cancelled";
    }

    public void Log(ILogger logger, HttpContext context, EvidenceIdentity identity, int sampleLimitBytes)
    {
        // Read the authoritative resolution; never resolve the client a second time for evidence.
        var client = context.Features.Get<ResolvedClient>()?.Address?.ToString() ?? "unknown";
        int? statusCode = Disposition is "cancelled" or "failed" ? null : context.Response.StatusCode;
        logger.LogInformation(
            "Request completed. EventType={EventType} SchemaVersion={SchemaVersion} RequestId={RequestId} " +
            "ConfigurationRevision={ConfigurationRevision} GatewayVersion={GatewayVersion} EngineVersion={EngineVersion} " +
            "WindowsRulesVersion={WindowsRulesVersion} WordPressRulesVersion={WordPressRulesVersion} " +
            "SiteId={SiteId} Mode={Mode} Client={Client} Disposition={Disposition} Reason={Reason} " +
            "ForwardingAttempted={ForwardingAttempted} StatusCode={StatusCode} RateLimitRuleId={RateLimitRuleId} " +
            "PathStatus={PathStatus} PathReason={PathReason} PathAction={PathAction} PathScore={PathScore} " +
            "PathRuleIds={PathRuleIds} PathRuleIdsTruncated={PathRuleIdsTruncated} " +
            "UploadStatus={UploadStatus} UploadReason={UploadReason} UploadAction={UploadAction} UploadScore={UploadScore} " +
            "UploadRuleIds={UploadRuleIds} UploadRuleIdsTruncated={UploadRuleIdsTruncated} " +
            "FilesRead={FilesRead} FilesInspected={FilesInspected} SampleBytesInspected={SampleBytesInspected} SampleLimitBytes={SampleLimitBytes}",
            "request_completed", 1, context.TraceIdentifier,
            identity.ConfigurationRevision, identity.GatewayVersion, identity.EngineVersion,
            identity.WindowsRulesVersion, identity.WordPressRulesVersion,
            SiteId, Mode?.ToString(), client, Disposition, Reason, ForwardingAttempted, statusCode, RateLimitRuleId,
            Path.Status, Path.Reason, Path.Action?.ToString(), Path.Score, Path.RuleIds, Path.RuleIdsTruncated,
            Upload.Status, Upload.Reason, Upload.Action?.ToString(), Upload.Score, Upload.RuleIds, Upload.RuleIdsTruncated,
            FilesRead, FilesInspected, SampleBytesInspected, sampleLimitBytes);
    }
}

internal sealed class InspectionEvidence
{
    private const int MaximumRuleIds = 16;
    private readonly SortedSet<string> _ruleIds = new(StringComparer.Ordinal);

    public string Status { get; private set; } = "not_started";
    public string Reason { get; private set; } = "not_reached";
    public InspectionAction? Action { get; private set; }
    public int? Score { get; private set; }
    public string RuleIds => string.Join(',', _ruleIds);
    public bool RuleIdsTruncated { get; private set; }

    public void Skip(string reason) => SetStatus("not_inspected", reason);
    public void Start() => SetStatus("partial", "interrupted");
    public void Complete(string reason = "rules_completed")
    {
        SetStatus("complete", reason);
        Action ??= InspectionAction.Allow;
        Score ??= 0;
    }

    public void Partial(string reason) => SetStatus("partial", reason);

    public void Record(InspectionResult result)
    {
        Score = Math.Max(Score ?? 0, result.Score);
        if (Action is null || result.RecommendedAction > Action)
        {
            Action = result.RecommendedAction;
        }

        foreach (var finding in result.Findings)
        {
            if (_ruleIds.Contains(finding.RuleId))
            {
                continue;
            }

            if (_ruleIds.Count < MaximumRuleIds)
            {
                _ruleIds.Add(finding.RuleId);
            }
            else
            {
                RuleIdsTruncated = true;
            }
        }
    }

    private void SetStatus(string status, string reason)
    {
        Status = status;
        Reason = reason;
    }
}

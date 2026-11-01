using WPShield.Abstractions;

namespace WPShield.NetworkFilter.Rules;

/// <summary>Shared shape of a network rule result: score to action, and normalized evidence only.</summary>
internal static class NetworkFinding
{
    public static NetworkInspectionResult Create(
        string ruleId,
        int score,
        string messageKey,
        NetworkInspectionContext context,
        Dictionary<string, object> evidence)
    {
        evidence["source_ip"] = context.SourceIp;
        evidence["destination_port"] = context.DestinationPort;
        return new NetworkInspectionResult
        {
            RuleId = ruleId,
            Score = score,
            Action = score switch
            {
                0 => NetworkInspectionAction.Allow,
                >= 80 => NetworkInspectionAction.Block,
                _ => NetworkInspectionAction.Observe,
            },
            MessageKey = messageKey,
            Evidence = evidence,
        };
    }
}

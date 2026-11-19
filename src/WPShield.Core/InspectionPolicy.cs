using WPShield.Abstractions;

namespace WPShield.Core;

/// <summary>Maps an already-aggregated score to a recommendation, shared by serving and offline preview.</summary>
public static class InspectionPolicy
{
    public static InspectionAction Recommend(int score, ProtectionMode mode, int observeThreshold, int blockThreshold)
    {
        if (mode == ProtectionMode.Disabled) return InspectionAction.Allow;
        return score >= blockThreshold
            ? mode == ProtectionMode.Block ? InspectionAction.Block : InspectionAction.Observe
            : score >= observeThreshold ? InspectionAction.Observe : InspectionAction.Allow;
    }
}

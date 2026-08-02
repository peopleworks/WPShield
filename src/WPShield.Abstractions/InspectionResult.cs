namespace WPShield.Abstractions;

public sealed record InspectionResult(
    string SiteId,
    int Score,
    InspectionAction RecommendedAction,
    IReadOnlyList<RuleFinding> Findings);

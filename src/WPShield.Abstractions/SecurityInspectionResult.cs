namespace WPShield.Abstractions;

/// <summary>
/// Result of a single security event inspection rule evaluation.
/// </summary>
public sealed record SecurityInspectionResult
{
    public required string RuleId { get; init; }
    public required int Score { get; init; } // 0-100
    public required NetworkInspectionAction Action { get; init; }
    public required string MessageKey { get; init; }
    public required IReadOnlyDictionary<string, object> Evidence { get; init; }
}

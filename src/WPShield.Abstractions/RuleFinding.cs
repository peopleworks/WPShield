namespace WPShield.Abstractions;

public sealed record RuleFinding(
    string RuleId,
    int Score,
    string MessageKey,
    IReadOnlyDictionary<string, string>? Evidence = null);

namespace WPShield.Abstractions;

public interface IInspectionRule
{
    string Id { get; }
    ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default);
}

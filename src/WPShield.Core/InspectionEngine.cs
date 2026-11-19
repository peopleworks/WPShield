using WPShield.Abstractions;

namespace WPShield.Core;

public sealed class InspectionEngine(IEnumerable<IInspectionRule> rules)
{
    private readonly IReadOnlyList<IInspectionRule> _rules = rules?.ToArray()
        ?? throw new ArgumentNullException(nameof(rules));

    public async ValueTask<InspectionResult> InspectAsync(
        InspectionContext context,
        SiteOptions site,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(site);

        if (site.Mode == ProtectionMode.Disabled)
        {
            return new InspectionResult(site.Id, 0, InspectionAction.Allow, []);
        }

        var findings = new List<RuleFinding>();
        foreach (var rule in _rules)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var finding = await rule.EvaluateAsync(context, cancellationToken);
            if (finding is not null) findings.Add(finding);
        }

        var score = Math.Min(100, findings.Sum(f => Math.Max(0, f.Score)));
        var action = InspectionPolicy.Recommend(score, site.Mode, site.ObserveThreshold, site.BlockThreshold);

        return new InspectionResult(site.Id, score, action, findings);
    }
}

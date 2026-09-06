using WPShield.Abstractions;

namespace WPShield.Core;

/// <summary>
/// Evaluates the request-path rules once per request and applies the site's policy to the result.
/// </summary>
/// <remarks>
/// <para>
/// A deliberate near-twin of <see cref="InspectionEngine"/>, and not a shared base class. The two
/// aggregate differently and will keep diverging: an upload result is one file's score and the
/// caller takes the maximum across files, while a path result is the whole request's score and there
/// is nothing to take a maximum over. Folding them together would produce an abstraction whose only
/// content is "call some rules and add up", which is the part that was never hard.
/// </para>
/// <para>
/// <b>Findings are summed, and that is the right choice here.</b> Unlike the per-file case — where
/// summing lets an attacker push a request over the threshold by attaching more innocent files —
/// every path finding describes the same single path. Two of them mean two independent things are
/// wrong with one request, which is more suspicious than either alone, not less.
/// </para>
/// <para>
/// <b>Disabled short-circuits before any rule runs.</b> Same contract as the upload engine: a site an
/// operator has switched off is forwarded untouched, and the gateway must not be able to spend work
/// on it by accident.
/// </para>
/// </remarks>
public sealed class RequestPathEngine(IEnumerable<IRequestPathRule> rules)
{
    private readonly IReadOnlyList<IRequestPathRule> _rules = rules?.ToArray()
        ?? throw new ArgumentNullException(nameof(rules));

    /// <summary>The rules this engine will evaluate, in evaluation order.</summary>
    public IReadOnlyList<IRequestPathRule> Rules => _rules;

    public async ValueTask<InspectionResult> InspectAsync(
        InspectionContext context,
        SiteOptions site,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(site);

        if (site.Mode == ProtectionMode.Disabled || _rules.Count == 0)
        {
            return new InspectionResult(site.Id, 0, InspectionAction.Allow, []);
        }

        var findings = new List<RuleFinding>();
        foreach (var rule in _rules)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var finding = await rule.EvaluateAsync(context, cancellationToken);
            if (finding is not null)
            {
                findings.Add(finding);
            }
        }

        var score = Math.Min(100, findings.Sum(finding => Math.Max(0, finding.Score)));

        // The Monitor downgrade lives here and nowhere else, exactly as it does for uploads. A
        // second implementation in the gateway is where a future edit forgets it and Monitor
        // silently starts refusing traffic.
        var action = score >= site.BlockThreshold
            ? site.Mode == ProtectionMode.Block ? InspectionAction.Block : InspectionAction.Observe
            : score >= site.ObserveThreshold ? InspectionAction.Observe : InspectionAction.Allow;

        return new InspectionResult(site.Id, score, action, findings);
    }
}

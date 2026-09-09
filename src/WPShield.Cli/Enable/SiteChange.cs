namespace WPShield.Cli.Enable;

/// <summary>
/// One change to one site, and how to undo it.
/// </summary>
/// <remarks>
/// Every change carries its own reversal rather than relying on a single restore at the end. A
/// failure at step three has to undo steps one and two, and a restore that only knows how to put a
/// whole file back cannot help when the change was a binding.
/// </remarks>
internal sealed record SiteChange(string Description, Action Apply, Action Revert);

/// <summary>What <c>enable</c> found, and what it would do about it.</summary>
internal sealed record EnablePlan
{
    public required string SiteName { get; init; }
    public required string PublicHost { get; init; }
    public required int DestinationPort { get; init; }
    public bool NeedsLoopbackBinding { get; init; }
    public bool NeedsServerVariable { get; init; }
    public bool NeedsRule { get; init; }
    public IReadOnlyList<string> RuleOrderedBefore { get; init; } = [];

    public bool Empty => !NeedsLoopbackBinding && !NeedsServerVariable && !NeedsRule;
}

/// <summary>The result of asking the site whether it still works.</summary>
/// <param name="Healthy">
/// False for a 5xx, and false for a redirect chain that does not terminate inside the hop limit —
/// which is the shape <c>ERR_TOO_MANY_REDIRECTS</c> takes when <c>wp-config.php</c> is not
/// translating the header.
/// </param>
/// <param name="Detail">
/// The status line and nothing else. No body, no headers beyond it, following the same rule as
/// everything else in this project that writes evidence.
/// </param>
internal sealed record SiteHealth(bool Healthy, string Detail);

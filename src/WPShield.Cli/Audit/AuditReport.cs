namespace WPShield.Cli.Audit;

/// <summary>
/// How much one posture finding matters.
/// </summary>
/// <remarks>
/// A separate vocabulary from <c>PreflightStatus</c> on purpose. A preflight <c>Blocker</c> means "do
/// not install WPShield yet"; a posture finding says nothing about installing WPShield and must never
/// read as if it did. An operator holding both outputs should not be able to confuse them.
/// </remarks>
internal enum AuditSeverity
{
    /// <summary>Checked, and not a problem.</summary>
    Pass,

    /// <summary>Reported, not judged.</summary>
    Info,

    /// <summary>A weakness worth fixing that does not on its own hand an intruder the server.</summary>
    Warn,

    /// <summary>
    /// The configuration that turns one compromised site into a compromised server. Every critical
    /// finding carries a remedy, and every remedy is a change made by hand.
    /// </summary>
    Critical
}

/// <summary>One posture finding.</summary>
/// <param name="Id">The stable identifier, <c>AUDIT-nnn</c>. Operators cite these to each other.</param>
/// <param name="Items">
/// The pools, sites or folders the finding is about, already safe to print. Rendered as a list under
/// the finding rather than folded into <paramref name="Detail"/>, because on a host with dozens of sites
/// the list is the finding.
/// </param>
/// <param name="Remedy">
/// What to do about it, by hand. Required on every warning and critical finding, and asserted: this
/// verb names the fix and never applies it.
/// </param>
/// <param name="Data">Machine-readable fields for the JSON Lines report.</param>
internal sealed record AuditFinding(
    string Id,
    AuditSeverity Severity,
    string Title,
    string Detail = "",
    string Remedy = "",
    IReadOnlyList<string>? Items = null,
    IReadOnlyDictionary<string, object?>? Data = null);

/// <summary>Everything one audit concluded.</summary>
internal sealed class AuditReport
{
    private readonly List<AuditFinding> _findings = [];

    public IReadOnlyList<AuditFinding> Findings => _findings;

    public IReadOnlyList<AuditFinding> Criticals =>
        [.. _findings.Where(finding => finding.Severity == AuditSeverity.Critical)];

    public IReadOnlyList<AuditFinding> Warnings =>
        [.. _findings.Where(finding => finding.Severity == AuditSeverity.Warn)];

    /// <summary>
    /// Whether the audit could look at all. An unelevated run, or one that could not read IIS, is not
    /// a clean run with nothing found: "nobody could look" must never read as "there is nothing there".
    /// </summary>
    public bool Complete { get; set; } = true;

    public void Add(AuditFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        _findings.Add(finding);
    }

    /// <summary>Convenience for the common case of a handful of scalar fields.</summary>
    public static IReadOnlyDictionary<string, object?> Fields(params (string Key, object? Value)[] pairs)
    {
        ArgumentNullException.ThrowIfNull(pairs);
        return pairs.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
    }
}

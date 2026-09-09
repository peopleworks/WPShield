namespace WPShield.Cli.Preflight;

/// <summary>
/// What one check concluded. The four values are the ones the PowerShell preflight used, kept
/// identical so an operator reading either output reads the same vocabulary.
/// </summary>
internal enum PreflightStatus
{
    /// <summary>Reported, not judged. A site inventory is Info; it is neither good nor bad.</summary>
    Info,

    /// <summary>Checked and correct.</summary>
    Pass,

    /// <summary>Worth knowing before proceeding, but not on its own a reason to stop.</summary>
    Warn,

    /// <summary>Proceeding from here breaks something. Every blocker carries a remedy.</summary>
    Blocker
}

/// <summary>
/// One finding.
/// </summary>
/// <param name="Id">
/// The stable identifier — <c>PRE-007</c>, or <c>PRE-012.Default Web Site</c> for a check that runs
/// once per site. Stable because operators cite them to each other and to us.
/// </param>
/// <param name="Remedy">
/// What to do about it. <b>Required on every blocker</b>, and asserted: a readiness check that
/// reports a problem without saying what to do about it has moved the problem rather than solved it.
/// </param>
/// <param name="Data">
/// The machine-readable fields for the JSON Lines report, in the same envelope the gateway log and
/// the triage tool use.
/// </param>
internal sealed record PreflightCheck(
    string Id,
    PreflightStatus Status,
    string Title,
    string Detail = "",
    string Remedy = "",
    IReadOnlyDictionary<string, object?>? Data = null);

/// <summary>
/// Everything a run concluded, and the verdict that follows from it.
/// </summary>
internal sealed class PreflightReport
{
    private readonly List<PreflightCheck> _checks = [];

    public IReadOnlyList<PreflightCheck> Checks => _checks;

    public IReadOnlyList<PreflightCheck> Blockers =>
        [.. _checks.Where(check => check.Status == PreflightStatus.Blocker)];

    public IReadOnlyList<PreflightCheck> Warnings =>
        [.. _checks.Where(check => check.Status == PreflightStatus.Warn)];

    public bool Ready => Blockers.Count == 0;

    public void Add(PreflightCheck check)
    {
        ArgumentNullException.ThrowIfNull(check);
        _checks.Add(check);
    }

    public void Add(
        string id,
        PreflightStatus status,
        string title,
        string detail = "",
        string remedy = "",
        IReadOnlyDictionary<string, object?>? data = null)
    {
        Add(new PreflightCheck(id, status, title, detail, remedy, data));
    }

    /// <summary>Convenience for the common case of a handful of scalar fields.</summary>
    public static IReadOnlyDictionary<string, object?> Fields(params (string Key, object? Value)[] pairs)
    {
        ArgumentNullException.ThrowIfNull(pairs);
        return pairs.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
    }
}

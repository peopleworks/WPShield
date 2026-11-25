namespace WPShield.Evidence.Decisions;

/// <summary>
/// The values <see cref="DecisionRecord.Action"/> takes when the decision engine writes it (ADR 0009).
/// Stable and untranslated: readers match on them and the store keeps them for 400 days.
/// </summary>
public static class DecisionActions
{
    /// <summary>The engine would block the target for the decision's duration. Monitor: nothing is enforced.</summary>
    public const string WouldBlock = "would-block";

    /// <summary>
    /// A rule fired, and the target is one the engine never decides against (the allow-list, the host's
    /// own addresses, a private range, a Remote Desktop session). Recorded so the operator sees what
    /// would have happened to an address they trust; its expiry is when that block would have ended.
    /// </summary>
    public const string Protected = "protected";

    /// <summary>A report-only rule fired (<c>HOST-AUTH-004</c>). Never blocks, has no expiry.</summary>
    public const string Report = "report";

    /// <summary>A <see cref="WouldBlock"/> decision reached its expiry. Its timestamp is the moment it ended.</summary>
    public const string Expire = "expire";

    /// <summary>
    /// A rule fired and the engine refused to decide: the facts it needs could not be read ("nobody could
    /// look" is not "nobody is connected"), or the bound on active decisions was reached.
    /// </summary>
    public const string Refused = "refused";

    /// <summary>Decisions this version records. Nothing is enforced in it.</summary>
    public const string MonitorMode = "monitor";
}

/// <summary>The engine's rule IDs. Stable and untranslated, like every WPShield rule ID.</summary>
public static class DecisionRules
{
    /// <summary>One address fails N times within W minutes.</summary>
    public const string RepeatedFailures = "HOST-AUTH-001";

    /// <summary>One address tries M account names that do not exist within W minutes.</summary>
    public const string NonexistentAccounts = "HOST-AUTH-002";

    /// <summary>K different addresses of one /24 (IPv4) or /64 (IPv6) fail within W minutes.</summary>
    public const string Network = "HOST-AUTH-003";

    /// <summary>One existing account fails from A different addresses within W minutes. Report only.</summary>
    public const string SharedAccount = "HOST-AUTH-004";
}

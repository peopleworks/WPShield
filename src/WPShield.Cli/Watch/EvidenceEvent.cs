namespace WPShield.Cli.Watch;

/// <summary>
/// What one line of the gateway's JSON Lines log is, once it has been read for the console.
/// </summary>
/// <remarks>
/// <para>
/// The gateway writes several shapes of line — a per-finding line, a per-request verdict, a dropped
/// notice, and ordinary startup and configuration lines. This enum is the console's reading of which
/// shape a line is, decided from the stable message prefixes the gateway uses, not from guessing at
/// the presence of a field.
/// </para>
/// <para>
/// <b>What is deliberately missing is any category for clean traffic.</b> The gateway does not log a
/// request that produced no finding — the request-path pass returns before logging when there are no
/// findings, and only a multipart upload records an <c>Allow</c> verdict. So the console can count
/// what WPShield <i>saw and did</i>, and must never imply a total request rate it has no line for.
/// </para>
/// </remarks>
internal enum EvidenceKind
{
    /// <summary>A line the console does not surface: startup, configuration, health, anything else.</summary>
    Other,

    /// <summary>One rule fired. Carries a rule id, a score, and normalized evidence.</summary>
    Finding,

    /// <summary>One request's verdict: its total score and the action taken.</summary>
    Verdict,

    /// <summary>The gateway admitting it dropped log lines under queue pressure.</summary>
    DroppedNotice
}

/// <summary>
/// The action the gateway recorded for a request, read back from the log rather than recomputed.
/// </summary>
internal enum EvidenceAction
{
    /// <summary>No action field on the line, or one the console did not recognise.</summary>
    Unknown,

    /// <summary>Forwarded untouched.</summary>
    Allow,

    /// <summary>Scored over the observe threshold and forwarded anyway — Monitor mode, or an upload below block.</summary>
    Observe,

    /// <summary>Refused. Block mode, over the block threshold.</summary>
    Block
}

/// <summary>
/// One parsed evidence line, reduced to the fields the console shows and counts.
/// </summary>
/// <remarks>
/// This is an eager, immutable projection rather than a wrapper over a live <c>JsonDocument</c>: the
/// console keeps a rolling window of recent events, and holding a document per retained line would
/// keep the whole parse tree of each alive. Everything the console needs is pulled out once, here,
/// and the document is discarded.
/// </remarks>
internal sealed record EvidenceEvent
{
    public required DateTimeOffset Timestamp { get; init; }

    public required string Level { get; init; }

    public required EvidenceKind Kind { get; init; }

    /// <summary>The site the line is about — the gateway's <c>SiteId</c>. Null on lines that carry none.</summary>
    public string? Host { get; init; }

    /// <summary>
    /// The rule or rules on the line. A path finding carries one <c>RuleId</c>; an upload finding
    /// and an upload verdict carry a comma-joined <c>RuleIds</c>. Empty when the line names none.
    /// </summary>
    public string? Rules { get; init; }

    /// <summary>The score on the line, or null if it carried none.</summary>
    public int? Score { get; init; }

    public EvidenceAction Action { get; init; }

    /// <summary>The HTTP method, when the line records one.</summary>
    public string? Method { get; init; }

    /// <summary>The normalized request path, when the line records one. Never a raw client value.</summary>
    public string? Path { get; init; }

    /// <summary>The rendered message, kept for the detail view and for lines the console shows verbatim.</summary>
    public required string Message { get; init; }
}

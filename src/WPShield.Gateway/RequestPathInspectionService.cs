using WPShield.Abstractions;
using WPShield.Core;

namespace WPShield.Gateway;

/// <summary>
/// Runs the request-path rules once per request, before anything reads a body.
/// </summary>
/// <remarks>
/// <para>
/// <b>Position in the pipeline is most of the value.</b> This runs after the site is resolved and
/// before <see cref="UploadInspectionService"/>, which means a refusal here costs no buffer, no
/// multipart parse and no sample — the request is answered from the request line alone. It also means
/// the pass applies to <i>every</i> request, including the overwhelming majority that carry no body
/// at all, which is precisely the traffic M2 was structurally unable to examine.
/// </para>
/// <para>
/// <b>Cost.</b> One normalization of the path plus three rule evaluations, all of it string work on a
/// value bounded by <see cref="NormalizedRequestPath.MaximumSegments"/> and
/// <see cref="NormalizedRequestPath.MaximumSegmentLength"/>. The second normalization view is built
/// only when the path contains a percent sign and only when decoding changes it, so ordinary traffic
/// pays for one pass and no allocation beyond the segment list.
/// </para>
/// <para>
/// <b>Disabled sites are skipped here as well as in the engine.</b> The engine's guard is the
/// contract; this one keeps the gateway from normalizing a path nobody will look at.
/// </para>
/// </remarks>
internal sealed class RequestPathInspectionService(RequestPathEngine engine)
{
    /// <summary>
    /// The most rule identifiers disclosed in a refusal. The published catalogue is small, so this
    /// is a bound on the response rather than a policy about disclosure.
    /// </summary>
    private const int MaximumDisclosedRuleIds = 8;

    /// <summary>
    /// Evaluates the request path.
    /// </summary>
    /// <returns>
    /// A rejection when the site is in Block mode and the score crossed its block threshold, and
    /// <see langword="null"/> in every other case — including when findings were recorded and the
    /// request is forwarded anyway, which is what Monitor mode does.
    /// </returns>
    public async ValueTask<GatewayRejection?> EvaluateAsync(
        HttpContext context,
        SiteOptions site,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(site);
        ArgumentNullException.ThrowIfNull(logger);

        if (site.Mode == ProtectionMode.Disabled)
        {
            return null;
        }

        // Path only, never Path + QueryString, for the same reason the forwarding log line takes
        // only the path: satisfying "never log a full query string" at the source is more durable
        // than remembering to redact one later.
        var inspectionContext = new InspectionContext(
            site.Id,
            context.Request.Host.Host,
            context.Request.Method,
            context.Request.Path.Value ?? "/");

        var result = await engine.InspectAsync(inspectionContext, site, cancellationToken);

        if (result.Findings.Count == 0)
        {
            return null;
        }

        var ruleIds = result.Findings
            .Select(finding => finding.RuleId)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();

        LogFindings(context, site, result, logger);

        // Take the action, do not re-derive it. RequestPathEngine has already applied the thresholds
        // and the Monitor downgrade; a second implementation here is exactly where a future edit
        // forgets the downgrade and Monitor starts refusing traffic.
        if (result.RecommendedAction != InspectionAction.Block)
        {
            return null;
        }

        return new GatewayRejection(
            StatusCodes.Status403Forbidden,
            "request_blocked",
            null,
            ruleIds.Length <= MaximumDisclosedRuleIds ? ruleIds : ruleIds[..MaximumDisclosedRuleIds]);
    }

    /// <summary>
    /// Writes one line per finding plus a summary.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Warning rather than Error for a refusal, following the upload path: a blocked request is
    /// WPShield working, while Error is reserved for the gateway failing. An operator alerting on
    /// Error must not be paged because someone probed for a webshell.
    /// </para>
    /// <para>
    /// <b>Evidence is emitted as the rules produced it, and the rules produce only normalized
    /// values.</b> A raw request target can carry control characters and ANSI escape sequences
    /// straight into a terminal or a log viewer, so no rule in this family puts one in a finding, and
    /// this method adds none of its own.
    /// </para>
    /// </remarks>
    private static void LogFindings(
        HttpContext context,
        SiteOptions site,
        InspectionResult result,
        ILogger logger)
    {
        var level = result.RecommendedAction == InspectionAction.Block
            ? LogLevel.Warning
            : LogLevel.Information;

        foreach (var finding in result.Findings)
        {
            logger.Log(
                level,
                "Request path finding. RequestId={RequestId} SiteId={SiteId} RuleId={RuleId} Score={Score} Evidence={Evidence}",
                context.TraceIdentifier,
                site.Id,
                finding.RuleId,
                finding.Score,
                FormatEvidence(finding.Evidence));
        }

        logger.Log(
            level,
            "Request path inspected. RequestId={RequestId} SiteId={SiteId} Method={Method} Score={Score} Action={Action} Mode={Mode}",
            context.TraceIdentifier,
            site.Id,
            context.Request.Method,
            result.Score,
            result.RecommendedAction,
            site.Mode);
    }

    private static string FormatEvidence(IReadOnlyDictionary<string, string>? evidence)
    {
        return evidence is null || evidence.Count == 0
            ? string.Empty
            : string.Join(" ", evidence.OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => $"{pair.Key}={pair.Value}"));
    }
}

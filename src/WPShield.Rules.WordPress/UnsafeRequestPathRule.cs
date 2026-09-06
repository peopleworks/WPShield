using WPShield.Abstractions;

namespace WPShield.Rules.WordPress;

/// <summary>
/// <c>IIS-PATH-001</c> — the request path carried a form no well-behaved client produces.
/// </summary>
/// <remarks>
/// <para>
/// Reports what normalization had to undo before the path could be compared: a <c>..</c> segment, a
/// backslash acting as a separator, an NTFS alternate data stream suffix, trailing dots or spaces
/// that Windows strips at open time, embedded control characters, a path longer than the bounds allow,
/// or a second percent-decode that produced a different path than the first. Each of these makes the
/// path that reaches disk differ from the path that was inspected, which is the entire technique.
/// </para>
/// <para>
/// <b>Score 60, matching <c>FILE-NAME-001</c> deliberately.</b> On its own an odd path shape is worth
/// recording rather than refusing: sloppy clients, badly built theme URLs and old caching layers all
/// produce paths that need tidying, and a rule that blocked on tidiness alone would refuse working
/// traffic. Below the default block threshold, it stays an observation. Combined with either path
/// rule above — both of which score 100 — it changes nothing, because those already block; combined
/// with an upload finding it is what pushes a borderline request over. Its real job is the log line:
/// an operator who sees <c>traversal</c> or <c>doubleEncoded</c> on a request is looking at
/// reconnaissance, whether or not this particular attempt reached anything.
/// </para>
/// <para>
/// <b><c>doubleEncoded</c> is the one worth reading twice.</b> The host decodes a path once before
/// WPShield sees it. Some IIS URL Rewrite chains decode again, so a request written as
/// <c>%252e%252e%252f</c> arrives here looking inert and becomes traversal one step later, at a point
/// where nothing is inspecting. <see cref="NormalizedRequestPath"/> evaluates that second view for
/// exactly this reason, and reports the divergence rather than silently resolving it — the same
/// reasoning that made the upload rules evaluate WordPress's own filename rewrite alongside the
/// Windows one.
/// </para>
/// <para>
/// <b>False positives.</b> A doubled slash is explicitly <i>not</i> an anomaly here. Theme and plugin
/// code concatenates URLs carelessly and produces <c>//</c> constantly, so treating it as hostile
/// would put a finding on a large slice of ordinary traffic. It is recorded in the evidence when
/// something else fired, and never on its own.
/// </para>
/// </remarks>
public sealed class UnsafeRequestPathRule : IRequestPathRule
{
    internal const int Score = 60;

    public string Id => "IIS-PATH-001";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var path = context.NormalizedPath;
        if (!path.HasUnsafeForm)
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        var evidence = new Dictionary<string, string>(3)
        {
            ["anomalies"] = string.Join(",", path.Anomalies),
            ["normalizedPath"] = path.Literal.Value
        };

        if (path.DivergesWhenDecodedAgain)
        {
            // Both readings, because the divergence is the finding. One value alone would leave an
            // operator unable to see why the request was reported at all.
            evidence["decodedPath"] = path.Decoded.Value;
        }

        return ValueTask.FromResult<RuleFinding?>(
            new RuleFinding(Id, Score, "Findings.UnsafeRequestPath", evidence));
    }
}

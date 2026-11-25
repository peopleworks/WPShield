using System.Collections.Frozen;
using System.Globalization;
using WPShield.Abstractions;
using WPShield.Evidence;
using WPShield.Rules.WordPress;

namespace WPShield.WebEvidence;

/// <summary>What the rules and the observations said about one logged request.</summary>
/// <param name="Path">The normalized path, rebuilt from normalized segments. The only form ever stored.</param>
/// <param name="Rules">Rule findings, with the rules' own scores.</param>
/// <param name="PhpOutsideEntryPoints"><c>WEB-OBS-001</c>: a 2xx answer to PHP that is not a WordPress entry point.</param>
/// <param name="LoginPost"><c>WEB-OBS-002</c>: a POST to <c>wp-login.php</c>.</param>
/// <param name="XmlrpcPost"><c>WEB-OBS-003</c>: a POST to <c>xmlrpc.php</c>.</param>
public sealed record WebEvaluation(string Path, IReadOnlyList<WebHit> Rules, bool PhpOutsideEntryPoints, bool LoginPost, bool XmlrpcPost)
{
    /// <summary>Whether the request is stored as a finding row: a rule fired, or <c>WEB-OBS-001</c> did.</summary>
    public bool Stored => Rules.Count > 0 || PhpOutsideEntryPoints;

    /// <summary>The rule findings and the stored observation, as one list for the finding row.</summary>
    public IReadOnlyList<WebHit> Hits => PhpOutsideEntryPoints ? [.. Rules, new WebHit(WebObservationIds.PhpOutsideEntryPoints, 0)] : Rules;
}

/// <summary>
/// Runs the request-path rules of <see cref="RequestPathRuleCatalog"/> - the same catalog the gateway
/// registers - and the sensor's observations on a request read from an IIS log.
/// </summary>
/// <remarks>
/// <para>
/// <b>Rules see a context built the way the gateway builds one:</b> the site, the method and the path
/// only. Nothing a rule reads is raw: rules match <see cref="InspectionContext.NormalizedPath"/>, which
/// applies every normalization and both views AGENTS.md requires.
/// </para>
/// <para>
/// <b>Observations are not rules.</b> They need the status code, which a path rule never sees, and they
/// are evidence only: no score, never eligible to decide alone (ADR 0011, amendment 1). They exist
/// because the incident's shells sat in folders that legitimately hold PHP, the known gap no path rule
/// can close, and what gave them away was that they answered.
/// </para>
/// </remarks>
public sealed class WebRequestEvaluator
{
    /// <summary>
    /// The WordPress files a client is meant to request directly, by name, at any install depth. Anything
    /// under <c>wp-content</c> or <c>wp-includes</c> is never one of them.
    /// </summary>
    internal static readonly FrozenSet<string> EntryPoints = new[]
    {
        "index.php", "wp-login.php", "xmlrpc.php", "wp-cron.php", "wp-comments-post.php", "wp-trackback.php",
        "wp-signup.php", "wp-activate.php", "wp-mail.php", "wp-links-opml.php"
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> AdminSubfolders = new[] { "network", "user" }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>
    /// The folders under <c>wp-content</c> whose <c>index.php</c> WordPress core ships as an empty
    /// "Silence is golden" placeholder: <c>wp-content</c> itself, <c>plugins</c> and <c>themes</c>.
    /// </summary>
    /// <remarks>
    /// Scanners fetch <c>/wp-content/index.php</c> to learn that a site runs WordPress, and it answers 200
    /// with an empty body on every healthy install - the first <c>WEB-OBS-001</c> on the real host was
    /// exactly that (ADR 0011, amendment 2). Only a GET or HEAD of these three files, as the last segment,
    /// is excused. A POST to one is still observed: nothing legitimate posts to a placeholder, and a
    /// placeholder replaced by a shell is driven with POST. An <c>index.php</c> inside a plugin or theme is
    /// not excused, because that is where the incident's shells were hidden.
    /// </remarks>
    private static readonly FrozenSet<string> PlaceholderFolders = new[] { "plugins", "themes" }.ToFrozenSet(StringComparer.Ordinal);
    private readonly IReadOnlyList<IRequestPathRule> rules;

    public WebRequestEvaluator()
        : this(RequestPathRuleCatalog.Create())
    {
    }

    internal WebRequestEvaluator(IReadOnlyList<IRequestPathRule> rules) => this.rules = rules ?? throw new ArgumentNullException(nameof(rules));

    /// <summary>The rules evaluated, in order. The same list the gateway runs.</summary>
    public IReadOnlyList<IRequestPathRule> Rules => rules;

    public WebEvaluation Evaluate(long siteId, W3cRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var context = new InspectionContext("w3svc" + siteId.ToString(CultureInfo.InvariantCulture), string.Empty, request.Method, request.Stem);
        var path = context.NormalizedPath;
        var hits = new List<WebHit>();
        foreach (var rule in rules)
        {
            var pending = rule.EvaluateAsync(context);
            var finding = pending.IsCompletedSuccessfully ? pending.Result : pending.AsTask().GetAwaiter().GetResult();
            if (finding is not null) hits.Add(new WebHit(finding.RuleId, Math.Max(0, finding.Score)));
        }

        var post = string.Equals(request.Method, "POST", StringComparison.Ordinal);
        var read = request.Method is "GET" or "HEAD";
        var script = path.FirstAcrossViews(Script);
        return new WebEvaluation(path.Literal.Value, hits,
            PhpOutsideEntryPoints: request.Status is >= 200 and < 300 &&
                path.FirstAcrossViews(view => Script(view) is { } s && !s.EntryPoint && !(read && s.Placeholder) ? s : null) is not null,
            LoginPost: post && script is { EntryPoint: true, Name: "wp-login.php" },
            XmlrpcPost: post && script is { EntryPoint: true, Name: "xmlrpc.php" });
    }

    /// <summary>The PHP file a request executes, path-info included: the first segment that ends in <c>.php</c>.</summary>
    internal static ScriptSegment? Script(RequestPathView view)
    {
        var segments = view.Segments;
        for (var index = 0; index < segments.Count; index++)
        {
            var segment = segments[index];
            if (segment.Length <= 4 || !segment.EndsWith(".php", StringComparison.Ordinal)) continue;
            var underContent = false;
            for (var parent = 0; parent < index; parent++)
                if (segments[parent] is "wp-content" or "wp-includes") underContent = true;
            var entry = !underContent && (EntryPoints.Contains(segment)
                || (index >= 1 && segments[index - 1] == "wp-admin")
                || (index >= 2 && segments[index - 2] == "wp-admin" && AdminSubfolders.Contains(segments[index - 1])));
            var placeholder = segment == "index.php" && index == segments.Count - 1
                && ((index >= 1 && segments[index - 1] == "wp-content")
                    || (index >= 2 && segments[index - 2] == "wp-content" && PlaceholderFolders.Contains(segments[index - 1])));
            return new ScriptSegment(segment, entry, placeholder);
        }
        return null;
    }

    /// <param name="Placeholder">One of WordPress core's "Silence is golden" <c>index.php</c> files, requested by name.</param>
    internal sealed record ScriptSegment(string Name, bool EntryPoint, bool Placeholder = false);
}

using WPShield.Abstractions;

namespace WPShield.Rules.Windows;

/// <summary>
/// <c>NET-PATH-001</c> - a request for an ASP.NET Core settings file.
/// </summary>
/// <remarks>
/// <para>
/// <c>appsettings.json</c> and <c>appsettings.&lt;Environment&gt;.json</c> are where an ASP.NET Core
/// application keeps connection strings and API keys. A week of logs from a shared Windows host
/// carried about 1,200 requests for them across 48 sites, with <c>Development</c>,
/// <c>Production</c>, <c>Staging</c>, <c>QA</c> and <c>Local</c> all probed by name.
/// </para>
/// <para>
/// <b>Score 30: it observes and never blocks, and that is the whole design.</b> A Blazor WebAssembly
/// application loads <c>appsettings.json</c> - and its environment variant - from <c>wwwroot</c> in
/// the browser, on every page load, by design. On a site that ships one, this rule fires on every
/// visitor. Blocking it would break every such application; observing it tells an operator that the
/// file is public, which on a Blazor site is intended and on a server-side ASP.NET Core site is a
/// leak. That judgement needs a person, so the rule gives it to one.
/// </para>
/// <para>
/// The final segment only: the name <c>appsettings</c>, an optional environment, and <c>.json</c>.
/// <c>blazor.boot.json</c> and <c>_framework/</c> are not settings and never match.
/// </para>
/// </remarks>
public sealed class AppSettingsRequestRule : IRequestPathRule
{
    internal const int Score = 30;

    public string Id => "NET-PATH-001";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var match = context.NormalizedPath.FirstAcrossViews(view => PathSegments.Final(view, Classify));

        return ValueTask.FromResult(match is null
            ? null
            : PathSegments.Finding(Id, Score, "Findings.AppSettingsRequest", match, "file"));
    }

    /// <summary><c>appsettings.json</c>, or <c>appsettings.X.json</c> for one environment name X.</summary>
    internal static string? Classify(string segment)
    {
        const string prefix = "appsettings";
        const string suffix = ".json";

        if (!segment.StartsWith(prefix, StringComparison.Ordinal) ||
            !segment.EndsWith(suffix, StringComparison.Ordinal))
        {
            return null;
        }

        var middle = segment[prefix.Length..^suffix.Length];
        if (middle.Length == 0)
        {
            return segment;
        }

        // ".Development" - one dot, then a name with no further dots.
        return middle.Length > 1 && middle[0] == '.' && !middle[1..].Contains('.', StringComparison.Ordinal)
            ? segment
            : null;
    }
}

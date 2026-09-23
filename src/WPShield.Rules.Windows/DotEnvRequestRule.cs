using WPShield.Abstractions;

namespace WPShield.Rules.Windows;

/// <summary>
/// <c>EXPOSE-PATH-001</c> - a request for a dotenv file, in any folder.
/// </summary>
/// <remarks>
/// <para>
/// <b>The most requested probe on the web.</b> A week of IIS logs from a shared Windows host carried
/// about 94,000 requests of this shape across 50 sites - WordPress, .NET and Blazor alike. A
/// <c>.env</c> file holds database passwords, API keys and signing secrets in plain text, and a site
/// that serves one hands all of them over in a single <c>GET</c>.
/// </para>
/// <para>
/// <b>A shape, never a list.</b> Scanner catalogues enumerate paths: <c>/.env</c>,
/// <c>/.env.production</c>, <c>/backend/.env</c>. Measured against the same logs, a rule built from
/// such a list missed about 84% of the probes, because scanners walk every folder name they can guess
/// - <c>/app/.env</c>, <c>/api/.env</c>, <c>/laravel/.env</c>. So the rule matches the segment, in any
/// position: <c>.env</c> itself, or <c>.env</c> followed by <c>.</c>, <c>-</c>, <c>_</c> or a digit -
/// <c>.env.local</c>, <c>.env-example</c>, <c>.env_copy</c>, <c>.env2</c>. A segment that merely
/// starts with the letters, such as <c>.envrc</c>, is a different file and is left alone.
/// </para>
/// <para>
/// <b>Score 100, which blocks on its own.</b> No browser, crawler or application asks a web server
/// for a dotenv file; it is configuration for a process, read from disk. A <c>.env</c> folder - a
/// Python virtual environment is often named that - is no more a legitimate thing to request over
/// HTTP, so directory position counts too.
/// </para>
/// </remarks>
public sealed class DotEnvRequestRule : IRequestPathRule
{
    internal const int Score = 100;

    public string Id => "EXPOSE-PATH-001";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var match = context.NormalizedPath.FirstAcrossViews(view => PathSegments.Any(view, Classify));

        return ValueTask.FromResult(match is null
            ? null
            : PathSegments.Finding(Id, Score, "Findings.DotEnvRequest", match, "file"));
    }

    internal static string? Classify(string segment)
    {
        if (segment == ".env")
        {
            return segment;
        }

        if (segment.Length > 4 && segment.StartsWith(".env", StringComparison.Ordinal))
        {
            var next = segment[4];
            if (next is '.' or '-' or '_' || char.IsAsciiDigit(next))
            {
                return segment;
            }
        }

        return null;
    }
}

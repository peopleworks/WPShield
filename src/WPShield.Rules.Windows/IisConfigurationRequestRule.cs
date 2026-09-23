using System.Collections.Frozen;
using WPShield.Abstractions;

namespace WPShield.Rules.Windows;

/// <summary>
/// <c>IIS-PATH-002</c> - a request for an IIS or ASP.NET configuration file.
/// </summary>
/// <remarks>
/// <para>
/// <c>web.config</c> holds connection strings, machine keys and handler mappings;
/// <c>launchSettings.json</c> is a development file that names environments, ports and sometimes
/// secrets, and reaches a server when a project folder is published whole, often under
/// <c>Properties/</c>. A week of logs from a shared Windows host carried requests for them against 33
/// sites.
/// </para>
/// <para>
/// <b>IIS already refuses <c>web.config</c> by default</b> - request filtering answers it with
/// 404.8, and those logs show exactly that. The rule is not redundant with it: a site whose request
/// filtering was loosened serves the file, and on every site the finding is the log line that says
/// someone asked. <c>launchSettings.json</c> has no such default protection.
/// </para>
/// <para>
/// <b>Exact names, in any segment.</b> <c>/../../web.config</c> normalizes to <c>/web.config</c> and
/// fires here, and <c>IIS-PATH-001</c> reports the traversal beside it. A page whose slug merely
/// mentions the file, such as <c>/blog/what-is-web.config</c>, does not match.
/// </para>
/// <para>
/// <b>Score 100.</b> Neither file has a legitimate HTTP caller.
/// </para>
/// </remarks>
public sealed class IisConfigurationRequestRule : IRequestPathRule
{
    internal const int Score = 100;

    private static readonly FrozenSet<string> Files =
        new[] { "web.config", "launchsettings.json" }.ToFrozenSet(StringComparer.Ordinal);

    public string Id => "IIS-PATH-002";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var match = context.NormalizedPath.FirstAcrossViews(view =>
            PathSegments.Any(view, segment => Files.Contains(segment) ? segment : null));

        return ValueTask.FromResult(match is null
            ? null
            : PathSegments.Finding(Id, Score, "Findings.IisConfigurationRequest", match, "file"));
    }
}

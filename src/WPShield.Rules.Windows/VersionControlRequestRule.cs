using System.Collections.Frozen;
using WPShield.Abstractions;

namespace WPShield.Rules.Windows;

/// <summary>
/// <c>EXPOSE-PATH-002</c> - a request into a version-control folder.
/// </summary>
/// <remarks>
/// <para>
/// A <c>.git</c> folder left in a web root gives away the whole repository: <c>.git/config</c> names
/// the remote, sometimes with a token in the URL, and the object store reconstructs every file ever
/// committed, secrets that were "removed" included. <c>.svn</c>, <c>.hg</c> and <c>.bzr</c> do the same
/// for their systems. A week of logs from a shared Windows host carried about 4,900 requests into these
/// folders across 50 sites.
/// </para>
/// <para>
/// <b>Exact folder names, in any position.</b> <c>.gitignore</c>, <c>.gitattributes</c>,
/// <c>.github</c> and <c>.gitlab-ci.yml</c> are not repositories and are left alone. Neither is
/// <c>.well-known</c>, which is the one dot-folder with a legitimate caller on almost every site:
/// certificate renewal reads <c>.well-known/acme-challenge/</c>, and a rule shaped as "any dot-folder"
/// would break it.
/// </para>
/// <para>
/// <b>Score 100.</b> Nothing legitimate fetches a repository's internals from a production web
/// server over HTTP.
/// </para>
/// </remarks>
public sealed class VersionControlRequestRule : IRequestPathRule
{
    internal const int Score = 100;

    private static readonly FrozenSet<string> Folders =
        new[] { ".git", ".svn", ".hg", ".bzr" }.ToFrozenSet(StringComparer.Ordinal);

    public string Id => "EXPOSE-PATH-002";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var match = context.NormalizedPath.FirstAcrossViews(view =>
            PathSegments.Any(view, segment => Folders.Contains(segment) ? segment : null));

        return ValueTask.FromResult(match is null
            ? null
            : PathSegments.Finding(Id, Score, "Findings.VersionControlRequest", match, "folder"));
    }
}

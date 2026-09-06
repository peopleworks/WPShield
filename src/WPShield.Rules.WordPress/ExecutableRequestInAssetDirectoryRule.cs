using System.Collections.Frozen;
using WPShield.Abstractions;

namespace WPShield.Rules.WordPress;

/// <summary>
/// <c>WP-PATH-002</c> — an executable file was requested from a directory that holds only static
/// assets or build output.
/// </summary>
/// <remarks>
/// <para>
/// This rule exists because of a measured incident rather than a threat model. The webshells that
/// motivated it were not in <c>uploads</c>, where <c>WP-PATH-001</c> would have caught them. They were
/// inside a plugin's vendored front-end libraries — a <c>.php</c> file dropped beside the JavaScript
/// of a code editor, and another beside a slider skin's stylesheets. Both were reached with an
/// ordinary <c>GET</c>, both returned 200, and nothing in the upload rule set could see either,
/// because no upload was taking place.
/// </para>
/// <para>
/// <b>The directory list is deliberately narrow, and what is missing from it is the point.</b> Every
/// name below denotes a directory that exists to hold bytes a browser fetches verbatim: build output,
/// a vendored package tree, fonts, images. A script there is either an intruder or a packaging
/// accident, and in both readings there is no caller who needs the request to succeed.
/// </para>
/// <para>
/// <c>assets</c>, <c>css</c>, <c>js</c>, <c>media</c> and <c>vendor</c> are excluded on purpose, even
/// though they are the names most people would add first. Older plugins genuinely do serve generated
/// stylesheets and scripts from PHP — <c>css/style.php</c> and <c>js/script.php</c> are a real, if
/// unfashionable, pattern — and <c>vendor</c> is a Composer tree whose contents are reached by
/// autoload rather than by URL, but which some plugins expose anyway. Including them would have put a
/// blocking score on traffic that works today, and a security tool that breaks a working site gets
/// switched off, taking the rules that were right with it.
/// </para>
/// <para>
/// <b>Score 100, which blocks on its own.</b> That is a strong claim and it rests on the narrowness
/// above rather than on confidence about attackers: the rule fires only where a script cannot have a
/// legitimate HTTP caller. The moment a name is added to this list for which that sentence is not
/// true, the score is wrong and the addition is the bug.
/// </para>
/// <para>
/// <b>False positives.</b> A plugin that ships a genuine PHP endpoint inside <c>static</c> or
/// <c>dist</c> would be refused. No such plugin is known to the project, and the shape is itself a
/// packaging defect — but this is the rule to look at first when a site reports something broken, and
/// Monitor mode exists so that it is reported rather than discovered.
/// </para>
/// </remarks>
public sealed class ExecutableRequestInAssetDirectoryRule : IRequestPathRule
{
    internal const int Score = 100;

    /// <summary>
    /// Directories whose entire purpose is to be served verbatim. See the remarks for the names that
    /// were considered and left out.
    /// </summary>
    private static readonly FrozenSet<string> AssetDirectories = new[]
    {
        // Front-end build output. Never routable; regenerated wholesale by a build step.
        "dist", "build", "_next", "out",

        // Vendored package trees fetched by a package manager, shipped by accident more often than
        // by design, and never a place a request should reach a script.
        "node_modules", "bower_components",

        // The conventional name for "files the server hands over unchanged".
        "static",

        // Binary asset directories. A script among fonts or images is not a script anyone calls.
        "fonts", "webfonts", "img", "images"
    }.ToFrozenSet(StringComparer.Ordinal);

    public string Id => "WP-PATH-002";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var path = context.NormalizedPath;

        var match = path.FirstAcrossViews(view =>
        {
            var assetDirectory = view.IndexOfSegment(AssetDirectories);
            if (assetDirectory < 0)
            {
                return null;
            }

            var executable = view.FindExecutableSegment(DangerousUploadExtensions.AllExecutable);

            // Strictly after the directory, so that a request for /static.php is not attributed to a
            // directory named "static" that the path never entered.
            return executable is not null && executable.SegmentIndex > assetDirectory
                ? new AssetDirectoryMatch(view.Segments[assetDirectory], executable)
                : null;
        });

        if (match is null)
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        var evidence = new Dictionary<string, string>(5)
        {
            ["normalizedPath"] = match.Executable.View.Value,
            ["assetDirectory"] = match.Directory,
            ["segment"] = match.Executable.Segment,
            ["extension"] = match.Executable.Extension,
            ["view"] = match.Executable.View.Token
        };

        if (!match.Executable.IsFinalSegment)
        {
            evidence["pathInfo"] = "true";
        }

        return ValueTask.FromResult<RuleFinding?>(
            new RuleFinding(Id, Score, "Findings.ExecutableRequestInAssetDirectory", evidence));
    }

    private sealed record AssetDirectoryMatch(string Directory, ExecutablePathSegment Executable);
}

using System.Collections.Frozen;
using WPShield.Abstractions;

namespace WPShield.Rules.WordPress;

/// <summary>
/// <c>WP-PATH-001</c> — an executable file was requested from inside <c>wp-content/uploads</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>The uploads directory is data, never code.</b> WordPress writes media there and serves it back
/// as bytes; nothing in core, and no correct plugin, routes execution through it. So a request that
/// would run a script from that directory is not an unusual request — it is the request an attacker
/// makes after an upload succeeded, and there is no benign version of it to weigh against.
/// </para>
/// <para>
/// This is the half of the problem M2 could not see. M2 inspects <c>multipart/form-data</c> bodies,
/// which means it can refuse a webshell as it arrives — but a shell already on disk is reached with a
/// plain <c>GET</c> that carries no body at all, and every rule in the upload set correctly declines
/// to fire on it. The two rule families cover the two halves: one refuses the write, this one refuses
/// the read.
/// </para>
/// <para>
/// <b>Score 100, which blocks on its own, and the justification is that it cannot be wrong about
/// what it claims.</b> It claims only that an HTTP request would execute a script under the uploads
/// directory. Plugins do place PHP under <c>uploads</c> — All-In-One WP Security keeps its firewall
/// settings there — but such files are reached with <c>include</c> from PHP, never over HTTP, so
/// refusing the HTTP request takes nothing away. Requesting one is exactly the operation that has no
/// legitimate caller.
/// </para>
/// <para>
/// <b>False positives.</b> WordPress drops a silence-guard <c>index.php</c> into upload directories,
/// and a crawler that follows a directory URL can request it; that request is reported. The guard
/// returns an empty page, so nothing is lost by refusing it — and exempting the name would be worse
/// than the false positive it avoids, because <c>index.php</c> is a name attackers actively choose
/// for exactly that reason. One of the shells in the incident that motivated this rule was called
/// <c>index.php</c>.
/// </para>
/// <para>
/// The match runs against <see cref="InspectionContext.NormalizedPath"/> and across every one of its
/// views, so <c>/wp-content/uploads/shell.php.</c>, <c>/WP-CONTENT/UPLOADS/SHELL.PHP</c>,
/// <c>/wp-content/uploads/shell.php::$DATA</c>, <c>/wp-content\uploads\shell.php</c> and
/// <c>/wp-content/uploads/shell.php/logo.jpg</c> all resolve to the same finding.
/// </para>
/// </remarks>
public sealed class ExecutableRequestUnderUploadsRule : IRequestPathRule
{
    internal const int Score = 100;

    /// <summary>
    /// The directory run that identifies WordPress media storage. Matched as a consecutive pair
    /// anywhere in the path, so a site installed in a subdirectory matches too.
    /// </summary>
    private static readonly string[] UploadsSequence = ["wp-content", "uploads"];

    /// <summary>
    /// Also treated as uploads storage. <c>wp-content/upgrade</c> holds plugin and theme archives
    /// mid-installation and <c>wp-content/updraft</c> holds backups; both are written by upload
    /// paths, neither is ever executed, and both are directories attackers plant into precisely
    /// because operators forget they exist.
    /// </summary>
    private static readonly FrozenSet<string> AdditionalDataDirectories =
        new[] { "upgrade", "updraft" }.ToFrozenSet(StringComparer.Ordinal);

    public string Id => "WP-PATH-001";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        // NormalizedPath recomputes on every access by design, so it is hoisted once.
        var path = context.NormalizedPath;

        var match = path.FirstAcrossViews(view =>
        {
            var dataDirectoryEnd = FindDataDirectoryEnd(view);
            if (dataDirectoryEnd < 0)
            {
                return null;
            }

            var executable = view.FindExecutableSegment(DangerousUploadExtensions.AllExecutable);

            // The executable segment must sit inside the data directory, not merely somewhere in a
            // path that also mentions it. Without this, /shell.php?x=/wp-content/uploads would be a
            // finding while the real request it describes would not.
            return executable is not null && executable.SegmentIndex >= dataDirectoryEnd
                ? executable
                : null;
        });

        if (match is null)
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        // Evidence is the normalized path and the matched segment, never the raw request target: a
        // raw path can carry control characters and ANSI escapes straight into a log consumer.
        var evidence = new Dictionary<string, string>(5)
        {
            ["normalizedPath"] = match.View.Value,
            ["segment"] = match.Segment,
            ["extension"] = match.Extension,
            ["view"] = match.View.Token
        };

        if (!match.IsFinalSegment)
        {
            // PHP path-info execution. The requested path ends in something else entirely, so an
            // operator reading this line needs to be told which segment actually runs.
            evidence["pathInfo"] = "true";
        }

        return ValueTask.FromResult<RuleFinding?>(
            new RuleFinding(Id, Score, "Findings.ExecutableRequestUnderUploads", evidence));
    }

    private static int FindDataDirectoryEnd(RequestPathView view)
    {
        var uploads = view.IndexAfterSequence(UploadsSequence);
        if (uploads >= 0)
        {
            return uploads;
        }

        // wp-content/<upgrade|updraft>, checked as a pair so that a plugin directory merely named
        // "upgrade" somewhere else in the tree is not swept in.
        for (var index = 0; index + 1 < view.Segments.Count; index++)
        {
            if (string.Equals(view.Segments[index], "wp-content", StringComparison.Ordinal) &&
                AdditionalDataDirectories.Contains(view.Segments[index + 1]))
            {
                return index + 2;
            }
        }

        return -1;
    }
}

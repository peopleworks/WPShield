using System.Collections.Frozen;
using WPShield.Abstractions;

namespace WPShield.Rules.Windows;

/// <summary>
/// <c>EXPOSE-PATH-004</c> - a request for a stray backup copy of a file.
/// </summary>
/// <remarks>
/// <para>
/// An editor or a hurried administrator leaves <c>wp-config.php.bak</c>, <c>web.config.old</c>,
/// <c>.env.save</c> or <c>index.php~</c> beside the original. The original is executed or protected;
/// the copy is not, and the server hands its source - passwords included - to anyone who asks. A week
/// of logs from a shared Windows host carried about 8,500 requests of this shape across 50 sites.
/// </para>
/// <para>
/// <b>The final extension only</b>, a deliberate departure from the every-segment rule the executable
/// rules follow. That rule exists because PHP executes a script found earlier in the path; nothing
/// executes a backup, so what matters is the file actually requested. And a backup suffix inside a name
/// is not a backup: <c>photo.bak.jpg</c> is a renamed photo.
/// </para>
/// <para>
/// <b>What counts, and why <c>.bak</c> is split.</b> A trailing <c>~</c>, and the suffixes
/// <c>.old</c>, <c>.orig</c>, <c>.save</c>, <c>.swp</c> and <c>.swo</c> - no download format uses any
/// of them. <c>.bak</c> and <c>.backup</c> count only when they follow another name with an extension
/// or a dotfile: <c>wp-config.php.bak</c>, <c>.env.backup</c>. On its own, <c>.bak</c> is SQL Server's
/// native backup format and <c>.backup</c> is pgAdmin's, and a site can publish one on purpose - so
/// <c>database.bak</c> is left to <c>EXPOSE-PATH-005</c>, which observes rather than blocks. That keeps
/// this rule's score honest.
/// </para>
/// <para>
/// <b>Score 100.</b> A copy of a named source file has no legitimate HTTP caller.
/// </para>
/// </remarks>
public sealed class BackupCopyRequestRule : IRequestPathRule
{
    internal const int Score = 100;

    /// <summary>Suffixes that only ever mean "a copy of something".</summary>
    private static readonly FrozenSet<string> CopyOnly =
        new[] { "old", "orig", "save", "swp", "swo" }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>Suffixes that are also a database backup format when they stand alone.</summary>
    internal static readonly FrozenSet<string> CopyOrDatabaseBackup =
        new[] { "bak", "backup" }.ToFrozenSet(StringComparer.Ordinal);

    public string Id => "EXPOSE-PATH-004";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var match = context.NormalizedPath.FirstAcrossViews(view => PathSegments.Final(view, Classify));

        return ValueTask.FromResult(match is null
            ? null
            : PathSegments.Finding(Id, Score, "Findings.BackupCopyRequest", match, "form"));
    }

    internal static string? Classify(string segment)
    {
        if (segment.Length > 1 && segment.EndsWith('~'))
        {
            return "~";
        }

        var split = PathSegments.SplitFinalExtension(segment);
        if (split is null)
        {
            return null;
        }

        var (stem, extension) = split.Value;

        if (CopyOnly.Contains(extension))
        {
            return extension;
        }

        return CopyOrDatabaseBackup.Contains(extension) && stem.Contains('.', StringComparison.Ordinal)
            ? extension
            : null;
    }
}

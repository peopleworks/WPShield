using System.Collections.Frozen;
using WPShield.Abstractions;

namespace WPShield.Rules.Windows;

/// <summary>
/// <c>EXPOSE-PATH-005</c> - a request for a database file or dump.
/// </summary>
/// <remarks>
/// <para>
/// <c>/database.sql</c>, <c>/backup.sql.gz</c>, <c>/data/db.sqlite</c>, an Access <c>.mdb</c> left
/// in an old site's root. A week of logs from a shared Windows host carried about 2,100 requests of
/// this shape across 45 sites.
/// </para>
/// <para>
/// <b>Every extension position of the final segment</b>, so <c>backup.sql.gz</c> and
/// <c>dump.sql.zip</c> match on <c>sql</c>. An archive extension on its own does not: <c>.gz</c>,
/// <c>.zip</c> and <c>.7z</c> are ordinary downloads, and <c>sitemap.xml.gz</c> is a sitemap. A
/// <c>.bak</c> or <c>.backup</c> that is the file's only extension lands here too - it is SQL Server's
/// and pgAdmin's native backup format - while one appended to another name is a copy and belongs to
/// <c>EXPOSE-PATH-004</c>.
/// </para>
/// <para>
/// <b>Score 30: it observes and never blocks on its own.</b> Unlike a backup copy of a source file, a
/// database file can be published deliberately - a tutorial's sample schema, a dataset offered for
/// download. The log line is the value: an operator who sees these knows what is being looked for, and
/// a site that answers one with a real file has a problem no score can undo.
/// </para>
/// </remarks>
public sealed class DatabaseDumpRequestRule : IRequestPathRule
{
    internal const int Score = 30;

    private static readonly FrozenSet<string> DatabaseExtensions =
        new[] { "sql", "sqlite", "sqlite3", "db", "mdb", "dump" }.ToFrozenSet(StringComparer.Ordinal);

    public string Id => "EXPOSE-PATH-005";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var match = context.NormalizedPath.FirstAcrossViews(view => PathSegments.Final(view, Classify));

        return ValueTask.FromResult(match is null
            ? null
            : PathSegments.Finding(Id, Score, "Findings.DatabaseDumpRequest", match, "extension"));
    }

    internal static string? Classify(string segment)
    {
        foreach (var extension in PathSegments.ExtensionPositions(segment))
        {
            if (DatabaseExtensions.Contains(extension))
            {
                return extension;
            }
        }

        // A native database backup: the backup suffix is the file's only extension.
        var split = PathSegments.SplitFinalExtension(segment);
        if (split is null)
        {
            return null;
        }

        var (stem, final) = split.Value;
        return BackupCopyRequestRule.CopyOrDatabaseBackup.Contains(final) &&
               stem.Length > 0 &&
               !stem.Contains('.', StringComparison.Ordinal)
            ? final
            : null;
    }
}

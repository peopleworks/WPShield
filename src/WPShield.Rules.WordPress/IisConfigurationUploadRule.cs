using WPShield.Abstractions;

namespace WPShield.Rules.WordPress;

/// <summary>
/// <c>IIS-CONFIG-001</c> — the upload is a <c>web.config</c> file.
/// </summary>
/// <remarks>
/// <para>
/// This is the highest-confidence rule WPShield ships, and it is specific to Windows hosting. IIS
/// reads <c>web.config</c> from every directory it serves and applies it to that directory and its
/// children. An attacker who writes one into <c>wp-content/uploads</c> can register a handler
/// mapping that executes files of their choosing, re-enable script execution the operator disabled,
/// or relax authorization for the directory. It converts an arbitrary file write into remote code
/// execution without ever uploading a script.
/// </para>
/// <para>
/// Normalization means <c>web.config.</c>, <c>WEB.CONFIG</c>, <c>web.config::$DATA</c> and
/// <c>../web.config</c> are all recognized.
/// </para>
/// <para>
/// <b>The name has to match under either normalization view, and that is not a refinement — it is
/// the difference between the rule working and not.</b> Because this rule matches an exact reserved
/// name rather than a suffix, it was the most brittle rule in the set: <c>web.con{f}ig</c> is not
/// <c>web.config</c> to NTFS, so a single brace turned off the 100-point "no false positives
/// expected" rule and the whole request scored zero. WordPress's <c>sanitize_file_name()</c> deletes
/// that brace and writes the live <c>web.config</c> anyway. The same applies to <c>web.config-</c>
/// and <c>web.config~</c> through the final <c>trim($filename, '.-_')</c> and the deletion set.
/// </para>
/// <para>
/// <b>False positives.</b> Still none expected. No WordPress workflow uploads a <c>web.config</c>
/// through a request body, and the rule deliberately matches only the exact reserved name rather
/// than every <c>.config</c> extension, so a site distributing an unrelated configuration file as a
/// download is not affected. The second view does not weaken that claim: the names it adds
/// (<c>web.config~</c> from an editor, <c>web.config-</c> from a backup convention, <c>web.con(f)ig</c>
/// from a manual rename) are all names WordPress writes to disk <i>as</i> <c>web.config</c>. If one
/// of them arrives by accident it is still an accident that hands IIS a live configuration file, so
/// reporting it is correct rather than a cost. What the second view cannot see is a site that
/// filters <c>sanitize_file_name_chars</c> to keep a character WordPress deletes by default; there
/// the rewrite WPShield predicts would not happen, and the finding would be a false positive.
/// </para>
/// </remarks>
public sealed class IisConfigurationUploadRule : IInspectionRule
{
    internal const int Score = 100;

    /// <summary>
    /// Internal so <see cref="UnsafeFileNameRule"/> can ask whether a WordPress rewrite <i>produces</i>
    /// this name. One spelling of the reserved name, in the rule that owns it.
    /// </summary>
    internal const string ReservedName = "web.config";

    public string Id => "IIS-CONFIG-001";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        // NormalizedFile recomputes on every access by design, so it is hoisted once here.
        var normalized = context.NormalizedFile;
        var view = normalized.FindViewNamed(ReservedName);
        if (view is null)
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        var evidence = new Dictionary<string, string>(3)
        {
            ["normalizedName"] = normalized.BaseName,
            ["view"] = view.Token
        };

        if (normalized.DivergesUnderWordPress)
        {
            // When the rewrite is what produced the reserved name, normalizedName on its own reads
            // as an unexplained 100-point block. Both names, always.
            evidence["wordpressName"] = normalized.WordPress.BaseName;
        }

        RuleFinding finding = new(Id, Score, "Findings.IisConfigurationUpload", evidence);

        return ValueTask.FromResult<RuleFinding?>(finding);
    }
}

using WPShield.Abstractions;

namespace WPShield.Rules.WordPress;

/// <summary>
/// <c>WP-UPLOAD-001</c> — the upload carries an extension a PHP handler will execute.
/// </summary>
/// <remarks>
/// <para>
/// Matching runs over every segment of the normalized name, not only the last one, because
/// <c>photo.php.jpg</c> executes under a PHP-FastCGI installation with <c>cgi.fix_pathinfo</c>
/// enabled. Normalization also means <c>shell.php.</c>, <c>shell.php </c> and
/// <c>shell.php::$DATA</c> are all recognized as <c>shell.php</c>.
/// </para>
/// <para>
/// <b>Both normalization views are searched, and the more severe result wins.</b> The NTFS view
/// alone models what <i>Windows</i> writes, and that is only half of what decides the name on the
/// endpoints this rule defends. <c>shell.p{h}p</c> is not a PHP file to NTFS — the extension segment
/// is <c>p{h}p</c> and nothing executes it — but WordPress's <c>sanitize_file_name()</c> deletes
/// braces, so what lands in <c>wp-content/uploads</c> is <c>shell.php</c>. The same single character
/// defeats the check for <c>%</c>, <c>#</c>, <c>&amp;</c>, <c>$</c> and the rest of that deletion
/// set, and a trailing <c>-</c> defeats it through the final <c>trim($filename, '.-_')</c>.
/// Searching both views is what closes that, and <c>NormalizedFileName.FindMostSevereExtension</c>
/// is where the "final beats embedded, NTFS breaks ties" ordering lives.
/// </para>
/// <para>
/// <b>False positives.</b> A dangerous extension in a non-final position scores lower than one in the
/// final position, because a benign name such as <c>readme.php.txt</c> is structurally identical to
/// a disguised payload and cannot be separated from it by name alone. Combined with
/// <see cref="DisguisedExtensionRule"/> such a name reaches the default block threshold, so operators
/// should stay in Monitor mode until they have reviewed their own upload traffic.
/// </para>
/// <para>
/// The second view is cheaper than it looks in false positives, and it is worth being precise about
/// why. Legitimate uploads are rewritten by <c>sanitize_file_name()</c> constantly — <c>Captura de
/// pantalla (3).png</c>, <c>Q&amp;A final.pdf</c>, <c>Rechnung #42.pdf</c> all come out different —
/// but every one of those rewrites lands in the <i>stem</i>. This rule only reacts when the rewrite
/// produces an executable token <i>between two dots</i>, which ordinary punctuation in a file name
/// does not do. The cases it adds are overwhelmingly names whose rewritten form is genuinely
/// dangerous even when the intent was not: an editor backup uploaded as <c>functions.php~</c> is
/// still a file WordPress writes as <c>functions.php</c>.
/// </para>
/// <para>
/// The honest cost is the opposite direction. WordPress defuses <i>some</i> of these itself, by
/// postfixing an unrecognized intermediate extension with an underscore, so real WordPress writes
/// <c>shell.php_.jpg</c> rather than <c>shell.php.jpg</c>. That defence depends on
/// <c>get_allowed_mime_types()</c>, which varies with the uploading user's capabilities and with
/// site filters, so WPShield does not model it and will report the embedded <c>php</c> anyway. For a
/// name of that shape — hostile-looking either way — reporting is the right side to be wrong on.
/// </para>
/// </remarks>
public sealed class ExecutableUploadExtensionRule : IInspectionRule
{
    internal const int FinalPositionScore = 90;
    internal const int NonFinalPositionScore = 50;

    public string Id => "WP-UPLOAD-001";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        // NormalizedFile recomputes on every access by design, so it is hoisted once here.
        var normalized = context.NormalizedFile;
        var match = normalized.FindMostSevereExtension(DangerousUploadExtensions.PhpExecutable);
        if (match is null)
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        var evidence = new Dictionary<string, string>(5)
        {
            ["extension"] = $".{match.Extension}",
            ["position"] = match.IsFinalPosition ? "final" : "embedded",
            ["normalizedName"] = normalized.BaseName,

            // Which component's normalization produced the match. Without it, a finding on
            // shell.p{h}p reads as a mistake: the name in the log plainly has no .php in it.
            ["view"] = match.View.Token
        };

        if (normalized.DivergesUnderWordPress)
        {
            // Both names, whichever one matched. The disagreement between them is the substance of
            // the finding, and an operator in Monitor mode has to be able to see it before Block
            // mode turns it into a refusal.
            evidence["wordpressName"] = normalized.WordPress.BaseName;
        }

        RuleFinding finding = new(
            Id,
            match.IsFinalPosition ? FinalPositionScore : NonFinalPositionScore,
            "Findings.ExecutableUploadExtension",
            evidence);

        return ValueTask.FromResult<RuleFinding?>(finding);
    }
}

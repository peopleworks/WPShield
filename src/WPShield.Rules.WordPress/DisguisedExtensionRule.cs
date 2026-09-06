using WPShield.Abstractions;

namespace WPShield.Rules.WordPress;

/// <summary>
/// <c>WP-UPLOAD-002</c> — an executable extension is hidden behind a harmless-looking final one.
/// </summary>
/// <remarks>
/// <para>
/// <c>photo.php.jpg</c> presents itself as an image to any check that only inspects the last
/// extension, while remaining executable under a PHP-FastCGI installation with
/// <c>cgi.fix_pathinfo</c> enabled or an IIS handler mapping that matches on a wildcard.
/// </para>
/// <para>
/// This rule contributes a deliberately small score. It is a disguise signal, not proof of
/// execution, and it only reaches the default block threshold when combined with
/// <see cref="ExecutableUploadExtensionRule"/> or <see cref="IisExecutableUploadRule"/> reporting the
/// same name. That combination is the project requirement that rules combine signals instead of
/// blocking on a single weak one.
/// </para>
/// <para>
/// <b>Every normalization view is examined, and the first that shows a disguise reports it.</b>
/// Unlike the extension rules there is no severity to rank — the disguise either exists in a view or
/// it does not — so the NTFS view is tried first and the WordPress view answers for the names it
/// alone creates, such as <c>photo.p{h}p.jpg</c>. The evidence names the view that matched, because
/// <c>executableExtension=.php</c> against a <c>normalizedName</c> that visibly contains no
/// <c>.php</c> is otherwise unreadable.
/// </para>
/// <para>
/// <b>False positives.</b> Ordinary multi-extension names such as <c>archive.tar.gz</c>,
/// <c>style.min.css</c> and <c>report.2024.xlsx</c> never match, because the rule requires an
/// executable segment rather than merely more than one segment. A genuinely benign
/// <c>readme.php.txt</c> does match and cannot be distinguished by name alone. The WordPress view
/// adds one class of its own: WordPress postfixes an unrecognized intermediate extension with an
/// underscore, so the name it really writes for <c>photo.php.jpg</c> is <c>photo.php_.jpg</c>, which
/// is not disguised and not executable. That defence depends on <c>get_allowed_mime_types()</c>,
/// which WPShield cannot see from the request, so the finding stands. It is worth 30 points and
/// never blocks alone, which is the right weight for a signal whose worst case is describing a name
/// the backend would have defused.
/// </para>
/// </remarks>
public sealed class DisguisedExtensionRule : IInspectionRule
{
    internal const int Score = 30;

    public string Id => "WP-UPLOAD-002";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        // NormalizedFile recomputes on every access by design, so it is hoisted once here.
        var normalized = context.NormalizedFile;

        foreach (var view in normalized.Views)
        {
            if (view.ExtensionSegments.Count < 2)
            {
                continue;
            }

            var executable = view.FindExtension(DangerousUploadExtensions.AllExecutable);
            if (executable is null || view.IsFinalExtension(executable))
            {
                continue;
            }

            var evidence = new Dictionary<string, string>(5)
            {
                ["executableExtension"] = $".{executable}",
                ["presentedExtension"] = view.Extension ?? string.Empty,
                ["normalizedName"] = normalized.BaseName,
                ["view"] = view.Token
            };

            if (normalized.DivergesUnderWordPress)
            {
                evidence["wordpressName"] = normalized.WordPress.BaseName;
            }

            RuleFinding finding = new(Id, Score, "Findings.DisguisedUploadExtension", evidence);

            return ValueTask.FromResult<RuleFinding?>(finding);
        }

        return ValueTask.FromResult<RuleFinding?>(null);
    }
}

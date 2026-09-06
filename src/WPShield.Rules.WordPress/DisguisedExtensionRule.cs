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
/// <b>False positives.</b> Ordinary multi-extension names such as <c>archive.tar.gz</c>,
/// <c>style.min.css</c> and <c>report.2024.xlsx</c> never match, because the rule requires an
/// executable segment rather than merely more than one segment. A genuinely benign
/// <c>readme.php.txt</c> does match and cannot be distinguished by name alone.
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

        var normalized = context.NormalizedFile;
        if (normalized.ExtensionSegments.Count < 2)
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        var executable = normalized.FindExtension(DangerousUploadExtensions.AllExecutable);
        if (executable is null || normalized.IsFinalExtension(executable))
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        RuleFinding finding = new(
            Id,
            Score,
            "Findings.DisguisedUploadExtension",
            new Dictionary<string, string>
            {
                ["executableExtension"] = $".{executable}",
                ["presentedExtension"] = normalized.Extension ?? string.Empty,
                ["normalizedName"] = normalized.BaseName
            });

        return ValueTask.FromResult<RuleFinding?>(finding);
    }
}

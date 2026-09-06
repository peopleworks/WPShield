using WPShield.Abstractions;

namespace WPShield.Rules.WordPress;

/// <summary>
/// <c>IIS-UPLOAD-001</c> — the upload carries an extension IIS maps to a managed or native handler.
/// </summary>
/// <remarks>
/// <para>
/// WPShield protects WordPress on Windows Server, where the web server executes far more than PHP.
/// An <c>.aspx</c> or <c>.ashx</c> file dropped into a writable uploads directory runs as the
/// application pool identity, which is a strictly larger capability than a PHP shell. Protection
/// layers written for Linux hosting do not cover this, which is the gap WPShield exists to close.
/// </para>
/// <para>
/// <b>False positives.</b> A WordPress site has no legitimate reason to accept an ASP.NET handler
/// file through an upload endpoint. If a site genuinely distributes such files as downloads, the
/// operator should keep the site in Monitor mode and record the finding rather than block it.
/// </para>
/// </remarks>
public sealed class IisExecutableUploadRule : IInspectionRule
{
    internal const int FinalPositionScore = 90;
    internal const int NonFinalPositionScore = 50;

    public string Id => "IIS-UPLOAD-001";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var normalized = context.NormalizedFile;
        var extension = normalized.FindExtension(DangerousUploadExtensions.IisExecutable);
        if (extension is null)
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        var isFinal = normalized.IsFinalExtension(extension);
        RuleFinding finding = new(
            Id,
            isFinal ? FinalPositionScore : NonFinalPositionScore,
            "Findings.IisExecutableUpload",
            new Dictionary<string, string>
            {
                ["extension"] = $".{extension}",
                ["position"] = isFinal ? "final" : "embedded",
                ["normalizedName"] = normalized.BaseName
            });

        return ValueTask.FromResult<RuleFinding?>(finding);
    }
}

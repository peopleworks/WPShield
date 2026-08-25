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
/// <b>Both normalization views are searched, and the more severe result wins.</b> The rule that
/// matters here is the one the whole engine now follows: WPShield must see what the <i>backend</i>
/// will write, and two different components decide that. <c>shell.as{p}x</c> carries no extension
/// IIS knows — the segment is <c>as{p}x</c> — right up until WordPress's <c>sanitize_file_name()</c>
/// deletes the braces and writes <c>shell.aspx</c> into a directory IIS serves. The interesting
/// property of the WordPress rewrite is that it makes this <i>worse</i> than the PHP case rather
/// than equal to it: a PHP handler mapping can be removed from an uploads directory, while the
/// ASP.NET pipeline is the platform the site runs on.
/// </para>
/// <para>
/// <b>False positives.</b> A WordPress site has no legitimate reason to accept an ASP.NET handler
/// file through an upload endpoint. If a site genuinely distributes such files as downloads, the
/// operator should keep the site in Monitor mode and record the finding rather than block it. The
/// second view does not widen that: WordPress rewrites benign names in the stem, and this rule only
/// reacts when a rewrite produces a handler extension between two dots. See
/// <see cref="ExecutableUploadExtensionRule"/> for the full argument, which applies unchanged.
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

        // NormalizedFile recomputes on every access by design, so it is hoisted once here.
        var normalized = context.NormalizedFile;
        var match = normalized.FindMostSevereExtension(DangerousUploadExtensions.IisExecutable);
        if (match is null)
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        var evidence = new Dictionary<string, string>(5)
        {
            ["extension"] = $".{match.Extension}",
            ["position"] = match.IsFinalPosition ? "final" : "embedded",
            ["normalizedName"] = normalized.BaseName,
            ["view"] = match.View.Token
        };

        if (normalized.DivergesUnderWordPress)
        {
            // Both names, so the log line answers "why is this a finding when the name has no .aspx
            // in it" without the operator having to reconstruct the rewrite by hand.
            evidence["wordpressName"] = normalized.WordPress.BaseName;
        }

        RuleFinding finding = new(
            Id,
            match.IsFinalPosition ? FinalPositionScore : NonFinalPositionScore,
            "Findings.IisExecutableUpload",
            evidence);

        return ValueTask.FromResult<RuleFinding?>(finding);
    }
}

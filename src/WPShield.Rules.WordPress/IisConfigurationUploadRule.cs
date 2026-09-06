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
/// <b>False positives.</b> None expected. No WordPress workflow uploads a <c>web.config</c> through
/// a request body. The rule deliberately matches only the exact reserved name rather than every
/// <c>.config</c> extension, so a site distributing an unrelated configuration file as a download is
/// not affected.
/// </para>
/// </remarks>
public sealed class IisConfigurationUploadRule : IInspectionRule
{
    internal const int Score = 100;
    private const string ReservedName = "web.config";

    public string Id => "IIS-CONFIG-001";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var normalized = context.NormalizedFile;
        if (!string.Equals(normalized.BaseName, ReservedName, StringComparison.OrdinalIgnoreCase))
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        RuleFinding finding = new(
            Id,
            Score,
            "Findings.IisConfigurationUpload",
            new Dictionary<string, string>
            {
                ["normalizedName"] = normalized.BaseName
            });

        return ValueTask.FromResult<RuleFinding?>(finding);
    }
}

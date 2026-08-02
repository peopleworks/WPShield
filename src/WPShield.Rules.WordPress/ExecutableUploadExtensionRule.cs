using WPShield.Abstractions;

namespace WPShield.Rules.WordPress;

public sealed class ExecutableUploadExtensionRule : IInspectionRule
{
    private static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".phar"
    };

    public string Id => "WP-UPLOAD-001";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(context.FileName)) return ValueTask.FromResult<RuleFinding?>(null);

        var extension = Path.GetExtension(context.FileName);
        if (!Extensions.Contains(extension)) return ValueTask.FromResult<RuleFinding?>(null);

        RuleFinding finding = new(
            Id,
            90,
            "Findings.ExecutableUploadExtension",
            new Dictionary<string, string> { ["extension"] = extension.ToLowerInvariant() });
        return ValueTask.FromResult<RuleFinding?>(finding);
    }
}

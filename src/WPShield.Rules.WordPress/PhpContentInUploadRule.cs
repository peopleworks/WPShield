using System.Text;
using WPShield.Abstractions;

namespace WPShield.Rules.WordPress;

public sealed class PhpContentInUploadRule : IInspectionRule
{
    public string Id => "PHP-CONTENT-001";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (context.Sample.IsEmpty) return ValueTask.FromResult<RuleFinding?>(null);

        var text = Encoding.UTF8.GetString(context.Sample.Span);
        if (!text.Contains("<?php", StringComparison.OrdinalIgnoreCase) &&
            !text.Contains("<?=", StringComparison.OrdinalIgnoreCase))
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        RuleFinding finding = new(Id, 75, "Findings.PhpTagInUpload");
        return ValueTask.FromResult<RuleFinding?>(finding);
    }
}

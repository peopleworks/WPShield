using WPShield.Abstractions;

namespace WPShield.Rules.Windows;

/// <summary>
/// <c>PHP-PATH-001</c> - a request into PHPUnit, the remote code execution that never goes away.
/// </summary>
/// <remarks>
/// <para>
/// PHPUnit shipped <c>src/Util/PHP/eval-stdin.php</c>, which evaluates the request body as PHP. It
/// is a test tool, installed as a development dependency, and it reaches production whenever a
/// <c>vendor</c> folder is deployed whole. The flaw is from 2017 (CVE-2017-9841) and scanners still
/// ask for it on every site they find, under every folder they can guess - <c>/api/vendor/...</c>,
/// <c>/laravel/vendor/...</c>, <c>/lib/phpunit/...</c>.
/// </para>
/// <para>
/// <b>Two shapes.</b> The folder sequence <c>vendor/phpunit</c> anywhere in the path, and the file
/// <c>eval-stdin.php</c> anywhere, which catches the copies outside <c>vendor</c>. Both are shapes, not
/// the enumerated paths a scanner catalogue lists.
/// </para>
/// <para>
/// <b>Score 100.</b> <c>vendor</c> itself is left out of <c>WP-PATH-002</c>'s asset list on purpose,
/// because some plugins do expose a Composer tree. PHPUnit is different: it has no web entry point at
/// all, so nothing under it has a legitimate HTTP caller.
/// </para>
/// </remarks>
public sealed class PhpUnitRequestRule : IRequestPathRule
{
    internal const int Score = 100;

    private static readonly string[] VendorPhpUnit = ["vendor", "phpunit"];

    public string Id => "PHP-PATH-001";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var match = context.NormalizedPath.FirstAcrossViews(view =>
        {
            var after = view.IndexAfterSequence(VendorPhpUnit);
            if (after > 0)
            {
                return new SegmentMatch(view, after - 1, view.Segments[after - 1], "vendor/phpunit");
            }

            return PathSegments.Any(view, segment => segment == "eval-stdin.php" ? "eval-stdin.php" : null);
        });

        return ValueTask.FromResult(match is null
            ? null
            : PathSegments.Finding(Id, Score, "Findings.PhpUnitRequest", match, "form"));
    }
}

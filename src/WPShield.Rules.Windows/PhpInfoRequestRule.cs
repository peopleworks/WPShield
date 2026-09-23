using System.Collections.Frozen;
using WPShield.Abstractions;

namespace WPShield.Rules.Windows;

/// <summary>
/// <c>PHP-PATH-002</c> - a request for a <c>phpinfo()</c> page or a test script.
/// </summary>
/// <remarks>
/// <para>
/// <c>phpinfo()</c> prints the PHP version, every loaded module, the server's paths and its
/// environment variables - on a badly configured host, secrets included. It is the reconnaissance
/// step before choosing an exploit, and developers leave it behind as <c>info.php</c>,
/// <c>phpinfo.php</c> or <c>test.php</c>. A week of logs from a shared Windows host carried about
/// 14,000 requests of this shape across 49 sites.
/// </para>
/// <para>
/// <b>The shape:</b> a <c>.php</c> segment whose name contains <c>phpinfo</c> - <c>phpinfo.php</c>,
/// <c>_phpinfo.php</c>, <c>old_phpinfo.php</c> - or is one of the short names these pages go by:
/// <c>info</c>, <c>php_info</c>, <c>php-info</c>, <c>pinfo</c>, <c>php</c>, <c>i</c>, <c>pi</c>,
/// <c>test</c>, <c>server-info</c>. Any segment, because PHP's path-info reading executes
/// <c>/info.php/x</c>.
/// </para>
/// <para>
/// <b>Score 30: it observes and never blocks on its own.</b> These are real file names on real
/// installations - a leftover <c>test.php</c> that someone still uses, and the shortest names,
/// <c>i.php</c> and <c>pi.php</c>, are sometimes a real endpoint rather than a <c>phpinfo()</c> page -
/// and refusing one would break something that works today. The log line is what matters: a scanner reading these
/// names across every site is choosing what to try next.
/// </para>
/// </remarks>
public sealed class PhpInfoRequestRule : IRequestPathRule
{
    internal const int Score = 30;

    private static readonly FrozenSet<string> ShortNames = new[]
    {
        "info", "php_info", "php-info", "pinfo", "php", "i", "pi", "test", "server-info", "server_info"
    }.ToFrozenSet(StringComparer.Ordinal);

    public string Id => "PHP-PATH-002";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var match = context.NormalizedPath.FirstAcrossViews(view => PathSegments.Any(view, Classify));

        return ValueTask.FromResult(match is null
            ? null
            : PathSegments.Finding(Id, Score, "Findings.PhpInfoRequest", match, "file"));
    }

    internal static string? Classify(string segment)
    {
        const string extension = ".php";

        if (!segment.EndsWith(extension, StringComparison.Ordinal))
        {
            return null;
        }

        var stem = segment[..^extension.Length];
        if (stem.Length == 0 || stem.Contains('.', StringComparison.Ordinal))
        {
            return null;
        }

        return stem.Contains("phpinfo", StringComparison.Ordinal) || ShortNames.Contains(stem)
            ? segment
            : null;
    }
}

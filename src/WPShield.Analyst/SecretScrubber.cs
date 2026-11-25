using System.Text.RegularExpressions;
using WPShield.Evidence;

namespace WPShield.Analyst;

/// <summary>
/// The one place provider text is made safe to show: the key is removed, anything shaped like an
/// Anthropic key or a Relay token is removed too, and control and format characters are replaced.
/// </summary>
/// <remarks>
/// An error body from a provider or a proxy in front of it can echo the request's headers. The key the
/// process holds is removed by value, and the key shapes by pattern, so a second key that is not the one
/// this process holds (a proxy's own, say) is not shown either.
/// </remarks>
internal static partial class SecretScrubber
{
    public const string Redacted = "[redacted]";

    public static string Scrub(string? text, string? key, int max = 500)
    {
        if (string.IsNullOrEmpty(text)) return "";
        var scrubbed = text;
        if (!string.IsNullOrEmpty(key) && key.Length >= 8)
            scrubbed = scrubbed.Replace(key, Redacted, StringComparison.Ordinal);
        scrubbed = KeyShape().Replace(scrubbed, Redacted);
        return EvidenceText.Clean(scrubbed, max);
    }

    [GeneratedRegex(@"(sk-ant-[A-Za-z0-9_\-]{8,}|pwr_[A-Za-z0-9_\-]{8,}|Bearer\s+[A-Za-z0-9._\-]{16,})")]
    private static partial Regex KeyShape();
}

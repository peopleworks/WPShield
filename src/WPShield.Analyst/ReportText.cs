using System.Text;
using WPShield.Evidence;

namespace WPShield.Analyst;

/// <summary>
/// Model text made safe to keep and to print: control and format characters replaced, line by line so
/// the line breaks survive, and bounded in UTF-8 bytes.
/// </summary>
/// <remarks>
/// <see cref="EvidenceText.Clean"/> is the rule for every attacker-influenced string in WPShield, and a
/// line break is a control character to it. A report is several lines, so each line is cleaned with that
/// same rule rather than with a second one that could drift from it.
/// </remarks>
internal static class ReportText
{
    public const int MaxBytes = 64 * 1024;
    private const int MaxLineChars = 4000;

    public static (string Text, bool Truncated) Clean(string? text, int maxBytes = MaxBytes)
    {
        if (string.IsNullOrEmpty(text)) return ("", false);
        var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Split('\n');
        var builder = new StringBuilder();
        var bytes = 0;
        var truncated = false;
        foreach (var raw in lines)
        {
            var line = EvidenceText.Clean(raw.Replace("\t", "    ", StringComparison.Ordinal), MaxLineChars);
            truncated |= raw.Length > MaxLineChars;
            var size = Encoding.UTF8.GetByteCount(line) + (builder.Length > 0 ? 1 : 0);
            if (bytes + size > maxBytes)
            {
                truncated = true;
                var room = maxBytes - bytes - (builder.Length > 0 ? 1 : 0);
                if (room > 0)
                {
                    if (builder.Length > 0) builder.Append('\n');
                    builder.Append(Prefix(line, room));
                }
                break;
            }
            if (builder.Length > 0) builder.Append('\n');
            builder.Append(line);
            bytes += size;
        }
        return (builder.ToString().TrimEnd(), truncated);
    }

    /// <summary>One line of operator or model text: no line breaks at all.</summary>
    public static string Line(string? text, int max) => EvidenceText.Clean(text, max);

    /// <summary>The longest prefix of <paramref name="line"/> that fits in <paramref name="maxBytes"/> UTF-8 bytes, never splitting a character.</summary>
    private static string Prefix(string line, int maxBytes)
    {
        var builder = new StringBuilder();
        var bytes = 0;
        foreach (var rune in line.EnumerateRunes())
        {
            var size = rune.Utf8SequenceLength;
            if (bytes + size > maxBytes) break;
            builder.Append(rune.ToString());
            bytes += size;
        }
        return builder.ToString();
    }
}

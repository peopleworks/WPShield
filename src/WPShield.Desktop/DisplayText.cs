using System.Globalization;
using System.Text;

namespace WPShield.Desktop;

/// <summary>
/// Makes text that came from outside this process safe to show: adapter names, capture device IDs,
/// process names, reason codes.
/// </summary>
/// <remarks>
/// The same reasoning as the gateway's evidence rule, applied to a window instead of a log line. A
/// control character or a bidirectional override (U+202E) in an adapter or process name reorders or
/// hides what the operator reads. Letters are kept, accented ones included: a Spanish Windows names
/// its adapters "Conexión de área local", and replacing that with question marks would make the view
/// wrong in the operator's own language.
/// </remarks>
internal static class DisplayText
{
    internal const char Replacement = '�';

    internal static string Clean(string? value, int max = 160)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var builder = new StringBuilder(Math.Min(value.Length, max + 1));
        foreach (var rune in value.EnumerateRunes())
        {
            if (builder.Length >= max)
            {
                builder.Append('…');
                break;
            }
            if (IsHidden(Rune.GetUnicodeCategory(rune))) builder.Append(Replacement);
            else builder.Append(rune.ToString());
        }
        return builder.ToString();
    }

    private static bool IsHidden(UnicodeCategory category) => category is UnicodeCategory.Control
        or UnicodeCategory.Format or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator
        or UnicodeCategory.Surrogate or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned;
}

using System.Collections.Frozen;

namespace WPShield.Abstractions;

/// <summary>
/// A Windows-aware normalization of an uploaded file name, together with the structural anomalies
/// that were removed to produce it.
/// </summary>
/// <remarks>
/// <para>
/// Rules must never match against a raw client-supplied file name. Windows and NTFS silently
/// normalize several forms before a file reaches disk, so a name that looks harmless to a naive
/// extension check can still land as an executable script:
/// </para>
/// <list type="bullet">
///   <item><description><c>shell.php.</c> — trailing dots are stripped, arriving as <c>shell.php</c>.</description></item>
///   <item><description><c>shell.php </c> — trailing spaces are stripped, arriving as <c>shell.php</c>.</description></item>
///   <item><description><c>shell.php::$DATA</c> — the NTFS alternate data stream suffix is removed.</description></item>
///   <item><description><c>..\..\shell.php</c> — only the final path segment is used.</description></item>
///   <item><description><c>shell.p\0hp</c> — control characters are discarded by downstream consumers.</description></item>
/// </list>
/// <para>
/// It is not enough to rely on WordPress calling <c>sanitize_file_name()</c>. The vulnerable plugin
/// endpoints that cause upload incidents are precisely the ones that write files without it, which
/// is the reason WPShield inspects the request in the first place.
/// </para>
/// </remarks>
public sealed class NormalizedFileName
{
    /// <summary>Longest file name WPShield considers ordinary. NTFS permits 255 UTF-16 units.</summary>
    public const int MaximumSafeLength = 255;

    private static readonly FrozenSet<string> ReservedDeviceNames = new[]
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    private static readonly NormalizedFileName EmptyName = new(
        string.Empty,
        string.Empty,
        string.Empty,
        []);

    private NormalizedFileName(
        string raw,
        string baseName,
        string stem,
        IReadOnlyList<string> extensionSegments)
    {
        Raw = raw;
        BaseName = baseName;
        Stem = stem;
        ExtensionSegments = extensionSegments;
    }

    /// <summary>The unmodified value supplied by the client.</summary>
    public string Raw { get; }

    /// <summary>
    /// The name after directory, alternate-data-stream, control-character and trailing dot or space
    /// removal. This approximates what Windows would actually place on disk.
    /// </summary>
    public string BaseName { get; }

    /// <summary>The portion of <see cref="BaseName"/> before the first dot.</summary>
    public string Stem { get; }

    /// <summary>
    /// Every extension segment in order, lowercased and without the leading dot. <c>photo.php.jpg</c>
    /// yields <c>php</c> then <c>jpg</c>. Rules must examine all of them, because IIS and PHP-FastCGI
    /// can execute a dangerous extension that is not in the final position.
    /// </summary>
    public IReadOnlyList<string> ExtensionSegments { get; }

    /// <summary>The final extension including its dot, lowercased, or <see langword="null"/>.</summary>
    public string? Extension => ExtensionSegments.Count > 0 ? $".{ExtensionSegments[^1]}" : null;

    public bool IsEmpty => BaseName.Length == 0;

    /// <summary>The raw name contained a directory separator, so it attempted to steer its own path.</summary>
    public bool HadPathSeparator { get; private init; }

    /// <summary>The raw name contained an NTFS alternate data stream suffix such as <c>::$DATA</c>.</summary>
    public bool HadAlternateDataStream { get; private init; }

    /// <summary>The raw name ended in dots or spaces that Windows would silently strip.</summary>
    public bool HadTrailingDotsOrSpaces { get; private init; }

    /// <summary>The raw name contained control characters, including embedded NUL.</summary>
    public bool HadControlCharacter { get; private init; }

    public bool ExceedsSafeLength => BaseName.Length > MaximumSafeLength;

    /// <summary>The stem is a reserved Windows device name such as <c>CON</c> or <c>LPT1</c>.</summary>
    public bool IsReservedDeviceName => ReservedDeviceNames.Contains(Stem);

    /// <summary>
    /// Whether the name carries any structural anomaly. A well-formed upload never sets this.
    /// </summary>
    public bool HasUnsafeForm =>
        HadPathSeparator ||
        HadAlternateDataStream ||
        HadTrailingDotsOrSpaces ||
        HadControlCharacter ||
        ExceedsSafeLength ||
        IsReservedDeviceName;

    /// <summary>Whether any extension segment matches <paramref name="extensions"/>.</summary>
    public bool HasAnyExtension(IReadOnlySet<string> extensions)
    {
        ArgumentNullException.ThrowIfNull(extensions);

        foreach (var segment in ExtensionSegments)
        {
            if (extensions.Contains(segment))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// The first extension segment matching <paramref name="extensions"/>, or <see langword="null"/>.
    /// </summary>
    public string? FindExtension(IReadOnlySet<string> extensions)
    {
        ArgumentNullException.ThrowIfNull(extensions);

        foreach (var segment in ExtensionSegments)
        {
            if (extensions.Contains(segment))
            {
                return segment;
            }
        }

        return null;
    }

    /// <summary>
    /// Whether <paramref name="extension"/> occupies the final position, which is the form that
    /// executes under a default IIS or PHP-FastCGI handler mapping.
    /// </summary>
    public bool IsFinalExtension(string extension)
    {
        return ExtensionSegments.Count > 0 &&
               string.Equals(ExtensionSegments[^1], extension, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Normalizes a client-supplied file name. Never throws.</summary>
    public static NormalizedFileName Create(string? rawFileName)
    {
        if (string.IsNullOrEmpty(rawFileName))
        {
            return EmptyName;
        }

        var working = rawFileName;

        var hadControlCharacter = ContainsControlCharacter(working);
        if (hadControlCharacter)
        {
            working = RemoveControlCharacters(working);
        }

        var separator = Math.Max(working.LastIndexOf('/'), working.LastIndexOf('\\'));
        var hadPathSeparator = separator >= 0;
        if (hadPathSeparator)
        {
            working = working[(separator + 1)..];
        }

        // Any colon in a file name is an alternate data stream suffix, never a legitimate character.
        var colon = working.IndexOf(':');
        var hadAlternateDataStream = colon >= 0;
        if (hadAlternateDataStream)
        {
            working = working[..colon];
        }

        var trimmed = working.TrimEnd('.', ' ').TrimStart(' ');
        var hadTrailingDotsOrSpaces = trimmed.Length != working.Length;
        working = trimmed;

        var firstDot = working.IndexOf('.');
        var stem = firstDot >= 0 ? working[..firstDot] : working;

        return new NormalizedFileName(rawFileName, working, stem, SplitExtensions(working))
        {
            HadControlCharacter = hadControlCharacter,
            HadPathSeparator = hadPathSeparator,
            HadAlternateDataStream = hadAlternateDataStream,
            HadTrailingDotsOrSpaces = hadTrailingDotsOrSpaces
        };
    }

    private static IReadOnlyList<string> SplitExtensions(string baseName)
    {
        var firstDot = baseName.IndexOf('.');
        if (firstDot < 0 || firstDot == baseName.Length - 1)
        {
            return [];
        }

        var segments = new List<string>();
        foreach (var part in baseName[(firstDot + 1)..].Split('.'))
        {
            if (part.Length > 0)
            {
                segments.Add(part.ToLowerInvariant());
            }
        }

        return segments;
    }

    private static bool ContainsControlCharacter(string value)
    {
        foreach (var character in value)
        {
            if (char.IsControl(character))
            {
                return true;
            }
        }

        return false;
    }

    private static string RemoveControlCharacters(string value)
    {
        var buffer = new char[value.Length];
        var written = 0;

        foreach (var character in value)
        {
            if (!char.IsControl(character))
            {
                buffer[written++] = character;
            }
        }

        return new string(buffer, 0, written);
    }
}

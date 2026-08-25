using System.Buffers;
using System.Collections.Frozen;

namespace WPShield.Abstractions;

/// <summary>
/// One normalization view of an uploaded file name: the name as a particular piece of software would
/// write it to disk, already split into the parts the upload rules match against.
/// </summary>
/// <remarks>
/// <para>
/// A view holds no opinion about what is dangerous. It answers one question — <i>if this component
/// wrote the file, what would the name be?</i> — and leaves severity to the rules. WPShield carries
/// two of them for every upload, because two different components decide the final name and they do
/// not agree; <see cref="NormalizedFileName"/> explains why that disagreement is the attack.
/// </para>
/// <para>
/// The type lives in this file rather than its own because it is meaningless apart from
/// <see cref="NormalizedFileName"/>, which is the only thing that can construct one.
/// </para>
/// </remarks>
public sealed class FileNameView
{
    /// <summary>
    /// Evidence token for the view that models what Windows and NTFS write. Also the token a name
    /// carries when both components would write it identically, which is the ordinary case.
    /// </summary>
    public const string NtfsToken = "ntfs";

    /// <summary>Evidence token for the view that models WordPress's <c>sanitize_file_name()</c>.</summary>
    public const string WordPressToken = "wordpress";

    private static readonly FrozenSet<string> ReservedDeviceNames = new[]
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    internal FileNameView(string token, string baseName)
    {
        Token = token;
        BaseName = baseName;

        var firstDot = baseName.IndexOf('.');
        Stem = firstDot >= 0 ? baseName[..firstDot] : baseName;
        ExtensionSegments = SplitExtensions(baseName);
    }

    /// <summary>Which component this view models. Reported in evidence so a finding names its source.</summary>
    public string Token { get; }

    /// <summary>The name this view says reaches disk.</summary>
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

    /// <summary>The stem is a reserved Windows device name such as <c>CON</c> or <c>LPT1</c>.</summary>
    public bool IsReservedDeviceName => ReservedDeviceNames.Contains(Stem);

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

    /// <summary>Whether this view's whole name is <paramref name="reservedName"/>, case-insensitively.</summary>
    public bool IsNamed(string reservedName)
    {
        ArgumentNullException.ThrowIfNull(reservedName);

        return string.Equals(BaseName, reservedName, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The first segment matching <paramref name="extensions"/> together with its position, or
    /// <see langword="null"/>. Position is what separates a 90 from a 50 in the extension rules.
    /// </summary>
    public ExtensionSegmentMatch? MatchExtension(IReadOnlySet<string> extensions)
    {
        var extension = FindExtension(extensions);

        return extension is null
            ? null
            : new ExtensionSegmentMatch(extension, IsFinalExtension(extension), this);
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
}

/// <summary>
/// An extension segment found in one view of a name, together with where it sat and which view saw
/// it.
/// </summary>
/// <param name="Extension">The matched segment, lowercased and without its dot.</param>
/// <param name="IsFinalPosition">Whether it is the last segment, the form a handler mapping executes.</param>
/// <param name="View">The view the match came from, so evidence can name it.</param>
public sealed record ExtensionSegmentMatch(string Extension, bool IsFinalPosition, FileNameView View);

/// <summary>
/// The normalization views of an uploaded file name, together with the structural anomalies that had
/// to be removed to produce them.
/// </summary>
/// <remarks>
/// <para>
/// Rules must never match against a raw client-supplied file name, and matching against a single
/// normalization of it is not enough either. <b>Two different components decide what the file on
/// disk is called, and they disagree</b>, so WPShield carries both answers and lets the rules take
/// the more severe one.
/// </para>
/// <para>
/// <b>The NTFS view (<see cref="Windows"/>).</b> Windows and NTFS silently normalize several forms
/// before a file reaches disk, so a name that looks harmless to a naive extension check can still
/// land as an executable script:
/// </para>
/// <list type="bullet">
///   <item><description><c>shell.php.</c> — trailing dots are stripped, arriving as <c>shell.php</c>.</description></item>
///   <item><description><c>shell.php </c> — trailing spaces are stripped, arriving as <c>shell.php</c>.</description></item>
///   <item><description><c>shell.php::$DATA</c> — the NTFS alternate data stream suffix is removed.</description></item>
///   <item><description><c>..\..\shell.php</c> — only the final path segment is used.</description></item>
///   <item><description><c>shell.p\0hp</c> — control characters are discarded by downstream consumers.</description></item>
/// </list>
/// <para>
/// <b>The WordPress view (<see cref="WordPress"/>).</b> The NTFS view answers "what would Windows
/// write". On the plugin endpoints WPShield exists to defend, the function that frequently decides
/// the final name is WordPress's <c>sanitize_file_name()</c>, and it does something the file system
/// never does: it <b>deletes</b> characters from the middle of a name and closes the gap. A name
/// that is inert under NTFS rules therefore becomes executable under WordPress's:
/// </para>
/// <list type="bullet">
///   <item><description><c>shell.p{h}p</c> — braces are deleted, arriving as <c>shell.php</c>.</description></item>
///   <item><description><c>shell.p%hp</c> — so is the percent sign.</description></item>
///   <item><description><c>web.con{f}ig</c> — one brace turned off a 100-point rule.</description></item>
///   <item><description><c>shell.php-</c> — the trailing hyphen is trimmed, which NTFS keeps.</description></item>
/// </list>
/// <para>
/// Neither view is the truth, and that is the point. The <b>same bytes</b> reach a plugin that writes
/// the name verbatim and a plugin that sanitizes it first, and an attacker only needs one of the two
/// resulting names to be dangerous. Both views are evaluated and the more severe result wins, which
/// is the same shape as the existing <c>filename</c>/<c>filename*</c> two-name handling.
/// </para>
/// <para>
/// It is not enough to rely on WordPress calling <c>sanitize_file_name()</c>. The vulnerable plugin
/// endpoints that cause upload incidents are precisely the ones that write files without it, which
/// is the reason WPShield inspects the request in the first place. The WordPress view does not
/// contradict that: it covers the inverse case, where WordPress <i>is</i> called and <i>creates</i>
/// the dangerous name out of one that was already suspicious.
/// </para>
/// </remarks>
public sealed class NormalizedFileName
{
    /// <summary>Longest file name WPShield considers ordinary. NTFS permits 255 UTF-16 units.</summary>
    public const int MaximumSafeLength = 255;

    // The invisible characters below are written as code points rather than as literals, and are
    // never pasted into this file as themselves. A source file is read by people too, and a
    // right-to-left override sitting in a security check is exactly the trick the check exists to
    // report.
    private const char NoBreakSpace = '\u00a0';
    private const char ZeroWidthSpace = '\u200b';
    private const char ZeroWidthNonJoiner = '\u200c';
    private const char ZeroWidthJoiner = '\u200d';
    private const char RightToLeftMark = '\u200f';
    private const char FirstBidirectionalEmbedding = '\u202a';
    private const char LastBidirectionalOverride = '\u202e';
    private const char FirstBidirectionalIsolate = '\u2066';
    private const char LastBidirectionalIsolate = '\u2069';

    /// <summary>
    /// The characters <c>sanitize_file_name()</c> deletes outright, in WordPress's own order. Note
    /// that these are <b>removed</b>, not replaced: the characters on either side become adjacent,
    /// which is what turns <c>shell.p{h}p</c> into <c>shell.php</c>.
    /// </summary>
    /// <remarks>
    /// WordPress exposes this list through the <c>sanitize_file_name_chars</c> filter, so a site can
    /// widen or narrow it. The set here is the shipped default, including the typographic quotes and
    /// guillemets a copy-and-paste name picks up. <c>NUL</c> is listed for fidelity even though the
    /// control-character strip has already removed it.
    /// </remarks>
    private static readonly SearchValues<char> WordPressDeletedCharacters =
        SearchValues.Create("?[]/\\=<>:;,'\"&$#*()|~`!{}%+’«»”“\0");

    private static readonly NormalizedFileName EmptyName = new(string.Empty, string.Empty, string.Empty);

    private NormalizedFileName(string raw, string windowsBaseName, string wordPressBaseName)
    {
        Raw = raw;
        Windows = new FileNameView(FileNameView.NtfsToken, windowsBaseName);

        // When both components would write the same name there is nothing to disagree about, so the
        // views are one object. This is the ordinary case — every benign upload lands here — and
        // sharing keeps a second segment split off the hot path, since InspectionContext recomputes
        // the normalization for each of the eight rules that asks for it.
        WordPress = string.Equals(windowsBaseName, wordPressBaseName, StringComparison.Ordinal)
            ? Windows
            : new FileNameView(FileNameView.WordPressToken, wordPressBaseName);

        Views = ReferenceEquals(Windows, WordPress) ? [Windows] : [Windows, WordPress];
    }

    /// <summary>The unmodified value supplied by the client.</summary>
    public string Raw { get; }

    /// <summary>
    /// The name after directory, alternate-data-stream, control-character and trailing dot or space
    /// removal. This approximates what Windows would actually place on disk.
    /// </summary>
    public FileNameView Windows { get; }

    /// <summary>
    /// The name WordPress's <c>sanitize_file_name()</c> would produce. Equal to <see cref="Windows"/>
    /// — the same object — when the two components agree.
    /// </summary>
    public FileNameView WordPress { get; }

    /// <summary>
    /// Every distinct view, NTFS first. A rule that evaluates over this and takes the most severe
    /// result cannot be evaded by choosing which component's normalization to hide behind.
    /// </summary>
    public IReadOnlyList<FileNameView> Views { get; }

    /// <summary>
    /// The two components would write different names. On its own this is not suspicious — ordinary
    /// uploads carry spaces, parentheses and ampersands, and WordPress rewrites every one of them —
    /// so it is evidence, never a score. A rule must ask what the rewrite <i>produced</i>.
    /// </summary>
    public bool DivergesUnderWordPress => !ReferenceEquals(Windows, WordPress);

    /// <summary>The NTFS view's name. Kept as the primary name in evidence and in log lines.</summary>
    public string BaseName => Windows.BaseName;

    /// <summary>The portion of <see cref="BaseName"/> before the first dot.</summary>
    public string Stem => Windows.Stem;

    /// <summary>The NTFS view's extension segments in order, lowercased and without leading dots.</summary>
    public IReadOnlyList<string> ExtensionSegments => Windows.ExtensionSegments;

    /// <summary>The NTFS view's final extension including its dot, or <see langword="null"/>.</summary>
    public string? Extension => Windows.Extension;

    public bool IsEmpty => Windows.IsEmpty;

    /// <summary>The raw name contained a directory separator, so it attempted to steer its own path.</summary>
    public bool HadPathSeparator { get; private init; }

    /// <summary>The raw name contained an NTFS alternate data stream suffix such as <c>::$DATA</c>.</summary>
    public bool HadAlternateDataStream { get; private init; }

    /// <summary>The raw name ended in dots or spaces that Windows would silently strip.</summary>
    public bool HadTrailingDotsOrSpaces { get; private init; }

    /// <summary>The raw name contained control characters, including embedded NUL.</summary>
    public bool HadControlCharacter { get; private init; }

    /// <summary>
    /// The raw name contained an invisible formatting character that can make a rendered name differ
    /// from the uploaded one — a bidirectional override, an isolate, or a zero-width space.
    /// </summary>
    /// <remarks>
    /// The attack is on the reader, not on the file system. A name of the form
    /// <c>shell&lt;U+202E&gt;gpj.php</c> renders in a terminal, a log viewer or a dashboard as
    /// though it ended in <c>.jpg</c>, while the bytes say <c>.php</c> — so an operator reviewing
    /// the Monitor output approves an upload they never saw. Zero-width joiners and non-joiners are
    /// excluded from this flag on purpose; see <see cref="IsDisplaySpoofing(char)"/>.
    /// </remarks>
    public bool HadInvisibleFormatting { get; private init; }

    public bool ExceedsSafeLength => BaseName.Length > MaximumSafeLength;

    /// <summary>The stem is a reserved Windows device name such as <c>CON</c> or <c>LPT1</c>.</summary>
    public bool IsReservedDeviceName => Windows.IsReservedDeviceName;

    /// <summary>
    /// Whether the name carries any structural anomaly. A well-formed upload never sets this.
    /// </summary>
    /// <remarks>
    /// A WordPress rewrite is deliberately absent. Rewrites are routine on legitimate traffic — every
    /// <c>Captura de pantalla (3).png</c> diverges — so treating divergence itself as an anomaly
    /// would put a 60-point finding on ordinary uploads. Whether a particular rewrite matters is a
    /// question about what it produced, which only a rule that knows the dangerous vocabularies can
    /// answer.
    /// </remarks>
    public bool HasUnsafeForm =>
        HadPathSeparator ||
        HadAlternateDataStream ||
        HadTrailingDotsOrSpaces ||
        HadControlCharacter ||
        HadInvisibleFormatting ||
        ExceedsSafeLength ||
        IsReservedDeviceName;

    /// <summary>Whether any extension segment of the NTFS view matches <paramref name="extensions"/>.</summary>
    public bool HasAnyExtension(IReadOnlySet<string> extensions) => Windows.HasAnyExtension(extensions);

    /// <summary>
    /// The first NTFS-view extension segment matching <paramref name="extensions"/>, or
    /// <see langword="null"/>.
    /// </summary>
    public string? FindExtension(IReadOnlySet<string> extensions) => Windows.FindExtension(extensions);

    /// <summary>
    /// Whether <paramref name="extension"/> occupies the final position of the NTFS view, which is
    /// the form that executes under a default IIS or PHP-FastCGI handler mapping.
    /// </summary>
    public bool IsFinalExtension(string extension) => Windows.IsFinalExtension(extension);

    /// <summary>
    /// Searches every view and returns the most severe match: a final-position segment beats an
    /// embedded one, and the NTFS view wins a tie so that evidence stays stable for the names where
    /// the two components agree.
    /// </summary>
    /// <remarks>
    /// This is the single place the "evaluate both views, most severe wins" decision lives, so the
    /// extension rules cannot drift apart on it.
    /// </remarks>
    public ExtensionSegmentMatch? FindMostSevereExtension(IReadOnlySet<string> extensions)
    {
        ArgumentNullException.ThrowIfNull(extensions);

        ExtensionSegmentMatch? best = null;
        foreach (var view in Views)
        {
            var match = view.MatchExtension(extensions);
            if (match is null)
            {
                continue;
            }

            if (best is null || (match.IsFinalPosition && !best.IsFinalPosition))
            {
                best = match;
            }
        }

        return best;
    }

    /// <summary>
    /// The first view whose whole name is <paramref name="reservedName"/>, or <see langword="null"/>.
    /// A reserved name is dangerous whichever component produces it.
    /// </summary>
    public FileNameView? FindViewNamed(string reservedName)
    {
        ArgumentNullException.ThrowIfNull(reservedName);

        foreach (var view in Views)
        {
            if (view.IsNamed(reservedName))
            {
                return view;
            }
        }

        return null;
    }

    /// <summary>Normalizes a client-supplied file name. Never throws.</summary>
    public static NormalizedFileName Create(string? rawFileName)
    {
        if (string.IsNullOrEmpty(rawFileName))
        {
            return EmptyName;
        }

        // Both views start from the same cleaned string. WordPress itself only deletes NUL, so this
        // is WPShield being stricter than the component it models, in two directions that both fail
        // closed: a name WPShield will not put in a log, and a name whose hidden characters cannot
        // be used to break an extension token apart. The cost is stated rather than hidden — a
        // Persian or Indic name using a zero-width non-joiner, or an emoji sequence joined by
        // U+200D, appears in evidence with those characters gone.
        var working = RemoveInvisibleCharacters(
            rawFileName,
            out var hadControlCharacter,
            out var hadInvisibleFormatting);

        var separator = Math.Max(working.LastIndexOf('/'), working.LastIndexOf('\\'));
        var hadPathSeparator = separator >= 0;
        if (hadPathSeparator)
        {
            working = working[(separator + 1)..];
        }

        // The WordPress view starts from the path segment, not from the whole submitted string,
        // because PHP gets there first: rfc1867.c runs _php_rfc1867_basename() over the filename
        // parameter before it ever reaches $_FILES, so sanitize_file_name() never sees a directory
        // component. Deriving it from the full value instead would model nothing real, and it would
        // put the client's whole local path — C:\Users\<name>\... — into a log line, which is the
        // one thing this type exists to prevent.
        //
        // The two NTFS steps that follow — the alternate-data-stream cut and the trailing dot and
        // space trim — stay out of the WordPress view on purpose. WordPress performs neither; its
        // own deletion set and final trim($filename, '.-_') are what handle those names, and they
        // reach a different answer, which is the entire reason for carrying two views.
        var wordPressBaseName = ApplyWordPressSanitizeFileName(working);

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

        return new NormalizedFileName(rawFileName, working, wordPressBaseName)
        {
            HadControlCharacter = hadControlCharacter,
            HadInvisibleFormatting = hadInvisibleFormatting,
            HadPathSeparator = hadPathSeparator,
            HadAlternateDataStream = hadAlternateDataStream,
            HadTrailingDotsOrSpaces = hadTrailingDotsOrSpaces
        };
    }

    /// <summary>
    /// Reproduces WordPress's <c>sanitize_file_name()</c>: delete the special characters, collapse
    /// runs of whitespace and hyphens into a single hyphen, then trim <c>.</c>, <c>-</c> and
    /// <c>_</c> from both ends.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Where this deliberately stops.</b> Three parts of the real function are not modelled, and
    /// each omission is chosen so the view stays conservative — it may report a name WordPress would
    /// have defused, never miss one WordPress would have created:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>
    ///     <b>The intermediate-extension underscore.</b> For a name with three or more dot-separated
    ///     parts, WordPress postfixes each middle part with <c>_</c> unless it appears in
    ///     <c>get_allowed_mime_types()</c>, so real WordPress writes <c>shell.php_.jpg</c>. That list
    ///     depends on the uploading user's capabilities and on the <c>upload_mimes</c> filter, so
    ///     WPShield cannot know it from the request. Not modelling it means the view still reports
    ///     the embedded <c>php</c> — the same thing the NTFS view reports for a plugin that never
    ///     sanitizes — which is the safe direction.
    ///   </description></item>
    ///   <item><description>
    ///     <b>The non-UTF-8 branch.</b> When <c>seems_utf8()</c> fails, WordPress runs the stem
    ///     through <c>sanitize_title_with_dashes()</c> instead. By the time a name reaches this type
    ///     it is already a decoded .NET string, so the byte sequence that decision is made on is
    ///     gone.
    ///   </description></item>
    ///   <item><description>
    ///     <b>The <c>unnamed-file.</c> rescue.</b> A dotless name that happens to equal a known
    ///     extension becomes <c>unnamed-file.&lt;ext&gt;</c>. It only triggers for extensions in the
    ///     allowed-MIME map, which contains no executable one, so it cannot manufacture a dangerous
    ///     name.
    ///   </description></item>
    /// </list>
    /// <para>
    /// Plugins also vary: some call <c>sanitize_file_name()</c>, some call
    /// <c>wp_unique_filename()</c>, which calls it, some write the raw name, and a site can change
    /// the character set through a filter. This view is therefore a second <i>plausible</i> name for
    /// the same bytes, not a claim about what will happen.
    /// </para>
    /// </remarks>
    private static string ApplyWordPressSanitizeFileName(string value)
    {
        var buffer = new char[value.Length];
        var written = 0;
        var pendingSeparator = false;

        foreach (var character in value)
        {
            // WordPress replaces U+00A0 NO-BREAK SPACE with a plain space before anything else, which
            // then collapses like any other whitespace.
            var current = character == NoBreakSpace ? ' ' : character;

            if (WordPressDeletedCharacters.Contains(current))
            {
                // Deleted, and the gap closes behind it. This single branch is the whole of the
                // finding: it is what turns web.con{f}ig into web.config.
                continue;
            }

            if (current is '\r' or '\n' or '\t' or ' ' or '-')
            {
                // preg_replace('/[\r\n\t -]+/', '-') — a run of any length becomes one hyphen.
                pendingSeparator = true;
                continue;
            }

            if (pendingSeparator)
            {
                buffer[written++] = '-';
                pendingSeparator = false;
            }

            buffer[written++] = current;
        }

        if (pendingSeparator)
        {
            buffer[written++] = '-';
        }

        // trim($filename, '.-_'). This is what turns shell.php- into shell.php, a name NTFS keeps
        // exactly as sent and therefore never executes.
        return new string(buffer, 0, written).Trim('.', '-', '_');
    }

    /// <summary>
    /// Removes characters that must not reach a rule or a log: control characters, and the
    /// bidirectional and zero-width formatting characters that let a name render as something other
    /// than what was uploaded.
    /// </summary>
    private static string RemoveInvisibleCharacters(
        string value,
        out bool hadControlCharacter,
        out bool hadInvisibleFormatting)
    {
        hadControlCharacter = false;
        hadInvisibleFormatting = false;
        var mustRemove = false;

        foreach (var character in value)
        {
            if (char.IsControl(character))
            {
                hadControlCharacter = true;
                mustRemove = true;
            }
            else if (IsInvisibleFormatting(character))
            {
                mustRemove = true;
                hadInvisibleFormatting |= IsDisplaySpoofing(character);
            }
        }

        if (!mustRemove)
        {
            return value;
        }

        var buffer = new char[value.Length];
        var written = 0;

        foreach (var character in value)
        {
            if (!char.IsControl(character) && !IsInvisibleFormatting(character))
            {
                buffer[written++] = character;
            }
        }

        return new string(buffer, 0, written);
    }

    /// <summary>
    /// The invisible formatting characters WPShield removes: the zero-width and joining controls
    /// (U+200B to U+200F), the bidirectional embedding and override controls (U+202A to U+202E), and
    /// the bidirectional isolates (U+2066 to U+2069). None of them is
    /// <see cref="char.IsControl(char)"/>, which covers only the C0 and C1 ranges.
    /// </summary>
    private static bool IsInvisibleFormatting(char character)
    {
        return character is (>= ZeroWidthSpace and <= RightToLeftMark)
            or (>= FirstBidirectionalEmbedding and <= LastBidirectionalOverride)
            or (>= FirstBidirectionalIsolate and <= LastBidirectionalIsolate);
    }

    /// <summary>
    /// The subset of <see cref="IsInvisibleFormatting(char)"/> worth reporting as an anomaly: the
    /// characters that can reorder or hide what a reader sees.
    /// </summary>
    /// <remarks>
    /// U+200C ZERO WIDTH NON-JOINER and U+200D ZERO WIDTH JOINER are excluded deliberately. They
    /// cannot reorder anything, and they are ordinary content in Persian, Arabic and Indic file
    /// names and in every multi-person emoji sequence, so flagging them would put a 60-point
    /// <c>FILE-NAME-001</c> on legitimate uploads — and 60 alongside <c>FILE-TYPE-001</c>'s 40 is a
    /// blocked request. They are still removed, so a name that uses one to split an extension token
    /// is matched on the joined form and caught by the extension rule on its own merits.
    /// </remarks>
    private static bool IsDisplaySpoofing(char character)
    {
        return character is not (ZeroWidthNonJoiner or ZeroWidthJoiner) &&
               IsInvisibleFormatting(character);
    }
}

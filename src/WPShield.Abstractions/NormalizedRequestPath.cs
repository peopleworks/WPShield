using System.Collections.Frozen;
using System.Text;

namespace WPShield.Abstractions;

/// <summary>
/// One normalization view of a request path: the sequence of segments a particular consumer would
/// see after applying its own rules.
/// </summary>
/// <remarks>
/// Segments are lowercased because Windows paths are case-insensitive, so
/// <c>/WP-CONTENT/UPLOADS/SHELL.PHP</c> reaches the same file as the lowercase form and a rule that
/// compared case-sensitively would be bypassed by holding the shift key.
/// </remarks>
public sealed class RequestPathView
{
    /// <summary>The path exactly as the server handed it over, decoded once by the host.</summary>
    public const string LiteralToken = "literal";

    /// <summary>The path after one further percent-decode, which some IIS rewrite chains perform.</summary>
    public const string DecodedToken = "decoded";

    internal RequestPathView(string token, IReadOnlyList<string> segments)
    {
        Token = token;
        Segments = segments;
        Value = segments.Count == 0 ? "/" : "/" + string.Join('/', segments);
    }

    public string Token { get; }

    /// <summary>Normalized, lowercased path segments with traversal and empty segments resolved.</summary>
    public IReadOnlyList<string> Segments { get; }

    /// <summary>The rebuilt path, for evidence. Derived from <see cref="Segments"/>, never from input.</summary>
    public string Value { get; }

    /// <summary>
    /// Finds the first segment whose name carries one of the given extensions, in any extension
    /// position.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Every segment, and every extension position within it.</b> Checking only the last segment
    /// misses PHP's path-info execution: with <c>cgi.fix_pathinfo</c> enabled — the default on many
    /// Windows PHP-FastCGI installations — a request for <c>/uploads/shell.php/logo.jpg</c> executes
    /// <c>shell.php</c> and hands it <c>/logo.jpg</c> as <c>PATH_INFO</c>. The last segment is an
    /// image; the executed file is two segments earlier.
    /// </para>
    /// <para>
    /// Checking only the final extension of a segment misses <c>shell.php.jpg</c> on a handler
    /// mapping that matches by wildcard, which is the same reasoning
    /// <see cref="FileNameView.MatchExtension"/> already applies to upload names.
    /// </para>
    /// </remarks>
    public ExecutablePathSegment? FindExecutableSegment(IReadOnlySet<string> extensions)
    {
        ArgumentNullException.ThrowIfNull(extensions);

        for (var index = 0; index < Segments.Count; index++)
        {
            var segment = Segments[index];
            var dot = segment.IndexOf('.');
            while (dot >= 0 && dot < segment.Length - 1)
            {
                var next = segment.IndexOf('.', dot + 1);
                var candidate = next < 0 ? segment[(dot + 1)..] : segment[(dot + 1)..next];

                if (extensions.Contains(candidate))
                {
                    return new ExecutablePathSegment(
                        index,
                        segment,
                        candidate,
                        IsFinalSegment: index == Segments.Count - 1,
                        IsFinalExtension: next < 0,
                        View: this);
                }

                dot = next;
            }
        }

        return null;
    }

    /// <summary>
    /// Returns the index just past a consecutive run of segments, or -1 when the run is absent.
    /// </summary>
    /// <remarks>
    /// Consecutive rather than "contains each somewhere", because <c>wp-content</c> followed by
    /// <c>uploads</c> is a specific WordPress directory while a path that merely mentions both is
    /// not. The search starts at every position, so a site installed in a subdirectory still
    /// matches.
    /// </remarks>
    public int IndexAfterSequence(IReadOnlyList<string> sequence)
    {
        ArgumentNullException.ThrowIfNull(sequence);

        if (sequence.Count == 0 || sequence.Count > Segments.Count)
        {
            return -1;
        }

        for (var start = 0; start + sequence.Count <= Segments.Count; start++)
        {
            var matched = true;
            for (var offset = 0; offset < sequence.Count; offset++)
            {
                if (!string.Equals(Segments[start + offset], sequence[offset], StringComparison.Ordinal))
                {
                    matched = false;
                    break;
                }
            }

            if (matched)
            {
                return start + sequence.Count;
            }
        }

        return -1;
    }

    /// <summary>Returns the index of the first segment named in <paramref name="names"/>, or -1.</summary>
    public int IndexOfSegment(IReadOnlySet<string> names)
    {
        ArgumentNullException.ThrowIfNull(names);

        for (var index = 0; index < Segments.Count; index++)
        {
            if (names.Contains(Segments[index]))
            {
                return index;
            }
        }

        return -1;
    }
}

/// <summary>
/// A path segment that would be executed, and where it sits.
/// </summary>
/// <param name="SegmentIndex">Its position, which a rule compares against a directory's position.</param>
/// <param name="Segment">The normalized segment, safe to log.</param>
/// <param name="Extension">The matched extension, without a leading dot.</param>
/// <param name="IsFinalSegment">
/// <see langword="false"/> means the request reaches this segment through PHP path-info, which is
/// itself evidence: no ordinary client asks for a script with a suffix appended.
/// </param>
/// <param name="IsFinalExtension">
/// <see langword="false"/> means the extension is not last in its segment, as in
/// <c>shell.php.jpg</c>.
/// </param>
/// <param name="View">The normalization view that produced the match.</param>
public sealed record ExecutablePathSegment(
    int SegmentIndex,
    string Segment,
    string Extension,
    bool IsFinalSegment,
    bool IsFinalExtension,
    RequestPathView View);

/// <summary>
/// A request path reduced to what a Windows web server would actually resolve, in every view that
/// could resolve differently.
/// </summary>
/// <remarks>
/// <para>
/// <b>Two views, for the reason the upload rules already have two.</b> The host hands over a path it
/// has percent-decoded once. Some IIS URL Rewrite chains decode again before the rewritten request
/// reaches its handler, so <c>%252e%252e%252fshell.php</c> arrives here as the harmless-looking
/// <c>%2e%2e%2fshell.php</c> and becomes traversal one decode later. Modelling only what arrived is
/// the same mistake that let <c>web.con{f}ig</c> score zero: it models the normalization the
/// inspector performs rather than the one the backend performs. The second view exists only when it
/// differs, and rules take the most severe result.
/// </para>
/// <para>
/// <b>What is deliberately not modelled.</b> No third decode: a chain that decodes three times is
/// misconfigured beyond what any rule should paper over. No 8.3 short-name expansion, which needs the
/// filesystem and cannot be answered from a path alone. Both are recorded here rather than
/// discovered later.
/// </para>
/// </remarks>
public sealed class NormalizedRequestPath
{
    /// <summary>
    /// The most segments examined. Beyond this the path is flagged and truncated rather than walked,
    /// so a request cannot make normalization expensive by being deep.
    /// </summary>
    public const int MaximumSegments = 64;

    /// <summary>The longest segment kept intact. Longer ones are truncated and flagged.</summary>
    public const int MaximumSegmentLength = 255;

    private static readonly FrozenSet<char> SeparatorCharacters =
        new[] { '/', '\\' }.ToFrozenSet();

    private NormalizedRequestPath(string raw, RequestPathView literal, RequestPathView? decoded)
    {
        Raw = raw;
        Literal = literal;
        Decoded = decoded ?? literal;
        Views = ReferenceEquals(Literal, Decoded) ? [Literal] : [Literal, Decoded];
    }

    /// <summary>The path as received. Never use it in a rule or in evidence.</summary>
    public string Raw { get; }

    /// <summary>The path as the host handed it over.</summary>
    public RequestPathView Literal { get; }

    /// <summary>The path after one further percent-decode, or <see cref="Literal"/> when identical.</summary>
    public RequestPathView Decoded { get; }

    /// <summary>Every distinct view, in the order a rule should evaluate them.</summary>
    public IReadOnlyList<RequestPathView> Views { get; }

    /// <summary>Whether the second decode produced a different path.</summary>
    public bool DivergesWhenDecodedAgain => !ReferenceEquals(Literal, Decoded);

    /// <summary>A <c>..</c> segment was present and resolved away.</summary>
    public bool HadTraversal { get; private init; }

    /// <summary>A backslash acted as a separator. IIS accepts it; no legitimate client sends it.</summary>
    public bool HadBackslash { get; private init; }

    /// <summary>An NTFS alternate data stream suffix was stripped from a segment.</summary>
    public bool HadAlternateDataStream { get; private init; }

    /// <summary>Trailing dots or spaces were stripped, which is what Windows itself does on open.</summary>
    public bool HadTrailingDotsOrSpaces { get; private init; }

    /// <summary>A control character was removed from a segment.</summary>
    public bool HadControlCharacter { get; private init; }

    /// <summary>An empty segment from a doubled separator was collapsed.</summary>
    public bool HadEmptySegment { get; private init; }

    /// <summary>The path exceeded <see cref="MaximumSegments"/> or a segment exceeded its length.</summary>
    public bool ExceedsBounds { get; private init; }

    /// <summary>
    /// Whether the path carried any form that a well-behaved client never produces.
    /// </summary>
    /// <remarks>
    /// <see cref="HadEmptySegment"/> is excluded on purpose: a doubled slash is produced constantly
    /// by careless string concatenation in themes and plugins, and treating it as hostile would put a
    /// finding on ordinary traffic. It is still recorded, so evidence keeps it, but it does not by
    /// itself make a path unsafe.
    /// </remarks>
    public bool HasUnsafeForm =>
        HadTraversal ||
        HadBackslash ||
        HadAlternateDataStream ||
        HadTrailingDotsOrSpaces ||
        HadControlCharacter ||
        ExceedsBounds ||
        DivergesWhenDecodedAgain;

    /// <summary>Names every anomaly, for evidence. Ordered so log lines are comparable.</summary>
    public IReadOnlyList<string> Anomalies
    {
        get
        {
            var anomalies = new List<string>(8);
            if (HadTraversal) anomalies.Add("traversal");
            if (HadBackslash) anomalies.Add("backslashSeparator");
            if (HadAlternateDataStream) anomalies.Add("alternateDataStream");
            if (HadTrailingDotsOrSpaces) anomalies.Add("trailingDotsOrSpaces");
            if (HadControlCharacter) anomalies.Add("controlCharacter");
            if (HadEmptySegment) anomalies.Add("emptySegment");
            if (ExceedsBounds) anomalies.Add("excessiveLength");
            if (DivergesWhenDecodedAgain) anomalies.Add("doubleEncoded");
            return anomalies;
        }
    }

    /// <summary>
    /// Evaluates <paramref name="select"/> against every view and returns the first non-null result.
    /// </summary>
    /// <remarks>
    /// The order of <see cref="Views"/> is literal first, so a path that is dangerous as received is
    /// reported as received, and the decoded view only speaks when the literal one found nothing.
    /// </remarks>
    public T? FirstAcrossViews<T>(Func<RequestPathView, T?> select) where T : class
    {
        ArgumentNullException.ThrowIfNull(select);

        foreach (var view in Views)
        {
            if (select(view) is { } result)
            {
                return result;
            }
        }

        return null;
    }

    public static NormalizedRequestPath Create(string? path)
    {
        var raw = path ?? string.Empty;
        var literal = Build(raw, RequestPathView.LiteralToken, out var anomalies);

        // The second view is built only from a path that still contains a percent sign, and is kept
        // only when decoding actually changed something. Anything else would double the work and the
        // evidence for every ordinary request.
        RequestPathView? decoded = null;
        if (raw.Contains('%', StringComparison.Ordinal))
        {
            var decodedRaw = PercentDecodeOnce(raw);
            if (!string.Equals(decodedRaw, raw, StringComparison.Ordinal))
            {
                var candidate = Build(decodedRaw, RequestPathView.DecodedToken, out var decodedAnomalies);
                if (!string.Equals(candidate.Value, literal.Value, StringComparison.Ordinal))
                {
                    decoded = candidate;
                    anomalies |= decodedAnomalies;
                }
            }
        }

        return new NormalizedRequestPath(raw, literal, decoded)
        {
            HadTraversal = anomalies.HasFlag(PathAnomalies.Traversal),
            HadBackslash = anomalies.HasFlag(PathAnomalies.Backslash),
            HadAlternateDataStream = anomalies.HasFlag(PathAnomalies.AlternateDataStream),
            HadTrailingDotsOrSpaces = anomalies.HasFlag(PathAnomalies.TrailingDotsOrSpaces),
            HadControlCharacter = anomalies.HasFlag(PathAnomalies.ControlCharacter),
            HadEmptySegment = anomalies.HasFlag(PathAnomalies.EmptySegment),
            ExceedsBounds = anomalies.HasFlag(PathAnomalies.ExceedsBounds)
        };
    }

    [Flags]
    private enum PathAnomalies
    {
        None = 0,
        Traversal = 1,
        Backslash = 2,
        AlternateDataStream = 4,
        TrailingDotsOrSpaces = 8,
        ControlCharacter = 16,
        EmptySegment = 32,
        ExceedsBounds = 64
    }

    private static RequestPathView Build(string raw, string token, out PathAnomalies anomalies)
    {
        anomalies = PathAnomalies.None;
        var segments = new List<string>(8);
        var start = 0;

        for (var index = 0; index <= raw.Length; index++)
        {
            if (index < raw.Length && !SeparatorCharacters.Contains(raw[index]))
            {
                continue;
            }

            if (index < raw.Length && raw[index] == '\\')
            {
                anomalies |= PathAnomalies.Backslash;
            }

            var segment = raw[start..index];
            start = index + 1;

            if (segment.Length == 0)
            {
                // Leading separator produces one of these and is not an anomaly; an interior doubled
                // separator is recorded but tolerated, because concatenation bugs in themes produce
                // it constantly.
                if (index > 0 && index < raw.Length)
                {
                    anomalies |= PathAnomalies.EmptySegment;
                }

                continue;
            }

            if (segment is ".")
            {
                continue;
            }

            if (segment is "..")
            {
                anomalies |= PathAnomalies.Traversal;
                if (segments.Count > 0)
                {
                    segments.RemoveAt(segments.Count - 1);
                }

                continue;
            }

            if (segments.Count >= MaximumSegments)
            {
                anomalies |= PathAnomalies.ExceedsBounds;
                break;
            }

            segments.Add(NormalizeSegment(segment, ref anomalies));
        }

        return new RequestPathView(token, segments);
    }

    /// <summary>
    /// Reduces one segment to the name Windows would open.
    /// </summary>
    /// <remarks>
    /// The order matters and mirrors <see cref="NormalizedFileName"/>. The alternate data stream
    /// suffix is cut first, because everything after <c>::</c> is stream metadata and must not
    /// contribute an extension; control characters go next, because they can hide the trailing dot
    /// that the following step looks for; the trailing dots and spaces are last, because Windows
    /// strips them at open time and <c>shell.php.</c> therefore reaches <c>shell.php</c>.
    /// </remarks>
    private static string NormalizeSegment(string segment, ref PathAnomalies anomalies)
    {
        var value = segment;

        var stream = value.IndexOf("::", StringComparison.Ordinal);
        if (stream >= 0)
        {
            anomalies |= PathAnomalies.AlternateDataStream;
            value = value[..stream];
        }

        if (ContainsControlCharacter(value))
        {
            anomalies |= PathAnomalies.ControlCharacter;
            var builder = new StringBuilder(value.Length);
            foreach (var character in value)
            {
                if (!char.IsControl(character))
                {
                    builder.Append(character);
                }
            }

            value = builder.ToString();
        }

        var trimmed = value.TrimEnd('.', ' ');
        if (trimmed.Length != value.Length)
        {
            anomalies |= PathAnomalies.TrailingDotsOrSpaces;
            value = trimmed;
        }

        if (value.Length > MaximumSegmentLength)
        {
            anomalies |= PathAnomalies.ExceedsBounds;
            value = value[..MaximumSegmentLength];
        }

        return value.ToLowerInvariant();
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

    /// <summary>
    /// Percent-decodes once, leaving malformed sequences exactly as they are.
    /// </summary>
    /// <remarks>
    /// Deliberately hand-written rather than delegating to a URI decoder. A decoder that repairs or
    /// rejects malformed input would answer a different question than the one being asked here, which
    /// is "what would a second naive decode produce". A trailing <c>%</c> or a <c>%zz</c> stays
    /// literal, which is what such a decode does.
    /// </remarks>
    private static string PercentDecodeOnce(string value)
    {
        var builder = new StringBuilder(value.Length);

        for (var index = 0; index < value.Length; index++)
        {
            if (value[index] == '%' &&
                index + 2 < value.Length &&
                TryParseHex(value[index + 1], out var high) &&
                TryParseHex(value[index + 2], out var low))
            {
                builder.Append((char)((high << 4) | low));
                index += 2;
                continue;
            }

            builder.Append(value[index]);
        }

        return builder.ToString();
    }

    private static bool TryParseHex(char character, out int value)
    {
        value = character switch
        {
            >= '0' and <= '9' => character - '0',
            >= 'a' and <= 'f' => character - 'a' + 10,
            >= 'A' and <= 'F' => character - 'A' + 10,
            _ => -1
        };

        return value >= 0;
    }
}

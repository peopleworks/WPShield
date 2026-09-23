using WPShield.Abstractions;

namespace WPShield.Rules.Windows;

/// <summary>A path segment a request-path rule matched, and the view it matched in.</summary>
/// <param name="Detail">What about the segment matched, for evidence: a name, an extension, a form.</param>
internal sealed record SegmentMatch(RequestPathView View, int Index, string Segment, string Detail);

/// <summary>
/// The segment-level decisions the exposure rules share.
/// </summary>
/// <remarks>
/// Every value handed to a classifier is an already-normalized, lowercased segment from
/// <see cref="RequestPathView.Segments"/> - never the raw target - so traversal, backslashes,
/// alternate data stream suffixes and the trailing dots Windows strips are resolved before any rule
/// sees them. <c>/events../.git/config</c> reaches these rules as <c>/events/.git/config</c>.
/// </remarks>
internal static class PathSegments
{
    /// <summary>The first segment, left to right, the classifier has something to say about.</summary>
    public static SegmentMatch? Any(RequestPathView view, Func<string, string?> classify)
    {
        ArgumentNullException.ThrowIfNull(view);
        ArgumentNullException.ThrowIfNull(classify);

        for (var index = 0; index < view.Segments.Count; index++)
        {
            if (classify(view.Segments[index]) is { } detail)
            {
                return new SegmentMatch(view, index, view.Segments[index], detail);
            }
        }

        return null;
    }

    /// <summary>The final segment, when the classifier has something to say about it.</summary>
    /// <remarks>
    /// For rules about a file that is served as bytes - a backup, a dump, a settings file. PHP's
    /// path-info reading does not apply to those, because no handler executes them, so a request for
    /// <c>/backup.sql/x</c> fetches nothing.
    /// </remarks>
    public static SegmentMatch? Final(RequestPathView view, Func<string, string?> classify)
    {
        ArgumentNullException.ThrowIfNull(view);
        ArgumentNullException.ThrowIfNull(classify);

        if (view.Segments.Count == 0)
        {
            return null;
        }

        var index = view.Segments.Count - 1;
        return classify(view.Segments[index]) is { } detail
            ? new SegmentMatch(view, index, view.Segments[index], detail)
            : null;
    }

    /// <summary>
    /// The name before the last dot and the extension after it, or <see langword="null"/> when the
    /// segment has no extension.
    /// </summary>
    public static (string Stem, string Extension)? SplitFinalExtension(string segment)
    {
        ArgumentNullException.ThrowIfNull(segment);

        var dot = segment.LastIndexOf('.');
        return dot < 0 || dot == segment.Length - 1 ? null : (segment[..dot], segment[(dot + 1)..]);
    }

    /// <summary>
    /// Every extension position in a segment, left to right: <c>db.sql.gz</c> gives <c>sql</c> and
    /// <c>gz</c>. A dotfile's name counts as its first position, so <c>.sql</c> gives <c>sql</c>.
    /// </summary>
    public static IEnumerable<string> ExtensionPositions(string segment)
    {
        ArgumentNullException.ThrowIfNull(segment);
        return segment.Split('.').Skip(1).Where(part => part.Length > 0);
    }

    /// <summary>
    /// A finding whose evidence is the normalized path, the segment, what matched and the view -
    /// never the raw target, which can carry control characters and escape sequences into a log.
    /// </summary>
    public static RuleFinding Finding(string id, int score, string messageKey, SegmentMatch match, string detailKey)
    {
        ArgumentNullException.ThrowIfNull(match);

        var evidence = new Dictionary<string, string>(4, StringComparer.Ordinal)
        {
            ["normalizedPath"] = match.View.Value,
            ["segment"] = match.Segment,
            [detailKey] = match.Detail,
            ["view"] = match.View.Token
        };

        return new RuleFinding(id, score, messageKey, evidence);
    }
}

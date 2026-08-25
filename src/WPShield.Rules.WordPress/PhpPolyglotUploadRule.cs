using System.Globalization;
using WPShield.Abstractions;

namespace WPShield.Rules.WordPress;

/// <summary>
/// <c>PHP-CONTENT-002</c> — a valid image carrying PHP source past the end of its own image data.
/// </summary>
/// <remarks>
/// <para>
/// <c>GIF89a;</c> followed by a PHP script is a valid GIF followed by a PHP script.
/// <c>getimagesize()</c> accepts it. Every signature check accepts it.
/// <see cref="FileTypeMismatchRule"/> accepts it, because the signature genuinely matches the
/// extension. It has been the standard bypass for WordPress upload validation for a decade, and the
/// only thing that separates it from a photograph is <b>where the PHP marker sits relative to the
/// image's own structure</b>.
/// </para>
/// <para>
/// The rule fires only when all three of the following hold. First, the sample opens with a
/// signature from the <c>getimagesize()</c> set — GIF, PNG, JPEG, BMP, or RIFF carrying the
/// <c>WEBP</c> form — which are exactly the formats WordPress's own image validation accepts, which
/// is exactly what the bypass targets. Second, a bounded structural walk establishes where the
/// container's data ends: a GIF block walk to the <c>3B</c> trailer, a PNG chunk walk to the end of
/// <c>IEND</c>, a JPEG segment walk to <c>FF D9</c>, or the file length a BMP or RIFF header
/// declares. Third, a validated PHP marker appears at or beyond that boundary. If the walk cannot
/// establish the boundary, the rule is silent; it never falls upward to a weaker tier.
/// </para>
/// <para>
/// <b>Why the rule is proof-based rather than heuristic.</b> This rule is a strict subset of
/// <c>PHP-CONTENT-001</c>: both look for <c>&lt;?php</c> and <c>&lt;?=</c> in the same bounded
/// sample, so whenever this one fires, <c>PHP-CONTENT-001</c>'s 75 is already on the board. The
/// engine sums findings and caps the total at 100, which means <i>any</i> co-firing score of 5 or
/// more carries the request past the default block threshold of 80. There is no score at which this
/// rule is a moderate signal. It is a block-or-not switch, and its only tuning knob is precision,
/// not points — which is why the firing condition was narrowed until it is a structural proof
/// instead of the score being tuned down.
/// </para>
/// <para>
/// 85 rather than 100 keeps a gradation below <see cref="IisConfigurationUploadRule"/>, which is
/// definitional rather than structural, and it gives an operator who raises the block threshold to
/// 90 a meaningful position: the polyglot alone would then observe, while the polyglot together
/// with <c>PHP-CONTENT-001</c> would still block.
/// </para>
/// <para>
/// The file name is ignored entirely. A polyglot is dangerous under every name — <c>avatar.gif</c>
/// when the attacker plans to reach it through an include, <c>shell.php</c> when the attacker is
/// defeating a check that only calls <c>getimagesize()</c> — and being content-only means the rule
/// composes cleanly with the name rules instead of double-counting with them. The normalized name
/// is still recorded in evidence so an operator can find the part.
/// </para>
/// <para>
/// <b>False positives.</b> The case that decides whether this rule is shippable is the photograph
/// with metadata, and three things keep it quiet. <c>&lt;?xpacket</c> and <c>&lt;?xml</c> are not
/// PHP markers — the set is <c>&lt;?php</c> and <c>&lt;?=</c> only, exactly as in
/// <c>PHP-CONTENT-001</c> — so an ordinary XMP packet matches nothing at all. A marker inside a
/// metadata segment is structurally below the boundary the walk establishes, so a JPEG <c>APPn</c>
/// or <c>COM</c> segment, a PNG <c>tEXt</c>, <c>iTXt</c> or <c>zTXt</c> chunk and a GIF comment
/// extension are all walked over and never searched: a developer who screenshots PHP code and
/// uploads it to their own blog with the code in an XMP caption gets <c>PHP-CONTENT-001</c> at 75,
/// an Observe, and nothing from this rule. And <c>&lt;?=</c> is believed only when the following
/// sixteen bytes read as printable text, without which roughly one image in four thousand would
/// become a blocked upload.
/// </para>
/// <para>
/// The remaining exposures are stated rather than hidden. A BMP whose writer emits a wrong
/// <c>bfSize</c> could place ordinary pixel data beyond its own declared length; two header
/// consistency checks catch the common form of that bug, and the marker would still have to appear
/// there. ZIP and PDF are excluded from the container set entirely — installing a plugin or a theme
/// <i>is</i> uploading a ZIP full of PHP, and a PDF about PHP contains the open tag as prose — as
/// are TIFF, ICO, ISO base media and Matroska, none of which offers a cheap proof and none of which
/// is the format the bypass uses.
/// </para>
/// <para>
/// <b>Known limit.</b> The walk sees only the bounded sample. For a real photograph with an appended
/// payload the JPEG <c>EOI</c> sits hundreds of kilobytes past the sample window, so nothing is
/// established and this rule is silent — as is <c>PHP-CONTENT-001</c>, since the payload is outside
/// the sample too. What this rule catches is the <i>minimal-carrier</i> polyglot: the seven-byte
/// <c>GIF89a;</c> stub, the small one-by-one GIF, the four-byte JPEG. Those are the shapes the
/// published bypasses actually use, because an attacker wants the smallest carrier that survives
/// validation. Large-carrier polyglots need a sampling strategy that also reads the tail of the
/// body, which is not something a rule can fix.
/// </para>
/// </remarks>
public sealed class PhpPolyglotUploadRule : IInspectionRule
{
    /// <summary>
    /// Blocks alone at the default block threshold of 80, and saturates at 100 alongside
    /// <c>PHP-CONTENT-001</c>. Justified because the finding is a proof rather than a heuristic: the
    /// file carries a valid image signature, and PHP source appears at an offset the image's own
    /// structure says is past its end. No encoder appends <c>&lt;?php</c> after a GIF trailer or a
    /// PNG <c>IEND</c>. Trailing data after a JPEG <c>EOI</c> is common — Samsung and Google motion
    /// photos append an entire MP4 — but trailing data <i>containing a PHP open tag</i> is not.
    /// </summary>
    internal const int Score = 85;

    public string Id => "PHP-CONTENT-002";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var sample = context.Sample.Span;

        if (!FileSignatures.TryGetImageContainer(sample, out var family, out var container))
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        if (!FileSignatures.TryGetDeclaredDataEnd(sample, family, out var declaredEnd, out var region))
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        // Searching from the boundary rather than from offset 0 is what makes the metadata case
        // silent and the decoy case unexploitable in one step: markers inside EXIF, XMP, tEXt or a
        // GIF comment are below the boundary and never examined, and an attacker cannot suppress the
        // rule by planting a first marker there.
        if (declaredEnd >= sample.Length ||
            !FileSignatures.TryFindPhpMarker(sample, declaredEnd, out var marker, out var offset))
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        var normalized = context.NormalizedFile;

        // No surrounding bytes are recorded. markerOffset is safe because it is a number WPShield
        // computed, not text the client supplied.
        RuleFinding finding = new(
            Id,
            Score,
            "Findings.PhpPolyglotUpload",
            new Dictionary<string, string>(5)
            {
                ["normalizedName"] = normalized.BaseName,
                ["container"] = container,
                ["region"] = region,
                ["marker"] = marker,
                ["markerOffset"] = offset.ToString(CultureInfo.InvariantCulture)
            });

        return ValueTask.FromResult<RuleFinding?>(finding);
    }
}

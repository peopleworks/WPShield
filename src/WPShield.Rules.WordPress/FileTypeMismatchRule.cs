using System.Globalization;
using WPShield.Abstractions;

namespace WPShield.Rules.WordPress;

/// <summary>
/// <c>FILE-TYPE-001</c> — the final extension claims one format and the leading bytes carry another.
/// </summary>
/// <remarks>
/// <para>
/// Every other upload rule WPShield ships reasons about the <i>name</i>. This one reasons about the
/// <i>bytes</i>, because <c>photo.jpg</c> is a perfect name and the name rules have nothing to say
/// about it. WordPress decides what an upload is from its extension, and
/// <c>wp_check_filetype_and_ext()</c> consults the real bytes for only a handful of types; a plugin
/// endpoint that writes the file itself consults nothing. So a file named <c>photo.jpg</c> whose body
/// is a PHP script lands in <c>wp-content/uploads</c> looking like an image and stays there until a
/// local file include, a second bug, or an IIS handler misconfiguration reaches it.
/// </para>
/// <para>
/// The one direction that fires is <b>final extension versus leading bytes</b>. The final segment is
/// the claim the file makes about itself: it is what the IIS static handler maps to a MIME type and
/// what WordPress stores in the attachment record. An executable segment in a non-final position is a
/// different question, already answered by <see cref="ExecutableUploadExtensionRule"/> and
/// <see cref="DisguisedExtensionRule"/>.
/// </para>
/// <para>
/// <b>The declared <c>Content-Type</c> never triggers a finding.</b> Browsers derive the part's
/// <c>Content-Type</c> from the same extension by way of the operating system registry, so on
/// legitimate traffic it carries no information the extension did not already carry — and every
/// non-browser client is entitled to send <c>application/octet-stream</c>, which <c>curl</c>,
/// <c>wp-cli</c>, mobile applications and the plupload fallback path all do. Triggering on a
/// disagreement between the declared type and the bytes would turn each of those into a finding,
/// which is the fastest route to an operator switching the rule off. It is recorded as a four-state
/// token and nothing more.
/// </para>
/// <para>
/// Neither tier blocks alone, and that is deliberate: the rule reports a <i>disagreement</i>, and a
/// disagreement always has a benign explanation somewhere in the long tail of upload clients. The
/// 70 tiers reach the default block threshold in combination with <c>PHP-CONTENT-001</c> at 75,
/// which is the correct outcome for a file named <c>photo.jpg</c> whose leading bytes are PHP text.
/// </para>
/// <para>
/// <b>False positives.</b> The rule is silent by construction on the cases that generate them, and
/// each silence costs something that is stated here rather than discovered in production:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <b>Chunked uploads.</b> WPShield caps a request at 6 MiB, so any large media upload must
///     arrive as plupload chunks, and every chunk after the first is a file part named
///     <c>photo.jpg</c> with no signature where one is mandatory. This is why unrecognized bytes are
///     never a finding — the load-bearing decision in the whole rule. It costs us a webshell written
///     in UTF-16 without a byte order mark, and one whose marker sits past the sample window; both
///     are unrecognizable blobs, inert on IIS until a second bug exists.
///   </description></item>
///   <item><description>
///     <b>Cross-format renames.</b> HEIC saved as <c>.jpg</c>, WebP as <c>.png</c>, JPEG as
///     <c>.webp</c>. Chrome's "save image as", iOS shares and Android galleries produce these
///     constantly and the file is still a benign image, so a recognized-but-different family is
///     silent. Matching by family also means <c>.docx</c>, <c>.xlsx</c>, <c>.pptx</c> and
///     <c>.odt</c> never disagree with each other, since all four are one ZIP family.
///   </description></item>
///   <item><description>
///     <b>Self-extracting archives.</b> A <c>.zip</c>, <c>.7z</c> or <c>.rar</c> legitimately begins
///     with <c>MZ</c>, so the nativeExecutable tier applies only to image, audio, video, font and
///     PDF extensions. The cost is that an executable renamed <c>invoice.doc</c> passes silently.
///   </description></item>
///   <item><description>
///     <b>A chunk that happens to open <c>4D 5A</c>.</b> <c>MZ</c> is two bytes, so one uniformly
///     random file in 65,536 starts with it, and chunk 2..N of a chunked upload starts at arbitrary
///     mid-file bytes. The executable header must therefore corroborate itself through
///     <c>e_lfanew</c> before this tier fires. The cost is a museum piece — a pure DOS-era <c>MZ</c>
///     binary with no PE, NE, LE or LX header behind it is not recognized.
///   </description></item>
///   <item><description>
///     <b>Reporting-plugin exports.</b> Writing an HTML table or a CSV under an <c>.xls</c> name is
///     endemic in reporting and analytics plugins. It is a bug in the exporter, not an attack, so
///     legacy Office extensions are exempt from the text tier — though not from the script tier.
///   </description></item>
///   <item><description>
///     <b>Signature-less and unknown formats.</b> SVG, TXT, CSV, JSON and XML have no magic number,
///     so there is no expectation to violate; an extension WPShield has never seen makes no claim at
///     all. Both are silent.
///   </description></item>
///   <item><description>
///     <b>An MP3 whose first frame header is <c>FF FE</c>.</b> That byte pair is both a valid MPEG
///     frame sync and a UTF-16LE byte order mark, and the UTF-16 branch is evaluated first so that a
///     BOM-prefixed UTF-16 webshell cannot hide behind the weakest signature in the table. Such a
///     file produces a finding only if its bytes also decode to a script marker in UTF-16, which
///     audio data does not.
///   </description></item>
///   <item><description>
///     <b>The one combination that blocks on benign traffic.</b> The text tier at 40 plus
///     <c>FILE-NAME-001</c> at 60 is exactly 100. <c>FILE-NAME-001</c> fires on legacy clients that
///     submit a full local path, so a text-bodied file with a binary extension from such a client
///     would be blocked in Block mode. It is a narrow intersection of two unusual client behaviours,
///     and it is the reason the text tier scores 40 rather than 70. Operators should stay in Monitor
///     mode until they have reviewed their own upload traffic.
///   </description></item>
///   <item><description>
///     <b><c>&lt;%</c> in prose.</b> Two bytes is a weak marker, so a hit is believed only when the
///     following sixteen bytes read as printable text. Ordinary prose such as <c>5 &lt;%10</c> in a
///     document with a mismatched extension therefore reports the script tier at 70 rather than the
///     text tier at 40. Both are Observe; neither blocks alone.
///   </description></item>
/// </list>
/// </remarks>
public sealed class FileTypeMismatchRule : IInspectionRule
{
    /// <summary>
    /// Text carrying a script marker where a binary format was claimed. Observe on its own;
    /// saturates the cap at 100 with <c>PHP-CONTENT-001</c>, which is the webshell-with-an-image-name
    /// case.
    /// </summary>
    internal const int ScriptContentScore = 70;

    /// <summary>
    /// <c>MZ</c> or ELF where a document was claimed. Scored equal to the script tier: a program is
    /// no less out of place in an uploads directory than a script is.
    /// </summary>
    internal const int NativeExecutableContentScore = 70;

    /// <summary>
    /// Human-readable text where a binary format was claimed. The weaker claim — the file is not
    /// what it says it is, and nothing more — deliberately scored so it cannot block with one
    /// mid-range name finding alone.
    /// </summary>
    internal const int TextContentScore = 40;

    private const string ObservedScript = "script";
    private const string ObservedNativeExecutable = "nativeExecutable";
    private const string ObservedText = "text";

    public string Id => "FILE-TYPE-001";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        // NormalizedFile recomputes on every access by design, so it is hoisted once here.
        var normalized = context.NormalizedFile;
        var segments = normalized.ExtensionSegments;
        if (segments.Count == 0)
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        var finalSegment = segments[^1];
        if (FileSignatures.IsSignatureLess(finalSegment) ||
            !FileSignatures.TryGetExpectedFamily(finalSegment, out var expected))
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        var sample = context.Sample.Span;
        if (sample.Length < FileSignatures.MinimumBytesToDecide)
        {
            // A truncated part, an empty file input, or a body too short to say anything about. The
            // absence of evidence is not evidence.
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        if (FileSignatures.MatchesExpectedFamily(sample, expected))
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        // The UTF-16 branch runs before signature identification because its own opening bytes are
        // signature-ambiguous: FF FE is simultaneously a UTF-16LE byte order mark and a valid MPEG
        // frame sync, and deferring would let a webshell hide behind the weakest entry in the table.
        if (FileSignatures.TryFindWideScriptMarker(sample, out var wideMarker, out _))
        {
            return Report(context, normalized, expected, ObservedScript, ScriptContentScore, wideMarker);
        }

        if (FileSignatures.TryIdentify(sample, out var observed))
        {
            if (observed != FileFormatFamily.NativeExecutable ||
                !FileSignatures.AllowsNativeExecutableTier(expected))
            {
                // Either a cross-format rename, which is endemic and benign, or a container whose
                // MZ header is a legitimate self-extracting stub.
                return ValueTask.FromResult<RuleFinding?>(null);
            }

            var executableMarker = sample[0] == 0x4D
                ? FileSignatures.DosExecutableToken
                : FileSignatures.ElfExecutableToken;

            return Report(
                context,
                normalized,
                expected,
                ObservedNativeExecutable,
                NativeExecutableContentScore,
                executableMarker);
        }

        var classification = FileSignatures.Classify(sample);
        if (classification == ContentClassification.Binary)
        {
            // Unrecognized binary: chunk 2..N of a chunked upload, or a format the table does not
            // know. Silent by construction, and the reason this rule survives contact with a real
            // media library.
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        if (FileSignatures.TryFindScriptMarker(sample, out var marker, out _))
        {
            return Report(context, normalized, expected, ObservedScript, ScriptContentScore, marker);
        }

        if (classification != ContentClassification.Text)
        {
            // Too short to classify and carrying no marker. Nothing to report.
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        if (expected == FileFormatFamily.CompoundFile)
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        return Report(context, normalized, expected, ObservedText, TextContentScore, marker: null);
    }

    private ValueTask<RuleFinding?> Report(
        InspectionContext context,
        NormalizedFileName normalized,
        FileFormatFamily expected,
        string observedContent,
        int score,
        string? marker)
    {
        // Evidence carries the normalized name, our own family and tier tokens, a marker drawn from
        // a closed set, and integers WPShield computed. Never the raw name, never the header value,
        // and never a byte from the sample — a sample byte rendered into a log is attacker-controlled
        // output.
        var evidence = new Dictionary<string, string>(6)
        {
            ["normalizedName"] = normalized.BaseName,
            ["presentedExtension"] = normalized.Extension ?? string.Empty,
            ["expectedFormat"] = FileSignatures.FamilyToken(expected),
            ["observedContent"] = observedContent,
            ["declaredType"] = FileSignatures.DescribeDeclaredType(context.DeclaredContentType, expected),
            ["sampleLength"] = context.Sample.Length.ToString(CultureInfo.InvariantCulture)
        };

        if (marker is not null)
        {
            evidence["marker"] = marker;
        }

        // One MessageKey with the tier reported in evidence, following WP-UPLOAD-001, which uses one
        // key and reports `position`. A localizer can branch on observedContent when the message
        // catalogue lands.
        RuleFinding finding = new(Id, score, "Findings.UploadContentSignatureMismatch", evidence);
        return ValueTask.FromResult<RuleFinding?>(finding);
    }
}

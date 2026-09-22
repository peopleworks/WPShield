using System.Text;
using WPShield.Abstractions;
using WPShield.Rules.Windows;
using static WPShield.Rules.Tests.Shared.ContentFixtures;

namespace WPShield.Rules.WordPress.Tests;

/// <summary>
/// The shipped rule set measured together: which combinations of content and name findings land on
/// which side of the block threshold, and whether an ordinary traffic corpus stays silent across all
/// of them.
/// </summary>
/// <remarks>
/// <para>
/// This file tests across BOTH rule packages on purpose, and lives here because this is the layer
/// that can see them both: <c>WPShield.Rules.WordPress</c> references <c>WPShield.Rules.Windows</c>,
/// never the reverse. The byte-level behaviour of <c>FILE-TYPE-001</c> and <c>PHP-CONTENT-002</c> on
/// their own is covered in <c>WPShield.Rules.Windows.Tests</c>, with the same fixtures, shared by
/// link from <c>tests/Shared/ContentFixtures.cs</c>.
/// </para>
/// <para>
/// <b>On the aggregate assertions.</b> This project deliberately does not reference
/// <c>WPShield.Core</c>: the rule layer has to build and be testable without the engine, and a Linux
/// CI leg proves it. So <see cref="AggregateScore"/> mirrors the arithmetic of
/// <c>InspectionEngine.InspectAsync</c> - sum the findings, clamp negatives to zero, cap at 100 -
/// rather than calling it. The engine's own behaviour is covered in
/// <c>tests/WPShield.Core.Tests/UploadScoringTests.cs</c>.
/// </para>
/// </remarks>
public sealed class ContentRuleTests
{
    /// <summary>
    /// The rule set as the gateway will register it in M2: the six rules that shipped in M1 plus the
    /// two content rules. Order is irrelevant to the result — the engine sums — but it matches the
    /// registration order so a reader can line the two up.
    /// </summary>
    private static readonly IInspectionRule[] ShippedRules =
    [
        new ExecutableUploadExtensionRule(),
        new DisguisedExtensionRule(),
        new IisExecutableUploadRule(),
        new IisConfigurationUploadRule(),
        new UnsafeFileNameRule(),
        new PhpContentInUploadRule(),
        new FileTypeMismatchRule(),
        new PhpPolyglotUploadRule()
    ];

    // =============================================================================================
    // Calibration — the numbers the README and docs/en/m2-upload-rules.md publish
    // =============================================================================================

    /// <summary>
    /// Pins the four published scores. They are load-bearing rather than decorative: 70 + 75 is the
    /// exact arithmetic that makes a PHP-bodied <c>photo.jpg</c> block, 40 is chosen so the weak text
    /// tier cannot block with one mid-range name finding, and 85 is what lets a proven polyglot block
    /// on its own. Changing any of them changes what a live site refuses, so it should fail a test.
    /// </summary>
    [Fact]
    public void PublishedScores_MatchTheDocumentedCalibration()
    {
        Assert.Equal(70, FileTypeMismatchRule.ScriptContentScore);
        Assert.Equal(70, FileTypeMismatchRule.NativeExecutableContentScore);
        Assert.Equal(40, FileTypeMismatchRule.TextContentScore);
        Assert.Equal(85, PhpPolyglotUploadRule.Score);

        // The polyglot rule is a strict subset of PHP-CONTENT-001, so -001's 75 is always already on
        // the board when it fires. Any co-firing score of five or more therefore blocks; there is no
        // score at which -002 is a moderate signal, which is why it was narrowed to a structural
        // proof instead of being tuned down.
        Assert.True(PhpPolyglotUploadRule.Score + 75 >= BlockThreshold);
        Assert.True(FileTypeMismatchRule.TextContentScore + UnsafeFileNameRule.Score >= BlockThreshold);
    }

    // =============================================================================================
    // FILE-TYPE-001 — the mismatches that must fire
    // =============================================================================================

    /// <summary>
    /// A byte order mark plus UTF-16 source. This is the one evasion the content rules close that
    /// <c>PHP-CONTENT-001</c> misses entirely, so the test asserts both halves: the mismatch rule
    /// fires, and the UTF-8 marker search that -001 performs finds nothing at all.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Utf16ScriptWithAByteOrderMark_ReportsTheScriptTier(bool littleEndian)
    {
        var sample = littleEndian
            ? Concat([0xFF, 0xFE], Encoding.Unicode.GetBytes(SyntheticMarker))
            : Concat([0xFE, 0xFF], Encoding.BigEndianUnicode.GetBytes(SyntheticMarker));
        var context = Upload("photo.jpg", sample, "image/jpeg");

        var finding = await TypeAsync(context);

        Assert.NotNull(finding);
        Assert.Equal(FileTypeMismatchRule.ScriptContentScore, finding.Score);
        Assert.Equal("script", finding.Evidence?["observedContent"]);
        Assert.Equal(FileSignatures.PhpOpenTagToken, finding.Evidence?["marker"]);

        Assert.Null(await new PhpContentInUploadRule().EvaluateAsync(context));
        Assert.Equal(FileTypeMismatchRule.ScriptContentScore, await AggregateScoreAsync(context));
    }

    // =============================================================================================
    // FILE-TYPE-001 — the silences, each of which is a decision rather than an oversight
    // =============================================================================================

    /// <summary>
    /// A ZIP under an image name reads like a case that ought to fire, and it deliberately does not.
    /// The trigger would have to be "a recognized family that is not the claimed one", which is the
    /// same trigger that turns HEIC-saved-as-JPEG, WebP-saved-as-PNG and every <c>.docx</c> against
    /// <c>.odt</c> comparison into a finding — the endemic renames the rule exists to stay quiet
    /// about. A ZIP is also inert under a <c>.png</c> name on IIS, since no handler maps it, so the
    /// noise buys nothing. Pinned here so that revisiting it is a whole-tier decision about
    /// cross-format renames rather than a special case bolted on for one container.
    /// </summary>
    [Fact]
    public async Task ZipBytesUnderAPngName_AreSilentByDesign()
    {
        var context = Upload("banner.png", ZipArchive("payload.txt"), "image/png");

        Assert.Null(await TypeAsync(context));
        Assert.Null(await PolyglotAsync(context));
        Assert.Equal(0, await AggregateScoreAsync(context));
    }

    /// <summary>
    /// Chunk 2..N of a chunked upload. WPShield caps a request at 6 MiB, so every large media upload
    /// must arrive as plupload chunks, and each chunk after the first is a part named
    /// <c>photo.jpg</c> whose leading bytes are arbitrary mid-file data with no signature at offset 0.
    /// Unrecognized binary being silent is the load-bearing decision in this rule; without it the
    /// rule would fire on every large photograph a site accepts.
    /// </summary>
    [Fact]
    public async Task MiddleChunkOfAChunkedUpload_IsSilent()
    {
        var context = Upload("photo.jpg", EntropyBytes(512), "application/octet-stream");

        Assert.Null(await TypeAsync(context));
        Assert.Null(await PolyglotAsync(context));
        Assert.Equal(0, await AggregateScoreAsync(context));
    }

    // =============================================================================================
    // PHP-CONTENT-002 — the polyglots that must fire
    // =============================================================================================

    /// <summary>
    /// The classic WordPress upload bypass: a seven-byte GIF that <c>getimagesize()</c> accepts,
    /// followed by a PHP script. Note the second assertion — <c>FILE-TYPE-001</c> stays silent,
    /// because the signature genuinely does match the extension. There is no triple counting here;
    /// the block comes from this rule plus <c>PHP-CONTENT-001</c>.
    /// </summary>
    [Fact]
    public async Task GifStubPolyglot_ReportsTheAppendedRegion()
    {
        var context = Upload("avatar.gif", Concat(GifStub(), Ascii(SyntheticMarker)), "image/gif");

        var finding = await PolyglotAsync(context);

        Assert.NotNull(finding);
        Assert.Equal("PHP-CONTENT-002", finding.RuleId);
        Assert.Equal(PhpPolyglotUploadRule.Score, finding.Score);
        Assert.Equal("Findings.PhpPolyglotUpload", finding.MessageKey);
        Assert.Equal(FileSignatures.ContainerGif, finding.Evidence?["container"]);
        Assert.Equal(FileSignatures.RegionAfterTrailer, finding.Evidence?["region"]);
        Assert.Equal(FileSignatures.PhpOpenTagToken, finding.Evidence?["marker"]);
        Assert.Equal("7", finding.Evidence?["markerOffset"]);
        Assert.Equal("avatar.gif", finding.Evidence?["normalizedName"]);

        Assert.Null(await TypeAsync(context));
        Assert.Equal(100, await AggregateScoreAsync(context));
    }

    [Fact]
    public async Task ShortMarkerFollowedByBinary_DoesNotFire()
    {
        var sample = Concat(Gif(GifImageBlock()), Ascii("<?="), new byte[FileSignatures.ShortMarkerGuardBytes]);
        var context = Upload("avatar.gif", sample, "image/gif");

        Assert.Null(await PolyglotAsync(context));

        // PHP-CONTENT-001 does fire, at 75, which is an Observe and not a refusal. That asymmetry is
        // the design: the unguarded search is affordable for a rule that only observes.
        var loose = await new PhpContentInUploadRule().EvaluateAsync(context);
        Assert.NotNull(loose);
        Assert.Equal(75, loose.Score);
        Assert.Equal(75, await AggregateScoreAsync(context));
    }

    // =============================================================================================
    // PHP-CONTENT-002 — the silences, led by the false positive that decides whether it is shippable
    // =============================================================================================

    /// <summary>
    /// The highest-risk false positive in either rule. An XMP packet genuinely begins
    /// <c>&lt;?xpacket</c>, every camera and every image editor writes one, and a marker set that
    /// matched <c>&lt;?x</c> would refuse a large share of the photographs uploaded to a WordPress
    /// site. The marker set is <c>&lt;?php</c> and <c>&lt;?=</c> only, so an ordinary XMP packet
    /// matches nothing at all and the whole request scores zero.
    /// </summary>
    [Fact]
    public async Task JpegCarryingAnXmpPacket_IsCompletelySilent()
    {
        var context = Upload("photo.jpg", JpegWithXmp(XmpPacket), "image/jpeg");

        AssertSampleContains(context, "<?xpacket");
        Assert.Null(await PolyglotAsync(context));
        Assert.Null(await TypeAsync(context));
        Assert.Null(await new PhpContentInUploadRule().EvaluateAsync(context));
        Assert.Equal(0, await AggregateScoreAsync(context));
    }

    /// <summary>
    /// An EXIF comment carrying arbitrary text, including the angle brackets, slashes and quotes that
    /// a camera or a caption plugin writes. A <c>COM</c> or <c>APPn</c> segment is allowed to contain
    /// anything, and the walk steps over it rather than reading it.
    /// </summary>
    [Fact]
    public async Task JpegCarryingAnExifComment_IsCompletelySilent()
    {
        var comment = "Aperture f/2.8 - 1/125s <ISO 100> \"sunset over the bay\" (c) 2026";
        var context = Upload("photo.jpg", JpegWithComment(comment), "image/jpeg");

        AssertSampleContains(context, comment);
        Assert.Null(await PolyglotAsync(context));
        Assert.Null(await TypeAsync(context));
        Assert.Equal(0, await AggregateScoreAsync(context));
    }

    /// <summary>
    /// A metadata field containing the literal marker — a developer who screenshots PHP code and
    /// uploads it to their own blog with the code in an XMP caption, a <c>tEXt</c> chunk or a GIF
    /// comment. The correct treatment is <c>PHP-CONTENT-001</c> at 75, an Observe, and nothing from
    /// the polyglot rule: a metadata field is allowed to contain arbitrary text, and the marker sits
    /// structurally below the boundary the walk establishes.
    /// </summary>
    [Theory]
    [InlineData("photo.jpg", "image/jpeg")]
    [InlineData("banner.png", "image/png")]
    [InlineData("animation.gif", "image/gif")]
    public async Task MarkerInsideImageMetadata_ObservesButNeverProves(string fileName, string contentType)
    {
        var sample = fileName switch
        {
            "photo.jpg" => JpegWithXmp(XmpPacket.Replace("photoshop:Credit=\"studio\"", $"photoshop:Credit=\"{SyntheticMarker}\"", StringComparison.Ordinal)),
            "banner.png" => Png(PngIhdr(), PngChunk("tEXt", Ascii($"Comment\0{SyntheticMarker}")), PngIdat(), PngIend()),
            _ => Gif(GifCommentBlock(Ascii(SyntheticMarker)), GifImageBlock())
        };
        var context = Upload(fileName, sample, contentType);

        AssertSampleContains(context, SyntheticMarker);
        Assert.Null(await PolyglotAsync(context));
        Assert.Null(await TypeAsync(context));
        var score = await AggregateScoreAsync(context);
        Assert.Equal(75, score);
        Assert.True(score < BlockThreshold);
    }

    /// <summary>
    /// A container the polyglot rule deliberately does not cover. Installing a plugin or a theme
    /// <i>is</i> uploading a ZIP full of PHP, and a PDF about PHP contains the open tag as prose, so
    /// both are excluded from the container set — the observation is left to <c>PHP-CONTENT-001</c>,
    /// which records it at 75 without refusing it.
    /// </summary>
    [Theory]
    [InlineData("wordpress-plugin.zip")]
    [InlineData("php-tutorial.pdf")]
    public async Task ExcludedContainersCarryingTheMarker_ObserveOnly(string fileName)
    {
        var sample = fileName.EndsWith(".zip", StringComparison.Ordinal)
            ? Concat(ZipArchive("plugin.php"), Ascii(SyntheticMarker))
            : Concat(PdfDocument(), Ascii($"BT (A tutorial: {SyntheticMarker}) Tj ET\n"));
        var context = Upload(fileName, sample, "application/octet-stream");

        Assert.Null(await PolyglotAsync(context));
        Assert.Null(await TypeAsync(context));
        Assert.Equal(75, await AggregateScoreAsync(context));
    }

    /// <summary>
    /// A real photograph with an appended payload is not caught, and the reason is structural rather
    /// than accidental: the JPEG walk goes inconclusive at <c>SOS</c>, because entropy-coded scan data
    /// carries no length and can legally contain any byte sequence at all. Failing closed there is
    /// also what keeps a marker inside an APP1 segment from ever being read as proof. Catching this
    /// needs a sampling strategy that reads the tail of the body as well as its head, which is not a
    /// question a rule can answer.
    /// </summary>
    [Fact]
    public async Task LargeCarrierPolyglot_IsNotProven_KnownLimit()
    {
        var context = Upload(
            "photo.jpg",
            Concat(JpegPhotograph(), Ascii(SyntheticMarker)),
            "image/jpeg");

        Assert.Null(await PolyglotAsync(context));
        Assert.Null(await TypeAsync(context));

        // PHP-CONTENT-001 still sees the marker because it is inside this sample; on a real
        // photograph it would be hundreds of kilobytes past the sample window and nothing would fire.
        Assert.Equal(75, await AggregateScoreAsync(context));
    }

    // =============================================================================================
    // Ordinary traffic — the corpus that must produce nothing at all
    // =============================================================================================

    /// <summary>
    /// Realistic WordPress, Elementor and Google Site Kit upload shapes. Every one asserts a total of
    /// zero across all eight shipped rules, not merely "does not block": a rule set that quietly
    /// observes on ordinary traffic produces a log an operator learns to ignore, which is the same
    /// failure as a false block arriving more slowly.
    /// </summary>
    public static TheoryData<string> SilentTraffic =>
    [
        "photo.jpg",
        "photo.jpeg",
        "banner.png",
        "animation.gif",
        "logo.webp",
        "diagram.bmp",
        "icon.svg",
        "analytics-report.pdf",
        "document.docx",
        "spreadsheet.xlsx",
        "presentation.pptx",
        "report.odt",
        "video.mp4",
        "video.webm",
        "audio.mp3",
        "podcast-raw.mp3",
        "font.ttf",
        "elementor-icons.woff",
        "elementor-icons.woff2",
        "elementor-kit-export.zip",
        "elementor-template.json",
        "elementor-background.jpg",
        "site-kit-export.csv",
        "googlesitekit-report.pdf",
        "photo-heic-rename.jpg",
        "screenshot-webp-rename.png",
        "chunked-upload-part-2.jpg",
        "presentación-española.pptx",
        "日本語のファイル.png",
        "My Vacation Photo.jpeg",
        "truncated-part.jpg",
        "empty-file-input.jpg",
        "sales-report.xls",
        "installer.zip"
    ];

    [Theory]
    [MemberData(nameof(SilentTraffic))]
    public async Task OrdinaryTraffic_ProducesNoFindingFromAnyRule(string fixtureName)
    {
        var context = TrafficFixture(fixtureName);

        foreach (var rule in ShippedRules)
        {
            var finding = await rule.EvaluateAsync(context);
            Assert.True(finding is null, $"{rule.Id} produced a false positive for '{fixtureName}'.");
        }

        Assert.Equal(0, await AggregateScoreAsync(context));
    }

    // =============================================================================================
    // Aggregate scoring — which combinations land on which side of 80
    // =============================================================================================

    /// <summary>
    /// The combination the content rules were calibrated for. Neither tier of
    /// <c>FILE-TYPE-001</c> blocks on its own, because a disagreement always has a benign explanation
    /// somewhere; 70 together with <c>PHP-CONTENT-001</c>'s 75 does block, which is the right answer
    /// for a file named <c>photo.jpg</c> whose leading bytes are PHP source.
    /// </summary>
    [Fact]
    public async Task PhpBodiedImage_ReachesTheBlockThreshold()
    {
        var context = Upload("photo.jpg", Ascii(SyntheticMarker), "image/jpeg");
        var findings = await EvaluateAllAsync(context);

        Assert.Equal(
            new[] { "FILE-TYPE-001", "PHP-CONTENT-001" },
            findings.Select(finding => finding.RuleId).OrderBy(id => id, StringComparer.Ordinal));
        Assert.Equal(70, findings.Single(f => f.RuleId == "FILE-TYPE-001").Score);
        Assert.Equal(75, findings.Single(f => f.RuleId == "PHP-CONTENT-001").Score);
        Assert.Equal(100, AggregateScore(findings));
        Assert.True(AggregateScore(findings) >= BlockThreshold);
    }

    /// <summary>
    /// The polyglot, scored end to end. <c>FILE-TYPE-001</c> is absent by design — the signature
    /// genuinely matches the extension — so the block is carried by the structural proof plus the
    /// looser content rule it is a subset of.
    /// </summary>
    [Fact]
    public async Task GifPolyglot_ReachesTheBlockThresholdWithoutTheMismatchRule()
    {
        var context = Upload("avatar.gif", Concat(GifStub(), Ascii(SyntheticMarker)), "image/gif");
        var findings = await EvaluateAllAsync(context);

        Assert.Equal(
            new[] { "PHP-CONTENT-001", "PHP-CONTENT-002" },
            findings.Select(finding => finding.RuleId).OrderBy(id => id, StringComparer.Ordinal));
        Assert.Equal(85, findings.Single(f => f.RuleId == "PHP-CONTENT-002").Score);
        Assert.Equal(100, AggregateScore(findings));
    }

    /// <summary>
    /// The same polyglot under an executable name — an attacker defeating a check that calls only
    /// <c>getimagesize()</c>. Four rules would fire if the name rules stacked with the content rules
    /// without limit; the cap at 100 is what keeps the score interpretable.
    /// </summary>
    [Fact]
    public async Task PolyglotUnderAPhpName_CombinesNameAndContentSignals()
    {
        var context = Upload("polyglot.php", Concat(GifStub(), Ascii(SyntheticMarker)), "image/gif");
        var findings = await EvaluateAllAsync(context);

        Assert.Equal(
            new[] { "PHP-CONTENT-001", "PHP-CONTENT-002", "WP-UPLOAD-001" },
            findings.Select(finding => finding.RuleId).OrderBy(id => id, StringComparer.Ordinal));
        Assert.Equal(90 + 85 + 75, findings.Sum(finding => finding.Score));
        Assert.Equal(100, AggregateScore(findings));
    }

    /// <summary>
    /// A disguised name whose body corroborates the disguise. Four rules, each contributing a signal
    /// none of the others could produce alone: the embedded extension, the disguise, the byte
    /// mismatch and the PHP marker.
    /// </summary>
    [Fact]
    public async Task DisguisedNameWithPhpBody_CombinesFourSignals()
    {
        var context = Upload("photo.php.jpg", Ascii(SyntheticMarker), "image/jpeg");
        var findings = await EvaluateAllAsync(context);

        Assert.Equal(
            new[] { "FILE-TYPE-001", "PHP-CONTENT-001", "WP-UPLOAD-001", "WP-UPLOAD-002" },
            findings.Select(finding => finding.RuleId).OrderBy(id => id, StringComparer.Ordinal));
        Assert.Equal(50 + 30 + 70 + 75, findings.Sum(finding => finding.Score));
        Assert.Equal(100, AggregateScore(findings));
    }

    /// <summary>
    /// The one benign combination that reaches 100, documented in the rule's own remarks and pinned
    /// here so it cannot be discovered in production instead. <c>FILE-NAME-001</c> fires on the legacy
    /// clients that submit a full local path, and 60 plus the text tier's 40 is exactly the block
    /// threshold plus twenty. It is a narrow intersection of two unusual client behaviours, and it is
    /// the reason the text tier scores 40 rather than 70 — at 70 it would be reachable from a single
    /// mid-range name finding as well.
    /// </summary>
    [Fact]
    public async Task TextBodiedFileFromALegacyPathSubmittingClient_Blocks_KnownRoughEdge()
    {
        var context = Upload(@"C:\Users\author\Documents\notes.jpg", Ascii(HtmlExport));
        var findings = await EvaluateAllAsync(context);

        Assert.Equal(
            new[] { "FILE-NAME-001", "FILE-TYPE-001" },
            findings.Select(finding => finding.RuleId).OrderBy(id => id, StringComparer.Ordinal));
        Assert.Equal(100, AggregateScore(findings));

        // The same client uploading an actual photograph is unaffected: only the name fires, at 60,
        // which is an Observe. This is what keeps the rough edge narrow.
        var photograph = await EvaluateAllAsync(
            Upload(@"C:\Users\author\Pictures\photo.jpg", JpegPhotograph(), "image/jpeg"));
        Assert.Equal(UnsafeFileNameRule.Score, AggregateScore(photograph));
        Assert.True(AggregateScore(photograph) < BlockThreshold);
    }

    /// <summary>
    /// Bulk upload from a legacy client that submits full local paths: twenty ordinary photographs,
    /// each scoring <c>FILE-NAME-001</c>'s 60, in one multipart request.
    /// </summary>
    /// <remarks>
    /// This is the test behind the gateway's decision to aggregate across file parts by <b>maximum</b>
    /// rather than by sum. Summed, these twenty benign files reach 1,200 and the request is refused
    /// with nothing wrong in it; taken as a maximum the request scores 60 and is observed, while a
    /// single file at 90 would still block regardless of how many benign files surround it. The
    /// arithmetic is asserted in both directions so that a future change to the gateway's aggregation
    /// has to confront it.
    /// </remarks>
    [Fact]
    public async Task TwentyBenignFilesInOneRequest_DoNotAggregateIntoABlock()
    {
        var scores = new List<int>(20);
        for (var index = 1; index <= 20; index++)
        {
            var name = $@"C:\Users\author\Pictures\vacation-{index:D2}.jpg";
            scores.Add(await AggregateScoreAsync(Upload(name, JpegPhotograph(), "image/jpeg")));
        }

        Assert.All(scores, score => Assert.Equal(UnsafeFileNameRule.Score, score));

        var maximum = scores.Max();
        Assert.True(maximum < BlockThreshold, $"Bulk benign upload reached {maximum}.");
        Assert.True(maximum >= ObserveThreshold, "The finding should still be visible to an operator.");

        // The rejected alternative, stated as arithmetic rather than as a claim.
        Assert.True(scores.Sum() > BlockThreshold);
    }

    // =============================================================================================
    // Structural requirements
    // =============================================================================================

    /// <summary>
    /// Evidence hygiene, asserted over every fixture that produces a finding: no evidence value may
    /// contain the raw client-supplied file name, and no value may carry a control character into a
    /// log consumer. Both rules record the <i>normalized</i> name, never the raw one.
    /// </summary>
    [Fact]
    public async Task Evidence_NeverCarriesTheRawNameOrControlCharacters()
    {
        var raw = "..\\..\\pho\u0000to.jpg ";
        var context = Upload(raw, Concat(GifStub(), Ascii(SyntheticMarker)), "image/gif\u0007");

        foreach (var rule in ShippedRules)
        {
            var finding = await rule.EvaluateAsync(context);
            if (finding?.Evidence is null)
            {
                continue;
            }

            foreach (var value in finding.Evidence.Values)
            {
                Assert.DoesNotContain("\u0000", value, StringComparison.Ordinal);
                Assert.False(value.Contains('\u0007', StringComparison.Ordinal));
                Assert.NotEqual(raw, value);
            }
        }
    }

    // =============================================================================================
    // Aggregation mirrored from InspectionEngine (see the class remarks)
    // =============================================================================================

    private static async Task<IReadOnlyList<RuleFinding>> EvaluateAllAsync(InspectionContext context)
    {
        var findings = new List<RuleFinding>(ShippedRules.Length);
        foreach (var rule in ShippedRules)
        {
            var finding = await rule.EvaluateAsync(context);
            if (finding is not null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }

    private static int AggregateScore(IReadOnlyList<RuleFinding> findings) =>
        Math.Min(100, findings.Sum(finding => Math.Max(0, finding.Score)));

    private static async Task<int> AggregateScoreAsync(InspectionContext context) =>
        AggregateScore(await EvaluateAllAsync(context));
}

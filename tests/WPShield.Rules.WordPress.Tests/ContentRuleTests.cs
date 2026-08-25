using System.Globalization;
using System.Text;
using WPShield.Abstractions;

namespace WPShield.Rules.WordPress.Tests;

/// <summary>
/// <c>FILE-TYPE-001</c> and <c>PHP-CONTENT-002</c> — the two M2 rules that reason about the bytes of
/// an upload rather than about its name.
/// </summary>
/// <remarks>
/// <para>
/// The half of this file that matters is the silent half. Both rules run on every file part of every
/// multipart request a WordPress site receives, so a false positive is not a wrong log line: in Block
/// mode it is a media library that stops accepting photographs, and the operator's fastest remedy is
/// to switch WPShield off. The corpus below is therefore weighted towards ordinary traffic — a JFIF
/// photograph, an XMP packet, a Site Kit CSV export, an Elementor kit ZIP, a chunked upload's second
/// chunk — and each of those fixtures asserts an exact score rather than merely "no block", so that a
/// future change which nudges one of them upward fails here instead of on a live site.
/// </para>
/// <para>
/// Every fixture is a synthetic byte array built in this file. Nothing reads a real media file,
/// nothing writes to disk, and the only script marker used anywhere is
/// <c>&lt;?php echo 'synthetic marker';</c> — the same harmless string the existing fixtures use. No
/// test constructs a working webshell.
/// </para>
/// <para>
/// <b>On the aggregate assertions.</b> This project deliberately does not reference
/// <c>WPShield.Core</c>: the rule layer has to build and be testable without the engine, and a Linux
/// CI leg proves it. So <see cref="AggregateScore"/> mirrors the arithmetic of
/// <c>InspectionEngine.InspectAsync</c> — sum the findings, clamp negatives to zero, cap at 100 —
/// rather than calling it. The engine's own behaviour (thresholds, the Monitor downgrade, the
/// Disabled short circuit) is covered where it belongs, in
/// <c>tests/WPShield.Core.Tests/UploadScoringTests.cs</c>. What is asserted here is the calibration
/// question that only the rule set can answer: which combinations of these eight rules land on which
/// side of 80.
/// </para>
/// </remarks>
public sealed class ContentRuleTests
{
    /// <summary>The only marker any fixture in this file carries. Inert: it echoes a string.</summary>
    private const string SyntheticMarker = "<?php echo 'synthetic marker';";

    /// <summary><c>SiteOptions.ObserveThreshold</c>'s default, restated because Core is not referenced.</summary>
    private const int ObserveThreshold = 30;

    /// <summary><c>SiteOptions.BlockThreshold</c>'s default, restated because Core is not referenced.</summary>
    private const int BlockThreshold = 80;

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

    private static InspectionContext Upload(string? fileName, byte[]? sample = null, string? contentType = null) =>
        new(
            "site",
            "wordpress-one.example",
            "POST",
            "/wp-admin/async-upload.php",
            fileName,
            contentType,
            sample ?? []);

    private static ValueTask<RuleFinding?> TypeAsync(InspectionContext context) =>
        new FileTypeMismatchRule().EvaluateAsync(context);

    private static ValueTask<RuleFinding?> PolyglotAsync(InspectionContext context) =>
        new PhpPolyglotUploadRule().EvaluateAsync(context);

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
    /// The case the rule exists for. <c>photo.jpg</c> is a perfect name, so every name rule WPShield
    /// ships has nothing to say about it; only the bytes give it away.
    /// </summary>
    [Fact]
    public async Task PhpTextUnderAnImageName_ReportsTheScriptTier()
    {
        var context = Upload("photo.jpg", Ascii(SyntheticMarker), "image/jpeg");

        var finding = await TypeAsync(context);

        Assert.NotNull(finding);
        Assert.Equal("FILE-TYPE-001", finding.RuleId);
        Assert.Equal(FileTypeMismatchRule.ScriptContentScore, finding.Score);
        Assert.Equal("Findings.UploadContentSignatureMismatch", finding.MessageKey);
        Assert.Equal("script", finding.Evidence?["observedContent"]);
        Assert.Equal(FileSignatures.PhpOpenTagToken, finding.Evidence?["marker"]);
        Assert.Equal("jpeg", finding.Evidence?["expectedFormat"]);
        Assert.Equal(".jpg", finding.Evidence?["presentedExtension"]);
        Assert.Equal("photo.jpg", finding.Evidence?["normalizedName"]);
    }

    /// <summary>
    /// Each script form the rule recognizes, under a different binary extension. WPShield protects
    /// Windows hosting, so an <c>.aspx</c> handler body is as interesting as a PHP one, and the
    /// shebang covers the case where the payload is a shell script dropped for a later scheduled task.
    /// </summary>
    [Theory]
    [InlineData("photo.jpg", "<?php echo 'synthetic marker';", "<?php")]
    [InlineData("report.docx", "<?php echo 'synthetic marker';", "<?php")]
    [InlineData("banner.png", "<?= 'synthetic marker' ?> and some ordinary trailing prose", "<?=")]
    [InlineData("logo.gif", "<% Response.Write(\"synthetic marker\") %> trailing prose here", "<%")]
    [InlineData("clip.mp4", "<script>window.alert('synthetic marker');</script>", "<script")]
    [InlineData("track.mp3", "#!/bin/sh\necho 'synthetic marker'\nexit 0\n", "#!/")]
    public async Task ScriptTextUnderABinaryExtension_ReportsTheScriptTier(
        string fileName,
        string body,
        string expectedMarker)
    {
        var finding = await TypeAsync(Upload(fileName, Ascii(body)));

        Assert.NotNull(finding);
        Assert.Equal(FileTypeMismatchRule.ScriptContentScore, finding.Score);
        Assert.Equal("script", finding.Evidence?["observedContent"]);
        Assert.Equal(expectedMarker, finding.Evidence?["marker"]);
    }

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

    /// <summary>
    /// A program under a media name. Both native forms are covered because the DOS header is the one
    /// that needs corroboration and the ELF header is the one that does not.
    /// </summary>
    [Theory]
    [InlineData("photo.png")]
    [InlineData("avatar.jpg")]
    [InlineData("intro.mp4")]
    [InlineData("brand.woff2")]
    public async Task PortableExecutableUnderAMediaName_ReportsTheNativeExecutableTier(string fileName)
    {
        var finding = await TypeAsync(Upload(fileName, PortableExecutable()));

        Assert.NotNull(finding);
        Assert.Equal(FileTypeMismatchRule.NativeExecutableContentScore, finding.Score);
        Assert.Equal("nativeExecutable", finding.Evidence?["observedContent"]);
        Assert.Equal(FileSignatures.DosExecutableToken, finding.Evidence?["marker"]);
    }

    [Fact]
    public async Task ElfExecutableUnderAMediaName_ReportsTheNativeExecutableTier()
    {
        var finding = await TypeAsync(Upload("photo.jpg", ElfExecutable()));

        Assert.NotNull(finding);
        Assert.Equal(FileTypeMismatchRule.NativeExecutableContentScore, finding.Score);
        Assert.Equal("nativeExecutable", finding.Evidence?["observedContent"]);
        Assert.Equal(FileSignatures.ElfExecutableToken, finding.Evidence?["marker"]);
    }

    /// <summary>
    /// The weakest claim the rule makes: human-readable text where a binary format was promised, with
    /// no script marker anywhere in it. Scored 40 rather than 70 precisely because a disagreement of
    /// this kind always has a benign explanation somewhere in the long tail of upload clients.
    /// </summary>
    [Fact]
    public async Task HtmlDocumentUnderAnImageName_ReportsTheTextTier()
    {
        var finding = await TypeAsync(Upload("notes.jpg", Ascii(HtmlExport)));

        Assert.NotNull(finding);
        Assert.Equal(FileTypeMismatchRule.TextContentScore, finding.Score);
        Assert.Equal("text", finding.Evidence?["observedContent"]);

        // The text tier is the one tier that carries no marker, because there is no marker to carry.
        Assert.False(finding.Evidence?.ContainsKey("marker"));
    }

    // =============================================================================================
    // FILE-TYPE-001 — the silences, each of which is a decision rather than an oversight
    // =============================================================================================

    /// <summary>
    /// A recognized format under the name of a different recognized format. Chrome's "save image as",
    /// iOS shares and Android galleries produce these constantly and the file is still a benign image,
    /// so identification is by family and a cross-format rename says nothing.
    /// </summary>
    [Theory]
    [InlineData("photo.jpg")]
    [InlineData("photo.jpeg")]
    public async Task HeicBytesUnderAJpegName_AreSilent(string fileName)
    {
        Assert.Null(await TypeAsync(Upload(fileName, HeicImage(), "image/jpeg")));
    }

    [Fact]
    public async Task WebPBytesUnderAPngName_AreSilent()
    {
        Assert.Null(await TypeAsync(Upload("screenshot.png", WebPImage(), "image/png")));
    }

    /// <summary>
    /// The OOXML and OpenDocument extensions are one ZIP family underneath, so none of them can
    /// disagree with any other or with a plain <c>.zip</c>. A rule that compared exact formats rather
    /// than families would report an Office document as disagreeing with itself on every upload.
    /// </summary>
    [Theory]
    [InlineData("document.docx")]
    [InlineData("spreadsheet.xlsx")]
    [InlineData("presentation.pptx")]
    [InlineData("report.odt")]
    [InlineData("elementor-kit-export.zip")]
    public async Task ZipContainerExtensions_AgreeWithOneAnother(string fileName)
    {
        Assert.Null(await TypeAsync(Upload(fileName, ZipArchive("content.xml"))));
    }

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

    /// <summary>
    /// <c>MZ</c> is two bytes, so one uniformly random file in 65,536 opens with it — and chunk 2..N
    /// of a chunked upload is uniformly random as far as this rule can tell. The DOS header must
    /// therefore corroborate itself through <c>e_lfanew</c> before the executable tier fires. At 70,
    /// plus <c>FILE-NAME-001</c>'s 60 from a legacy client, an uncorroborated match would have blocked
    /// an ordinary video chunk.
    /// </summary>
    [Fact]
    public async Task UncorroboratedDosHeader_IsSilent()
    {
        var sample = new byte[128];
        sample[0] = (byte)'M';
        sample[1] = (byte)'Z';
        // e_lfanew left at zero: no secondary header can live below the DOS header itself.

        Assert.Null(await TypeAsync(Upload("photo.jpg", sample)));
    }

    /// <summary>
    /// A self-extracting archive legitimately begins with <c>MZ</c>, so the executable tier is a
    /// narrow whitelist of media, font and document families rather than "everything". The stated cost
    /// is that an executable renamed <c>invoice.doc</c> passes silently, which is asserted here so the
    /// gap is visible rather than folklore.
    /// </summary>
    [Theory]
    [InlineData("installer.zip")]
    [InlineData("bundle.7z")]
    [InlineData("archive.rar")]
    [InlineData("invoice.doc")]
    [InlineData("budget.xls")]
    public async Task NativeExecutableUnderAContainerOrLegacyOfficeName_IsSilent(string fileName)
    {
        Assert.Null(await TypeAsync(Upload(fileName, PortableExecutable())));
    }

    /// <summary>
    /// Writing an HTML table or a CSV under an <c>.xls</c> name is endemic in reporting and analytics
    /// plugins. It is a bug in the exporter, not an attack, so legacy Office extensions are exempt
    /// from the text tier — the same bytes under an image name still report 40, which is what makes
    /// this an exemption rather than a length accident.
    /// </summary>
    [Theory]
    [InlineData("sales-report.xls")]
    [InlineData("minutes.doc")]
    [InlineData("deck.ppt")]
    public async Task HtmlExportUnderALegacyOfficeName_IsSilent(string fileName)
    {
        Assert.Null(await TypeAsync(Upload(fileName, Ascii(HtmlExport))));

        // The exemption, not the classifier, is doing the work: identical bytes, image name, 40.
        var comparison = await TypeAsync(Upload("notes.jpg", Ascii(HtmlExport)));
        Assert.NotNull(comparison);
        Assert.Equal(FileTypeMismatchRule.TextContentScore, comparison.Score);
    }

    /// <summary>
    /// SVG, TXT, CSV, JSON and XML have no magic number, so there is no expectation for the bytes to
    /// violate. An SVG is the interesting member of that list: it is XML, it may open with an
    /// <c>&lt;?xml</c> declaration, and WordPress sites that accept it accept it by the thousand.
    /// </summary>
    [Theory]
    [InlineData("icon.svg")]
    [InlineData("readme.txt")]
    [InlineData("site-kit-export.csv")]
    [InlineData("elementor-template.json")]
    [InlineData("sitemap.xml")]
    [InlineData("captions.vtt")]
    public async Task SignatureLessExtensions_AreSilentWhateverTheBytesAre(string fileName)
    {
        Assert.Null(await TypeAsync(Upload(fileName, Ascii(SvgDocument))));
        Assert.Null(await TypeAsync(Upload(fileName, Ascii(HtmlExport))));
        Assert.Null(await TypeAsync(Upload(fileName, EntropyBytes(256))));
    }

    /// <summary>
    /// An extension WPShield has never seen makes no claim that can be violated. This is a different
    /// statement from "signature-less" even though both end in silence, and the difference matters:
    /// one is a format we know has no magic number, the other is a format we know nothing about.
    /// </summary>
    [Theory]
    [InlineData("firmware.bin")]
    [InlineData("model.glb")]
    [InlineData("backup.sql")]
    [InlineData("photo")]
    public async Task UnknownOrAbsentExtensions_AreSilent(string fileName)
    {
        Assert.Null(await TypeAsync(Upload(fileName, Ascii(SyntheticMarker))));
    }

    /// <summary>
    /// Below the decision floor the rule says nothing. An empty file input, a truncated part and a
    /// four-byte first chunk all land here, and the absence of evidence is not evidence.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(8)]
    [InlineData(15)]
    public async Task SamplesBelowTheDecisionFloor_AreSilent(int length)
    {
        var sample = Ascii(SyntheticMarker)[..length];
        var context = Upload("photo.jpg", sample, "image/jpeg");

        Assert.True(length < FileSignatures.MinimumBytesToDecide);
        Assert.Null(await TypeAsync(context));
        Assert.Null(await PolyglotAsync(context));
    }

    /// <summary>
    /// The declared <c>Content-Type</c> never triggers a finding, in either direction, and never
    /// reaches evidence verbatim. A header value is as attacker-controlled as a file name and can
    /// carry control characters into a log consumer just as easily, so it is reduced to one of four
    /// tokens and nothing else.
    /// </summary>
    [Theory]
    [InlineData(null, "absent")]
    [InlineData("image/jpeg", "agrees")]
    [InlineData("image/jpeg; charset=binary", "agrees")]
    [InlineData("image/png", "disagrees")]
    [InlineData("application/octet-stream", "opaque")]
    [InlineData("not a media type", "opaque")]
    [InlineData("image/jpeg\r\nX-Injected: 1", "opaque")]
    public async Task DeclaredContentType_IsReducedToAToken(string? declared, string expectedToken)
    {
        // A valid JPEG under a JPEG name: whatever the header says, there is nothing to report.
        Assert.Null(await TypeAsync(Upload("photo.jpg", JpegPhotograph(), declared)));

        // And when something else does produce a finding, the header appears only as its token.
        var finding = await TypeAsync(Upload("photo.jpg", Ascii(SyntheticMarker), declared));

        Assert.NotNull(finding);
        Assert.Equal(expectedToken, finding.Evidence?["declaredType"]);
        Assert.All(
            finding.Evidence!.Values,
            value => Assert.DoesNotContain("X-Injected", value, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// A PHP-bodied upload whose name carries an executable extension is left to the name rules.
    /// <c>.php</c> is in neither the signature table nor the signature-less set, so this rule makes no
    /// claim about it — which is what keeps <c>WP-UPLOAD-001</c> from being counted twice.
    /// </summary>
    [Theory]
    [InlineData("shell.php")]
    [InlineData("shell.aspx")]
    [InlineData("web.config")]
    public async Task ExecutableExtensions_AreLeftToTheNameRules(string fileName)
    {
        Assert.Null(await TypeAsync(Upload(fileName, Ascii(SyntheticMarker))));
    }

    /// <summary>
    /// A known limit, pinned so that closing it is a deliberate act. A byte order mark of <c>FF FE</c>
    /// is also a valid MPEG frame sync, so under an <c>.mp3</c> name the signature agrees with the
    /// extension and the rule returns before the UTF-16 branch is ever reached. The exposure is
    /// narrow — WordPress serves <c>.mp3</c> as audio and no IIS handler executes it — but the rule's
    /// own remarks describe the UTF-16 branch as running first, and for this one extension it does not.
    /// </summary>
    [Fact]
    public async Task Utf16ScriptUnderAnMp3Name_IsSilent_KnownLimit()
    {
        var sample = Concat([0xFF, 0xFE], Encoding.Unicode.GetBytes(SyntheticMarker));

        Assert.Null(await TypeAsync(Upload("track.mp3", sample, "audio/mpeg")));
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

    /// <summary>
    /// The same payload behind a fully formed GIF rather than the stub, so the walk has to traverse a
    /// logical screen descriptor, an image descriptor and its LZW sub-blocks before it reaches the
    /// trailer.
    /// </summary>
    [Fact]
    public async Task WellFormedGifWithAppendedScript_ReportsTheAppendedRegion()
    {
        var image = Gif(GifImageBlock());
        var context = Upload("avatar.gif", Concat(image, Ascii(SyntheticMarker)), "image/gif");

        var finding = await PolyglotAsync(context);

        Assert.NotNull(finding);
        Assert.Equal(PhpPolyglotUploadRule.Score, finding.Score);
        Assert.Equal(FileSignatures.RegionAfterTrailer, finding.Evidence?["region"]);
        Assert.Equal(image.Length.ToString(CultureInfo.InvariantCulture), finding.Evidence?["markerOffset"]);
    }

    [Fact]
    public async Task PngWithScriptAfterIend_ReportsTheAppendedRegion()
    {
        var image = Png(PngIhdr(), PngIdat(), PngIend());
        var context = Upload("avatar.png", Concat(image, Ascii(SyntheticMarker)), "image/png");

        var finding = await PolyglotAsync(context);

        Assert.NotNull(finding);
        Assert.Equal(PhpPolyglotUploadRule.Score, finding.Score);
        Assert.Equal(FileSignatures.ContainerPng, finding.Evidence?["container"]);
        Assert.Equal(FileSignatures.RegionAfterIend, finding.Evidence?["region"]);
        Assert.Null(await TypeAsync(context));
    }

    [Fact]
    public async Task JpegWithScriptAfterEndOfImage_ReportsTheAppendedRegion()
    {
        var context = Upload("avatar.jpg", Concat([0xFF, 0xD8, 0xFF, 0xD9], Ascii(SyntheticMarker)), "image/jpeg");

        var finding = await PolyglotAsync(context);

        Assert.NotNull(finding);
        Assert.Equal(PhpPolyglotUploadRule.Score, finding.Score);
        Assert.Equal(FileSignatures.ContainerJpeg, finding.Evidence?["container"]);
        Assert.Equal(FileSignatures.RegionAfterEoi, finding.Evidence?["region"]);
        Assert.Equal("4", finding.Evidence?["markerOffset"]);
    }

    [Fact]
    public async Task WebPWithScriptBeyondTheDeclaredLength_ReportsTheDeclaredLengthRegion()
    {
        var image = WebPImage();
        var context = Upload("avatar.webp", Concat(image, Ascii(SyntheticMarker)), "image/webp");

        var finding = await PolyglotAsync(context);

        Assert.NotNull(finding);
        Assert.Equal(PhpPolyglotUploadRule.Score, finding.Score);
        Assert.Equal(FileSignatures.ContainerWebp, finding.Evidence?["container"]);
        Assert.Equal(FileSignatures.RegionBeyondDeclaredLength, finding.Evidence?["region"]);
        Assert.Null(await TypeAsync(context));
    }

    [Fact]
    public async Task BitmapWithScriptBeyondTheDeclaredLength_ReportsTheDeclaredLengthRegion()
    {
        var image = BitmapImage();
        var context = Upload("avatar.bmp", Concat(image, Ascii(SyntheticMarker)), "image/bmp");

        var finding = await PolyglotAsync(context);

        Assert.NotNull(finding);
        Assert.Equal(PhpPolyglotUploadRule.Score, finding.Score);
        Assert.Equal(FileSignatures.ContainerBmp, finding.Evidence?["container"]);
        Assert.Equal(FileSignatures.RegionBeyondDeclaredLength, finding.Evidence?["region"]);
    }

    /// <summary>
    /// The short-marker guard, both ways round. <c>&lt;?=</c> is three bytes and turns up in 4 KiB of
    /// uniform binary roughly once in four thousand files, so a rule that blocks on it cannot believe
    /// it on sight; a printable run after the marker is what separates the minimal <c>&lt;?=</c> shell
    /// from a coincidence in an image's trailing bytes. <c>PHP-CONTENT-001</c> carries the unguarded
    /// weakness harmlessly at 75 because 75 is an Observe, and the second half asserts exactly that
    /// difference in treatment.
    /// </summary>
    [Fact]
    public async Task ShortMarkerFollowedByPrintableText_Fires()
    {
        var sample = Concat(Gif(GifImageBlock()), Ascii("<?= $value ?> trailing"));

        var finding = await PolyglotAsync(Upload("avatar.gif", sample, "image/gif"));

        Assert.NotNull(finding);
        Assert.Equal(FileSignatures.PhpShortEchoToken, finding.Evidence?["marker"]);
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

    [Fact]
    public async Task NonImageBodies_NeverReachTheStructuralWalk()
    {
        Assert.Null(await PolyglotAsync(Upload("shell.php", Ascii(SyntheticMarker))));
        Assert.Null(await PolyglotAsync(Upload("notes.txt", Ascii(SyntheticMarker))));
        Assert.Null(await PolyglotAsync(Upload("clip.mp4", Concat(Mp4Video(), Ascii(SyntheticMarker)))));
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

    [Fact]
    public async Task ContentRules_HonorCancellationBeforeAnyEarlyReturn()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        IInspectionRule[] rules = [new FileTypeMismatchRule(), new PhpPolyglotUploadRule()];

        foreach (var rule in rules)
        {
            // A context with no sample and no name is the shape that would take the earliest return
            // path, so cancellation has to be observed before any of them.
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                async () => await rule.EvaluateAsync(Upload(fileName: null), cancellation.Token));

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                async () => await rule.EvaluateAsync(
                    Upload("photo.jpg", Ascii(SyntheticMarker), "image/jpeg"),
                    cancellation.Token));
        }
    }

    [Fact]
    public async Task ContentRules_RejectANullContext()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            async () => await new FileTypeMismatchRule().EvaluateAsync(null!));
        await Assert.ThrowsAsync<ArgumentNullException>(
            async () => await new PhpPolyglotUploadRule().EvaluateAsync(null!));
    }

    [Fact]
    public void ContentRules_CarryTheDocumentedIdentifiers()
    {
        Assert.Equal("FILE-TYPE-001", new FileTypeMismatchRule().Id);
        Assert.Equal("PHP-CONTENT-002", new PhpPolyglotUploadRule().Id);
    }

    /// <summary>
    /// Random bytes under a rotation of benign extensions. The seed is fixed so a failure is
    /// reproducible rather than a flake, and the two assertions are the ones the design commits to:
    /// the polyglot rule never fires without a structural proof, and the mismatch rule never reaches
    /// its 70 tiers on bytes that carry no marker and no executable header. The weaker text tier is
    /// allowed to appear, because a run of bytes that reads as text under a binary extension is
    /// precisely what that tier is for.
    /// </summary>
    [Fact]
    public async Task RandomBodies_NeverProduceAHighScoringContentFinding()
    {
        var random = new Random(20260824);
        string[] extensions = ["jpg", "png", "gif", "webp", "bmp", "pdf", "mp4", "docx", "mp3", "zip"];

        for (var iteration = 0; iteration < 400; iteration++)
        {
            var sample = new byte[random.Next(0, 4097)];
            random.NextBytes(sample);
            var fileName = $"fuzz-{iteration}.{extensions[iteration % extensions.Length]}";
            var context = Upload(fileName, sample);

            Assert.True(
                await PolyglotAsync(context) is null,
                $"PHP-CONTENT-002 fired on random bytes: '{fileName}', {sample.Length} bytes.");

            var mismatch = await TypeAsync(context);
            if (mismatch is not null)
            {
                Assert.Equal("text", mismatch.Evidence?["observedContent"]);
                Assert.Equal(FileTypeMismatchRule.TextContentScore, mismatch.Score);
            }
        }
    }

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

    // =============================================================================================
    // Synthetic fixtures. No file is read, no file is written, and nothing here is a working payload.
    // =============================================================================================

    /// <summary>
    /// An ordinary XMP packet, which genuinely opens <c>&lt;?xpacket</c>. Trimmed but structurally
    /// faithful: the processing instruction, the <c>x:xmpmeta</c> wrapper and the closing instruction
    /// are what a camera or an image editor actually writes.
    /// </summary>
    private const string XmpPacket =
        "<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>" +
        "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"XMP Core 6.0.0\">" +
        "<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">" +
        "<rdf:Description rdf:about=\"\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" " +
        "photoshop:Credit=\"studio\" photoshop:DateCreated=\"2026-08-24\"/>" +
        "</rdf:RDF></x:xmpmeta><?xpacket end=\"w\"?>";

    /// <summary>An exporter's HTML table: printable, well over the classification window's floor.</summary>
    private const string HtmlExport =
        "<html><head><title>Sales</title></head><body><table>" +
        "<tr><th>Quarter</th><th>Revenue</th></tr>" +
        "<tr><td>Q1</td><td>1200</td></tr><tr><td>Q2</td><td>1450</td></tr>" +
        "</table></body></html>\n";

    private const string SvgDocument =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\" width=\"24\" height=\"24\">" +
        "<path d=\"M4 4h16v16H4z\" fill=\"none\" stroke=\"currentColor\"/></svg>\n";

    private static byte[] Ascii(string value) => Encoding.ASCII.GetBytes(value);

    /// <summary>
    /// Guards a silence assertion against going vacuous. A fixture that quietly stopped containing
    /// the bytes it is named for would satisfy every "produces no finding" assertion in this file for
    /// entirely the wrong reason, and nothing else here would notice.
    /// </summary>
    private static void AssertSampleContains(InspectionContext context, string expected) =>
        Assert.True(
            context.Sample.Span.IndexOf(Ascii(expected)) >= 0,
            $"The fixture no longer carries the bytes this test exists to prove are harmless: '{expected}'.");

    private static byte[] Concat(params byte[][] parts)
    {
        var buffer = new byte[parts.Sum(part => part.Length)];
        var offset = 0;
        foreach (var part in parts)
        {
            part.CopyTo(buffer, offset);
            offset += part.Length;
        }

        return buffer;
    }

    private static byte[] BigEndian16(int value) => [(byte)(value >> 8), (byte)value];

    private static byte[] LittleEndian16(int value) => [(byte)value, (byte)(value >> 8)];

    private static byte[] BigEndian32(int value) =>
        [(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value];

    private static byte[] LittleEndian32(int value) =>
        [(byte)value, (byte)(value >> 8), (byte)(value >> 16), (byte)(value >> 24)];

    /// <summary>
    /// Deterministic pseudo-entropy standing in for compressed image or video data. Uniform over all
    /// 256 values, so it classifies as binary the way real entropy-coded data does, with the
    /// <c>FF 00</c> byte stuffing a JPEG encoder emits sprayed through it.
    /// </summary>
    private static byte[] EntropyBytes(int count)
    {
        var buffer = new byte[count];
        for (var index = 0; index < count; index++)
        {
            buffer[index] = (byte)((index * 37) + 11);
        }

        for (var index = 8; index + 1 < count; index += 16)
        {
            buffer[index] = 0xFF;
            buffer[index + 1] = 0x00;
        }

        return buffer;
    }

    private static byte[] JpegSegment(byte marker, byte[] payload) =>
        Concat([0xFF, marker], BigEndian16(payload.Length + 2), payload);

    /// <summary>
    /// A JPEG in the shape a camera writes it: <c>SOI</c>, the given metadata segments, then
    /// <c>SOS</c> and scan data. The scan is what makes the structural walk go inconclusive, which is
    /// the ordinary outcome for a genuine photograph.
    /// </summary>
    private static byte[] Jpeg(params byte[][] segments) => Concat(
        [0xFF, 0xD8],
        Concat(segments),
        JpegSegment(0xDA, [0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]),
        EntropyBytes(96));

    private static byte[] JpegPhotograph() => Jpeg(JfifSegment());

    private static byte[] JfifSegment() =>
        JpegSegment(0xE0, Concat(Ascii("JFIF"), [0x00, 0x01, 0x02, 0x01], [0x00, 0x48, 0x00, 0x48], [0x00, 0x00]));

    private static byte[] JpegWithXmp(string packet) => Jpeg(
        JfifSegment(),
        JpegSegment(0xE1, Concat(Ascii("Exif\0\0"), Ascii("II*\0"), [0x08, 0x00, 0x00, 0x00], [0x00, 0x00])),
        JpegSegment(0xE1, Concat(Ascii("http://ns.adobe.com/xap/1.0/\0"), Ascii(packet))));

    private static byte[] JpegWithComment(string comment) =>
        Jpeg(JfifSegment(), JpegSegment(0xFE, Ascii(comment)));

    /// <summary>
    /// The seven-byte carrier the published WordPress bypass actually uses: a GIF header and a
    /// trailer, with no logical screen descriptor at all. <c>getimagesize()</c> accepts it.
    /// </summary>
    private static byte[] GifStub() => Concat(Ascii("GIF89a"), [0x3B]);

    /// <summary>A one-by-one GIF: header, logical screen descriptor, the given blocks, trailer.</summary>
    private static byte[] Gif(params byte[][] blocks) => Concat(
        Ascii("GIF89a"),
        [0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        Concat(blocks),
        [0x3B]);

    /// <summary>Image descriptor, LZW minimum code size, one data sub-block and its terminator.</summary>
    private static byte[] GifImageBlock() =>
        [0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x4C, 0x01, 0x00];

    private static byte[] GifCommentBlock(byte[] text) =>
        Concat([0x21, 0xFE, (byte)text.Length], text, [0x00]);

    /// <summary>
    /// A PNG chunk: length, type, data, CRC. The CRC is zero because nothing in WPShield validates it
    /// — the structural walk follows declared lengths, which is the property the rule depends on and
    /// also the property an attacker controls.
    /// </summary>
    private static byte[] PngChunk(string type, byte[] data) =>
        Concat(BigEndian32(data.Length), Ascii(type), data, [0x00, 0x00, 0x00, 0x00]);

    private static byte[] Png(params byte[][] chunks) => Concat(
        [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        Concat(chunks));

    private static byte[] PngIhdr() =>
        PngChunk("IHDR", Concat(BigEndian32(1), BigEndian32(1), [0x08, 0x06, 0x00, 0x00, 0x00]));

    private static byte[] PngIdat() =>
        PngChunk("IDAT", [0x78, 0x9C, 0x62, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01]);

    private static byte[] PngIend() => PngChunk("IEND", []);

    private static byte[] PngImage() => Png(PngIhdr(), PngIdat(), PngIend());

    private static byte[] Riff(string form, byte[] payload) =>
        Concat(Ascii("RIFF"), LittleEndian32(4 + payload.Length), Ascii(form), payload);

    private static byte[] WebPImage() =>
        Riff("WEBP", Concat(Ascii("VP8L"), LittleEndian32(8), [0x2F, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88, 0x08]));

    /// <summary>
    /// A 24-bit bitmap: a 14-byte file header declaring the total size and the pixel offset, a 40-byte
    /// information header, and eight bytes of pixel data. The declared size is what the polyglot walk
    /// reads, so it is set honestly here and any appended bytes fall beyond it.
    /// </summary>
    private static byte[] BitmapImage()
    {
        var pixels = new byte[] { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00 };
        var infoHeader = Concat(
            LittleEndian32(40),
            LittleEndian32(1),
            LittleEndian32(1),
            [0x01, 0x00],
            [0x18, 0x00],
            LittleEndian32(0),
            LittleEndian32(pixels.Length),
            LittleEndian32(2835),
            LittleEndian32(2835),
            LittleEndian32(0),
            LittleEndian32(0));
        var declaredSize = 14 + infoHeader.Length + pixels.Length;
        var fileHeader = Concat(
            Ascii("BM"),
            LittleEndian32(declaredSize),
            [0x00, 0x00, 0x00, 0x00],
            LittleEndian32(14 + infoHeader.Length));

        return Concat(fileHeader, infoHeader, pixels);
    }

    private static byte[] ZipArchive(string entryName) => Concat(
        [0x50, 0x4B, 0x03, 0x04],
        [0x14, 0x00],
        [0x00, 0x00],
        [0x08, 0x00],
        [0x00, 0x00, 0x00, 0x00],
        LittleEndian32(0),
        LittleEndian32(32),
        LittleEndian32(64),
        LittleEndian16(entryName.Length),
        [0x00, 0x00],
        Ascii(entryName),
        EntropyBytes(32));

    private static byte[] Mp4Video() => Concat(
        BigEndian32(0x20),
        Ascii("ftyp"),
        Ascii("isom"),
        BigEndian32(0x200),
        Ascii("isomiso2avc1mp41"),
        EntropyBytes(64));

    private static byte[] HeicImage() => Concat(
        BigEndian32(0x18),
        Ascii("ftyp"),
        Ascii("heic"),
        BigEndian32(0),
        Ascii("mif1heic"),
        EntropyBytes(64));

    private static byte[] WebmVideo() => Concat(
        [0x1A, 0x45, 0xDF, 0xA3],
        [0x9F, 0x42, 0x86, 0x81, 0x01, 0x42, 0xF7, 0x81, 0x01],
        EntropyBytes(64));

    private static byte[] Mp3WithId3() => Concat(
        Ascii("ID3"),
        [0x04, 0x00, 0x00],
        [0x00, 0x00, 0x02, 0x01],
        EntropyBytes(96));

    private static byte[] Mp3RawFrame() => Concat([0xFF, 0xFB, 0x90, 0x44], EntropyBytes(96));

    private static byte[] TrueTypeFont() => Concat(
        [0x00, 0x01, 0x00, 0x00],
        BigEndian16(9),
        BigEndian16(128),
        BigEndian16(3),
        BigEndian16(64),
        EntropyBytes(64));

    private static byte[] WoffFont() => Concat(
        Ascii("wOFF"),
        Ascii("OTTO"),
        BigEndian32(1024),
        BigEndian16(9),
        BigEndian16(0),
        EntropyBytes(64));

    private static byte[] Woff2Font() => Concat(
        Ascii("wOF2"),
        Ascii("OTTO"),
        BigEndian32(1024),
        BigEndian16(9),
        BigEndian16(0),
        EntropyBytes(64));

    private static byte[] PdfDocument() => Concat(
        Ascii("%PDF-1.7\n"),
        [0x25, 0xE2, 0xE3, 0xCF, 0xD3, 0x0A],
        Ascii("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"));

    /// <summary>
    /// An MS-DOS header with a plausible <c>e_lfanew</c> and a real <c>PE</c> signature behind it.
    /// Corroboration matters: <c>MZ</c> alone is two bytes and would otherwise match one uniformly
    /// random chunk in 65,536.
    /// </summary>
    private static byte[] PortableExecutable()
    {
        var image = new byte[0x88];
        image[0] = (byte)'M';
        image[1] = (byte)'Z';
        LittleEndian32(0x80).CopyTo(image, 0x3C);
        image[0x80] = (byte)'P';
        image[0x81] = (byte)'E';
        return image;
    }

    private static byte[] ElfExecutable() =>
        Concat([0x7F], Ascii("ELF"), [0x02, 0x01, 0x01, 0x00], new byte[56]);

    /// <summary>
    /// The ordinary-traffic corpus. Keyed by name so the theory data stays serializable and each case
    /// shows up in the runner under the name of the upload it stands for.
    /// </summary>
    private static InspectionContext TrafficFixture(string fixtureName) => fixtureName switch
    {
        "photo.jpg" => Upload("photo.jpg", JpegPhotograph(), "image/jpeg"),
        "photo.jpeg" => Upload("photo.jpeg", JpegWithXmp(XmpPacket), "image/jpeg"),
        "banner.png" => Upload("banner.png", PngImage(), "image/png"),
        "animation.gif" => Upload("animation.gif", Gif(GifImageBlock()), "image/gif"),
        "logo.webp" => Upload("logo.webp", WebPImage(), "image/webp"),
        "diagram.bmp" => Upload("diagram.bmp", BitmapImage(), "image/bmp"),
        "icon.svg" => Upload("icon.svg", Ascii(SvgDocument), "image/svg+xml"),
        "analytics-report.pdf" => Upload("analytics-report.pdf", PdfDocument(), "application/pdf"),
        "document.docx" => Upload(
            "document.docx",
            ZipArchive("word/document.xml"),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        "spreadsheet.xlsx" => Upload(
            "spreadsheet.xlsx",
            ZipArchive("xl/workbook.xml"),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        "presentation.pptx" => Upload(
            "presentation.pptx",
            ZipArchive("ppt/presentation.xml"),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
        "report.odt" => Upload("report.odt", ZipArchive("content.xml"), "application/vnd.oasis.opendocument.text"),
        "video.mp4" => Upload("video.mp4", Mp4Video(), "video/mp4"),
        "video.webm" => Upload("video.webm", WebmVideo(), "video/webm"),
        "audio.mp3" => Upload("audio.mp3", Mp3WithId3(), "audio/mpeg"),
        "podcast-raw.mp3" => Upload("podcast-raw.mp3", Mp3RawFrame(), "audio/mpeg"),
        "font.ttf" => Upload("font.ttf", TrueTypeFont(), "font/ttf"),
        "elementor-icons.woff" => Upload("elementor-icons.woff", WoffFont(), "font/woff"),
        "elementor-icons.woff2" => Upload("elementor-icons.woff2", Woff2Font(), "font/woff2"),
        "elementor-kit-export.zip" => Upload("elementor-kit-export.zip", ZipArchive("manifest.json"), "application/zip"),
        "elementor-template.json" => Upload(
            "elementor-template.json",
            Ascii("{\"version\":\"0.4\",\"title\":\"Hero\",\"type\":\"section\",\"content\":[]}"),
            "application/json"),
        // The plupload fallback and every non-browser client send octet-stream, so the declared type
        // disagreeing with the extension must never be a finding on its own.
        "elementor-background.jpg" => Upload("elementor-background.jpg", JpegPhotograph(), "application/octet-stream"),
        "site-kit-export.csv" => Upload(
            "site-kit-export.csv",
            Ascii("Date,Sessions,Users\n2026-08-01,1240,980\n2026-08-02,1310,1024\n"),
            "text/csv"),
        "googlesitekit-report.pdf" => Upload("googlesitekit-report.pdf", PdfDocument(), "application/pdf"),
        "photo-heic-rename.jpg" => Upload("photo-heic-rename.jpg", HeicImage(), "image/jpeg"),
        "screenshot-webp-rename.png" => Upload("screenshot-webp-rename.png", WebPImage(), "image/png"),
        "chunked-upload-part-2.jpg" => Upload("chunked-upload-part-2.jpg", EntropyBytes(2048), "application/octet-stream"),
        "presentación-española.pptx" => Upload(
            "presentación-española.pptx",
            ZipArchive("ppt/presentation.xml"),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
        "日本語のファイル.png" => Upload("日本語のファイル.png", PngImage(), "image/png"),
        "My Vacation Photo.jpeg" => Upload("My Vacation Photo.jpeg", JpegPhotograph(), "image/jpeg"),
        // A part cut short by a chunk boundary, and an unselected file input the browser still sends.
        "truncated-part.jpg" => Upload("truncated-part.jpg", [0xFF, 0xD8, 0xFF], "image/jpeg"),
        "empty-file-input.jpg" => Upload("empty-file-input.jpg", [], "image/jpeg"),
        "sales-report.xls" => Upload("sales-report.xls", Ascii(HtmlExport), "application/vnd.ms-excel"),
        "installer.zip" => Upload("installer.zip", PortableExecutable(), "application/zip"),
        _ => throw new ArgumentOutOfRangeException(nameof(fixtureName), fixtureName, "Unknown fixture.")
    };
}

using System.Globalization;
using System.Text;
using WPShield.Abstractions;
using static WPShield.Rules.Tests.Shared.ContentFixtures;

namespace WPShield.Rules.Windows.Tests;

/// <summary>
/// <c>FILE-TYPE-001</c> and <c>PHP-CONTENT-002</c> - the two rules that reason about the bytes of an
/// upload rather than about its name.
/// </summary>
/// <remarks>
/// <para>
/// The half of this file that matters is the silent half. Both rules run on every file part of every
/// multipart request a site receives, so a false positive is not a wrong log line: in Block mode it is
/// a media library that stops accepting photographs, and the operator's fastest remedy is to switch
/// WPShield off. Each ordinary-traffic fixture therefore asserts an exact score rather than merely
/// "no block", so that a change which nudges one of them upward fails here instead of on a live site.
/// </para>
/// <para>
/// These two rules moved to <c>WPShield.Rules.Windows</c> when ADR 0004's first exit condition split
/// the rule packages: nothing in them is WordPress. What they do together with the rest of the
/// shipped set - which combinations land on which side of the block threshold, and whether an
/// ordinary traffic corpus stays silent across all of them - is asserted in
/// <c>WPShield.Rules.WordPress.Tests</c>, the layer that can see both packages. The fixtures are
/// shared by link, never copied: <c>tests/Shared/ContentFixtures.cs</c>.
/// </para>
/// </remarks>
public sealed class ContentRuleTests
{
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

    // =============================================================================================
    // PHP-CONTENT-002 — the silences, led by the false positive that decides whether it is shippable
    // =============================================================================================

    [Fact]
    public async Task NonImageBodies_NeverReachTheStructuralWalk()
    {
        Assert.Null(await PolyglotAsync(Upload("shell.php", Ascii(SyntheticMarker))));
        Assert.Null(await PolyglotAsync(Upload("notes.txt", Ascii(SyntheticMarker))));
        Assert.Null(await PolyglotAsync(Upload("clip.mp4", Concat(Mp4Video(), Ascii(SyntheticMarker)))));
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
}

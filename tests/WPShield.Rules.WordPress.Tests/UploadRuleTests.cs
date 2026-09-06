using WPShield.Abstractions;

namespace WPShield.Rules.WordPress.Tests;

public sealed class UploadRuleTests
{
    private static InspectionContext Upload(string? fileName, string? contentType = null)
    {
        return new InspectionContext(
            "site",
            "example.test",
            "POST",
            "/wp-admin/async-upload.php",
            fileName,
            contentType);
    }

    // ---------------------------------------------------------------------------------------------
    // WP-UPLOAD-001 — PHP-executable extensions
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("shell.php")]
    [InlineData("shell.php3")]
    [InlineData("shell.php5")]
    [InlineData("shell.php8")]
    [InlineData("shell.phps")]
    [InlineData("shell.pht")]
    [InlineData("shell.phtm")]
    [InlineData("image.phtml")]
    [InlineData("archive.phar")]
    [InlineData("shell.PHP")]
    [InlineData("shell.PhP5")]
    public async Task ExecutableExtensions_AreFlagged(string fileName)
    {
        var finding = await new ExecutableUploadExtensionRule().EvaluateAsync(Upload(fileName));

        Assert.NotNull(finding);
        Assert.Equal("WP-UPLOAD-001", finding.RuleId);
        Assert.Equal(ExecutableUploadExtensionRule.FinalPositionScore, finding.Score);
    }

    /// <summary>
    /// Regression coverage for the evasions that defeated the original <c>Path.GetExtension</c>
    /// implementation. Each of these reaches disk as <c>shell.php</c> on Windows.
    /// </summary>
    [Theory]
    [InlineData("shell.php.")]
    [InlineData("shell.php ")]
    [InlineData("shell.php::$DATA")]
    [InlineData("shell.pHp5.")]
    [InlineData("../../shell.php")]
    [InlineData(@"..\..\shell.php")]
    [InlineData("shell.p\u0000hp")]
    public async Task WindowsEvasionForms_AreFlagged(string fileName)
    {
        var finding = await new ExecutableUploadExtensionRule().EvaluateAsync(Upload(fileName));

        Assert.NotNull(finding);
        Assert.Equal("WP-UPLOAD-001", finding.RuleId);
        Assert.Equal(ExecutableUploadExtensionRule.FinalPositionScore, finding.Score);
        Assert.Equal("final", finding.Evidence?["position"]);
    }

    [Fact]
    public async Task EmbeddedExecutableExtension_ScoresLowerThanFinalPosition()
    {
        var finding = await new ExecutableUploadExtensionRule().EvaluateAsync(Upload("photo.php.jpg"));

        Assert.NotNull(finding);
        Assert.Equal(ExecutableUploadExtensionRule.NonFinalPositionScore, finding.Score);
        Assert.Equal("embedded", finding.Evidence?["position"]);
    }

    [Fact]
    public async Task Evidence_ReportsTheNormalizedNameNotTheRawOne()
    {
        var finding = await new ExecutableUploadExtensionRule().EvaluateAsync(Upload(@"..\..\shell.php."));

        Assert.NotNull(finding);
        Assert.Equal("shell.php", finding.Evidence?["normalizedName"]);
        Assert.Equal(".php", finding.Evidence?["extension"]);
    }

    // ---------------------------------------------------------------------------------------------
    // IIS-CONFIG-001 — web.config, the Windows-specific remote code execution vector
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("web.config")]
    [InlineData("WEB.CONFIG")]
    [InlineData("Web.Config")]
    [InlineData("web.config.")]
    [InlineData("web.config ")]
    [InlineData("web.config::$DATA")]
    [InlineData("../web.config")]
    [InlineData(@"..\..\wp-content\uploads\web.config")]
    public async Task WebConfigUpload_ScoresMaximum(string fileName)
    {
        var finding = await new IisConfigurationUploadRule().EvaluateAsync(Upload(fileName));

        Assert.NotNull(finding);
        Assert.Equal("IIS-CONFIG-001", finding.RuleId);
        Assert.Equal(IisConfigurationUploadRule.Score, finding.Score);
    }

    [Theory]
    [InlineData("app.config")]
    [InlineData("database.config")]
    [InlineData("webbing.config")]
    [InlineData("web.configuration")]
    [InlineData("my-web.config-notes.txt")]
    public async Task OtherConfigNames_AreNotTreatedAsWebConfig(string fileName)
    {
        Assert.Null(await new IisConfigurationUploadRule().EvaluateAsync(Upload(fileName)));
    }

    // ---------------------------------------------------------------------------------------------
    // IIS-UPLOAD-001 — extensions IIS itself executes
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("shell.aspx")]
    [InlineData("shell.asp")]
    [InlineData("handler.ashx")]
    [InlineData("service.asmx")]
    [InlineData("control.ascx")]
    [InlineData("page.cshtml")]
    [InlineData("global.asax")]
    [InlineData("shell.ASPX")]
    [InlineData("shell.aspx::$DATA")]
    [InlineData("shell.aspx.")]
    public async Task IisExecutableExtensions_AreFlagged(string fileName)
    {
        var finding = await new IisExecutableUploadRule().EvaluateAsync(Upload(fileName));

        Assert.NotNull(finding);
        Assert.Equal("IIS-UPLOAD-001", finding.RuleId);
        Assert.Equal(IisExecutableUploadRule.FinalPositionScore, finding.Score);
    }

    [Fact]
    public async Task PhpRule_DoesNotClaimIisExtensions()
    {
        Assert.Null(await new ExecutableUploadExtensionRule().EvaluateAsync(Upload("shell.aspx")));
    }

    [Fact]
    public async Task IisRule_DoesNotClaimPhpExtensions()
    {
        Assert.Null(await new IisExecutableUploadRule().EvaluateAsync(Upload("shell.php")));
    }

    // ---------------------------------------------------------------------------------------------
    // WP-UPLOAD-002 — disguised extensions
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("photo.php.jpg", ".php", ".jpg")]
    [InlineData("document.pdf.phtml.pdf", ".phtml", ".pdf")]
    [InlineData("logo.aspx.png", ".aspx", ".png")]
    public async Task DisguisedExecutableExtension_IsFlagged(
        string fileName,
        string expectedExecutable,
        string expectedPresented)
    {
        var finding = await new DisguisedExtensionRule().EvaluateAsync(Upload(fileName));

        Assert.NotNull(finding);
        Assert.Equal("WP-UPLOAD-002", finding.RuleId);
        Assert.Equal(expectedExecutable, finding.Evidence?["executableExtension"]);
        Assert.Equal(expectedPresented, finding.Evidence?["presentedExtension"]);
    }

    [Theory]
    [InlineData("shell.php")]
    [InlineData("archive.tar.gz")]
    [InlineData("style.min.css")]
    [InlineData("report.2024.xlsx")]
    [InlineData("jquery.min.js")]
    public async Task MultipleExtensionsAlone_DoNotTriggerTheDisguiseRule(string fileName)
    {
        Assert.Null(await new DisguisedExtensionRule().EvaluateAsync(Upload(fileName)));
    }

    // ---------------------------------------------------------------------------------------------
    // FILE-NAME-001 — structural anomalies
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("../../photo.jpg", "pathSeparator")]
    [InlineData("photo.jpg::$DATA", "alternateDataStream")]
    [InlineData("photo.jpg.", "trailingDotsOrSpaces")]
    [InlineData("pho\u0000to.jpg", "controlCharacter")]
    [InlineData("NUL.jpg", "reservedDeviceName")]
    public async Task StructuralAnomalies_AreReportedWithTheirKind(string fileName, string expectedAnomaly)
    {
        var finding = await new UnsafeFileNameRule().EvaluateAsync(Upload(fileName));

        Assert.NotNull(finding);
        Assert.Equal("FILE-NAME-001", finding.RuleId);
        Assert.Contains(expectedAnomaly, finding.Evidence?["anomalies"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task EmptyNameAfterNormalization_IsReported()
    {
        var finding = await new UnsafeFileNameRule().EvaluateAsync(Upload("::$DATA"));

        Assert.NotNull(finding);
        Assert.Contains("emptyAfterNormalization", finding.Evidence?["anomalies"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task AbsentFileName_ProducesNoStructuralFinding()
    {
        Assert.Null(await new UnsafeFileNameRule().EvaluateAsync(Upload(fileName: null)));
    }

    // ---------------------------------------------------------------------------------------------
    // False positives — legitimate WordPress traffic must stay silent across every rule
    // ---------------------------------------------------------------------------------------------

    public static TheoryData<string> BenignUploads =>
    [
        "photo.jpg",
        "photo.jpeg",
        "banner.png",
        "animation.gif",
        "icon.svg",
        "document.pdf",
        "spreadsheet.xlsx",
        "presentation.pptx",
        "archive.tar.gz",
        "archive.zip",
        "style.min.css",
        "jquery.min.js",
        "report.2024.xlsx",
        "My Vacation Photo.jpeg",
        "informe-anual-2024.pdf",
        "presentación-española.pptx",
        "日本語のファイル.png",
        "elementor-template.json",
        "site-kit-export.csv",
        "video.mp4",
        "audio.mp3",
        "font.woff2"
    ];

    [Theory]
    [MemberData(nameof(BenignUploads))]
    public async Task BenignUploads_ProduceNoFindingFromAnyRule(string fileName)
    {
        IInspectionRule[] rules =
        [
            new ExecutableUploadExtensionRule(),
            new DisguisedExtensionRule(),
            new IisExecutableUploadRule(),
            new IisConfigurationUploadRule(),
            new UnsafeFileNameRule()
        ];

        foreach (var rule in rules)
        {
            var finding = await rule.EvaluateAsync(Upload(fileName));
            Assert.True(finding is null, $"{rule.Id} produced a false positive for '{fileName}'.");
        }
    }

    // ---------------------------------------------------------------------------------------------
    // F4 — the rules have to model WordPress's normalization, not only Windows's
    //
    // Every payload below was inert to the shipped engine: NTFS writes the name verbatim, so the
    // extension segment is p{h}p or as{p}x or config-, which no handler mapping has ever heard of and
    // no rule matched. WordPress's sanitize_file_name() deletes the characters in its own set and
    // trims '.-_' from the ends, and what lands in wp-content/uploads is the executable form. The
    // whole kill chain is one request, and web.con{f}ig is the sharpest case: one brace turned off
    // the 100-point rule that has no false positives.
    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// <c>WP-UPLOAD-001</c> under the WordPress view. The finding names the view that matched,
    /// because <c>extension=.php</c> against a <c>normalizedName</c> that visibly contains no
    /// <c>.php</c> reads as a mistake otherwise.
    /// </summary>
    [Theory]
    [InlineData("shell.p{h}p", "shell.php")]
    [InlineData("shell.php-", "shell.php")]
    [InlineData("shell.p%hp", "shell.php")]
    [InlineData("shell.p(h)p", "shell.php")]
    [InlineData("shell.p!hp", "shell.php")]
    [InlineData("shell.p+hp", "shell.php")]
    [InlineData("shell.p#hp", "shell.php")]
    [InlineData("shell.p~hp", "shell.php")]
    [InlineData("shell.php_", "shell.php")]
    [InlineData("shell.php~", "shell.php")]
    [InlineData("shell.p\u0060hp", "shell.php")]
    [InlineData("shell.p[h]p", "shell.php")]
    [InlineData("shell.p&hp", "shell.php")]
    [InlineData("shell.p$hp", "shell.php")]
    [InlineData("shell.p'hp", "shell.php")]
    [InlineData("shell.p\"hp", "shell.php")]
    [InlineData("functions.php-", "functions.php")]
    [InlineData("archive.p{h}ar", "archive.phar")]
    [InlineData("image.p{h}tml", "image.phtml")]
    public async Task WordPressRewriteEvasions_AreFlaggedAsExecutableUploads(
        string fileName,
        string expectedWordPressName)
    {
        var finding = await new ExecutableUploadExtensionRule().EvaluateAsync(Upload(fileName));

        Assert.NotNull(finding);
        Assert.Equal("WP-UPLOAD-001", finding.RuleId);
        Assert.Equal(ExecutableUploadExtensionRule.FinalPositionScore, finding.Score);
        Assert.Equal("final", finding.Evidence?["position"]);
        Assert.Equal("wordpress", finding.Evidence?["view"]);

        // The name as sent stays the primary evidence; the rewritten name sits beside it, so an
        // operator in Monitor mode can see the divergence before Block mode makes it a refusal.
        Assert.Equal(fileName, finding.Evidence?["normalizedName"]);
        Assert.Equal(expectedWordPressName, finding.Evidence?["wordpressName"]);
    }

    /// <summary>
    /// The measured baseline the review started from: <c>shell.php</c> itself must still score 90,
    /// and it must still be attributed to the NTFS view rather than acquiring a rewrite explanation
    /// it does not have.
    /// </summary>
    [Fact]
    public async Task PlainShellPhp_StillScoresNinetyUnderTheNtfsView()
    {
        var finding = await new ExecutableUploadExtensionRule().EvaluateAsync(Upload("shell.php"));

        Assert.NotNull(finding);
        Assert.Equal(ExecutableUploadExtensionRule.FinalPositionScore, finding.Score);
        Assert.Equal("ntfs", finding.Evidence?["view"]);
        Assert.False(finding.Evidence?.ContainsKey("wordpressName"));
    }

    /// <summary>
    /// <c>IIS-CONFIG-001</c> was the most brittle rule in the set, because it matches an exact
    /// reserved name rather than a suffix. A single brace or a trailing hyphen took a 100-point
    /// finding to zero while WordPress wrote the live IIS configuration file anyway.
    /// </summary>
    [Theory]
    [InlineData("web.con{f}ig")]
    [InlineData("web.config-")]
    [InlineData("web.config_")]
    [InlineData("web.config~")]
    [InlineData("web.con(f)ig")]
    [InlineData("web.co#nfig")]
    [InlineData("web.con!fig")]
    [InlineData("we{b}.config")]
    public async Task WordPressRewriteEvasions_StillReachTheWebConfigRule(string fileName)
    {
        var finding = await new IisConfigurationUploadRule().EvaluateAsync(Upload(fileName));

        Assert.NotNull(finding);
        Assert.Equal("IIS-CONFIG-001", finding.RuleId);
        Assert.Equal(IisConfigurationUploadRule.Score, finding.Score);
        Assert.Equal("wordpress", finding.Evidence?["view"]);
        Assert.Equal("web.config", finding.Evidence?["wordpressName"]);
        Assert.Equal(fileName, finding.Evidence?["normalizedName"]);
    }

    /// <summary>
    /// <c>IIS-UPLOAD-001</c> under the WordPress view. This is the worse half of the finding rather
    /// than the equal one: a PHP handler mapping can be removed from an uploads directory, while the
    /// ASP.NET pipeline is the platform the site runs on.
    /// </summary>
    [Theory]
    [InlineData("shell.as{p}x", "shell.aspx")]
    [InlineData("shell.as(p)x", "shell.aspx")]
    [InlineData("shell.as!px", "shell.aspx")]
    [InlineData("shell.aspx-", "shell.aspx")]
    [InlineData("handler.as{h}x", "handler.ashx")]
    [InlineData("page.cs{h}tml", "page.cshtml")]
    [InlineData("global.as{a}x", "global.asax")]
    public async Task WordPressRewriteEvasions_AreFlaggedAsIisExecutables(
        string fileName,
        string expectedWordPressName)
    {
        var finding = await new IisExecutableUploadRule().EvaluateAsync(Upload(fileName));

        Assert.NotNull(finding);
        Assert.Equal("IIS-UPLOAD-001", finding.RuleId);
        Assert.Equal(IisExecutableUploadRule.FinalPositionScore, finding.Score);
        Assert.Equal("final", finding.Evidence?["position"]);
        Assert.Equal("wordpress", finding.Evidence?["view"]);
        Assert.Equal(expectedWordPressName, finding.Evidence?["wordpressName"]);
    }

    /// <summary>
    /// A rewrite that manufactures a disguise. The NTFS view of <c>photo.p{h}p.jpg</c> has two
    /// extension segments and neither is executable; WordPress deletes the braces and writes the
    /// classic <c>photo.php.jpg</c>.
    /// </summary>
    [Theory]
    [InlineData("photo.p{h}p.jpg", ".php", ".jpg", "photo.php.jpg")]
    [InlineData("logo.as{p}x.png", ".aspx", ".png", "logo.aspx.png")]
    [InlineData("document.p{h}tml.pdf", ".phtml", ".pdf", "document.phtml.pdf")]
    public async Task WordPressRewriteEvasions_AreFlaggedAsDisguisedExtensions(
        string fileName,
        string expectedExecutable,
        string expectedPresented,
        string expectedWordPressName)
    {
        var finding = await new DisguisedExtensionRule().EvaluateAsync(Upload(fileName));

        Assert.NotNull(finding);
        Assert.Equal("WP-UPLOAD-002", finding.RuleId);
        Assert.Equal(expectedExecutable, finding.Evidence?["executableExtension"]);
        Assert.Equal(expectedPresented, finding.Evidence?["presentedExtension"]);
        Assert.Equal("wordpress", finding.Evidence?["view"]);
        Assert.Equal(expectedWordPressName, finding.Evidence?["wordpressName"]);
    }

    /// <summary>
    /// The two views can each contribute a different rule to the same request. NTFS reads
    /// <c>photo.php.as{p}x</c> as a <c>.php</c> hidden behind a segment nothing executes; WordPress
    /// writes <c>photo.php.aspx</c>, where IIS runs the final segment as the application pool
    /// identity.
    /// </summary>
    [Fact]
    public async Task APayloadCanBeDangerousUnderBothViewsForDifferentReasons()
    {
        var context = Upload("photo.php.as{p}x");

        var php = await new ExecutableUploadExtensionRule().EvaluateAsync(context);
        var iis = await new IisExecutableUploadRule().EvaluateAsync(context);

        Assert.NotNull(php);
        Assert.Equal(ExecutableUploadExtensionRule.NonFinalPositionScore, php.Score);
        Assert.Equal("ntfs", php.Evidence?["view"]);

        Assert.NotNull(iis);
        Assert.Equal(IisExecutableUploadRule.FinalPositionScore, iis.Score);
        Assert.Equal("final", iis.Evidence?["position"]);
        Assert.Equal("wordpress", iis.Evidence?["view"]);
    }

    // ---------------------------------------------------------------------------------------------
    // FILE-NAME-001 — the wordpressRewrite anomaly
    //
    // The extension rules act on the divergence through their own two-view matching. This anomaly
    // exists so the divergence itself is on the log line: an operator running in Monitor mode has to
    // be able to read "the name in your media library is not the name that was sent" before Block
    // mode turns the same request into a refusal.
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("shell.p{h}p", "shell.php")]
    [InlineData("shell.php-", "shell.php")]
    [InlineData("shell.p%hp", "shell.php")]
    [InlineData("web.con{f}ig", "web.config")]
    [InlineData("web.config-", "web.config")]
    [InlineData("shell.as{p}x", "shell.aspx")]
    [InlineData("shell.php_", "shell.php")]
    [InlineData("photo.jpg.p{h}p", "photo.jpg.php")]
    public async Task WordPressRewriteIntoADangerousName_IsReportedAsAnAnomaly(
        string fileName,
        string expectedWordPressName)
    {
        var finding = await new UnsafeFileNameRule().EvaluateAsync(Upload(fileName));

        Assert.NotNull(finding);
        Assert.Equal("FILE-NAME-001", finding.RuleId);
        Assert.Equal(UnsafeFileNameRule.Score, finding.Score);
        Assert.Contains("wordpressRewrite", finding.Evidence?["anomalies"], StringComparison.Ordinal);
        Assert.Equal(expectedWordPressName, finding.Evidence?["wordpressName"]);
    }

    /// <summary>
    /// The rewrite does not have to produce an extension. <c>CO{N}.txt</c> is an ordinary text file
    /// to NTFS and a reserved Windows device name once WordPress deletes the braces.
    /// </summary>
    [Fact]
    public async Task WordPressRewriteIntoAReservedDeviceName_IsReportedAsAnAnomaly()
    {
        var finding = await new UnsafeFileNameRule().EvaluateAsync(Upload("CO{N}.txt"));

        Assert.NotNull(finding);
        Assert.Contains("wordpressRewrite", finding.Evidence?["anomalies"], StringComparison.Ordinal);
        Assert.Equal("CON.txt", finding.Evidence?["wordpressName"]);
    }

    /// <summary>
    /// The anomaly reports a <i>change in exposure</i>, not the mere presence of a dangerous token.
    /// <c>sh ell.php</c> is rewritten to <c>sh-ell.php</c>, which is exactly as executable as the
    /// name that was sent — <c>WP-UPLOAD-001</c> is the rule with something to say about it, and
    /// adding a second finding here would double-count one fact.
    /// </summary>
    [Theory]
    [InlineData("sh ell.php")]
    [InlineData("my shell.php")]
    [InlineData("web config.php")]
    public async Task ARewriteThatChangesNothingDangerous_IsNotAnAnomaly(string fileName)
    {
        Assert.Null(await new UnsafeFileNameRule().EvaluateAsync(Upload(fileName)));
    }

    /// <summary>
    /// Whitespace is replaced with a hyphen rather than deleted, so a space cannot be used to break
    /// an extension token apart the way a brace can. Both readings of these names are inert, and a
    /// rule that fired here would be blocking a name no component ever writes as an executable.
    /// </summary>
    [Theory]
    [InlineData("shell.ph p")]
    [InlineData("web.co nfig")]
    [InlineData("shell.p\u00a0hp")]
    public async Task WhitespaceInsideAnExtension_DoesNotBecomeExecutable(string fileName)
    {
        IInspectionRule[] rules =
        [
            new ExecutableUploadExtensionRule(),
            new IisExecutableUploadRule(),
            new IisConfigurationUploadRule(),
            new UnsafeFileNameRule()
        ];

        foreach (var rule in rules)
        {
            var finding = await rule.EvaluateAsync(Upload(fileName));
            Assert.True(finding is null, $"{rule.Id} fired on '{fileName}', which WordPress writes with a hyphen.");
        }
    }

    // ---------------------------------------------------------------------------------------------
    // F6 — evidence must render as what was uploaded
    //
    // A bidi override or a zero-width space in a file name is an attack on the reader: the log line,
    // the dashboard, the terminal. It is written as an escape here and never pasted as itself.
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("photo\u200b.jpg")]           // ZERO WIDTH SPACE
    [InlineData("photo\u202e.jpg")]           // RIGHT-TO-LEFT OVERRIDE
    [InlineData("photo\u2066.jpg")]           // LEFT-TO-RIGHT ISOLATE
    [InlineData("invoice\u202egpj.pdf")]
    public async Task InvisibleFormatting_IsReportedAsAnAnomaly(string fileName)
    {
        var finding = await new UnsafeFileNameRule().EvaluateAsync(Upload(fileName));

        Assert.NotNull(finding);
        Assert.Equal("FILE-NAME-001", finding.RuleId);
        Assert.Contains("invisibleFormatting", finding.Evidence?["anomalies"], StringComparison.Ordinal);
    }

    /// <summary>
    /// The property that matters more than the anomaly label: nothing a rule writes into evidence may
    /// carry a character that reorders or hides the characters around it. A dashboard rendering
    /// <c>normalizedName</c> must show the name that was uploaded.
    /// </summary>
    [Theory]
    [InlineData("shell\u202egpj.php")]
    [InlineData("shell.p\u200bhp")]
    [InlineData("web\u2066.con{f}ig")]
    [InlineData("photo\u202b\u200b.jpg")]
    [InlineData("shell\u200f.as{p}x")]
    public async Task EvidenceNeverCarriesAnInvisibleCharacter(string fileName)
    {
        IInspectionRule[] rules =
        [
            new ExecutableUploadExtensionRule(),
            new DisguisedExtensionRule(),
            new IisExecutableUploadRule(),
            new IisConfigurationUploadRule(),
            new UnsafeFileNameRule()
        ];

        var sawAtLeastOne = false;
        foreach (var rule in rules)
        {
            var finding = await rule.EvaluateAsync(Upload(fileName));
            if (finding?.Evidence is null)
            {
                continue;
            }

            sawAtLeastOne = true;
            foreach (var value in finding.Evidence.Values)
            {
                Assert.DoesNotContain(value, IsInvisible);
            }
        }

        Assert.True(sawAtLeastOne, $"'{fileName}' produced no finding at all, so nothing was inspected.");

        static bool IsInvisible(char character) =>
            char.IsControl(character) ||
            character is (>= '\u200b' and <= '\u200f')
                or (>= '\u202a' and <= '\u202e')
                or (>= '\u2066' and <= '\u2069');
    }

    /// <summary>
    /// An invisible character inside an extension token cannot hide it. Both views carry the joined
    /// form, so the extension rule matches on its own merits.
    /// </summary>
    [Theory]
    [InlineData("shell.p\u200bhp")]
    [InlineData("shell.ph\u202ep")]
    [InlineData("shell.p\u200fhp")]
    public async Task AnExtensionSplitByAnInvisibleCharacter_IsStillMatched(string fileName)
    {
        var finding = await new ExecutableUploadExtensionRule().EvaluateAsync(Upload(fileName));

        Assert.NotNull(finding);
        Assert.Equal(ExecutableUploadExtensionRule.FinalPositionScore, finding.Score);
        Assert.Equal("shell.php", finding.Evidence?["normalizedName"]);
    }

    /// <summary>
    /// U+200C and U+200D are excluded from the anomaly on purpose: they cannot reorder anything and
    /// they are ordinary content in Persian, Arabic and Indic names and in emoji sequences. Flagging
    /// them would put 60 points on legitimate uploads, and 60 alongside <c>FILE-TYPE-001</c>'s 40 is
    /// a blocked request.
    /// </summary>
    [Theory]
    [InlineData("photo\u200c.jpg")]
    [InlineData("photo\u200d.jpg")]
    [InlineData("\u0645\u200c\u0644\u0641.png")]
    public async Task JoinersInLegitimateNames_ProduceNoFinding(string fileName)
    {
        Assert.Null(await new UnsafeFileNameRule().EvaluateAsync(Upload(fileName)));
    }

    // ---------------------------------------------------------------------------------------------
    // The false-positive half of F4 — this is what decides whether the second view is shippable
    //
    // sanitize_file_name() rewrites a large fraction of real WordPress uploads: every space, every
    // parenthesis, every ampersand, every accented copy-and-paste name. If any of these fires, that
    // is a media library that stops accepting photographs on a live site, and the operator's fastest
    // remedy is to switch WPShield off.
    // ---------------------------------------------------------------------------------------------

    public static TheoryData<string> BenignUploadsThatWordPressRewrites =>
    [
        "Captura de pantalla (3).png",
        "Q&A final.pdf",
        "report [final].xlsx",
        "price=list.csv",
        "a\u00f1o-nuevo.jpg",
        "photo (1).jpeg",
        "50% off banner.png",
        "my file - copy.docx",
        "R\u00e9sum\u00e9, 2026.pdf",
        "elementor-1234-post.json",
        "Elementor Kit #3 (backup).zip",
        "elementor-icons.woff2",
        "site-kit-analytics-export.csv",
        "googlesitekit-1.2.3.zip",
        "Google Site Kit \u2014 settings.json",
        "invoice #42 [paid].pdf",
        "100% cotton.png",
        "don't panic.gif",
        "a&b~c.png",
        "budget (2026) v2.xlsx",
        "C++ notes.txt",
        "menu ~ dinner.pdf",
        "test!.png",
        "1+1=2.png",
        "Pantallazo (copia 2).png",
        "Screenshot 2026-08-24 at 12.00.00.png",
        "factura n.\u00ba 42.pdf",
        "wc-product-export-24-8-2026.csv",
        "IMG_20260824_120000.jpg",
        "photo+1.jpg",
        "chart.p-h-p",
        "style.css~",
        "notes.txt-"
    ];

    [Theory]
    [MemberData(nameof(BenignUploadsThatWordPressRewrites))]
    public async Task BenignNamesWordPressRewrites_ProduceNoFindingFromAnyRule(string fileName)
    {
        // All eight shipped rules, not only the name rules. The two content rules stay silent on an
        // absent sample, which is what a name-only regression sweep should confirm rather than
        // assume.
        IInspectionRule[] rules =
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

        foreach (var rule in rules)
        {
            var finding = await rule.EvaluateAsync(Upload(fileName));
            Assert.True(
                finding is null,
                $"{rule.Id} produced a false positive for '{fileName}' " +
                $"(score {finding?.Score}). A live media library rejects this name.");
        }
    }

    [Fact]
    public async Task NormalImageExtension_IsNotFlaggedByExtensionRule()
    {
        Assert.Null(await new ExecutableUploadExtensionRule().EvaluateAsync(Upload("photo.jpg")));
    }

    [Fact]
    public async Task Rules_HonorCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        IInspectionRule[] rules =
        [
            new ExecutableUploadExtensionRule(),
            new DisguisedExtensionRule(),
            new IisExecutableUploadRule(),
            new IisConfigurationUploadRule(),
            new UnsafeFileNameRule(),
            new PhpContentInUploadRule()
        ];

        foreach (var rule in rules)
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                async () => await rule.EvaluateAsync(Upload("shell.php"), cancellation.Token));
        }
    }
}

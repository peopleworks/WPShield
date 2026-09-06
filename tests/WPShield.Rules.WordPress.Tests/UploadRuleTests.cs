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

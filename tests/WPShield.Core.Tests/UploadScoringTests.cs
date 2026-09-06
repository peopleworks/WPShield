using WPShield.Abstractions;
using WPShield.Core;
using WPShield.Rules.WordPress;

namespace WPShield.Core.Tests;

/// <summary>
/// Verifies the calibration of the shipped rule set against the engine, which is what an operator
/// actually experiences. Individual rule scores are meaningless until they are summed and compared
/// to a site's thresholds.
/// </summary>
public sealed class UploadScoringTests
{
    private static readonly IInspectionRule[] ShippedRules =
    [
        new ExecutableUploadExtensionRule(),
        new DisguisedExtensionRule(),
        new IisExecutableUploadRule(),
        new IisConfigurationUploadRule(),
        new UnsafeFileNameRule(),
        new PhpContentInUploadRule()
    ];

    /// <summary>
    /// The set the gateway actually registers — <c>GatewayApplication</c> adds all eight — which is
    /// what the F4 cases below run against.
    /// </summary>
    /// <remarks>
    /// <see cref="ShippedRules"/> above is the six-rule M1 set, and the cases written against it are
    /// left on it deliberately: they pin the name-only calibration this file has always asserted, and
    /// moving them would silently restate content-rule scores that
    /// <c>tests/WPShield.Rules.WordPress.Tests/ContentRuleTests.cs</c> owns. The F4 payloads are
    /// name-only, so both engines agree on them — running them through the full eight is what proves
    /// that, rather than assuming it.
    /// </remarks>
    private static readonly IInspectionRule[] EveryShippedRule =
    [
        .. ShippedRules,
        new FileTypeMismatchRule(),
        new PhpPolyglotUploadRule()
    ];

    private static SiteOptions Site(ProtectionMode mode) => new()
    {
        Id = "site",
        Hosts = ["example.test"],
        Destination = new Uri("http://127.0.0.1:8081"),
        Mode = mode,
        ObserveThreshold = 30,
        BlockThreshold = 80
    };

    private static Task<InspectionResult> InspectAsync(
        string? fileName,
        ProtectionMode mode = ProtectionMode.Block,
        byte[]? sample = null)
    {
        var engine = new InspectionEngine(ShippedRules);
        var context = new InspectionContext(
            "site",
            "example.test",
            "POST",
            "/wp-admin/async-upload.php",
            fileName,
            "image/jpeg",
            sample ?? []);

        return engine.InspectAsync(context, Site(mode)).AsTask();
    }

    private static Task<InspectionResult> InspectWithEveryRuleAsync(
        string? fileName,
        ProtectionMode mode = ProtectionMode.Block,
        ReadOnlyMemory<byte> sample = default)
    {
        var engine = new InspectionEngine(EveryShippedRule);
        var context = new InspectionContext(
            "site",
            "example.test",
            "POST",
            "/wp-admin/async-upload.php",
            fileName,
            "image/jpeg",
            sample);

        return engine.InspectAsync(context, Site(mode)).AsTask();
    }

    /// <summary>
    /// The score before <c>InspectionEngine</c> caps it at 100. Two views contributing separate
    /// findings routinely sum past the cap, and asserting only the capped value would hide a rule
    /// silently dropping out.
    /// </summary>
    private static int RawScore(InspectionResult result) => result.Findings.Sum(finding => finding.Score);

    [Theory]
    [InlineData("shell.php")]
    [InlineData("shell.php.")]
    [InlineData("shell.php ")]
    [InlineData("shell.php::$DATA")]
    [InlineData("../../shell.php")]
    [InlineData("photo.php.jpg")]
    [InlineData("shell.aspx")]
    [InlineData("web.config")]
    [InlineData("../wp-content/uploads/web.config")]
    public async Task DangerousUploads_ReachTheBlockThreshold(string fileName)
    {
        var result = await InspectAsync(fileName);

        Assert.Equal(InspectionAction.Block, result.RecommendedAction);
        Assert.True(result.Score >= 80, $"'{fileName}' scored only {result.Score}.");
    }

    [Theory]
    [InlineData("photo.jpg")]
    [InlineData("archive.tar.gz")]
    [InlineData("style.min.css")]
    [InlineData("informe-anual.pdf")]
    [InlineData("presentación-española.pptx")]
    [InlineData("日本語のファイル.png")]
    public async Task BenignUploads_AreAllowed(string fileName)
    {
        var result = await InspectAsync(fileName);

        Assert.Equal(InspectionAction.Allow, result.RecommendedAction);
        Assert.Equal(0, result.Score);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task MonitorMode_NeverBlocksEvenAtMaximumScore()
    {
        var result = await InspectAsync("web.config", ProtectionMode.Monitor);

        Assert.Equal(100, result.Score);
        Assert.Equal(InspectionAction.Observe, result.RecommendedAction);
    }

    [Fact]
    public async Task DisabledMode_SkipsEvaluationEntirely()
    {
        var result = await InspectAsync("web.config", ProtectionMode.Disabled);

        Assert.Equal(0, result.Score);
        Assert.Equal(InspectionAction.Allow, result.RecommendedAction);
        Assert.Empty(result.Findings);
    }

    /// <summary>
    /// A structural anomaly on its own is an observation, not grounds for blocking. Some browsers
    /// submit a full local path instead of a bare file name, so this must stay below the threshold.
    /// </summary>
    [Fact]
    public async Task PathPrefixOnBenignFile_IsObservedNotBlocked()
    {
        var result = await InspectAsync(@"C:\Users\author\Pictures\photo.jpg");

        Assert.Equal(InspectionAction.Observe, result.RecommendedAction);
        Assert.Equal(UnsafeFileNameRule.Score, result.Score);
    }

    [Fact]
    public async Task DisguisedUpload_CombinesExtensionAndDisguiseSignals()
    {
        var result = await InspectAsync("photo.php.jpg");

        var ruleIds = result.Findings.Select(finding => finding.RuleId).ToArray();
        Assert.Contains("WP-UPLOAD-001", ruleIds);
        Assert.Contains("WP-UPLOAD-002", ruleIds);
        Assert.Equal(80, result.Score);
    }

    [Fact]
    public async Task PhpContentInAnImageUpload_IsCaughtEvenWhenTheNameLooksBenign()
    {
        var result = await InspectAsync("photo.jpg", sample: "<?php echo 'synthetic marker';"u8.ToArray());

        Assert.Equal(InspectionAction.Observe, result.RecommendedAction);
        Assert.Contains(result.Findings, finding => finding.RuleId == "PHP-CONTENT-001");
    }

    [Fact]
    public async Task ScoreIsCappedAtOneHundred()
    {
        var result = await InspectAsync(
            @"..\..\shell.php.",
            sample: "<?php echo 'synthetic marker';"u8.ToArray());

        Assert.Equal(100, result.Score);
        Assert.Equal(InspectionAction.Block, result.RecommendedAction);
    }

    // ---------------------------------------------------------------------------------------------
    // F4 — the seven measured evasions, through the engine an operator actually runs
    //
    // Each of these scored 0 and was forwarded in Block mode. NTFS writes the name verbatim, so the
    // extension segment was p{h}p or config- and no rule matched; WordPress's sanitize_file_name()
    // deletes its character set and trims '.-_', and the file that lands in wp-content/uploads is
    // the executable one. Scores are asserted exactly rather than as ">= 80", so a future change
    // that weakens one of them fails here instead of on a live site.
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("shell.php", 90)]
    [InlineData("shell.p{h}p", 100)]
    [InlineData("shell.php-", 100)]
    [InlineData("shell.p%hp", 100)]
    [InlineData("web.con{f}ig", 100)]
    [InlineData("web.config-", 100)]
    [InlineData("shell.as{p}x", 100)]
    [InlineData("shell.p(h)p", 100)]
    [InlineData("shell.p!hp", 100)]
    [InlineData("shell.p+hp", 100)]
    [InlineData("shell.p#hp", 100)]
    [InlineData("shell.p~hp", 100)]
    [InlineData("shell.php_", 100)]
    [InlineData("shell.php~", 100)]
    [InlineData("web.config~", 100)]
    [InlineData("web.con(f)ig", 100)]
    [InlineData("functions.php-", 100)]
    [InlineData("photo.p{h}p.jpg", 100)]
    public async Task WordPressRewriteEvasions_ReachTheBlockThreshold(string fileName, int expectedScore)
    {
        var result = await InspectWithEveryRuleAsync(fileName);

        Assert.Equal(expectedScore, result.Score);
        Assert.Equal(InspectionAction.Block, result.RecommendedAction);
    }

    /// <summary>
    /// The arithmetic behind the cap, so a rule quietly dropping out of one of these payloads shows
    /// up as a failure rather than as a still-blocking 100.
    /// </summary>
    [Theory]
    [InlineData("shell.p{h}p", 150, "WP-UPLOAD-001", "FILE-NAME-001")]
    [InlineData("shell.php-", 150, "WP-UPLOAD-001", "FILE-NAME-001")]
    [InlineData("shell.p%hp", 150, "WP-UPLOAD-001", "FILE-NAME-001")]
    [InlineData("shell.as{p}x", 150, "IIS-UPLOAD-001", "FILE-NAME-001")]
    [InlineData("web.con{f}ig", 160, "IIS-CONFIG-001", "FILE-NAME-001")]
    [InlineData("web.config-", 160, "IIS-CONFIG-001", "FILE-NAME-001")]
    public async Task WordPressRewriteEvasions_CombineAnExtensionFindingWithTheRewriteAnomaly(
        string fileName,
        int expectedRawScore,
        params string[] expectedRuleIds)
    {
        var result = await InspectWithEveryRuleAsync(fileName);

        Assert.Equal(expectedRuleIds, result.Findings.Select(finding => finding.RuleId).ToArray());
        Assert.Equal(expectedRawScore, RawScore(result));
        Assert.Equal(100, result.Score);
    }

    /// <summary>
    /// A payload that is dangerous under both views for different reasons. NTFS reads
    /// <c>photo.php.as{p}x</c> as a <c>.php</c> hidden behind a segment nothing executes — 50 plus
    /// the 30-point disguise — and WordPress writes <c>photo.php.aspx</c>, where IIS runs the final
    /// segment as the application pool identity for another 90. Neither view alone reaches 100.
    /// </summary>
    [Fact]
    public async Task BothViewsCanContributeSeparateFindingsToOneRequest()
    {
        var result = await InspectWithEveryRuleAsync("photo.php.as{p}x");

        var ruleIds = result.Findings.Select(finding => finding.RuleId).ToArray();
        Assert.Contains("WP-UPLOAD-001", ruleIds);
        Assert.Contains("WP-UPLOAD-002", ruleIds);
        Assert.Contains("IIS-UPLOAD-001", ruleIds);

        Assert.Equal(50 + 30 + 90, RawScore(result));
        Assert.Equal(100, result.Score);
        Assert.Equal(InspectionAction.Block, result.RecommendedAction);
    }

    /// <summary>
    /// The full kill chain the review described, in one request: a name inert to every check that
    /// reads it as sent, and a body whose only script marker sits past the sample the gateway keeps.
    /// </summary>
    /// <remarks>
    /// <c>PHP-CONTENT-001</c>, <c>PHP-CONTENT-002</c> and <c>FILE-TYPE-001</c> can all be made silent
    /// by an attacker who controls the body — padding past <c>Gateway:Multipart:SampleBytes</c> costs
    /// nothing — so the name rules have to carry this request on their own. Before the WordPress view
    /// they did not: the total was 0, and the upload was forwarded in Block mode without even a
    /// Warning.
    /// </remarks>
    [Theory]
    [InlineData("shell.p{h}p")]
    [InlineData("web.con{f}ig")]
    [InlineData("shell.php-")]
    [InlineData("shell.as{p}x")]
    public async Task TheKillChainIsCaughtOnTheNameWhenTheContentRulesAreBlind(string fileName)
    {
        var result = await InspectWithEveryRuleAsync(fileName, sample: PaddedBodyWithTheMarkerOutOfReach());

        Assert.Equal(InspectionAction.Block, result.RecommendedAction);
        Assert.Equal(100, result.Score);
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "PHP-CONTENT-001");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "PHP-CONTENT-002");
        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "FILE-TYPE-001");
    }

    /// <summary>
    /// What the gateway hands the engine for a body whose marker sits beyond the retained sample:
    /// <c>Gateway:Multipart:SampleBytes</c> bytes of padding and nothing else. The constant is
    /// restated here because Core must not reference the gateway assembly, which is ASP.NET-bound.
    /// </summary>
    private static ReadOnlyMemory<byte> PaddedBodyWithTheMarkerOutOfReach()
    {
        const int sampleBytes = 4096;

        var body = new byte[sampleBytes + 512];
        Array.Fill(body, (byte)'A');

        // Inert: it echoes a string. Placed past the truncation point on purpose, so the assertions
        // above are about the name and nothing else.
        "<?php echo 'synthetic marker'; ?>"u8.CopyTo(body.AsSpan(sampleBytes + 32));

        return body.AsMemory(0, sampleBytes);
    }

    /// <summary>
    /// Monitor mode is where an operator is told to sit while they review their own upload traffic,
    /// so the rewrite has to be visible there before Block mode turns it into a refusal.
    /// </summary>
    [Fact]
    public async Task WordPressRewrite_IsVisibleInMonitorModeWithoutBlocking()
    {
        var result = await InspectWithEveryRuleAsync("web.con{f}ig", ProtectionMode.Monitor);

        Assert.Equal(100, result.Score);
        Assert.Equal(InspectionAction.Observe, result.RecommendedAction);

        var rewrite = Assert.Single(result.Findings, finding => finding.RuleId == "FILE-NAME-001");
        Assert.Contains("wordpressRewrite", rewrite.Evidence?["anomalies"], StringComparison.Ordinal);
        Assert.Equal("web.config", rewrite.Evidence?["wordpressName"]);
    }

    // ---------------------------------------------------------------------------------------------
    // F6 — an invisible character is an anomaly, not a block on its own
    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// A bidi override on an otherwise ordinary name records 60 and stays below the threshold: the
    /// name is suspicious, the file is not. The same override on a <c>.php</c> upload blocks, because
    /// the extension rule has its own reason.
    /// </summary>
    [Theory]
    [InlineData("photo\u202egpj.png", 60, InspectionAction.Observe)]
    [InlineData("photo\u200b.jpg", 60, InspectionAction.Observe)]
    [InlineData("photo\u2066.jpg", 60, InspectionAction.Observe)]
    [InlineData("shell\u202egpj.php", 100, InspectionAction.Block)]
    [InlineData("sh\u200bell.p{h}p", 100, InspectionAction.Block)]
    public async Task InvisibleFormatting_IsScoredAsAnAnomalyNotAsAVerdict(
        string fileName,
        int expectedScore,
        InspectionAction expectedAction)
    {
        var result = await InspectWithEveryRuleAsync(fileName);

        Assert.Equal(expectedScore, result.Score);
        Assert.Equal(expectedAction, result.RecommendedAction);
    }

    /// <summary>
    /// Nothing the engine hands a log consumer may render as something other than what was uploaded.
    /// </summary>
    [Theory]
    [InlineData("shell\u202egpj.php")]
    [InlineData("web\u2066.con{f}ig")]
    [InlineData("photo\u202b\u200b.jpg")]
    public async Task EvidenceReachingTheLogNeverCarriesAnInvisibleCharacter(string fileName)
    {
        var result = await InspectWithEveryRuleAsync(fileName);

        Assert.NotEmpty(result.Findings);
        foreach (var finding in result.Findings)
        {
            foreach (var value in finding.Evidence?.Values ?? [])
            {
                Assert.DoesNotContain(value, IsInvisible);
            }
        }

        static bool IsInvisible(char character) =>
            char.IsControl(character) ||
            character is (>= '\u200b' and <= '\u200f')
                or (>= '\u202a' and <= '\u202e')
                or (>= '\u2066' and <= '\u2069');
    }

    // ---------------------------------------------------------------------------------------------
    // The false-positive half — twenty real upload names the WordPress view rewrites
    //
    // This is the half that decides whether the second view is shippable. Every name here contains a
    // character sanitize_file_name() deletes or collapses. If one of them scores, a live media
    // library stops accepting it, and the operator's fastest remedy is to switch WPShield off.
    // ---------------------------------------------------------------------------------------------

    /// <summary>The names themselves, so the aggregate case can enumerate them directly.</summary>
    private static readonly string[] BenignUploadNames =
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
        "site-kit-analytics-export.csv",
        "Elementor Kit #3 (backup).zip",
        "invoice #42 [paid].pdf",
        "100% cotton.png",
        "don't panic.gif",
        "a&b~c.png",
        "test!.png",
        "1+1=2.png",
        "menu ~ dinner.pdf",
        "C++ notes.txt"
    ];

    public static TheoryData<string> TwentyBenignUploads => [.. BenignUploadNames];

    [Theory]
    [MemberData(nameof(TwentyBenignUploads))]
    public async Task BenignNamesWordPressRewrites_AreAllowed(string fileName)
    {
        var result = await InspectWithEveryRuleAsync(fileName);

        Assert.Equal(0, result.Score);
        Assert.Equal(InspectionAction.Allow, result.RecommendedAction);
        Assert.Empty(result.Findings);
    }

    /// <summary>
    /// The same twenty names taken together. A per-name assertion catches a rule that blocks one
    /// upload; this catches a calibration drift that puts a few points on all of them, which is the
    /// shape a false positive takes when a rewrite-based signal is scored too eagerly.
    /// </summary>
    [Fact]
    public async Task TwentyBenignUploads_DoNotAggregateIntoABlock()
    {
        Assert.Equal(20, BenignUploadNames.Length);

        var total = 0;
        var offenders = new List<string>();

        foreach (var fileName in BenignUploadNames)
        {
            var result = await InspectWithEveryRuleAsync(fileName);
            total += result.Score;

            if (result.RecommendedAction != InspectionAction.Allow)
            {
                offenders.Add($"{fileName} => {result.Score} " +
                              $"[{string.Join(", ", result.Findings.Select(finding => finding.RuleId))}]");
            }
        }

        Assert.True(offenders.Count == 0, "False positives on real upload names: " + string.Join("; ", offenders));
        Assert.Equal(0, total);
    }

}

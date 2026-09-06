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
}

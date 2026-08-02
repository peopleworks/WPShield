using WPShield.Abstractions;
using WPShield.Rules.WordPress;

namespace WPShield.Rules.WordPress.Tests;

public sealed class UploadRuleTests
{
    [Theory]
    [InlineData("shell.php")]
    [InlineData("image.phtml")]
    [InlineData("archive.phar")]
    public async Task ExecutableExtensions_AreFlagged(string fileName)
    {
        var rule = new ExecutableUploadExtensionRule();
        var context = new InspectionContext("site", "example.test", "POST", "/upload", fileName);

        var finding = await rule.EvaluateAsync(context);

        Assert.NotNull(finding);
        Assert.Equal("WP-UPLOAD-001", finding.RuleId);
    }

    [Fact]
    public async Task NormalImageExtension_IsNotFlaggedByExtensionRule()
    {
        var rule = new ExecutableUploadExtensionRule();
        var context = new InspectionContext("site", "example.test", "POST", "/upload", "photo.jpg");

        var finding = await rule.EvaluateAsync(context);

        Assert.Null(finding);
    }
}

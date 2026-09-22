using WPShield.Abstractions;

namespace WPShield.Rules.Windows.Tests;

/// <summary>
/// <c>WP-PATH-002</c> and <c>IIS-PATH-001</c> - the request-path rules with nothing WordPress in them.
/// </summary>
/// <remarks>
/// Both moved to <c>WPShield.Rules.Windows</c> when ADR 0004's first exit condition split the rule
/// packages. <c>WP-PATH-002</c> keeps its identifier even so: a rule ID appears in every stored
/// finding, and renaming one is its own decision. The incident paths and the ordinary-traffic corpus,
/// which score the whole request-path family together, stay in <c>WPShield.Rules.WordPress.Tests</c>.
/// </remarks>
public sealed class RequestPathRuleTests
{
    private static InspectionContext Request(string path, string method = "GET")
    {
        return new InspectionContext("site", "example.test", method, path);
    }

    // ---------------------------------------------------------------------------------------------
    // WP-PATH-002 — executable requested from an asset-only directory
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/wp-content/plugins/example/static/shell.php")]
    [InlineData("/wp-content/plugins/example/dist/shell.php")]
    [InlineData("/wp-content/plugins/example/build/shell.php")]
    [InlineData("/wp-content/plugins/example/node_modules/pkg/shell.php")]
    [InlineData("/wp-content/plugins/example/bower_components/pkg/shell.php")]
    [InlineData("/wp-content/themes/example/fonts/shell.php")]
    [InlineData("/wp-content/themes/example/images/shell.php")]
    [InlineData("/wp-content/themes/example/img/shell.aspx")]
    public async Task ExecutableInAssetDirectory_IsFlagged(string path)
    {
        var finding = await new ExecutableRequestInAssetDirectoryRule().EvaluateAsync(Request(path));

        Assert.NotNull(finding);
        Assert.Equal("WP-PATH-002", finding.RuleId);
        Assert.Equal(ExecutableRequestInAssetDirectoryRule.Score, finding.Score);
    }

    /// <summary>
    /// The names deliberately left out of the asset list, asserted as silent so that adding one later
    /// is a decision rather than an accident.
    /// </summary>
    /// <remarks>
    /// Older plugins genuinely serve generated stylesheets and scripts from PHP, and <c>vendor</c> is
    /// a Composer tree. Flagging these would have put a blocking score on traffic that works today,
    /// and a security tool that breaks a working site gets switched off — taking the rules that were
    /// right with it.
    /// </remarks>
    [Theory]
    [InlineData("/wp-content/plugins/example/css/style.php")]
    [InlineData("/wp-content/plugins/example/js/script.php")]
    [InlineData("/wp-content/plugins/example/assets/handler.php")]
    [InlineData("/wp-content/plugins/example/media/stream.php")]
    [InlineData("/wp-content/plugins/example/vendor/autoload.php")]
    public async Task DirectoriesLeftOutOfTheAssetList_StaySilent(string path)
    {
        Assert.Null(await new ExecutableRequestInAssetDirectoryRule().EvaluateAsync(Request(path)));
    }

    /// <summary>A non-executable file in an asset directory is what asset directories are for.</summary>
    [Theory]
    [InlineData("/wp-content/plugins/example/static/app.js")]
    [InlineData("/wp-content/plugins/example/dist/bundle.min.js")]
    [InlineData("/wp-content/themes/example/fonts/icons.woff2")]
    [InlineData("/wp-content/themes/example/images/hero.jpg")]
    public async Task AssetsInAssetDirectories_StaySilent(string path)
    {
        Assert.Null(await new ExecutableRequestInAssetDirectoryRule().EvaluateAsync(Request(path)));
    }

    // ---------------------------------------------------------------------------------------------
    // IIS-PATH-001 — unsafe path form
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/wp-content/../wp-config.php", "traversal")]
    [InlineData("/wp-content\\themes\\example\\style.css", "backslashSeparator")]
    [InlineData("/wp-config.php::$DATA", "alternateDataStream")]
    [InlineData("/wp-config.php.", "trailingDotsOrSpaces")]
    public async Task UnsafePathForms_AreReportedWithTheAnomalyNamed(string path, string anomaly)
    {
        var finding = await new UnsafeRequestPathRule().EvaluateAsync(Request(path));

        Assert.NotNull(finding);
        Assert.Equal("IIS-PATH-001", finding.RuleId);
        Assert.Equal(UnsafeRequestPathRule.Score, finding.Score);
        Assert.NotNull(finding.Evidence);
        Assert.Contains(anomaly, finding.Evidence["anomalies"], StringComparison.Ordinal);
    }

    /// <summary>
    /// The second decode. A request written as <c>%252e%252e%252f</c> arrives here already decoded
    /// once, looking inert, and becomes traversal one decode later — at a point where nothing is
    /// inspecting. Both readings are reported, because the divergence is the finding.
    /// </summary>
    [Fact]
    public async Task DoubleEncodedTraversal_IsReportedWithBothReadings()
    {
        var finding = await new UnsafeRequestPathRule()
            .EvaluateAsync(Request("/wp-content/%2e%2e%2fwp-config.php"));

        Assert.NotNull(finding);
        Assert.NotNull(finding.Evidence);
        Assert.Contains("doubleEncoded", finding.Evidence["anomalies"], StringComparison.Ordinal);
        Assert.True(finding.Evidence.ContainsKey("decodedPath"));
    }

    /// <summary>
    /// A doubled slash is produced constantly by careless URL concatenation in themes and plugins.
    /// Treating it as hostile would put a finding on a large slice of ordinary traffic.
    /// </summary>
    [Fact]
    public async Task DoubledSlashAlone_IsNotAFinding()
    {
        Assert.Null(await new UnsafeRequestPathRule().EvaluateAsync(Request("/wp-content//themes//example//style.css")));
    }
}

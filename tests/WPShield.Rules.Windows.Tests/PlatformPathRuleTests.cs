using WPShield.Abstractions;

namespace WPShield.Rules.Windows.Tests;

/// <summary>
/// <c>IIS-PATH-002</c>, <c>NET-PATH-001</c>, <c>PHP-PATH-001</c> and <c>PHP-PATH-002</c> - the files
/// that are dangerous because of the platform serving them.
/// </summary>
public sealed class PlatformPathRuleTests
{
    private static InspectionContext Request(string path) => new("site", "example.test", "GET", path);

    // ---------------------------------------------------------------------------------------------
    // IIS-PATH-002 - IIS and ASP.NET configuration
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/web.config")]
    [InlineData("/WEB.CONFIG")]
    [InlineData("/app/web.config")]
    [InlineData("/launchSettings.json")]
    [InlineData("/Properties/launchSettings.json")]
    public async Task AConfigurationFile_IsBlocked(string path)
    {
        var finding = await new IisConfigurationRequestRule().EvaluateAsync(Request(path));

        Assert.NotNull(finding);
        Assert.Equal("IIS-PATH-002", finding.RuleId);
        Assert.Equal(100, finding.Score);
    }

    [Theory]
    [InlineData("/blog/what-is-web.config")]
    [InlineData("/web.config.html")]
    [InlineData("/docs/launchsettings-explained")]
    [InlineData("/config/")]
    public async Task PagesAboutConfiguration_StaySilent(string path)
    {
        Assert.Null(await new IisConfigurationRequestRule().EvaluateAsync(Request(path)));
    }

    /// <summary>
    /// Traversal toward the root's configuration. Normalization resolves the path to
    /// <c>/web.config</c>, which fires here, and <c>IIS-PATH-001</c> reports the traversal beside it:
    /// both, because each says something the other does not.
    /// </summary>
    [Fact]
    public async Task TraversalTowardWebConfig_FiresBothTheFileAndThePathRule()
    {
        var context = Request("/assets/../../web.config");

        var file = await new IisConfigurationRequestRule().EvaluateAsync(context);
        var form = await new UnsafeRequestPathRule().EvaluateAsync(context);

        Assert.NotNull(file);
        Assert.NotNull(file.Evidence);
        Assert.Equal("/web.config", file.Evidence["normalizedPath"]);
        Assert.NotNull(form);
        Assert.NotNull(form.Evidence);
        Assert.Contains("traversal", form.Evidence["anomalies"], StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------------------------------
    // NET-PATH-001 - ASP.NET Core settings
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/appsettings.json")]
    [InlineData("/appsettings.Development.json")]
    [InlineData("/appsettings.Production.json")]
    [InlineData("/api/appsettings.json")]
    public async Task ASettingsFile_IsObservedButNeverBlocked(string path)
    {
        var finding = await new AppSettingsRequestRule().EvaluateAsync(Request(path));

        Assert.NotNull(finding);
        Assert.Equal("NET-PATH-001", finding.RuleId);
        Assert.Equal(30, finding.Score);
    }

    [Theory]
    // What a Blazor WebAssembly client loads on every page, and none of it is a settings file.
    [InlineData("/_framework/blazor.boot.json")]
    [InlineData("/_framework/dotnet.wasm")]
    [InlineData("/_content/Component.Library/styles.css")]
    [InlineData("/manifest.json")]
    [InlineData("/appsettings")]
    [InlineData("/appsettings.a.b.json")]
    [InlineData("/myappsettings.json")]
    public async Task OrdinaryDotNetFiles_StaySilent(string path)
    {
        Assert.Null(await new AppSettingsRequestRule().EvaluateAsync(Request(path)));
    }

    // ---------------------------------------------------------------------------------------------
    // PHP-PATH-001 - PHPUnit
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "vendor/phpunit")]
    [InlineData("/api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "vendor/phpunit")]
    [InlineData("/laravel/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php", "vendor/phpunit")]
    [InlineData("/vendor/phpunit/", "vendor/phpunit")]
    [InlineData("/lib/phpunit/src/Util/PHP/eval-stdin.php", "eval-stdin.php")]
    public async Task PhpUnit_IsBlocked(string path, string form)
    {
        var finding = await new PhpUnitRequestRule().EvaluateAsync(Request(path));

        Assert.NotNull(finding);
        Assert.Equal("PHP-PATH-001", finding.RuleId);
        Assert.Equal(100, finding.Score);
        Assert.NotNull(finding.Evidence);
        Assert.Equal(form, finding.Evidence["form"]);
    }

    [Theory]
    // A Composer tree some plugins expose, and which WP-PATH-002 leaves alone on purpose.
    [InlineData("/wp-content/plugins/example/vendor/autoload.php")]
    [InlineData("/vendor/guzzlehttp/guzzle/src/Client.php")]
    [InlineData("/docs/phpunit/")]
    public async Task OtherVendoredCode_IsNotThisRule(string path)
    {
        Assert.Null(await new PhpUnitRequestRule().EvaluateAsync(Request(path)));
    }

    // ---------------------------------------------------------------------------------------------
    // PHP-PATH-002 - phpinfo and test scripts
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/phpinfo.php")]
    [InlineData("/info.php")]
    [InlineData("/test.php")]
    [InlineData("/php-info.php")]
    [InlineData("/_phpinfo.php")]
    [InlineData("/old_phpinfo.php")]
    [InlineData("/admin/phpinfo.php")]
    // PHP executes the script and hands it the rest as path-info.
    [InlineData("/info.php/anything")]
    public async Task APhpInfoPage_IsObservedButNeverBlocked(string path)
    {
        var finding = await new PhpInfoRequestRule().EvaluateAsync(Request(path));

        Assert.NotNull(finding);
        Assert.Equal("PHP-PATH-002", finding.RuleId);
        Assert.Equal(30, finding.Score);
    }

    [Theory]
    [InlineData("/index.php")]
    [InlineData("/wp-login.php")]
    [InlineData("/information.php")]
    [InlineData("/phpinfo")]
    [InlineData("/phpinfo.php.bak")]
    [InlineData("/testing.php")]
    public async Task OrdinaryScripts_StaySilent(string path)
    {
        Assert.Null(await new PhpInfoRequestRule().EvaluateAsync(Request(path)));
    }

    [Fact]
    public void Scores_AreThePublishedCalibration()
    {
        Assert.Equal(100, IisConfigurationRequestRule.Score);
        Assert.Equal(30, AppSettingsRequestRule.Score);
        Assert.Equal(100, PhpUnitRequestRule.Score);
        Assert.Equal(30, PhpInfoRequestRule.Score);
    }
}

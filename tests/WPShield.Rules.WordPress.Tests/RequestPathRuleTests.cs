using WPShield.Abstractions;
using WPShield.Rules.Windows;

namespace WPShield.Rules.WordPress.Tests;

/// <summary>
/// Covers the request-path family, which decides from the request line alone.
/// </summary>
/// <remarks>
/// The paths in the first section are the shapes taken from a real compromise of a WordPress site on
/// IIS, reduced to their structure: no hostname, no client address, and no payload — only the
/// directory shape and the file name pattern, which is the part a rule can act on. They are here
/// because a rule family invented from a threat model tends to cover the attacks the author imagined,
/// and these are the ones that actually happened.
/// </remarks>
public sealed class RequestPathRuleTests
{
    private static InspectionContext Request(string path, string method = "GET")
    {
        return new InspectionContext("site", "example.test", method, path);
    }

    /// <summary>
    /// Every request-path rule both packages ship, found by reflection rather than listed by hand.
    /// </summary>
    /// <remarks>
    /// A hand-written list is how a new rule escapes the ordinary-traffic corpus below: it is added to
    /// the gateway, never added here, and the one test that would have caught it scoring a real page
    /// never runs it. Discovered, a new rule is in the corpus the moment it exists.
    /// </remarks>
    private static readonly IRequestPathRule[] AllPathRules =
    [
        .. new[] { typeof(ExecutableRequestUnderUploadsRule).Assembly, typeof(UnsafeRequestPathRule).Assembly }
            .SelectMany(assembly => assembly.GetTypes())
            .Where(type => type is { IsClass: true, IsAbstract: false } && typeof(IRequestPathRule).IsAssignableFrom(type))
            .OrderBy(type => type.FullName, StringComparer.Ordinal)
            .Select(type => (IRequestPathRule)Activator.CreateInstance(type)!)
    ];

    private static async Task<int> ScoreAsync(string path)
    {
        var total = 0;
        foreach (var rule in AllPathRules)
        {
            if (await rule.EvaluateAsync(Request(path)) is { } finding)
            {
                total += finding.Score;
            }
        }

        return Math.Min(100, total);
    }

    // ---------------------------------------------------------------------------------------------
    // The incident. Default thresholds are 30 to observe and 80 to block.
    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// Five of the six webshell locations recovered from the incident reach the default block
    /// threshold from the request line alone, with no body to inspect.
    /// </summary>
    [Theory]
    // Planted beside a vendored code editor's JavaScript.
    [InlineData("/wp-content/plugins/exampleslider/static/codemirror/addon/display/index.php")]
    [InlineData("/wp-content/plugins/exampleslider/static/codemirror/addon/comment/archive1.php")]
    // Planted beside a slider skin's stylesheets.
    [InlineData("/wp-content/plugins/exampleslider/static/exampleslider/skins/lightskin/terms.php")]
    // Left in the media library years before the rest, and never noticed.
    [InlineData("/wp-content/uploads/2021/02/tuto1.php")]
    [InlineData("/wp-content/uploads/2021/10/Proprietary.php")]
    public async Task IncidentWebshellPaths_ReachTheBlockThreshold(string path)
    {
        Assert.True(await ScoreAsync(path) >= 80, $"'{path}' scored below the default block threshold.");
    }

    /// <summary>
    /// The sixth does not, and that is recorded rather than hidden.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The shell sat in a plugin's own PHP directory, beside the plugin's genuine PHP files, under a
    /// name one character away from a real one. Nothing about the <i>path</i> distinguishes it: the
    /// directory legitimately contains scripts, and the request is an ordinary <c>GET</c>. Catching it
    /// needs something this rule family does not have — knowledge of which files a given plugin
    /// version actually ships, or behaviour over time — and inventing a heuristic that happened to
    /// match this one name would be fitting the rule to the sample.
    /// </para>
    /// <para>
    /// This test asserts the gap so that closing it has to be deliberate. A future rule that catches
    /// this shape will fail here, and whoever writes it must come back and say why the new rule cannot
    /// be wrong about the plugin PHP files that are legitimate.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task IncidentShellInsideAPluginPhpDirectory_IsAKnownGap()
    {
        Assert.Equal(0, await ScoreAsync("/wp-content/plugins/exampleslider/wp/import1.php"));
    }

    // ---------------------------------------------------------------------------------------------
    // WP-PATH-001 — executable requested from the uploads tree
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/wp-content/uploads/shell.php")]
    [InlineData("/wp-content/uploads/2026/09/shell.php")]
    [InlineData("/WP-CONTENT/UPLOADS/SHELL.PHP")]
    [InlineData("/wp-content/uploads/shell.phtml")]
    [InlineData("/wp-content/uploads/shell.phar")]
    [InlineData("/wp-content/uploads/shell.aspx")]
    [InlineData("/wp-content/uploads/shell.ashx")]
    [InlineData("/blog/wp-content/uploads/shell.php")]
    [InlineData("/wp-content/upgrade/shell.php")]
    [InlineData("/wp-content/updraft/shell.php")]
    public async Task ExecutableUnderUploads_IsFlagged(string path)
    {
        var finding = await new ExecutableRequestUnderUploadsRule().EvaluateAsync(Request(path));

        Assert.NotNull(finding);
        Assert.Equal("WP-PATH-001", finding.RuleId);
        Assert.Equal(ExecutableRequestUnderUploadsRule.Score, finding.Score);
    }

    /// <summary>
    /// The Windows and IIS forms that reach the same file. Each of these opens
    /// <c>shell.php</c> on disk, so each must produce the same finding.
    /// </summary>
    [Theory]
    [InlineData("/wp-content/uploads/shell.php.")]
    [InlineData("/wp-content/uploads/shell.php ")]
    [InlineData("/wp-content/uploads/shell.php::$DATA")]
    [InlineData("/wp-content\\uploads\\shell.php")]
    [InlineData("/wp-content/uploads/./shell.php")]
    [InlineData("/wp-content/uploads/nested/../shell.php")]
    [InlineData("/wp-content//uploads//shell.php")]
    [InlineData("/wp-content/uploads/shell.php.jpg")]
    public async Task WindowsPathEvasions_ReachTheSameFinding(string path)
    {
        var finding = await new ExecutableRequestUnderUploadsRule().EvaluateAsync(Request(path));

        Assert.NotNull(finding);
        Assert.Equal("WP-PATH-001", finding.RuleId);
    }

    /// <summary>
    /// PHP path-info execution. With <c>cgi.fix_pathinfo</c> enabled — the default on many Windows
    /// PHP-FastCGI installations — this request runs <c>shell.php</c> and hands it <c>/logo.jpg</c>.
    /// A rule that looked only at the last segment would see an image.
    /// </summary>
    [Fact]
    public async Task PathInfoExecution_IsFlaggedAndReported()
    {
        var finding = await new ExecutableRequestUnderUploadsRule()
            .EvaluateAsync(Request("/wp-content/uploads/shell.php/logo.jpg"));

        Assert.NotNull(finding);
        Assert.NotNull(finding.Evidence);
        Assert.Equal("true", finding.Evidence["pathInfo"]);
        Assert.Equal("php", finding.Evidence["extension"]);
    }

    /// <summary>
    /// The uploads directory must be entered, not merely mentioned. Without the position check a
    /// request for a script at the root would be attributed to a directory it never reached.
    /// </summary>
    [Theory]
    [InlineData("/shell.php")]
    [InlineData("/uploads-report.php")]
    [InlineData("/wp-content/plugins/uploader/handler.php")]
    public async Task ExecutableOutsideUploads_IsNotFlaggedByThatRule(string path)
    {
        Assert.Null(await new ExecutableRequestUnderUploadsRule().EvaluateAsync(Request(path)));
    }

    // ---------------------------------------------------------------------------------------------
    // False positives — ordinary WordPress traffic must stay silent across the whole family
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/")]
    [InlineData("/index.php")]
    [InlineData("/wp-login.php")]
    [InlineData("/wp-admin/")]
    [InlineData("/wp-admin/admin-ajax.php")]
    [InlineData("/wp-admin/async-upload.php")]
    [InlineData("/wp-cron.php")]
    [InlineData("/xmlrpc.php")]
    [InlineData("/wp-json/wp/v2/posts")]
    [InlineData("/wp-includes/js/jquery/jquery.min.js")]
    [InlineData("/wp-content/themes/example/style.css")]
    [InlineData("/wp-content/plugins/elementor/assets/js/frontend.min.js")]
    [InlineData("/wp-content/plugins/google-site-kit/dist/assets/js/googlesitekit-main.js")]
    [InlineData("/wp-content/uploads/2026/09/photo.jpg")]
    [InlineData("/wp-content/uploads/2026/09/photo-1024x768.webp")]
    [InlineData("/wp-content/uploads/2026/09/informe-anual.pdf")]
    [InlineData("/wp-content/uploads/elementor/css/post-42.css")]
    [InlineData("/blog/2026/09/un-articulo-con-acentos-y-guiones/")]
    [InlineData("/feed/")]
    [InlineData("/robots.txt")]
    [InlineData("/favicon.ico")]
    public async Task OrdinaryWordPressTraffic_ScoresZero(string path)
    {
        Assert.Equal(0, await ScoreAsync(path));
    }

    /// <summary>
    /// The family covers far more than WordPress now, so the corpus does too: what an ASP.NET Core
    /// site, a Blazor WebAssembly client, an API and a certificate renewal ask for on an ordinary day.
    /// </summary>
    [Theory]
    [InlineData("/_framework/blazor.boot.json")]
    [InlineData("/_framework/blazor.webassembly.js")]
    [InlineData("/_framework/dotnet.native.wasm")]
    [InlineData("/_blazor/negotiate")]
    [InlineData("/_content/Component.Library/styles.css")]
    [InlineData("/css/app.css")]
    [InlineData("/Error")]
    [InlineData("/health")]
    [InlineData("/swagger/index.html")]
    [InlineData("/swagger/v1/swagger.json")]
    [InlineData("/api/v1.1/items")]
    [InlineData("/api/orders/42")]
    [InlineData("/login")]
    [InlineData("/admin")]
    [InlineData("/.well-known/acme-challenge/token-value")]
    [InlineData("/sitemap.xml.gz")]
    [InlineData("/downloads/brochure.zip")]
    [InlineData("/manifest.webmanifest")]
    public async Task OrdinaryDotNetTraffic_ScoresZero(string path)
    {
        Assert.Equal(0, await ScoreAsync(path));
    }

    /// <summary>
    /// A Blazor WebAssembly client loads its settings file on every page load, by design. The family
    /// observes it - an operator learns the file is public - and never reaches the block threshold,
    /// because blocking it would break every such application.
    /// </summary>
    [Theory]
    [InlineData("/appsettings.json")]
    [InlineData("/appsettings.Production.json")]
    public async Task ABlazorSettingsFile_IsObservedAndNeverBlocked(string path)
    {
        var score = await ScoreAsync(path);

        Assert.True(score is >= 30 and < 80, $"'{path}' scored {score}.");
    }

    /// <summary>
    /// The probes that reach every site on a shared host, whatever runs on it - the reason this family
    /// exists. Each reaches the default block threshold from the request line alone.
    /// </summary>
    [Theory]
    [InlineData("/.env")]
    [InlineData("/backend/.env.production")]
    [InlineData("/.git/config")]
    [InlineData("/.aws/credentials")]
    [InlineData("/wp-config.php.bak")]
    [InlineData("/web.config")]
    [InlineData("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php")]
    public async Task ExposureProbes_ReachTheBlockThreshold(string path)
    {
        Assert.True(await ScoreAsync(path) >= 80, $"'{path}' scored below the default block threshold.");
    }

    /// <summary>
    /// <c>/admin</c> is probed from hundreds of addresses and is deliberately not a rule. It is a real
    /// route on many real sites, and a rule that scored it would be scoring a page, not a probe.
    /// </summary>
    [Theory]
    [InlineData("/admin")]
    [InlineData("/dashboard")]
    [InlineData("/signin")]
    public async Task CommonlyProbedRealRoutes_AreDeliberatelyNotRules(string path)
    {
        Assert.Equal(0, await ScoreAsync(path));
    }

    [Fact]
    public void TheCorpusRunsEveryShippedPathRule()
    {
        // Positive control for the reflection above: the three rules this file started with, and the
        // nine the exposure family added.
        Assert.Equal(12, AllPathRules.Length);
    }

    /// <summary>
    /// Evidence must never carry the raw request target. A raw path can hold control characters and
    /// ANSI escape sequences that reach a terminal or a log viewer intact.
    /// </summary>
    [Fact]
    public async Task Evidence_ReportsTheNormalizedPathAndNotTheRawOne()
    {
        // An ANSI colour escape embedded in the request target. Written through an escape sequence
        // rather than as a literal, so that this source file stays free of control characters.
        const string escape = "\u001b";
        var hostile = $"/wp-content/uploads/sh{escape}[31mell.php";

        var finding = await new ExecutableRequestUnderUploadsRule().EvaluateAsync(Request(hostile));

        Assert.NotNull(finding);
        Assert.NotNull(finding.Evidence);

        foreach (var value in finding.Evidence.Values)
        {
            Assert.DoesNotContain(escape, value, StringComparison.Ordinal);
        }

        Assert.Equal("/wp-content/uploads/sh[31mell.php", finding.Evidence["normalizedPath"]);
    }

    [Fact]
    public async Task Rules_HonourCancellation()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await new ExecutableRequestUnderUploadsRule()
                .EvaluateAsync(Request("/wp-content/uploads/shell.php"), cancelled.Token));
    }
}

using WPShield.Cli;
using WPShield.Cli.Audit;
using WPShield.Cli.Preflight;

namespace WPShield.Cli.Tests.Audit;

/// <summary>
/// The posture checks, exercised without IIS.
/// </summary>
/// <remarks>
/// Each shape below is a common configuration of a shared IIS host, with placeholder names: a pool
/// running as the machine's administrator, PHP mapped for every site, site folders writable by every
/// account, and a site answering any host name from the folder that holds all the others. Together
/// they turn one compromised site into a compromised server.
/// </remarks>
public sealed class AuditRunnerTests
{
    private const string WebRoot = @"C:\inetpub\wwwroot";

    // =============================================================================================
    //  AUDIT-001 - an audit that could not look must not read as a clean one
    // =============================================================================================

    [Fact]
    public void NotElevated_IsCriticalAndMarksTheAuditIncomplete()
    {
        var report = Run(Facts(elevated: false));

        Assert.False(report.Complete);
        Assert.Contains(report.Findings, finding => finding.Id == "AUDIT-001" && finding.Severity == AuditSeverity.Critical);
        Assert.Equal(AuditCommand.ExitIncomplete, AuditCommand.ExitCode(report));
    }

    /// <summary>
    /// "Nobody could look" is not "there is nothing there". With IIS unreadable no IIS check runs at
    /// all, rather than every one of them passing over an empty list.
    /// </summary>
    [Fact]
    public void UnreadableIis_StopsBeforeAnyIisCheckCanPass()
    {
        var report = Run(Facts(iisReadable: false));

        Assert.False(report.Complete);
        Assert.All(report.Findings, finding => Assert.Equal("AUDIT-001", finding.Id));
        Assert.DoesNotContain(report.Findings, finding => finding.Severity == AuditSeverity.Pass);
    }

    [Fact]
    public void AWellBuiltServer_HasNoCriticalFindingAndExitsZero()
    {
        var report = Run(Facts(
            pools: [Pool("blog"), Pool("api")],
            sites:
            [
                Site("blog", $@"{WebRoot}\blog", pool: "blog", wordPress: true, php: true),
                Site("api", @"C:\sites\api", pool: "api")
            ]));

        Assert.True(report.Complete);
        Assert.Empty(report.Criticals);
        Assert.Empty(report.Warnings);
        Assert.Equal(AuditCommand.ExitClean, AuditCommand.ExitCode(report));
    }

    // =============================================================================================
    //  AUDIT-002 - pools with administrator rights
    // =============================================================================================

    [Fact]
    public void APoolRunningAsLocalSystem_IsCritical()
    {
        var report = Run(Facts(pools: [Pool("reports", identity: "LocalSystem")]));

        var finding = Find(report, "AUDIT-002");
        Assert.Equal(AuditSeverity.Critical, finding.Severity);
        Assert.Contains(finding.Items!, item => item.Contains("reports", StringComparison.Ordinal));
    }

    /// <summary>
    /// A pool configured with the machine's own administrator account. The finding names the sites
    /// the pool serves, because those are the sites a shell would have administrator rights from.
    /// </summary>
    [Fact]
    public void APoolRunningAsALocalAdministrator_IsCriticalAndNamesTheSitesItServes()
    {
        var report = Run(Facts(
            pools: [Pool("blog", identity: "SpecificUser", user: "Administrator", administrator: true)],
            sites: [Site("blog.example", $@"{WebRoot}\blog", pool: "blog", wordPress: true)]));

        var finding = Find(report, "AUDIT-002");
        Assert.Equal(AuditSeverity.Critical, finding.Severity);
        Assert.Contains(finding.Items!, item =>
            item.Contains("Administrator", StringComparison.Ordinal) &&
            item.Contains("blog.example", StringComparison.Ordinal));
        Assert.Equal(AuditCommand.ExitCritical, AuditCommand.ExitCode(report));
    }

    [Fact]
    public void APoolRunningAsAnOrdinaryAccount_IsNotAnAdministratorFinding()
    {
        var report = Run(Facts(pools: [Pool("app", identity: "SpecificUser", user: "svc-app", administrator: false)]));

        Assert.Equal(AuditSeverity.Pass, Find(report, "AUDIT-002").Severity);
    }

    /// <summary>
    /// An account that could not be resolved is unknown, and unknown is not "no". It is reported as a
    /// warning to check by hand rather than passed.
    /// </summary>
    [Fact]
    public void AnUnresolvedPoolAccount_IsAWarningRatherThanAPass()
    {
        var report = Run(Facts(pools: [Pool("app", identity: "SpecificUser", user: "OLDDOMAIN\\gone", administrator: null)]));

        var finding = Find(report, "AUDIT-002");
        Assert.Equal(AuditSeverity.Warn, finding.Severity);
        Assert.Contains(finding.Items!, item => item.Contains("could not tell", StringComparison.Ordinal));
    }

    // =============================================================================================
    //  AUDIT-003 - shared built-in identities
    // =============================================================================================

    [Fact]
    public void PoolsSharingNetworkService_AreAWarning()
    {
        var report = Run(Facts(pools: [Pool("a", identity: "NetworkService"), Pool("b", identity: "NetworkService")]));

        var finding = Find(report, "AUDIT-003");
        Assert.Equal(AuditSeverity.Warn, finding.Severity);
        Assert.Equal(2, finding.Items!.Count);
    }

    // =============================================================================================
    //  AUDIT-004 - PHP mapped for the whole server
    // =============================================================================================

    [Fact]
    public void ServerWidePhp_NamesTheSitesThatRunItWithoutWordPress()
    {
        var report = Run(Facts(
            handlers: [Php()],
            sites:
            [
                Site("blog", $@"{WebRoot}\blog", wordPress: true, php: true),
                Site("help", $@"{WebRoot}\help", php: true),
                Site("api", $@"{WebRoot}\api", php: true)
            ]));

        var finding = Find(report, "AUDIT-004");
        Assert.Equal(AuditSeverity.Warn, finding.Severity);
        Assert.Contains(finding.Items!, item => item.Contains("help", StringComparison.Ordinal));
        Assert.Contains(finding.Items!, item => item.Contains("api", StringComparison.Ordinal));
        Assert.DoesNotContain(finding.Items!, item => item.Contains("blog", StringComparison.Ordinal) && item.Contains("no WordPress", StringComparison.Ordinal));
    }

    [Fact]
    public void ServerWidePhp_WhereOnlyWordPressRunsIt_IsReportedButNotAWarning()
    {
        var report = Run(Facts(handlers: [Php()], sites: [Site("blog", $@"{WebRoot}\blog", wordPress: true, php: true)]));

        Assert.Equal(AuditSeverity.Info, Find(report, "AUDIT-004").Severity);
    }

    /// <summary>
    /// A site whose configuration could not be read may run PHP. It is listed as unknown and keeps the
    /// finding a warning, rather than silently dropping out of the count.
    /// </summary>
    [Fact]
    public void ServerWidePhp_WithAnUnreadableSiteConfiguration_ListsItAsUnknown()
    {
        var report = Run(Facts(
            handlers: [Php()],
            sites:
            [
                Site("blog", $@"{WebRoot}\blog", wordPress: true, php: true),
                Site("broken", $@"{WebRoot}\broken", php: null)
            ]));

        var finding = Find(report, "AUDIT-004");
        Assert.Equal(AuditSeverity.Warn, finding.Severity);
        Assert.Contains(finding.Items!, item => item.Contains("unknown: broken", StringComparison.Ordinal));
    }

    [Fact]
    public void PhpMappedOnlyPerSite_Passes()
    {
        var report = Run(Facts(
            handlers: [new AuditHandler("StaticFile", "*", string.Empty)],
            sites: [Site("blog", $@"{WebRoot}\blog", wordPress: true, php: true)]));

        Assert.Equal(AuditSeverity.Pass, Find(report, "AUDIT-004").Severity);
    }

    // =============================================================================================
    //  AUDIT-005 - site folders every account can write into
    // =============================================================================================

    [Fact]
    public void AFolderWritableByUsers_IsCriticalAndNamesTheGroup()
    {
        var report = Run(Facts(sites: [Site("help", $@"{WebRoot}\help", writers: ["BUILTIN\\Users (S-1-5-32-545)"])]));

        var finding = Find(report, "AUDIT-005");
        Assert.Equal(AuditSeverity.Critical, finding.Severity);
        Assert.Contains(finding.Items!, item => item.Contains("S-1-5-32-545", StringComparison.Ordinal));
    }

    [Fact]
    public void UnreadableFolderPermissions_AreAWarningRatherThanAPass()
    {
        var report = Run(Facts(sites:
        [
            new AuditSite("help", "Started", $@"{WebRoot}\help", "help", [Http("*:80:help.example")],
                false, false, new FolderAccess(true, [], "Access is denied."))
        ]));

        Assert.Equal(AuditSeverity.Warn, Find(report, "AUDIT-005").Severity);
    }

    [Fact]
    public void AMissingFolder_IsNotReportedAsWritable()
    {
        var report = Run(Facts(sites:
        [
            new AuditSite("gone", "Stopped", @"C:\nowhere", "gone", [Http("*:80:gone.example")],
                false, false, new FolderAccess(false, []))
        ]));

        Assert.Equal(AuditSeverity.Pass, Find(report, "AUDIT-005").Severity);
    }

    // =============================================================================================
    //  AUDIT-006 - a catch-all site over the others
    // =============================================================================================

    /// <summary>
    /// The shape that keeps a stopped site's files reachable: <c>Default Web Site</c> bound to
    /// <c>*:80:</c>, serving <c>C:\inetpub\wwwroot</c>, which holds every other site's folder.
    /// </summary>
    [Fact]
    public void ARunningCatchAllSiteOverOtherSites_IsCritical()
    {
        var report = Run(Facts(sites:
        [
            Site("Default Web Site", WebRoot, binding: "*:80:"),
            Site("blog", $@"{WebRoot}\blog", wordPress: true),
            Site("help", $@"{WebRoot}\help")
        ]));

        var finding = Find(report, "AUDIT-006.Default Web Site");
        Assert.Equal(AuditSeverity.Critical, finding.Severity);
        Assert.Equal(2, finding.Items!.Count);
    }

    [Fact]
    public void AStoppedCatchAllSite_IsAWarningBecauseStartingItReopensEverything()
    {
        var report = Run(Facts(sites:
        [
            Site("Default Web Site", WebRoot, binding: "*:80:", state: "Stopped"),
            Site("blog", $@"{WebRoot}\blog")
        ]));

        Assert.Equal(AuditSeverity.Warn, Find(report, "AUDIT-006.Default Web Site").Severity);
    }

    /// <summary>A sibling folder whose name merely starts the same is not inside.</summary>
    [Fact]
    public void ASiblingFolderWithASharedPrefix_IsNotContained()
    {
        var report = Run(Facts(sites:
        [
            Site("Default Web Site", WebRoot, binding: "*:80:"),
            Site("other", $"{WebRoot}2")
        ]));

        Assert.Equal(AuditSeverity.Pass, Find(report, "AUDIT-006").Severity);
    }

    [Theory]
    [InlineData("*:80:portal.example")]
    [InlineData("127.0.0.1:8081:")]
    public void ASiteWithAHostNameOrOnlyALoopbackBinding_IsNotACatchAll(string binding)
    {
        var report = Run(Facts(sites:
        [
            Site("portal", WebRoot, binding: binding),
            Site("blog", $@"{WebRoot}\blog")
        ]));

        Assert.Equal(AuditSeverity.Pass, Find(report, "AUDIT-006").Severity);
    }

    // =============================================================================================
    //  Contracts
    // =============================================================================================

    /// <summary>
    /// Every warning and critical finding says what to do. A posture audit that reports a problem
    /// without a remedy has moved the problem rather than solved it.
    /// </summary>
    [Fact]
    public void EveryWarningAndCriticalFinding_CarriesARemedy()
    {
        var report = Run(WorstCase());

        var actionable = report.Findings
            .Where(finding => finding.Severity is AuditSeverity.Warn or AuditSeverity.Critical)
            .ToArray();

        Assert.NotEmpty(actionable);
        Assert.All(actionable, finding => Assert.False(string.IsNullOrWhiteSpace(finding.Remedy), finding.Id));
    }

    /// <summary>
    /// Every remedy is a change made by hand. The verb names the fix and never applies it, so no
    /// remedy may read as if the tool will do it.
    /// </summary>
    [Fact]
    public void EveryRemedy_IsAChangeMadeByHand()
    {
        var report = Run(WorstCase());

        Assert.All(
            report.Findings.Where(finding => finding.Severity is AuditSeverity.Critical && finding.Id != "AUDIT-001"),
            finding => Assert.Contains("by hand", finding.Remedy, StringComparison.OrdinalIgnoreCase));
    }

    // =============================================================================================
    //  Helpers
    // =============================================================================================

    private static AuditFacts WorstCase() => Facts(
        pools:
        [
            Pool("blog", identity: "SpecificUser", user: "Administrator", administrator: true),
            Pool("bi", identity: "LocalSystem"),
            Pool("legacy", identity: "NetworkService")
        ],
        handlers: [Php()],
        sites:
        [
            Site("Default Web Site", WebRoot, binding: "*:80:", writers: ["Everyone (S-1-1-0)"]),
            Site("blog", $@"{WebRoot}\blog", pool: "blog", wordPress: true, php: true, writers: ["BUILTIN\\IIS_IUSRS (S-1-5-32-568)"]),
            Site("help", $@"{WebRoot}\help", pool: "legacy", php: true)
        ]);

    private static AuditReport Run(AuditFacts facts) => new AuditRunner(facts).Run();

    private static AuditFinding Find(AuditReport report, string id) =>
        Assert.Single(report.Findings, finding => finding.Id == id);

    private static AuditFacts Facts(
        IReadOnlyList<AuditPool>? pools = null,
        IReadOnlyList<AuditSite>? sites = null,
        IReadOnlyList<AuditHandler>? handlers = null,
        bool elevated = true,
        bool iisReadable = true) =>
        new(elevated, iisReadable, iisReadable ? null : "Access is denied.", pools ?? [], sites ?? [], handlers ?? []);

    private static AuditPool Pool(
        string name,
        string identity = "ApplicationPoolIdentity",
        string? user = null,
        bool? administrator = null) =>
        new(name, "Started", identity, user, administrator);

    private static AuditSite Site(
        string name,
        string path,
        string pool = "pool",
        string state = "Started",
        string? binding = null,
        bool wordPress = false,
        bool? php = false,
        IReadOnlyList<string>? writers = null) =>
        new(name, state, path, pool, [Http(binding ?? $"*:80:{name.Replace(' ', '-')}.example")],
            wordPress, php, new FolderAccess(true, writers ?? []));

    private static IisBinding Http(string bindingInformation) => new("http", bindingInformation);

    private static AuditHandler Php() =>
        new("PHP_via_FastCGI", "*.php", @"C:\Program Files\PHP\php-cgi.exe");
}

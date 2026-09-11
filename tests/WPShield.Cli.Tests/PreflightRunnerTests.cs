using WPShield.Cli.Preflight;

namespace WPShield.Cli.Tests;

/// <summary>
/// The readiness checks, exercised without IIS.
/// </summary>
/// <remarks>
/// <para>
/// <b>This file is the reason the preflight moved.</b> The PowerShell version could only be run on a
/// server that had IIS, ARR, URL Rewrite and the right failure conditions, which in practice meant it
/// was exercised once, on production. That is how <c>PRE-018</c> shipped unable to match the one rule
/// it existed to find, and how <c>PRE-019</c> passed on the very server where an unpacked copy of the
/// gateway sat inside a web root.
/// </para>
/// <para>
/// Both of those are asserted below, from facts a test can state.
/// </para>
/// </remarks>
public sealed class PreflightRunnerTests
{
    // =============================================================================================
    //  The two ARR switches the whole check exists for.
    // =============================================================================================

    [Fact]
    public void ArrProxyDisabled_IsABlockerThatExplainsTheSilent404()
    {
        var report = Run(iis: Iis(arrProxyEnabled: false));

        var check = Find(report, "PRE-007");
        Assert.Equal(PreflightStatus.Blocker, check.Status);
        Assert.Contains("404 for every request", check.Detail, StringComparison.Ordinal);
        Assert.NotEmpty(check.Remedy);
    }

    [Fact]
    public void ArrHostHeaderNotPreserved_IsABlockerThatExplainsThe421()
    {
        var report = Run(iis: Iis(preserveHostHeader: false));

        var check = Find(report, "PRE-008");
        Assert.Equal(PreflightStatus.Blocker, check.Status);
        Assert.Contains("421", check.Detail, StringComparison.Ordinal);
        Assert.Contains("SERVER-LEVEL", check.Remedy, StringComparison.Ordinal);
    }

    /// <summary>
    /// An unreadable setting is not a disabled one, and this check does not guess. Reporting a false
    /// here would send an operator to change a server-wide switch that was already correct.
    /// </summary>
    [Fact]
    public void AnUnreadableArrSetting_IsAWarningRatherThanAnInventedFalse()
    {
        var report = Run(iis: Iis(arrProxyEnabled: null, preserveHostHeader: null));

        Assert.Equal(PreflightStatus.Warn, Find(report, "PRE-007").Status);
        Assert.Equal(PreflightStatus.Warn, Find(report, "PRE-008").Status);
    }

    // =============================================================================================
    //  PRE-018 — the defect this migration is partly about.
    // =============================================================================================

    /// <summary>
    /// The WordPress permalink rule as WordPress actually writes it: <c>patternSyntax="Wildcard"</c>,
    /// <c>match url="*"</c>, and no <c>stopProcessing</c> attribute at all. The PowerShell check
    /// required a regex catch-all AND stopProcessing, so on a server with three WordPress sites it
    /// reported nothing.
    /// </summary>
    [Fact]
    public void TheWordPressPermalinkRule_IsRecognisedAsACatchAll()
    {
        var report = Run(iis: Iis(sites:
        [
            Site("blog", rules:
            [
                new IisRewriteRule("WordPress: https://example.test", "*", "Rewrite", "index.php", false)
            ])
        ]));

        var check = Find(report, "PRE-018");
        Assert.Equal(PreflightStatus.Warn, check.Status);
        Assert.Contains("ordered BEFORE", check.Detail, StringComparison.Ordinal);
        Assert.Contains("already-rewritten URL", check.Detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(".*")]
    [InlineData("^(.*)$")]
    [InlineData("(.*)")]
    [InlineData("*")]
    public void EveryCatchAllSpelling_IsRecognised(string match)
    {
        var report = Run(iis: Iis(sites:
        [
            Site("one", rules: [new IisRewriteRule("catch-all", match, "Rewrite", "index.php", true)])
        ]));

        Assert.Equal(PreflightStatus.Warn, Find(report, "PRE-018").Status);
    }

    /// <summary>
    /// Redirects are excluded deliberately. The follow-up request is inspected normally, so ordering
    /// the WPShield rule after one costs nothing — and flagging every "Force HTTPS" rule on a
    /// sixty-site server would bury the finding that matters.
    /// </summary>
    [Fact]
    public void ACatchAllRedirect_IsNotReported()
    {
        var report = Run(iis: Iis(sites:
        [
            Site("one", rules: [new IisRewriteRule("Force HTTPS", "(.*)", "Redirect", "https://example.test/{R:1}", true)])
        ]));

        Assert.DoesNotContain(report.Checks, check => check.Id == "PRE-018");
    }

    // =============================================================================================
    //  PRE-019 — passed on the server it was written for, while a copy sat in the web root.
    // =============================================================================================

    [Fact]
    public void AnUnpackedCopyInsideAServedDirectory_IsFound()
    {
        var host = new FakeHost
        {
            Children = { [@"C:\inetpub\wwwroot"] = [@"C:\inetpub\wwwroot\WPShield"] },
            Files = { @"C:\inetpub\wwwroot\WPShield\WPShield.Gateway.exe" }
        };

        var report = Run(host, Iis(sites: [Site("Default Web Site", physicalPath: @"C:\inetpub\wwwroot")]));

        var check = Find(report, "PRE-019");
        Assert.Equal(PreflightStatus.Blocker, check.Status);
        Assert.Contains("unpacked copy", check.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void AnInstallPathInsideAServedDirectory_IsABlocker()
    {
        var report = Run(
            options: new PreflightOptions { InstallPath = @"C:\inetpub\wwwroot\WPShield" },
            iis: Iis(sites: [Site("Default Web Site", physicalPath: @"C:\inetpub\wwwroot")]));

        Assert.Equal(PreflightStatus.Blocker, Find(report, "PRE-019").Status);
    }

    /// <summary>
    /// A site nobody asked about serves its directory just as effectively, so <c>--site</c> must not
    /// narrow what PRE-019 looks at.
    /// </summary>
    [Fact]
    public void SiteFiltering_DoesNotNarrowTheWebRootCheck()
    {
        var report = Run(
            options: new PreflightOptions
            {
                SiteNames = ["some-other-site"],
                InstallPath = @"D:\served\WPShield"
            },
            iis: Iis(sites: [Site("not-asked-about", physicalPath: @"D:\served")]));

        Assert.Equal(PreflightStatus.Blocker, Find(report, "PRE-019").Status);
    }

    [Fact]
    public void NothingUnderAWebRoot_Passes()
    {
        var report = Run(iis: Iis(sites: [Site("Default Web Site", physicalPath: @"C:\inetpub\wwwroot")]));

        Assert.Equal(PreflightStatus.Pass, Find(report, "PRE-019").Status);
    }

    // =============================================================================================
    //  The absence of a finding is not a finding.
    // =============================================================================================

    /// <summary>
    /// Without this the sites section would simply be empty, and an empty section reads as "there are
    /// no sites" rather than "nobody could look".
    /// </summary>
    [Fact]
    public void UnreadableIis_BlocksBothTheIisSectionAndTheSiteInventory()
    {
        var report = Run(iis: new FakeIis { Readable = false, UnreadableReason = "insufficient permissions" });

        Assert.Equal(PreflightStatus.Blocker, Find(report, "PRE-004").Status);

        var sites = Find(report, "PRE-012");
        Assert.Equal(PreflightStatus.Blocker, sites.Status);
        Assert.Contains("Do not read the absence of site findings", sites.Remedy, StringComparison.Ordinal);
    }

    [Fact]
    public void NotElevated_IsABlockerBecauseEveryAnswerBelowTurnsOptimistic()
    {
        var report = Run(new FakeHost { IsElevated = false });

        var check = Find(report, "PRE-001");
        Assert.Equal(PreflightStatus.Blocker, check.Status);
        Assert.Contains("optimistic", check.Detail, StringComparison.Ordinal);
    }

    // =============================================================================================
    //  PRE-016 — a blocker, not a warning.
    // =============================================================================================

    [Fact]
    public void ALogDirectoryReadableByUnprivilegedAccounts_IsABlocker()
    {
        var host = new FakeHost
        {
            Directories =
            {
                [@"C:\ProgramData\WPShield\logs"] = new DirectoryFacts(true, [@"BUILTIN\Users (S-1-5-32-545)"])
            }
        };

        var check = Find(Run(host), "PRE-016");
        Assert.Equal(PreflightStatus.Blocker, check.Status);
        Assert.NotEmpty(check.Remedy);
    }

    /// <summary>
    /// The remedy has to name the verb that performs it. Found on a real machine: this blocker fired
    /// on a directory left over from an earlier run, stopped <c>setup</c> at step 1, and told the
    /// operator to edit an ACL by hand — while <c>wpshield install</c> replaces the permissions on
    /// that exact directory and clears the blocker on its own. Sending someone to do by hand what the
    /// tool does for them is the same defect class as the rest of this file, in its politest form.
    /// </summary>
    [Fact]
    public void ThePRE016Remedy_NamesTheInstallThatPerformsIt()
    {
        var host = new FakeHost
        {
            Directories =
            {
                [@"C:\ProgramData\WPShield\logs"] = new DirectoryFacts(true, [@"BUILTIN\Users (S-1-5-32-545)"])
            }
        };

        Assert.Contains("wpshield install", Find(Run(host), "PRE-016").Remedy, StringComparison.Ordinal);
    }

    /// <summary>The install directory is the same condition and only a warning: it holds no evidence.</summary>
    [Fact]
    public void AnInstallDirectoryReadableByUnprivilegedAccounts_IsOnlyAWarning()
    {
        var host = new FakeHost
        {
            Directories =
            {
                [@"C:\Program Files\WPShield"] = new DirectoryFacts(true, [@"BUILTIN\Users (S-1-5-32-545)"])
            }
        };

        Assert.Equal(PreflightStatus.Warn, Find(Run(host), "PRE-015").Status);
    }

    // =============================================================================================
    //  Ports, and the existing service.
    // =============================================================================================

    [Fact]
    public void AGatewayPortAlreadyInUse_IsABlocker()
    {
        var report = Run(new FakeHost { Listening = [10000] });

        var check = Find(report, "PRE-009");
        Assert.Equal(PreflightStatus.Blocker, check.Status);
        Assert.Contains("--gateway-port", check.Remedy, StringComparison.Ordinal);
    }

    [Fact]
    public void AnExistingServiceOnTheWrongAccount_ShowsTheAccountInTheDetail()
    {
        var host = new FakeHost
        {
            Service = new InstalledService("Running", "LocalSystem", @"C:\Program Files\WPShield\WPShield.Gateway.exe")
        };

        var check = Find(Run(host), "PRE-014");
        Assert.Equal(PreflightStatus.Warn, check.Status);
        Assert.Contains("LocalSystem", check.Detail, StringComparison.Ordinal);
    }

    // =============================================================================================
    //  Every blocker carries a remedy. Asserted rather than hoped for.
    // =============================================================================================

    [Fact]
    public void EveryBlockerCarriesARemedy()
    {
        var report = Run(
            new FakeHost { IsElevated = false, UrlRewrite = false, Arr = false, W3svcState = null, Listening = [10000] },
            new FakeIis { Readable = false, UnreadableReason = "no" });

        Assert.NotEmpty(report.Blockers);
        Assert.All(report.Blockers, blocker => Assert.False(
            string.IsNullOrWhiteSpace(blocker.Remedy),
            $"{blocker.Id} is a blocker with no remedy. A readiness check that reports a problem without saying what to do about it has moved the problem rather than solved it."));
    }

    [Fact]
    public void EveryCheckIdIsUnique()
    {
        var report = Run(iis: Iis(sites: [Site("one"), Site("two")]));

        var duplicates = report.Checks
            .GroupBy(check => check.Id, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .ToArray();

        Assert.Empty(duplicates);
    }

    // =============================================================================================
    //  Helpers.
    // =============================================================================================

    private static PreflightReport Run(
        IHostFacts? host = null,
        IIisFacts? iis = null,
        PreflightOptions? options = null)
    {
        return new PreflightRunner(host ?? new FakeHost(), iis ?? Iis(), options ?? new PreflightOptions()).Run();
    }

    private static PreflightCheck Find(PreflightReport report, string id)
    {
        var check = report.Checks.FirstOrDefault(candidate => candidate.Id == id);
        Assert.True(check is not null, $"No check with id {id}. Present: {string.Join(", ", report.Checks.Select(c => c.Id))}");
        return check!;
    }

    private static FakeIis Iis(
        bool? arrProxyEnabled = true,
        bool? preserveHostHeader = true,
        IReadOnlyList<IisSite>? sites = null)
    {
        return new FakeIis
        {
            Readable = true,
            ArrProxyEnabled = arrProxyEnabled,
            ArrPreserveHostHeader = preserveHostHeader,
            Sites = sites ?? []
        };
    }

    private static IisSite Site(
        string name,
        string physicalPath = @"C:\sites\one",
        IReadOnlyList<IisBinding>? bindings = null,
        IReadOnlyList<IisRewriteRule>? rules = null)
    {
        return new IisSite(name, "Started", physicalPath, bindings ?? [], rules ?? []);
    }

    private sealed class FakeHost : IHostFacts
    {
        public bool IsElevated { get; init; } = true;
        public string OperatingSystem => "Windows Server 2022";
        public string RuntimeDescription => ".NET 10.0.0";
        public IReadOnlyList<string> AspNetCoreRuntimes { get; init; } = ["10.0.0"];
        public bool UrlRewrite { get; init; } = true;
        public bool Arr { get; init; } = true;
        public string? W3svcState { get; init; } = "Running";
        public InstalledService? Service { get; init; }
        public IReadOnlyList<int> Listening { get; init; } = [80, 443];

        public Dictionary<string, DirectoryFacts> Directories { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, IReadOnlyList<string>> Children { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Files { get; } = new(StringComparer.OrdinalIgnoreCase);

        bool IHostFacts.UrlRewriteInstalled => UrlRewrite;
        bool IHostFacts.ApplicationRequestRoutingInstalled => Arr;
        string? IHostFacts.WebServerServiceState => W3svcState;
        InstalledService? IHostFacts.WPShieldService => Service;
        IReadOnlyList<int> IHostFacts.ListeningPorts => Listening;

        public IReadOnlyList<string> PortOwners(int port) => [];

        public DirectoryFacts DescribeDirectory(string path) =>
            Directories.TryGetValue(path, out var facts) ? facts : new DirectoryFacts(false, []);

        public bool FileExists(string path) => Files.Contains(path);

        public IReadOnlyList<string> ChildDirectories(string path) =>
            Children.TryGetValue(path, out var children) ? children : [];
    }

    private sealed class FakeIis : IIisFacts
    {
        public bool Readable { get; init; }
        public string? UnreadableReason { get; init; }
        public bool? ArrProxyEnabled { get; init; }
        public bool? ArrPreserveHostHeader { get; init; }
        public IReadOnlyList<IisSite> Sites { get; init; } = [];
    }
}

using System.Text;
using System.Text.Json;
using WPShield.Evidence;
using WPShield.WebEvidence;
using Xunit;

namespace WPShield.WebEvidence.Tests;

/// <summary>
/// The sensor against real files in a temporary folder and a real store: what a reader of the store will
/// see, and what it must never see.
/// </summary>
public sealed class WebLogSensorTests : IDisposable
{
    private static readonly DateTimeOffset Now = SensorHarness.Now;
    private readonly SensorHarness harness = new();

    public void Dispose() => harness.Dispose();

    private const string Shell = "/wp-content/uploads/2026/11/x.php";

    // =============================================================================================
    //  Privacy: the query, the referer and the user name never exist anywhere WPShield keeps.
    // =============================================================================================

    [Fact]
    public void TheQueryTheRefererAndTheUserNameAppearNowhere()
    {
        const string query = "token=QMARKER7f3a";
        const string referer = "https://RMARKER9c1d.example/page";
        const string user = "UMARKER55e2";
        harness.Site(4);
        harness.Append(4, W3c.Header(Now.AddMinutes(-5)) +
            W3c.Line(Now.AddMinutes(-4), "POST", Shell, "203.0.113.7", 200, query: query, user: user, referer: referer) +
            W3c.Line(Now.AddMinutes(-3), "GET", "/wp-content/plugins/synthetic/a.php", "203.0.113.7", 200, query: query, user: user, referer: referer));

        var session = harness.Sensor.Start(harness.Store, Now);
        harness.Append(4, W3c.Line(Now.AddSeconds(5), "GET", Shell, "203.0.113.8", 200, query: query, user: user, referer: referer));
        session.Tick(Now.AddSeconds(30));
        session.Stop(Now.AddSeconds(40));

        var findings = harness.Findings();
        Assert.Equal(3, findings.Count);

        // Every reader answer, serialized.
        var queries = harness.Queries;
        var answers = JsonSerializer.Serialize(new object[]
        {
            findings, queries.Summary(Now.AddHours(-1), Now.AddHours(1)), queries.TopSources(Now.AddHours(-1), Now.AddHours(1), includeProtected: true),
            queries.RuleCounts(Now.AddHours(-1), Now.AddHours(1)), queries.Sites(), queries.Coverage(Now.AddHours(-1), Now.AddHours(1)),
            queries.Timeline(Now.AddHours(-1), Now.AddHours(1), TimeSpan.FromMinutes(5))
        });

        // The database files themselves, the write-ahead log included.
        harness.Store.Dispose();
        var bytes = Directory.GetFiles(harness.Root, EvidenceStore.FileName + "*").SelectMany(File.ReadAllBytes).ToArray();
        var stored = Encoding.Latin1.GetString(bytes);

        foreach (var marker in new[] { "QMARKER7f3a", "RMARKER9c1d", "UMARKER55e2" })
        {
            Assert.DoesNotContain(marker, stored, StringComparison.Ordinal);
            Assert.DoesNotContain(marker, answers, StringComparison.Ordinal);
            Assert.DoesNotContain(marker, harness.Logger.Text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void LogLinesCarryCountsNeverAPathOrAnAgent()
    {
        harness.Site(4);
        harness.Append(4, W3c.Header(Now.AddMinutes(-5)) + W3c.Line(Now.AddMinutes(-4), "GET", Shell, "203.0.113.7", 200, agent: "AGENTMARKER/1.0"));

        var session = harness.Sensor.Start(harness.Store, Now);
        session.Tick(Now.AddMinutes(6));

        Assert.Contains("Web evidence recorded", harness.Logger.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("x.php", harness.Logger.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("AGENTMARKER", harness.Logger.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("203.0.113.7", harness.Logger.Text, StringComparison.Ordinal);
    }

    // =============================================================================================
    //  Catch-up and live.
    // =============================================================================================

    [Fact]
    public void TheCatchUpKeepsTheLastFifteenMinutesAsHistoryAndWhatFollowsIsLive()
    {
        harness.Site(4);
        harness.Append(4, W3c.Header(Now.AddHours(-2)) +
            W3c.Line(Now.AddMinutes(-40), "GET", Shell, "203.0.113.1", 200) +
            W3c.Line(Now.AddMinutes(-10), "GET", Shell, "203.0.113.2", 200));

        var session = harness.Sensor.Start(harness.Store, Now);
        harness.Append(4, W3c.Line(Now.AddSeconds(20), "GET", Shell, "203.0.113.3", 200));
        session.Tick(Now.AddSeconds(30));

        var findings = harness.Findings().ToDictionary(f => f.Address);
        Assert.False(findings.ContainsKey("203.0.113.1"));
        Assert.False(findings["203.0.113.2"].Live);
        Assert.True(findings["203.0.113.3"].Live);
    }

    [Fact]
    public void ALargeFileIsEnteredWhereTheWindowStartsNotReadFromTheTop()
    {
        harness.Site(4);
        var text = new StringBuilder(W3c.Header(Now.AddHours(-3)));
        for (var i = 0; i < 6000; i++)
            text.Append(W3c.Line(Now.AddHours(-3).AddSeconds(i * 1.8), "GET", $"/page-{i}", "203.0.113.30", 200));
        text.Append(W3c.Line(Now.AddMinutes(-5), "GET", Shell, "203.0.113.31", 200));
        harness.Append(4, text.ToString());
        var length = new FileInfo(harness.File(4)).Length;
        Assert.True(length > WebLogSession.SearchThreshold);

        var start = WebLogSession.WindowStart(harness.File(4), Now - WebLogSensor.CatchUp, length);

        // Somewhere just before the window: past the first nine tenths of the file, never past the window's first line.
        Assert.NotNull(start);
        Assert.True(start > length * 8 / 10, $"{start} of {length}");
        harness.Sensor.Start(harness.Store, Now);
        Assert.Equal(["203.0.113.31"], harness.Findings().Select(f => f.Address));
        // 500 page lines in the last 15 minutes, and the shell.
        Assert.InRange(harness.Queries.Summary(Now.AddHours(-1), Now.AddHours(1)).Requests, 499, 503);
        Assert.DoesNotContain(harness.Queries.Coverage(Now.AddHours(-1), Now.AddHours(1)), c => c.Reason == "catch-up-bound");
    }

    [Fact]
    public void ARestartResumesFromTheStoredPositionAndCountsNothingTwice()
    {
        harness.Site(4);
        harness.Append(4, W3c.Header(Now.AddMinutes(-5)) + W3c.Line(Now.AddMinutes(-4), "GET", Shell, "203.0.113.1", 200));
        harness.Sensor.Start(harness.Store, Now).Stop(Now.AddSeconds(5));

        harness.Append(4, W3c.Line(Now.AddMinutes(1), "GET", Shell, "203.0.113.2", 200));
        harness.Sensor.Start(harness.Store, Now.AddMinutes(2)).Stop(Now.AddMinutes(2));

        Assert.Equal(["203.0.113.1", "203.0.113.2"], harness.Findings().Select(f => f.Address).Order());
        Assert.Equal(2, harness.Queries.Summary(Now.AddHours(-1), Now.AddHours(1)).Requests);
    }

    [Fact]
    public void TheDayRollsOverToTheNewFileAfterTheOldOneIsFinished()
    {
        harness.Site(4);
        harness.Append(4, W3c.Header(Now.AddMinutes(-5)) + W3c.Line(Now.AddMinutes(-4), "GET", Shell, "203.0.113.1", 200));
        var session = harness.Sensor.Start(harness.Store, Now);

        harness.Append(4, W3c.Line(Now.AddSeconds(10), "GET", Shell, "203.0.113.2", 200));
        harness.Append(4, W3c.Header(Now.AddMinutes(1)) + W3c.Line(Now.AddMinutes(1), "GET", Shell, "203.0.113.3", 200), "u_ex261126.log");
        File.SetLastWriteTimeUtc(harness.File(4, "u_ex261126.log"), DateTime.UtcNow.AddMinutes(1));
        session.Tick(Now.AddMinutes(2));

        Assert.Equal(["203.0.113.1", "203.0.113.2", "203.0.113.3"], harness.Findings().Select(f => f.Address).Order());
    }

    [Fact]
    public void AFileThatShrankIsReadAgainFromItsStartAndSaysSo()
    {
        harness.Site(4);
        harness.Append(4, W3c.Header(Now.AddMinutes(-5)) + W3c.Line(Now.AddMinutes(-4), "GET", Shell, "203.0.113.1", 200) +
            W3c.Line(Now.AddMinutes(-3), "GET", "/index.php", "203.0.113.9", 200));
        var session = harness.Sensor.Start(harness.Store, Now);

        File.WriteAllText(harness.File(4), W3c.Header(Now) + W3c.Line(Now.AddSeconds(5), "GET", Shell, "203.0.113.2", 200));
        session.Tick(Now.AddSeconds(30));

        Assert.Contains("203.0.113.2", harness.Findings().Select(f => f.Address));
        Assert.Contains(harness.Queries.Coverage(Now.AddHours(-1), Now.AddHours(1)), c => c.Reason == "file-restarted");
        Assert.Contains("read again from its beginning", harness.Logger.Text, StringComparison.Ordinal);
    }

    // =============================================================================================
    //  Coverage: a site nobody could read never looks like a quiet one.
    // =============================================================================================

    [Fact]
    public void AReadSiteIsCoveredFromTheCatchUpWindow()
    {
        harness.Site(4);
        harness.Append(4, W3c.Header(Now.AddMinutes(-5)));

        var session = harness.Sensor.Start(harness.Store, Now);
        session.Tick(Now.AddMinutes(2));

        var site = Assert.Single(harness.Queries.Sites());
        Assert.Equal("collected", site.Status);
        var buckets = harness.Queries.Timeline(Now.AddMinutes(-10), Now.AddMinutes(2), TimeSpan.FromMinutes(5), siteId: 4);
        Assert.All(buckets, b => Assert.True(b.Covered));
    }

    [Fact]
    public void AMissingFolderAFieldLessDirectiveAndAnFtpOnlySiteAreSaidSo()
    {
        harness.Site(4);
        harness.Append(4, W3c.Header(Now.AddMinutes(-5), "#Fields: date time cs-method cs-uri-stem sc-status") + "2026-11-25 11:56:00 GET / 200\r\n");
        harness.Configuration = harness.Configuration with
        {
            Sites = [.. harness.Configuration.Sites,
                new IisLogSite(7, "empty.example", harness.LogRoot, true, "W3C", true),
                new IisLogSite(9, "ftp.example", harness.LogRoot, true, "W3C", ServesHttp: false),
                new IisLogSite(11, "ncsa.example", harness.LogRoot, true, "NCSA", true)]
        };

        harness.Sensor.Start(harness.Store, Now);

        var sites = harness.Queries.Sites().ToDictionary(s => s.SiteId);
        Assert.Equal(("unavailable", "missing-field: c-ip"), (sites[4].Status, sites[4].Reason));
        Assert.Equal(("unavailable", "no-log-folder"), (sites[7].Status, sites[7].Reason));
        Assert.Equal(("ignored", "no-http-binding"), (sites[9].Status, sites[9].Reason));
        Assert.Equal(("unavailable", "log-format-not-w3c"), (sites[11].Status, sites[11].Reason));
        Assert.NotNull(sites[4].Remedy);
        Assert.Contains("missing-field: c-ip", harness.Logger.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnreadableIisConfigurationIsAGapNeverAnEmptyList()
    {
        // A site read in an earlier run must not keep saying "read" once nobody can look.
        harness.Site(4);
        harness.Append(4, W3c.Header(Now.AddMinutes(-5)));
        harness.Sensor.Start(harness.Store, Now).Stop(Now);
        harness.Configuration = IisLogConfiguration.Unreadable("UnauthorizedAccessException");

        harness.Sensor.Start(harness.Store, Now.AddMinutes(5));

        Assert.Contains(harness.Queries.Coverage(Now.AddHours(-1), Now.AddHours(1)),
            c => c.Source == WebEvidenceWriter.SensorSource && c.Status == "unavailable" && c.Reason == "iis-configuration-unreadable");
        var site = Assert.Single(harness.Queries.Sites());
        Assert.Equal(("unavailable", "iis-configuration-unreadable"), (site.Status, site.Reason));
    }

    [Fact]
    public void CentralLoggingIsReportedAsUnsupported()
    {
        harness.Site(4);
        harness.Configuration = harness.Configuration with { CentralLogging = "CentralW3C" };

        harness.Sensor.Start(harness.Store, Now);

        Assert.Contains(harness.Queries.Coverage(Now.AddHours(-1), Now.AddHours(1)), c => c.Reason == "central-logging-mode");
    }

    [Fact]
    public void AFolderNoSiteOwnsIsIgnoredAndSaidSo()
    {
        harness.Site(4);
        harness.Append(4, W3c.Header(Now));
        Directory.CreateDirectory(Path.Combine(harness.LogRoot, "W3SVC99"));

        harness.Sensor.Start(harness.Store, Now);

        Assert.Contains(harness.Queries.Coverage(Now.AddHours(-1), Now.AddHours(1)),
            c => c.Status == "ignored" && c.Reason!.Contains("W3SVC99", StringComparison.Ordinal));
    }

    // =============================================================================================
    //  What is kept per address.
    // =============================================================================================

    [Fact]
    public void AnAddressIsKeptWhenFlaggedOrNoisyAndAnOrdinaryVisitorIsNot()
    {
        harness.Site(4);
        var text = new StringBuilder(W3c.Header(Now.AddMinutes(-10)));
        for (var i = 0; i < 51; i++) text.Append(W3c.Line(Now.AddMinutes(-9), "GET", $"/probe-{i}", "203.0.113.20", 404));
        for (var i = 0; i < 30; i++) text.Append(W3c.Line(Now.AddMinutes(-8), "GET", $"/page-{i}", "203.0.113.21", 200));
        text.Append(W3c.Line(Now.AddMinutes(-7), "POST", "/wp-login.php", "203.0.113.22", 200));
        harness.Append(4, text.ToString());

        harness.Sensor.Start(harness.Store, Now);

        var addresses = harness.Queries.TopSources(Now.AddHours(-1), Now.AddHours(1)).Select(s => s.Address).ToArray();
        Assert.Contains("203.0.113.20", addresses);
        Assert.Contains("203.0.113.22", addresses);
        Assert.DoesNotContain("203.0.113.21", addresses);
        var summary = harness.Queries.Summary(Now.AddHours(-1), Now.AddHours(1));
        Assert.Equal(82, summary.Requests);
        Assert.Equal(51, summary.ClientErrors);
        Assert.Equal(1, summary.LoginPosts);
    }

    [Fact]
    public void ProtectedAddressesAreRecordedButNeverCountedAgainst()
    {
        harness.Site(4);
        harness.Append(4, W3c.Header(Now.AddMinutes(-5)) +
            W3c.Line(Now.AddMinutes(-4), "GET", Shell, "10.0.0.5", 200) +           // a private range
            W3c.Line(Now.AddMinutes(-4), "GET", Shell, "192.0.2.10", 200) +         // this host
            W3c.Line(Now.AddMinutes(-4), "GET", Shell, "203.0.113.7", 200));

        harness.Sensor.Start(harness.Store, Now);

        var findings = harness.Findings().ToDictionary(f => f.Address);
        Assert.Equal("a private range", findings["10.0.0.5"].Protection);
        Assert.Equal("an address of this host", findings["192.0.2.10"].Protection);
        Assert.Null(findings["203.0.113.7"].Protection);
        Assert.Equal(["203.0.113.7"], harness.Queries.TopSources(Now.AddHours(-1), Now.AddHours(1)).Select(s => s.Address));
        Assert.Equal(2, harness.Queries.Summary(Now.AddHours(-1), Now.AddHours(1)).ProtectedSources);
    }

    [Fact]
    public void AProxiedSitesFindingsAreMarkedAndNeverCountedAgainstTheProxy()
    {
        new EvidenceSettings(harness.Store).Set(WebSettings.ProxiedSites, "[\"shop.example\"]", "test", "behind a test proxy");
        harness.Site(4, "shop.example");
        harness.Append(4, W3c.Header(Now.AddMinutes(-5)) + W3c.Line(Now.AddMinutes(-4), "GET", Shell, "203.0.113.7", 200));

        harness.Sensor.Start(harness.Store, Now);

        Assert.True(Assert.Single(harness.Findings()).Proxied);
        Assert.Empty(harness.Queries.TopSources(Now.AddHours(-1), Now.AddHours(1)));
        Assert.True(Assert.Single(harness.Queries.Sites()).Proxied);
    }

    [Fact]
    public void ObservationsAndRulesAreCountedSeparately()
    {
        harness.Site(4);
        harness.Append(4, W3c.Header(Now.AddMinutes(-5)) +
            W3c.Line(Now.AddMinutes(-4), "POST", "/wp-content/plugins/synthetic/admin/modules.php", "203.0.113.7", 200) +
            W3c.Line(Now.AddMinutes(-4), "GET", Shell, "203.0.113.7", 200) +
            W3c.Line(Now.AddMinutes(-3), "POST", "/xmlrpc.php", "203.0.113.7", 200));

        harness.Sensor.Start(harness.Store, Now);

        var counts = harness.Queries.RuleCounts(Now.AddHours(-1), Now.AddHours(1)).ToDictionary(c => c.Id);
        Assert.Equal(2, counts[WebObservationIds.PhpOutsideEntryPoints].Requests); // the shell under uploads answered too
        Assert.True(counts[WebObservationIds.PhpOutsideEntryPoints].Observation);
        Assert.Equal(1, counts["WP-PATH-001"].Requests);
        Assert.False(counts["WP-PATH-001"].Observation);
        Assert.Equal(1, counts[WebObservationIds.XmlrpcPost].Requests);
    }
}

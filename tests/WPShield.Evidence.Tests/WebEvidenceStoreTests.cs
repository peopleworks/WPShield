using Microsoft.Data.Sqlite;
using WPShield.Evidence;
using Xunit;

namespace WPShield.Evidence.Tests;

/// <summary>
/// Schema 2 (ADR 0011): the IIS log evidence is added to a store without touching what it already holds,
/// and read back through fixed, bounded queries.
/// </summary>
public sealed class WebEvidenceStoreTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 25, 12, 0, 0, TimeSpan.Zero);
    private readonly string directory = Path.Combine(Path.GetTempPath(), "wpshield-web-store-tests", Guid.NewGuid().ToString("N"));

    public WebEvidenceStoreTests() => Directory.CreateDirectory(directory);

    public void Dispose()
    {
        try { Directory.Delete(directory, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string DbPath => Path.Combine(directory, EvidenceStore.FileName);

    /// <summary>
    /// The schema-1 tables exactly as the build before ADR 0011 created them (main at a0d026b,
    /// <c>EvidenceStore.Migrate</c>). Frozen here on purpose: a store on a real host was written by that code.
    /// </summary>
    private const string SchemaOne = """
        PRAGMA auto_vacuum = INCREMENTAL;
        PRAGMA journal_mode = WAL;
        CREATE TABLE auth_failures(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, channel TEXT NOT NULL, record_id INTEGER NOT NULL,
            address TEXT, port INTEGER, account TEXT NOT NULL, reason TEXT NOT NULL, logon_type INTEGER, UNIQUE(channel, record_id));
        CREATE INDEX ix_auth_failures_ts ON auth_failures(ts);
        CREATE INDEX ix_auth_failures_address_ts ON auth_failures(address, ts);
        CREATE TABLE hourly_sources(hour INTEGER NOT NULL, address TEXT NOT NULL, attempts INTEGER NOT NULL, unknown_account INTEGER NOT NULL,
            first_ts INTEGER NOT NULL, last_ts INTEGER NOT NULL, PRIMARY KEY(hour, address)) WITHOUT ROWID;
        CREATE TABLE decisions(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, rule_id TEXT NOT NULL,
            mode TEXT NOT NULL, reason TEXT NOT NULL, requested_by TEXT, expires_ts INTEGER);
        CREATE INDEX ix_decisions_ts ON decisions(ts);
        CREATE TABLE coverage(id INTEGER PRIMARY KEY, source TEXT NOT NULL, from_ts INTEGER NOT NULL, to_ts INTEGER NOT NULL,
            status TEXT NOT NULL, reason TEXT);
        CREATE INDEX ix_coverage_source ON coverage(source, from_ts);
        CREATE TABLE collector_state(channel TEXT PRIMARY KEY, last_record_id INTEGER NOT NULL, last_ts INTEGER NOT NULL);
        CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE events(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL, source TEXT NOT NULL, address TEXT,
            subject TEXT NOT NULL, detail TEXT NOT NULL CHECK (json_valid(detail)), dedupe_key TEXT, UNIQUE(kind, dedupe_key));
        CREATE INDEX ix_events_kind_ts ON events(kind, ts);
        CREATE INDEX ix_events_address_ts ON events(address, ts);
        CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL CHECK (json_valid(value)), version INTEGER NOT NULL,
            updated_ts INTEGER NOT NULL, updated_by TEXT NOT NULL);
        CREATE TABLE settings_history(id INTEGER PRIMARY KEY, key TEXT NOT NULL, old_value TEXT, new_value TEXT, ts INTEGER NOT NULL,
            changed_by TEXT NOT NULL, reason TEXT NOT NULL);
        CREATE INDEX ix_settings_history_key ON settings_history(key, ts);
        PRAGMA user_version = 1;
        """;

    private void CreateSchemaOneStoreWithAWeekOfMonitoring()
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = DbPath, Pooling = false }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = SchemaOne + """
            INSERT INTO auth_failures(ts, channel, record_id, address, port, account, reason, logon_type)
                VALUES (1764000000000, 'security-4625', 41, '203.0.113.9', NULL, 'administrator', 'bad-password', 3);
            INSERT INTO hourly_sources VALUES (490000, '203.0.113.9', 1, 0, 1764000000000, 1764000000000);
            INSERT INTO decisions(ts, action, target, rule_id, mode, reason, requested_by, expires_ts)
                VALUES (1764000000000, 'would-block', '203.0.113.9', 'HOST-AUTH-001', 'monitor', 'ten failures', 'security-4625', 1764003600000);
            INSERT INTO coverage(source, from_ts, to_ts, status, reason) VALUES ('auth-failures', 1763990000000, 1764000000000, 'collected', NULL);
            INSERT INTO collector_state VALUES ('security-4625', 41, 1764000000000);
            INSERT INTO settings VALUES ('defense.allow', '["198.51.100.7"]', 1, 1764000000000, 'operator');
            INSERT INTO settings_history(key, old_value, new_value, ts, changed_by, reason)
                VALUES ('defense.allow', NULL, '["198.51.100.7"]', 1764000000000, 'operator', 'my office');
            """;
        command.ExecuteNonQuery();
    }

    [Fact]
    public void ASchemaOneStoreKeepsEveryRowAndGainsTheWebTables()
    {
        CreateSchemaOneStoreWithAWeekOfMonitoring();

        using (var store = EvidenceStore.OpenForWriting(DbPath))
        {
            Assert.Equal(EvidenceStore.SchemaVersion, store.Scalar<long>("PRAGMA user_version;"));
            Assert.Equal(1, store.Scalar<long>("SELECT COUNT(*) FROM auth_failures;"));
            Assert.Equal(1, store.Scalar<long>("SELECT COUNT(*) FROM hourly_sources;"));
            Assert.Equal(1, store.Scalar<long>("SELECT COUNT(*) FROM decisions;"));
            Assert.Equal(1, store.Scalar<long>("SELECT COUNT(*) FROM coverage;"));
            Assert.Equal(41, store.Scalar<long>("SELECT last_record_id FROM collector_state WHERE channel = 'security-4625';"));
            Assert.Equal("[\"198.51.100.7\"]", new EvidenceSettings(store).Get("defense.allow").ToJsonString());
            Assert.Single(new EvidenceSettings(store).History("defense.allow"));
            foreach (var table in new[] { "web_findings", "web_hourly_sites", "web_hourly_sources", "web_sites" })
                Assert.Equal(0, store.Scalar<long>($"SELECT COUNT(*) FROM {table};"));
        }

        // Readers open it once the writer has migrated it.
        using var reader = EvidenceStore.OpenReadOnly(DbPath);
        Assert.Equal(1, new EvidenceQueries(reader).Summary(EvidenceStore.FromMs(1763990000000), EvidenceStore.FromMs(1764000000001)).Attempts);
    }

    [Fact]
    public void AReaderOfThisBuildWaitsForTheWriterToMigrate()
    {
        CreateSchemaOneStoreWithAWeekOfMonitoring();

        var error = Assert.Throws<InvalidDataException>(() => EvidenceStore.OpenReadOnly(DbPath));
        Assert.Contains("schema 1", error.Message, StringComparison.Ordinal);
    }

    private static WebFinding Finding(double minutes, string address = "203.0.113.7", long site = 4, string? protection = null,
        bool live = true, string path = "/wp-content/uploads/x.php") =>
        new(Now.AddMinutes(minutes), site, address, "GET", path, 200, [new WebHit("WP-PATH-001", 100), new WebHit("WEB-OBS-001", 0)],
            "agent", live, Proxied: false, protection);

    private static WebSourceCounts Source(string address, long findings = 1, string? protection = null, long site = 4) =>
        new(site, new DateTimeOffset(2026, 11, 25, 11, 0, 0, TimeSpan.Zero), address, 10, 2, findings, 1, 0, 0, Now.AddMinutes(-50), Now.AddMinutes(-10), protection);

    [Fact]
    public void ABatchIsReadBackThroughTheQueries()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new WebEvidenceWriter(store);
        writer.Write(new WebBatch(
            [Finding(-30), Finding(-20, protection: "a private range", address: "10.0.0.5")],
            [new WebSiteCounts(4, new DateTimeOffset(2026, 11, 25, 11, 0, 0, TimeSpan.Zero), 100, 12, 1, 2, 2, 3, 4, 5000)],
            [Source("203.0.113.7"), Source("203.0.113.8"), Source("10.0.0.5", protection: "a private range")],
            [new WebLogPosition(4, "u_ex261125.log", 1234, Now.AddMinutes(-20))]));
        // Counts add up across batches: a second read of the same hour adds, never replaces.
        writer.Write(new WebBatch([], [new WebSiteCounts(4, new DateTimeOffset(2026, 11, 25, 11, 0, 0, TimeSpan.Zero), 10, 0, 0, 0, 0, 0, 0, 100)],
            [Source("203.0.113.7")], []));

        var queries = new WebEvidenceQueries(store);
        var summary = queries.Summary(Now.AddHours(-2), Now);
        Assert.Equal(110, summary.Requests);
        Assert.Equal(3, summary.LoginPosts);
        Assert.Equal(2, summary.Sources);
        Assert.Equal(1, summary.ProtectedSources);

        var top = queries.TopSources(Now.AddHours(-2), Now);
        Assert.Equal(["203.0.113.7", "203.0.113.8"], top.Select(s => s.Address));
        Assert.Equal(20, top[0].Requests);
        Assert.Equal(1, top[0].Neighbors);
        Assert.Equal("203.0.113.0/24", top[0].Network);

        var findings = queries.Findings(Now.AddHours(-2), Now);
        Assert.Equal(2, findings.Count);
        Assert.Equal(["WP-PATH-001", "WEB-OBS-001"], findings[0].Hits.Select(h => h.Id));
        Assert.Equal(100, findings[0].Score);

        var counts = queries.RuleCounts(Now.AddHours(-2), Now).ToDictionary(c => c.Id);
        Assert.Equal(2, counts["WP-PATH-001"].Requests);
        Assert.Equal(3, counts["WEB-OBS-002"].Requests);
        Assert.Equal(4, counts["WEB-OBS-003"].Requests);

        Assert.Equal(1234, writer.Position(4, "U_EX261125.LOG")!.Offset);
        Assert.Null(writer.Position(4, "u_ex261126.log"));
    }

    [Fact]
    public void AttackerTextIsCleanedAndBoundedBeforeItIsStored()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        new WebEvidenceWriter(store).Write(new WebBatch(
            [Finding(-5, path: "/x\u001b[31m" + new string('a', 1000))], [], [], []));

        var path = new WebEvidenceQueries(store).Findings(Now.AddHours(-1), Now).Single().Path;
        Assert.DoesNotContain('\u001b', path);
        Assert.True(path.Length <= WebEvidenceWriter.MaxPathLength);
    }

    [Fact]
    public void PruningFollowsTheStoresBoundsAndSaysWhereFindingsStart()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new WebEvidenceWriter(store);
        writer.Write(new WebBatch([Finding(-60 * 24 * 20), Finding(-30)], [], [],
            [new WebLogPosition(4, "u_ex261101.log", 10, Now.AddDays(-20)), new WebLogPosition(4, "u_ex261125.log", 10, Now)]));

        var result = new EvidenceWriter(store).Prune(Now, new EvidenceLimits());

        Assert.Equal(1, result.WebRowsDeleted);
        Assert.Null(writer.Position(4, "u_ex261101.log"));
        Assert.NotNull(writer.Position(4, "u_ex261125.log"));
        var summary = new WebEvidenceQueries(store).Summary(Now.AddDays(-30), Now);
        Assert.Equal(Now - new EvidenceLimits().RawRetention, summary.FindingsFrom);
    }

    [Fact]
    public void SitesAreRecordedAndARemovedOneIsKeptMarked()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new WebEvidenceWriter(store);
        writer.RecordSites([new WebSiteState(4, "shop.example", "collected", null, null, false, Now),
            new WebSiteState(7, "blog.example", "unavailable", "access-denied", "grant read", false, Now)], Now);
        writer.RecordSites([new WebSiteState(4, "shop.example", "collected", null, null, true, Now)], Now.AddMinutes(15));

        var sites = new WebEvidenceQueries(store).Sites().ToDictionary(s => s.SiteId);
        Assert.True(sites[4].Proxied);
        Assert.Equal(("unavailable", "not-in-configuration"), (sites[7].Status, sites[7].Reason));
    }

    [Theory]
    [InlineData("[\"shop.example\", \"blog.example\"]", true)]
    [InlineData("[]", true)]
    [InlineData("\"shop.example\"", false)]
    [InlineData("[\"\"]", false)]
    [InlineData("[42]", false)]
    public void TheProxiedSitesSettingTakesSiteNames(string json, bool accepted)
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var settings = new EvidenceSettings(store);
        if (accepted)
        {
            settings.Set(WebSettings.ProxiedSites, json, "test", "a test");
            Assert.Equal(json.Count(c => c == '"') / 2, WebSettings.Read(settings).Count);
        }
        else
        {
            Assert.Throws<ArgumentException>(() => settings.Set(WebSettings.ProxiedSites, json, "test", "a test"));
        }
    }

    [Fact]
    public void ATimelineSaysWhereTheSensorDidNotLook()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var coverage = new EvidenceWriter(store);
        coverage.BeginCoverage(WebEvidenceWriter.SensorSource, Now.AddMinutes(-30), Now, "collected");
        new WebEvidenceWriter(store).Write(new WebBatch([Finding(-20), Finding(-10)], [], [], []));

        var buckets = new WebEvidenceQueries(store).Timeline(Now.AddHours(-1), Now, TimeSpan.FromMinutes(15));

        Assert.Equal([false, false, true, true], buckets.Select(b => b.Covered));
        Assert.Equal(2, buckets.Sum(b => b.Findings));
        Assert.All(buckets, b => Assert.Null(b.Requests));
    }

    [Fact]
    public void AnUnknownAddressIsRefusedNotQueried()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        Assert.Throws<ArgumentException>(() => new WebEvidenceQueries(store).Findings(Now.AddHours(-1), Now, address: "'; DROP TABLE x; --"));
    }
}

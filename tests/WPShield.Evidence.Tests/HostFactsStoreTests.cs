using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using WPShield.Evidence;
using Xunit;

namespace WPShield.Evidence.Tests;

/// <summary>
/// Schema 3 (ADR 0013): host facts are added to a store without touching what it holds, stored bounded and
/// cleaned, and read back through fixed queries.
/// </summary>
public sealed class HostFactsStoreTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 25, 12, 0, 0, TimeSpan.Zero);
    private readonly string directory = Path.Combine(Path.GetTempPath(), "wpshield-host-store-tests", Guid.NewGuid().ToString("N"));

    public HostFactsStoreTests() => Directory.CreateDirectory(directory);

    public void Dispose()
    {
        try { Directory.Delete(directory, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string DbPath => Path.Combine(directory, EvidenceStore.FileName);

    /// <summary>
    /// The schema-2 store exactly as the build before ADR 0013 wrote it (main at d5555b5, <c>EvidenceStore.Migrate</c>).
    /// Frozen here on purpose: a store on a real host holds a Monitor week written by that code.
    /// </summary>
    private const string SchemaTwo = """
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
        CREATE TABLE web_findings(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, site_id INTEGER NOT NULL, address TEXT NOT NULL,
            method TEXT NOT NULL, path TEXT NOT NULL, status INTEGER NOT NULL, rules TEXT NOT NULL, score INTEGER NOT NULL,
            user_agent TEXT NOT NULL, live INTEGER NOT NULL, proxied INTEGER NOT NULL, protection TEXT);
        CREATE INDEX ix_web_findings_ts ON web_findings(ts);
        CREATE INDEX ix_web_findings_address_ts ON web_findings(address, ts);
        CREATE INDEX ix_web_findings_site_ts ON web_findings(site_id, ts);
        CREATE TABLE web_hourly_sites(hour INTEGER NOT NULL, site_id INTEGER NOT NULL, requests INTEGER NOT NULL, client_errors INTEGER NOT NULL,
            server_errors INTEGER NOT NULL, findings INTEGER NOT NULL, observations INTEGER NOT NULL, login_posts INTEGER NOT NULL,
            xmlrpc_posts INTEGER NOT NULL, bytes_received INTEGER NOT NULL, PRIMARY KEY(hour, site_id)) WITHOUT ROWID;
        CREATE TABLE web_hourly_sources(hour INTEGER NOT NULL, site_id INTEGER NOT NULL, address TEXT NOT NULL, requests INTEGER NOT NULL,
            client_errors INTEGER NOT NULL, findings INTEGER NOT NULL, observations INTEGER NOT NULL, login_posts INTEGER NOT NULL,
            xmlrpc_posts INTEGER NOT NULL, first_ts INTEGER NOT NULL, last_ts INTEGER NOT NULL, protection TEXT,
            PRIMARY KEY(hour, site_id, address)) WITHOUT ROWID;
        CREATE INDEX ix_web_hourly_sources_address ON web_hourly_sources(address, hour);
        CREATE TABLE web_sites(site_id INTEGER PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL, reason TEXT, remedy TEXT,
            proxied INTEGER NOT NULL, updated_ts INTEGER NOT NULL);
        PRAGMA user_version = 2;
        """;

    private void CreateSchemaTwoStoreWithAWeekOfMonitoring()
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = DbPath, Pooling = false }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = SchemaTwo + """
            INSERT INTO auth_failures(ts, channel, record_id, address, port, account, reason, logon_type)
                VALUES (1764000000000, 'security-4625', 41, '203.0.113.9', NULL, 'administrator', 'bad-password', 3);
            INSERT INTO hourly_sources VALUES (490000, '203.0.113.9', 1, 0, 1764000000000, 1764000000000);
            INSERT INTO decisions(ts, action, target, rule_id, mode, reason, requested_by, expires_ts)
                VALUES (1764000000000, 'would-block', '203.0.113.9', 'HOST-AUTH-001', 'monitor', 'ten failures', 'security-4625', 1764003600000);
            INSERT INTO coverage(source, from_ts, to_ts, status, reason) VALUES ('auth-failures', 1763990000000, 1764000000000, 'collected', NULL);
            INSERT INTO collector_state VALUES ('security-4625', 41, 1764000000000);
            INSERT INTO settings VALUES ('defense.allow', '["198.51.100.7"]', 1, 1764000000000, 'operator');
            INSERT INTO web_findings(ts, site_id, address, method, path, status, rules, score, user_agent, live, proxied, protection)
                VALUES (1764000000000, 4, '203.0.113.7', 'GET', '/wp-content/uploads/x.php', 200, 'WP-PATH-001:100', 100, 'agent', 1, 0, NULL);
            INSERT INTO web_hourly_sites VALUES (490000, 4, 10, 2, 0, 1, 1, 0, 0, 1000);
            INSERT INTO web_sites VALUES (4, 'shop.example', 'read', NULL, NULL, 0, 1764000000000);
            """;
        command.ExecuteNonQuery();
    }

    private static HostFactReading Health(DateTimeOffset at, double cpu = 10, long free = 100) =>
        HostFactReading.Of(HostFacts.Health, null, at, new HostHealth(at.AddDays(-1), 86_400, cpu, 1000, free, [new HostVolume(@"C:\", 1000, free, true)], 10));

    [Fact]
    public void ASchemaTwoStoreKeepsEveryRowAndGainsTheHostTables()
    {
        CreateSchemaTwoStoreWithAWeekOfMonitoring();

        using (var store = EvidenceStore.OpenForWriting(DbPath))
        {
            Assert.Equal(3, store.Scalar<long>("PRAGMA user_version;"));
            foreach (var table in new[] { "auth_failures", "hourly_sources", "decisions", "coverage", "collector_state", "settings", "web_findings", "web_hourly_sites", "web_sites" })
                Assert.Equal(1, store.Scalar<long>($"SELECT COUNT(*) FROM {table};"));
            Assert.Equal(0, store.Scalar<long>("SELECT COUNT(*) FROM host_snapshots;"));
            Assert.Equal(0, store.Scalar<long>("SELECT COUNT(*) FROM host_health_hourly;"));
        }
        using var reader = EvidenceStore.OpenReadOnly(DbPath);
        Assert.Single(new WebEvidenceQueries(reader).Findings(EvidenceStore.FromMs(1763990000000), EvidenceStore.FromMs(1764000000001)));
    }

    [Fact]
    public void AReaderOfThisBuildWaitsForTheWriterToMigrateASchemaTwoStore()
    {
        CreateSchemaTwoStoreWithAWeekOfMonitoring();

        var error = Assert.Throws<InvalidDataException>(() => EvidenceStore.OpenReadOnly(DbPath));
        Assert.Contains("schema 2", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ASnapshotIsReadBackAsWrittenAndTheNewestWins()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new HostFactsWriter(store);
        writer.Write(Health(Now.AddMinutes(-5), cpu: 50));
        writer.Write(Health(Now, cpu: 12.5));
        writer.Write(HostFactReading.Failed(HostFacts.Sites, null, Now, HostFactStatus.NeedsElevation, "not-elevated", "Run it elevated."));

        var queries = new HostFactsQueries(store);
        var health = queries.Latest(HostFacts.Health)!;
        Assert.Equal(Now, health.TakenAt);
        Assert.Equal(12.5, health.Value<HostHealth>()!.CpuPercent);
        var sites = queries.Latest(HostFacts.Sites)!;
        Assert.Equal(HostFactStatus.NeedsElevation, sites.Status);
        Assert.Null(sites.Payload);
        Assert.Equal(2, queries.LatestAll().Count);
        Assert.Null(queries.Latest(HostFacts.Inventory, HostFacts.Tasks));
    }

    [Fact]
    public void AFactThatIsNotOkMustSayWhyAndWhatToDo()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new HostFactsWriter(store);

        Assert.Throws<ArgumentException>(() => writer.Write(new HostFactReading(HostFacts.Ports, null, Now, HostFactStatus.Unreadable, null, null, null)));
        Assert.Throws<ArgumentException>(() => writer.Write(new HostFactReading(HostFacts.Ports, null, Now, "fine", null, null, null)));
        Assert.Throws<ArgumentException>(() => writer.Write(new HostFactReading("host_secrets", null, Now, HostFactStatus.Ok, null, null, null)));
        Assert.Throws<ArgumentException>(() => writer.Write(new HostFactReading(HostFacts.Inventory, "drivers", Now, HostFactStatus.Ok, null, null, null)));
        Assert.Throws<ArgumentException>(() => writer.Write(new HostFactReading(HostFacts.Health, HostFacts.Tasks, Now, HostFactStatus.Ok, null, null, null)));
    }

    [Fact]
    public void AnOversizedPayloadIsCutToItsBoundAndSaysSo()
    {
        var tasks = Enumerable.Range(0, 2000).Select(i => new HostTask($@"\Vendor\Task-{i}-{new string('x', 200)}", "ready", "SYSTEM", null, null,
            $@"C:\Program Files\Vendor\{new string('y', 200)}\{i}.exe", HostSignature.Signed, "Vendor", [CommandFlags.HasArguments])).ToArray();
        using var store = EvidenceStore.OpenForWriting(DbPath);

        var stored = new HostFactsWriter(store).Write(HostFactReading.Of(HostFacts.Inventory, HostFacts.Tasks, Now, new HostTasks(tasks, 0)));

        Assert.Equal(HostFactStatus.Partial, stored.Status);
        Assert.Contains("payload-bound", stored.Reason, StringComparison.Ordinal);
        Assert.NotNull(stored.Remedy);
        Assert.True(Encoding.UTF8.GetByteCount(stored.Payload!.ToJsonString()) <= HostFacts.MaxPayloadBytes);
        Assert.InRange(new HostFactsQueries(store).Latest(HostFacts.Inventory, HostFacts.Tasks)!.Value<HostTasks>()!.Tasks.Count, 1, 1999);
    }

    [Fact]
    public void NamesReadFromAHostThatMayBeCompromisedAreCleanedBeforeTheyAreStored()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var service = new HostService("evil\u001b[31msvc", "Display\r\nInjected", "running", "automatic", "LocalSystem",
            @"C:\x\" + new string('a', 1000) + ".exe", HostSignature.Unsigned, null, []);

        var stored = new HostFactsWriter(store).Write(HostFactReading.Of(HostFacts.Inventory, HostFacts.Services, Now, new HostServices([service], 0)));

        var read = stored.Value<HostServices>()!.Services[0];
        Assert.DoesNotContain('\u001b', read.Name);
        Assert.DoesNotContain('\n', read.DisplayName);
        Assert.True(read.Executable!.Length <= HostFacts.MaxNameLength);
    }

    [Fact]
    public void HealthFoldsIntoOneRowPerHour()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new HostFactsWriter(store);
        writer.RecordHealth(Health(Now, cpu: 10, free: 300).Value<HostHealth>()!, Now);
        writer.RecordHealth(Health(Now, cpu: 30, free: 100).Value<HostHealth>()!, Now.AddMinutes(5));
        writer.RecordHealth(Health(Now, cpu: 90, free: 50).Value<HostHealth>()!, Now.AddHours(1));

        var hours = new HostFactsQueries(store).HealthHourly(Now.AddHours(-1), Now.AddHours(2));
        Assert.Equal(2, hours.Count);
        Assert.Equal(20, hours[0].CpuAverage);
        Assert.Equal(30, hours[0].CpuPeak);
        Assert.Equal(100, hours[0].MemoryMinAvailable);
        Assert.Equal(100, hours[0].VolumeMinFree[@"C:\"]);
    }

    [Fact]
    public void ARestartIsStoredOnceAndGainsItsBugcheckCodeWhenWerWritesItLater()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new HostFactsWriter(store);
        var kernelPower = new HostRestartRecord(Now.AddDays(-1), 700, 41, null);

        Assert.Equal(1, writer.RecordRestarts(HostRestarts.Group([kernelPower])));
        Assert.Equal(0, writer.RecordRestarts(HostRestarts.Group([kernelPower, new HostRestartRecord(Now.AddDays(-1).AddMinutes(3), 712, 1001, 0x133)])));
        writer.SetRestartsReadUntil(Now);

        var restart = Assert.Single(new HostFactsQueries(store).Restarts(Now.AddDays(-30), Now));
        Assert.Equal(0x133u, restart.BugCheckCode);
        Assert.Equal(Now, writer.RestartsReadUntil());
    }

    [Fact]
    public void InventoryChangesStopAtTheDailyBoundAndTheOverflowIsCounted()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new HostFactsWriter(store);
        var changes = Enumerable.Range(0, HostFacts.MaxChangeEventsPerDay + 5)
            .Select(i => new InventoryChange(HostFacts.Tasks, "added", $@"\Task{i}", [])).ToArray();

        Assert.Equal((HostFacts.MaxChangeEventsPerDay, 5), writer.RecordInventoryChanges(HostFacts.Tasks, changes, Now));
        Assert.Equal((0, 2), writer.RecordInventoryChanges(HostFacts.Tasks, changes[..2], Now.AddHours(1)));

        var queries = new HostFactsQueries(store);
        Assert.Equal(HostFacts.MaxChangeEventsPerDay, queries.InventoryChanges(Now.AddDays(-1), Now.AddDays(1), HostFacts.Tasks, 1000).Count);
        Assert.Equal(7, Assert.Single(queries.InventoryOverflows(Now.AddDays(-1), Now.AddDays(1))).Count);
    }

    [Fact]
    public void PruningKeepsTheNewestSnapshotOfEveryFactAndPostureForAYear()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new HostFactsWriter(store);
        writer.Write(Health(Now.AddDays(-20)));
        writer.Write(Health(Now.AddDays(-10)));
        writer.Write(HostFactReading.Failed(HostFacts.Ports, null, Now.AddDays(-30), HostFactStatus.Unreadable, "x", "y"));
        var posture = new HostPosture("collector", true, [], 81, 80, true, 64, 1);
        writer.Write(HostFactReading.Of(HostFacts.Posture, null, Now.AddDays(-300), posture));
        writer.Write(HostFactReading.Of(HostFacts.Posture, null, Now.AddDays(-500), posture));
        writer.Write(HostFactReading.Of(HostFacts.Posture, null, Now.AddDays(-1), posture with { PoolsAdministrator = 79 }));
        writer.RecordHealth(Health(Now).Value<HostHealth>()!, Now.AddDays(-100));

        var result = new EvidenceWriter(store).Prune(Now, new EvidenceLimits());

        var queries = new HostFactsQueries(store);
        Assert.Equal(Now.AddDays(-10), queries.Latest(HostFacts.Health)!.TakenAt);
        Assert.NotNull(queries.Latest(HostFacts.Ports));
        Assert.Equal(2, queries.PostureHistory(Now.AddDays(-600), Now).Count);
        Assert.Empty(queries.HealthHourly(Now.AddDays(-200), Now));
        Assert.Equal(3, result.HostRowsDeleted);
    }

    [Fact]
    public void TheHostDetailsSettingExistsAndIsOffByDefault()
    {
        var definition = SettingCatalog.All["mcp.host_details"];
        Assert.Equal(SettingEffect.NextStart, definition.Effect);
        Assert.False(definition.Default.GetValue<bool>());
        Assert.NotNull(definition.Validate(JsonValue.Create("yes")));
        Assert.Null(definition.Validate(JsonValue.Create(true)));
    }
}

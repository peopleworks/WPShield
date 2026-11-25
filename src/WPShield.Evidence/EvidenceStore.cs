using Microsoft.Data.Sqlite;

namespace WPShield.Evidence;

/// <summary>Bounds of the store (ADR 0007, section 4). Every table has one; so does the file.</summary>
public sealed record EvidenceLimits
{
    public TimeSpan RawRetention { get; init; } = TimeSpan.FromDays(14);
    public long MaxRawRows { get; init; } = 5_000_000;
    public TimeSpan AggregateRetention { get; init; } = TimeSpan.FromDays(400);
    public TimeSpan EventRetention { get; init; } = TimeSpan.FromDays(90);
    public long MaxEventRows { get; init; } = 2_000_000;
    public long MaxBytes { get; init; } = 2L * 1024 * 1024 * 1024;
}

/// <summary>
/// The SQLite file behind the evidence store. One writer (the WPShield service); every other caller
/// opens it read-only.
/// </summary>
/// <remarks>
/// The writer never creates the directory. <c>wpshield install</c> creates it with permissions that
/// replace inheritance; a directory created here would inherit <c>ProgramData</c>'s, which let every
/// local user read it.
/// </remarks>
public sealed class EvidenceStore : IDisposable
{
    /// <summary>
    /// 1: failed logons, decisions, coverage, events, settings. 2 adds the IIS log evidence of ADR 0011
    /// (<c>web_*</c> tables). 3 adds the host facts of ADR 0013 (<c>host_*</c> tables). Every migration is
    /// additive: a store written by an earlier build keeps every row it holds and gains the new tables.
    /// </summary>
    public const int SchemaVersion = 3;
    public const string FileName = "wpshield-evidence.db";

    private EvidenceStore(SqliteConnection connection, bool readOnly)
    {
        Connection = connection;
        ReadOnly = readOnly;
    }

    internal SqliteConnection Connection { get; }

    public bool ReadOnly { get; }

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WPShield", "evidence", FileName);

    /// <summary>
    /// Opens the store for the service (evidence and settings) or for an elevated operator tool
    /// (settings only, see <see cref="EvidenceSettings"/>). SQLite serialises the two writers.
    /// </summary>
    public static EvidenceStore OpenForWriting(string path)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (directory is null || !Directory.Exists(directory))
            throw new DirectoryNotFoundException(MissingDirectoryMessage(directory));
        var connection = Open(path, SqliteOpenMode.ReadWriteCreate);
        var store = new EvidenceStore(connection, readOnly: false);
        store.Migrate();
        return store;
    }

    /// <summary>
    /// What a writer says when the evidence directory is missing. Shared with the analyst's report store,
    /// which lives in the same directory and, like the evidence store, never creates it.
    /// </summary>
    public static string MissingDirectoryMessage(string? directory) =>
        $"The evidence directory '{directory}' does not exist. 'wpshield install' creates it with restricted permissions.";

    public static EvidenceStore OpenReadOnly(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("The evidence store does not exist.", path);
        var store = new EvidenceStore(Open(path, SqliteOpenMode.ReadOnly), readOnly: true);
        var version = store.Scalar<long>("PRAGMA user_version;");
        if (version != SchemaVersion)
        {
            store.Dispose();
            throw new InvalidDataException($"The evidence store has schema {version}; this build reads schema {SchemaVersion}.");
        }
        return store;
    }

    private static SqliteConnection Open(string path, SqliteOpenMode mode)
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = mode,
            Cache = SqliteCacheMode.Private,
            // A pooled connection keeps the file open after Dispose; the service owns the file's lifetime.
            Pooling = false,
            DefaultTimeout = 5
        };
        var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        using var pragma = connection.CreateCommand();
        pragma.CommandText = "PRAGMA busy_timeout = 5000;";
        pragma.ExecuteNonQuery();
        return connection;
    }

    private void Migrate()
    {
        var version = Scalar<long>("PRAGMA user_version;");
        if (version == SchemaVersion) return;
        if (version > SchemaVersion)
            throw new InvalidDataException($"The evidence store has schema {version}, newer than this build ({SchemaVersion}).");
        // auto_vacuum must be chosen before the first table exists.
        Execute("PRAGMA auto_vacuum = INCREMENTAL;");
        Execute("PRAGMA journal_mode = WAL;");
        using var transaction = Connection.BeginTransaction();
        Execute("""
            CREATE TABLE IF NOT EXISTS auth_failures(
                id INTEGER PRIMARY KEY,
                ts INTEGER NOT NULL,
                channel TEXT NOT NULL,
                record_id INTEGER NOT NULL,
                address TEXT,
                port INTEGER,
                account TEXT NOT NULL,
                reason TEXT NOT NULL,
                logon_type INTEGER,
                UNIQUE(channel, record_id));
            CREATE INDEX IF NOT EXISTS ix_auth_failures_ts ON auth_failures(ts);
            CREATE INDEX IF NOT EXISTS ix_auth_failures_address_ts ON auth_failures(address, ts);
            CREATE TABLE IF NOT EXISTS hourly_sources(
                hour INTEGER NOT NULL,
                address TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                unknown_account INTEGER NOT NULL,
                first_ts INTEGER NOT NULL,
                last_ts INTEGER NOT NULL,
                PRIMARY KEY(hour, address)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS decisions(
                id INTEGER PRIMARY KEY,
                ts INTEGER NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                mode TEXT NOT NULL,
                reason TEXT NOT NULL,
                requested_by TEXT,
                expires_ts INTEGER);
            CREATE INDEX IF NOT EXISTS ix_decisions_ts ON decisions(ts);
            CREATE TABLE IF NOT EXISTS coverage(
                id INTEGER PRIMARY KEY,
                source TEXT NOT NULL,
                from_ts INTEGER NOT NULL,
                to_ts INTEGER NOT NULL,
                status TEXT NOT NULL,
                reason TEXT);
            CREATE INDEX IF NOT EXISTS ix_coverage_source ON coverage(source, from_ts);
            CREATE TABLE IF NOT EXISTS collector_state(
                channel TEXT PRIMARY KEY,
                last_record_id INTEGER NOT NULL,
                last_ts INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS meta(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY,
                ts INTEGER NOT NULL,
                kind TEXT NOT NULL,
                source TEXT NOT NULL,
                address TEXT,
                subject TEXT NOT NULL,
                detail TEXT NOT NULL CHECK (json_valid(detail)),
                dedupe_key TEXT,
                UNIQUE(kind, dedupe_key));
            CREATE INDEX IF NOT EXISTS ix_events_kind_ts ON events(kind, ts);
            CREATE INDEX IF NOT EXISTS ix_events_address_ts ON events(address, ts);
            CREATE TABLE IF NOT EXISTS settings(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL CHECK (json_valid(value)),
                version INTEGER NOT NULL,
                updated_ts INTEGER NOT NULL,
                updated_by TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS settings_history(
                id INTEGER PRIMARY KEY,
                key TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                ts INTEGER NOT NULL,
                changed_by TEXT NOT NULL,
                reason TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS ix_settings_history_key ON settings_history(key, ts);
            """, transaction);
        // Schema 2 (ADR 0011): evidence from the IIS W3C logs. Additive only - nothing above changes, so a
        // schema-1 store keeps its rows. Paths are normalized and user agents cleaned before they get here;
        // no column exists for a query string, a referer or a user name.
        Execute("""
            CREATE TABLE IF NOT EXISTS web_findings(
                id INTEGER PRIMARY KEY,
                ts INTEGER NOT NULL,
                site_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                status INTEGER NOT NULL,
                rules TEXT NOT NULL,
                score INTEGER NOT NULL,
                user_agent TEXT NOT NULL,
                live INTEGER NOT NULL,
                proxied INTEGER NOT NULL,
                protection TEXT);
            CREATE INDEX IF NOT EXISTS ix_web_findings_ts ON web_findings(ts);
            CREATE INDEX IF NOT EXISTS ix_web_findings_address_ts ON web_findings(address, ts);
            CREATE INDEX IF NOT EXISTS ix_web_findings_site_ts ON web_findings(site_id, ts);
            CREATE TABLE IF NOT EXISTS web_hourly_sites(
                hour INTEGER NOT NULL,
                site_id INTEGER NOT NULL,
                requests INTEGER NOT NULL,
                client_errors INTEGER NOT NULL,
                server_errors INTEGER NOT NULL,
                findings INTEGER NOT NULL,
                observations INTEGER NOT NULL,
                login_posts INTEGER NOT NULL,
                xmlrpc_posts INTEGER NOT NULL,
                bytes_received INTEGER NOT NULL,
                PRIMARY KEY(hour, site_id)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS web_hourly_sources(
                hour INTEGER NOT NULL,
                site_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                requests INTEGER NOT NULL,
                client_errors INTEGER NOT NULL,
                findings INTEGER NOT NULL,
                observations INTEGER NOT NULL,
                login_posts INTEGER NOT NULL,
                xmlrpc_posts INTEGER NOT NULL,
                first_ts INTEGER NOT NULL,
                last_ts INTEGER NOT NULL,
                protection TEXT,
                PRIMARY KEY(hour, site_id, address)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS ix_web_hourly_sources_address ON web_hourly_sources(address, hour);
            CREATE TABLE IF NOT EXISTS web_sites(
                site_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT,
                remedy TEXT,
                proxied INTEGER NOT NULL,
                updated_ts INTEGER NOT NULL);
            """, transaction);
        // Schema 3 (ADR 0013): host facts. Additive only. Snapshots are bounded JSON written by the collector,
        // and one posture summary by 'wpshield audit'; hourly health draws the trends. Unexpected restarts and
        // inventory changes are rows of 'events', which needs no change.
        Execute("""
            CREATE TABLE IF NOT EXISTS host_snapshots(
                id INTEGER PRIMARY KEY,
                fact TEXT NOT NULL,
                kind TEXT NOT NULL,
                ts INTEGER NOT NULL,
                status TEXT NOT NULL,
                reason TEXT,
                remedy TEXT,
                payload TEXT CHECK (payload IS NULL OR json_valid(payload)));
            CREATE INDEX IF NOT EXISTS ix_host_snapshots_fact ON host_snapshots(fact, kind, ts);
            CREATE TABLE IF NOT EXISTS host_health_hourly(
                hour INTEGER PRIMARY KEY,
                samples INTEGER NOT NULL,
                cpu_sum REAL NOT NULL,
                cpu_samples INTEGER NOT NULL,
                cpu_peak REAL,
                memory_total INTEGER,
                memory_min_available INTEGER,
                volumes TEXT NOT NULL CHECK (json_valid(volumes)));
            """, transaction);
        Execute($"PRAGMA user_version = {SchemaVersion};", transaction);
        transaction.Commit();
    }

    internal void Execute(string sql, SqliteTransaction? transaction = null, params (string Name, object? Value)[] parameters)
    {
        using var command = Command(sql, transaction, parameters);
        command.ExecuteNonQuery();
    }

    internal T Scalar<T>(string sql, SqliteTransaction? transaction = null, params (string Name, object? Value)[] parameters)
    {
        using var command = Command(sql, transaction, parameters);
        var value = command.ExecuteScalar();
        if (value is null or DBNull) return default!;
        var target = Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T);
        return (T)Convert.ChangeType(value, target, System.Globalization.CultureInfo.InvariantCulture);
    }

    internal SqliteCommand Command(string sql, SqliteTransaction? transaction, params (string Name, object? Value)[] parameters)
    {
        var command = Connection.CreateCommand();
        command.CommandText = sql;
        command.Transaction = transaction;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return command;
    }

    /// <summary>Current size of the database file in bytes, as SQLite counts its pages.</summary>
    public long SizeInBytes => Scalar<long>("PRAGMA page_count;") * Scalar<long>("PRAGMA page_size;");

    internal static long ToMs(DateTimeOffset time) => time.ToUnixTimeMilliseconds();

    internal static DateTimeOffset FromMs(long ms) => DateTimeOffset.FromUnixTimeMilliseconds(ms);

    public void Dispose() => Connection.Dispose();
}

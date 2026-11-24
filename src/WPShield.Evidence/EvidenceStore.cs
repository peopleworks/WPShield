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
    public const int SchemaVersion = 1;
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
            throw new DirectoryNotFoundException(
                $"The evidence directory '{directory}' does not exist. 'wpshield install' creates it with restricted permissions.");
        var connection = Open(path, SqliteOpenMode.ReadWriteCreate);
        var store = new EvidenceStore(connection, readOnly: false);
        store.Migrate();
        return store;
    }

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

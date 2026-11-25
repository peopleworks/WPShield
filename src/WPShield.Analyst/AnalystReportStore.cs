using System.Globalization;
using Microsoft.Data.Sqlite;
using WPShield.Evidence;

namespace WPShield.Analyst;

/// <summary>How a run ended. Every one except <see cref="Completed"/> says the report is not a complete analysis.</summary>
internal static class ReportStatus
{
    public const string Running = "running";
    public const string Completed = "completed";
    /// <summary>The output cap cut the final answer.</summary>
    public const string Truncated = "truncated";
    /// <summary>The model declined (<c>stop_reason: refusal</c>).</summary>
    public const string Refused = "refused";
    /// <summary>A bound stopped the run: the tool calls, or the daily input tokens.</summary>
    public const string Stopped = "stopped";
    public const string TimedOut = "timeout";
    public const string Cancelled = "cancelled";
    public const string Failed = "failed";
}

internal sealed record AnalystReportToolCall(int Sequence, string Name, string Arguments, bool IsError);

/// <summary>One stored report. <see cref="Text"/> is already cleaned and bounded.</summary>
internal sealed record AnalystReport(
    long Id,
    DateTimeOffset Started,
    DateTimeOffset? Finished,
    string Provider,
    bool OperatorPays,
    string Model,
    string? AnsweredBy,
    string Role,
    string? Subject,
    string? Question,
    string Language,
    string Status,
    string? StopReason,
    string? Bound,
    string? RefusalCategory,
    string? RefusalExplanation,
    bool FellBack,
    long InputTokens,
    long OutputTokens,
    string? Error,
    string Text,
    bool TextTruncated,
    IReadOnlyList<AnalystReportToolCall> ToolCalls)
{
    public bool Spanish => Language == "es";
}

/// <param name="Runs">Runs started this UTC day, on any provider, whatever their outcome.</param>
/// <param name="InputTokens">Input tokens spent this UTC day on providers the operator pays.</param>
internal sealed record AnalystUsage(int Runs, long InputTokens, DateTimeOffset DayStart);

/// <summary>What a run is started with.</summary>
internal sealed record ReportStart(DateTimeOffset Started, string Provider, bool OperatorPays, string Model, AnalystRole Role,
    string? Subject, string? Question, string Language);

/// <summary>How a run ended.</summary>
internal sealed record ReportEnd(DateTimeOffset Finished, string Status, string? StopReason = null, string? Bound = null,
    string? RefusalCategory = null, string? RefusalExplanation = null, string? Error = null, string? Text = null);

/// <summary>
/// The analyst's reports (ADR 0010, section 9), in their own SQLite file beside the evidence store:
/// the evidence store holds what was observed, this file holds what a model thought about it. Keeping
/// them apart also leaves the evidence store's one-writer rule intact.
/// </summary>
/// <remarks>
/// <para>
/// <b>Never creates the directory.</b> It lives in the evidence directory that <c>wpshield install</c>
/// creates with replaced permissions; a directory created here would inherit <c>ProgramData</c>'s, which
/// every local user can read. The message for a missing directory is the evidence store's own.
/// </para>
/// <para>
/// A run's row is written when it starts and updated as it goes, so a run that fails, times out or is
/// cancelled still counts against the day's budgets with every token it spent.
/// </para>
/// </remarks>
internal sealed class AnalystReportStore : IDisposable
{
    public const string FileName = "wpshield-analyst.db";
    public const int SchemaVersion = 1;
    public const int MaxReports = 1000;
    public const int MaxArgumentChars = 2000;
    public static readonly TimeSpan Retention = TimeSpan.FromDays(90);

    private readonly SqliteConnection connection;

    private AnalystReportStore(SqliteConnection connection, bool readOnly)
    {
        this.connection = connection;
        ReadOnly = readOnly;
    }

    public bool ReadOnly { get; }

    /// <summary>The report file in the same directory as the evidence store at <paramref name="evidenceStorePath"/>.</summary>
    public static string PathBeside(string evidenceStorePath) =>
        Path.Combine(Path.GetDirectoryName(Path.GetFullPath(evidenceStorePath))!, FileName);

    /// <summary>Opens the store to write a report, creating the file (never the directory) the first time.</summary>
    public static AnalystReportStore Open(string path)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (directory is null || !Directory.Exists(directory))
            throw new DirectoryNotFoundException(EvidenceStore.MissingDirectoryMessage(directory));
        var store = new AnalystReportStore(Connect(path, SqliteOpenMode.ReadWriteCreate), readOnly: false);
        try
        {
            store.Migrate();
            return store;
        }
        catch
        {
            store.Dispose();
            throw;
        }
    }

    /// <summary>Opens the store to read reports, or returns null when no report has ever been written.</summary>
    public static AnalystReportStore? OpenReadOnly(string path)
    {
        if (!File.Exists(path)) return null;
        var store = new AnalystReportStore(Connect(path, SqliteOpenMode.ReadOnly), readOnly: true);
        var version = store.Scalar<long>("PRAGMA user_version;");
        if (version != SchemaVersion)
        {
            store.Dispose();
            throw new InvalidDataException($"The analyst's report store has schema {version}; this build reads schema {SchemaVersion}.");
        }
        return store;
    }

    private static SqliteConnection Connect(string path, SqliteOpenMode mode)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = mode,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            DefaultTimeout = 5
        }.ToString());
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
            throw new InvalidDataException($"The analyst's report store has schema {version}, newer than this build ({SchemaVersion}).");
        using var transaction = connection.BeginTransaction();
        Execute("""
            CREATE TABLE IF NOT EXISTS reports(
                id INTEGER PRIMARY KEY,
                started_ts INTEGER NOT NULL,
                finished_ts INTEGER,
                provider TEXT NOT NULL,
                operator_pays INTEGER NOT NULL,
                model TEXT NOT NULL,
                answered_by TEXT,
                role TEXT NOT NULL,
                subject TEXT,
                question TEXT,
                language TEXT NOT NULL,
                status TEXT NOT NULL,
                stop_reason TEXT,
                bound TEXT,
                refusal_category TEXT,
                refusal_explanation TEXT,
                fell_back INTEGER NOT NULL DEFAULT 0,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                text TEXT NOT NULL DEFAULT '',
                text_truncated INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS ix_reports_started ON reports(started_ts);
            CREATE TABLE IF NOT EXISTS tool_calls(
                id INTEGER PRIMARY KEY,
                report_id INTEGER NOT NULL,
                seq INTEGER NOT NULL,
                name TEXT NOT NULL,
                arguments TEXT NOT NULL,
                is_error INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS ix_tool_calls_report ON tool_calls(report_id, seq);
            """, transaction);
        Execute($"PRAGMA user_version = {SchemaVersion};", transaction);
        transaction.Commit();
    }

    // ---------------------------------------------------------------------------------------------
    //  Writing a run
    // ---------------------------------------------------------------------------------------------

    /// <summary>Records a run as started, before anything is sent, and prunes old reports.</summary>
    public long Begin(ReportStart start)
    {
        ThrowIfReadOnly();
        Prune(start.Started);
        Execute("""
            INSERT INTO reports(started_ts, provider, operator_pays, model, role, subject, question, language, status)
            VALUES ($ts, $provider, $pays, $model, $role, $subject, $question, $language, $status);
            """, null,
            ("$ts", ToMs(start.Started)), ("$provider", ReportText.Line(start.Provider, 40)), ("$pays", start.OperatorPays ? 1 : 0),
            ("$model", ReportText.Line(start.Model, 100)), ("$role", AnalystPrompts.RoleName(start.Role)),
            ("$subject", start.Subject is null ? null : ReportText.Line(start.Subject, 100)),
            ("$question", start.Question is null ? null : ReportText.Line(start.Question, AnalystLimits.MaxQuestionChars)),
            ("$language", ReportText.Line(start.Language, 8)), ("$status", ReportStatus.Running));
        return Scalar<long>("SELECT last_insert_rowid();");
    }

    /// <summary>Adds one turn's tokens and the model that answered it, as soon as the turn returns.</summary>
    public void AddTurn(long id, ProviderTurn turn)
    {
        ThrowIfReadOnly();
        Execute("""
            UPDATE reports SET input_tokens = input_tokens + $in, output_tokens = output_tokens + $out,
                answered_by = $model, fell_back = MAX(fell_back, $fell) WHERE id = $id;
            """, null, ("$in", turn.InputTokens), ("$out", turn.OutputTokens), ("$model", ReportText.Line(turn.Model, 100)),
            ("$fell", turn.FellBack ? 1 : 0), ("$id", id));
    }

    public void AddToolCall(long id, int sequence, string name, string arguments, bool isError)
    {
        ThrowIfReadOnly();
        Execute("INSERT INTO tool_calls(report_id, seq, name, arguments, is_error) VALUES ($id, $seq, $name, $args, $err);", null,
            ("$id", id), ("$seq", sequence), ("$name", ReportText.Line(name, 64)), ("$args", ReportText.Line(arguments, MaxArgumentChars)),
            ("$err", isError ? 1 : 0));
    }

    public void Finish(long id, ReportEnd end)
    {
        ThrowIfReadOnly();
        var (text, truncated) = ReportText.Clean(end.Text);
        Execute("""
            UPDATE reports SET finished_ts = $ts, status = $status, stop_reason = $stop, bound = $bound,
                refusal_category = $category, refusal_explanation = $explanation, error = $error,
                text = $text, text_truncated = $truncated WHERE id = $id;
            """, null,
            ("$ts", ToMs(end.Finished)), ("$status", end.Status), ("$stop", end.StopReason is null ? null : ReportText.Line(end.StopReason, 40)),
            ("$bound", end.Bound is null ? null : ReportText.Line(end.Bound, 200)),
            ("$category", end.RefusalCategory is null ? null : ReportText.Line(end.RefusalCategory, 60)),
            ("$explanation", end.RefusalExplanation is null ? null : ReportText.Line(end.RefusalExplanation, 500)),
            ("$error", end.Error is null ? null : ReportText.Line(end.Error, 600)),
            ("$text", text), ("$truncated", truncated ? 1 : 0), ("$id", id));
    }

    /// <summary>Removes reports older than 90 days, then all but the newest 1,000, with their tool calls.</summary>
    public void Prune(DateTimeOffset now)
    {
        ThrowIfReadOnly();
        using var transaction = connection.BeginTransaction();
        Execute("DELETE FROM reports WHERE started_ts < $cutoff;", transaction, ("$cutoff", ToMs(now - Retention)));
        Execute("DELETE FROM reports WHERE id NOT IN (SELECT id FROM reports ORDER BY started_ts DESC, id DESC LIMIT $max);", transaction,
            ("$max", MaxReports));
        Execute("DELETE FROM tool_calls WHERE report_id NOT IN (SELECT id FROM reports);", transaction);
        transaction.Commit();
    }

    // ---------------------------------------------------------------------------------------------
    //  Reading
    // ---------------------------------------------------------------------------------------------

    /// <summary>Today's usage, by the UTC day, which is the day the budgets count.</summary>
    public AnalystUsage UsageOn(DateTimeOffset now)
    {
        var day = new DateTimeOffset(now.UtcDateTime.Date, TimeSpan.Zero);
        var from = ToMs(day);
        var to = ToMs(day.AddDays(1));
        var runs = Scalar<long>("SELECT COUNT(*) FROM reports WHERE started_ts >= $from AND started_ts < $to;", null, ("$from", from), ("$to", to));
        var tokens = Scalar<long>("SELECT COALESCE(SUM(input_tokens), 0) FROM reports WHERE operator_pays = 1 AND started_ts >= $from AND started_ts < $to;",
            null, ("$from", from), ("$to", to));
        return new AnalystUsage((int)runs, tokens, day);
    }

    public IReadOnlyList<AnalystReport> Recent(int count)
    {
        var ids = new List<long>();
        using (var command = Command("SELECT id FROM reports ORDER BY started_ts DESC, id DESC LIMIT $n;", null, ("$n", Math.Clamp(count, 1, MaxReports))))
        using (var reader = command.ExecuteReader())
            while (reader.Read()) ids.Add(reader.GetInt64(0));
        return [.. ids.Select(id => Get(id)!)];
    }

    public int Count() => (int)Scalar<long>("SELECT COUNT(*) FROM reports;");

    public AnalystReport? Get(long id)
    {
        var calls = new List<AnalystReportToolCall>();
        using (var command = Command("SELECT seq, name, arguments, is_error FROM tool_calls WHERE report_id = $id ORDER BY seq;", null, ("$id", id)))
        using (var reader = command.ExecuteReader())
            while (reader.Read())
                calls.Add(new(reader.GetInt32(0), reader.GetString(1), reader.GetString(2), reader.GetInt64(3) != 0));
        using var select = Command("""
            SELECT id, started_ts, finished_ts, provider, operator_pays, model, answered_by, role, subject, question, language, status,
                stop_reason, bound, refusal_category, refusal_explanation, fell_back, input_tokens, output_tokens, error, text, text_truncated
            FROM reports WHERE id = $id;
            """, null, ("$id", id));
        using var row = select.ExecuteReader();
        if (!row.Read()) return null;
        string? Text(int i) => row.IsDBNull(i) ? null : row.GetString(i);
        return new AnalystReport(
            row.GetInt64(0), FromMs(row.GetInt64(1)), row.IsDBNull(2) ? null : FromMs(row.GetInt64(2)), row.GetString(3), row.GetInt64(4) != 0,
            row.GetString(5), Text(6), row.GetString(7), Text(8), Text(9), row.GetString(10), row.GetString(11), Text(12), Text(13),
            Text(14), Text(15), row.GetInt64(16) != 0, row.GetInt64(17), row.GetInt64(18), Text(19), row.GetString(20), row.GetInt64(21) != 0,
            calls);
    }

    private void ThrowIfReadOnly()
    {
        if (ReadOnly) throw new InvalidOperationException("The report store was opened read-only.");
    }

    private void Execute(string sql, SqliteTransaction? transaction = null, params (string Name, object? Value)[] parameters)
    {
        using var command = Command(sql, transaction, parameters);
        command.ExecuteNonQuery();
    }

    private T Scalar<T>(string sql, SqliteTransaction? transaction = null, params (string Name, object? Value)[] parameters)
    {
        using var command = Command(sql, transaction, parameters);
        var value = command.ExecuteScalar();
        if (value is null or DBNull) return default!;
        return (T)Convert.ChangeType(value, typeof(T), CultureInfo.InvariantCulture);
    }

    private SqliteCommand Command(string sql, SqliteTransaction? transaction, params (string Name, object? Value)[] parameters)
    {
        var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Transaction = transaction;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return command;
    }

    private static long ToMs(DateTimeOffset time) => time.ToUnixTimeMilliseconds();

    private static DateTimeOffset FromMs(long ms) => DateTimeOffset.FromUnixTimeMilliseconds(ms);

    public void Dispose() => connection.Dispose();
}

/// <summary>Bounds on what the operator gives a run.</summary>
internal static class AnalystLimits
{
    public const int MaxQuestionChars = 2000;
}

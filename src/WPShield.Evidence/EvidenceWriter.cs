namespace WPShield.Evidence;

/// <summary>A block decision, as the audit trail records it (ADR 0006, 0007 and 0009).</summary>
/// <param name="Action">
/// What the decision engine writes (<see cref="Decisions.DecisionActions"/>): <c>would-block</c>,
/// <c>protected</c>, <c>report</c>, <c>expire</c> and <c>refused</c>. Reserved for the enforcer of ADR 0006:
/// <c>block</c>, <c>unblock</c>, <c>allow</c>.
/// </param>
/// <param name="Target">The canonical address or range the decision is about.</param>
/// <param name="Mode"><c>monitor</c> or <c>block</c>.</param>
/// <param name="RequestedBy">The evidence channel whose record completed the rule, such as <c>security-4625</c>.</param>
public sealed record DecisionRecord(DateTimeOffset Timestamp, string Action, string Target, string RuleId, string Mode,
    string Reason, string? RequestedBy, DateTimeOffset? ExpiresAt);

/// <summary>What one pruning pass removed, so the caller can log it and the views can show it.</summary>
public sealed record PruneResult(long RawRowsDeleted, long AggregateRowsDeleted, long DecisionRowsDeleted,
    long EventRowsDeleted, DateTimeOffset? RawNowStartsAt)
{
    /// <summary>IIS log findings removed (ADR 0011). Their hourly counts are in <see cref="AggregateRowsDeleted"/>.</summary>
    public long WebRowsDeleted { get; init; }

    /// <summary>Host-fact snapshots and hourly health removed (ADR 0013). The latest snapshot of every fact is never removed.</summary>
    public long HostRowsDeleted { get; init; }
}

/// <summary>
/// The only code that writes evidence. It accepts typed records and nothing else: there is no method a
/// request body, a query string or a header could be passed to.
/// </summary>
public sealed class EvidenceWriter
{
    public const string RawSource = "auth-failures";
    private const string RawPrunedBeforeKey = "raw_pruned_before";
    private readonly EvidenceStore store;

    public EvidenceWriter(EvidenceStore store)
    {
        if (store.ReadOnly) throw new InvalidOperationException("A read-only evidence store cannot be written.");
        this.store = store;
    }

    /// <summary>
    /// Pairs the batch (see <see cref="AttemptPairing"/>) and inserts what survives. A record already
    /// stored - same channel and record ID - is ignored, so catching up from the event log after a
    /// restart never counts an attempt twice. Returns the number of rows inserted.
    /// </summary>
    public int Append(IEnumerable<AuthFailure> failures)
    {
        var batch = AttemptPairing.Pair(failures);
        if (batch.Count == 0) return 0;
        var inserted = 0;
        using var transaction = store.Connection.BeginTransaction();
        using var insert = store.Command("""
            INSERT OR IGNORE INTO auth_failures(ts, channel, record_id, address, port, account, reason, logon_type)
            VALUES ($ts, $channel, $record, $address, $port, $account, $reason, $type);
            """, transaction, ("$ts", 0L), ("$channel", ""), ("$record", 0L), ("$address", null), ("$port", null),
            ("$account", ""), ("$reason", ""), ("$type", null));
        using var hourly = store.Command("""
            INSERT INTO hourly_sources(hour, address, attempts, unknown_account, first_ts, last_ts)
            VALUES ($hour, $address, 1, $unknown, $ts, $ts)
            ON CONFLICT(hour, address) DO UPDATE SET
                attempts = attempts + 1,
                unknown_account = unknown_account + excluded.unknown_account,
                first_ts = MIN(first_ts, excluded.first_ts),
                last_ts = MAX(last_ts, excluded.last_ts);
            """, transaction, ("$hour", 0L), ("$address", ""), ("$unknown", 0), ("$ts", 0L));
        using var state = store.Command("""
            INSERT INTO collector_state(channel, last_record_id, last_ts) VALUES ($channel, $record, $ts)
            ON CONFLICT(channel) DO UPDATE SET
                last_record_id = MAX(last_record_id, excluded.last_record_id),
                last_ts = MAX(last_ts, excluded.last_ts);
            """, transaction, ("$channel", ""), ("$record", 0L), ("$ts", 0L));
        foreach (var failure in batch)
        {
            var ts = EvidenceStore.ToMs(failure.Timestamp);
            var address = failure.Address?.ToString();
            insert.Parameters["$ts"].Value = ts;
            insert.Parameters["$channel"].Value = failure.Channel;
            insert.Parameters["$record"].Value = failure.RecordId;
            insert.Parameters["$address"].Value = (object?)address ?? DBNull.Value;
            insert.Parameters["$port"].Value = (object?)failure.Port ?? DBNull.Value;
            insert.Parameters["$account"].Value = EvidenceText.Clean(failure.Account);
            insert.Parameters["$reason"].Value = EvidenceText.Clean(failure.Reason, 32);
            insert.Parameters["$type"].Value = (object?)failure.LogonType ?? DBNull.Value;
            state.Parameters["$channel"].Value = failure.Channel;
            state.Parameters["$record"].Value = failure.RecordId;
            state.Parameters["$ts"].Value = ts;
            state.ExecuteNonQuery();
            if (insert.ExecuteNonQuery() == 0) continue;
            inserted++;
            hourly.Parameters["$hour"].Value = ts / 3_600_000;
            hourly.Parameters["$address"].Value = address ?? "";
            hourly.Parameters["$unknown"].Value = failure.Reason == "unknown-account" ? 1 : 0;
            hourly.Parameters["$ts"].Value = ts;
            hourly.ExecuteNonQuery();
        }
        transaction.Commit();
        return inserted;
    }

    /// <summary>The newest record ID stored for a channel, so a restart can catch up from it.</summary>
    public (long RecordId, DateTimeOffset Timestamp)? LastRecord(string channel)
    {
        using var command = store.Command("SELECT last_record_id, last_ts FROM collector_state WHERE channel = $c;", null, ("$c", channel));
        using var reader = command.ExecuteReader();
        return reader.Read() ? (reader.GetInt64(0), EvidenceStore.FromMs(reader.GetInt64(1))) : null;
    }

    /// <summary>
    /// Starts an interval the collector vouches for. Extend it as time passes; anything outside every
    /// collected interval is drawn as "no data".
    /// </summary>
    public long BeginCoverage(string source, DateTimeOffset from, DateTimeOffset to, string status = "collected", string? reason = null)
    {
        store.Execute("INSERT INTO coverage(source, from_ts, to_ts, status, reason) VALUES ($s, $f, $t, $st, $r);", null,
            ("$s", source), ("$f", EvidenceStore.ToMs(from)), ("$t", EvidenceStore.ToMs(to)), ("$st", status), ("$r", reason));
        return store.Scalar<long>("SELECT last_insert_rowid();");
    }

    public void ExtendCoverage(long id, DateTimeOffset to) =>
        store.Execute("UPDATE coverage SET to_ts = MAX(to_ts, $t) WHERE id = $id;", null, ("$t", EvidenceStore.ToMs(to)), ("$id", id));

    public void RecordDecision(DecisionRecord decision) =>
        store.Execute("""
            INSERT INTO decisions(ts, action, target, rule_id, mode, reason, requested_by, expires_ts)
            VALUES ($ts, $a, $t, $rule, $m, $r, $by, $exp);
            """, null, ("$ts", EvidenceStore.ToMs(decision.Timestamp)), ("$a", EvidenceText.Clean(decision.Action, 16)),
            ("$t", EvidenceText.Clean(decision.Target, 64)), ("$rule", EvidenceText.Clean(decision.RuleId, 32)),
            ("$m", EvidenceText.Clean(decision.Mode, 16)), ("$r", EvidenceText.Clean(decision.Reason, 200)),
            ("$by", decision.RequestedBy is null ? null : EvidenceText.Clean(decision.RequestedBy, 64)),
            ("$exp", decision.ExpiresAt is null ? null : EvidenceStore.ToMs(decision.ExpiresAt.Value)));

    /// <summary>
    /// Records that a decision engine started in this process. Readers count a decision as in force only
    /// if this run made it: a decision never outlives the process that made it, and a restart writes no
    /// <c>expire</c> row for the decisions it forgot. The engine itself never reads it back.
    /// </summary>
    public void RecordEngineStart(DateTimeOffset at) =>
        store.Execute("INSERT INTO meta(key, value) VALUES ($k, $v) ON CONFLICT(key) DO UPDATE SET value = excluded.value;", null,
            ("$k", EvidenceQueries.EngineStartedKey), ("$v", EvidenceStore.ToMs(at).ToString(System.Globalization.CultureInfo.InvariantCulture)));

    /// <summary>
    /// Applies every bound in <paramref name="limits"/>: age, row count and file size. Detailed rows go
    /// first; the hourly aggregates and the decisions outlive them. Where detailed rows were removed is
    /// remembered, so a query over that period answers from the aggregates and says so.
    /// </summary>
    public PruneResult Prune(DateTimeOffset now, EvidenceLimits limits)
    {
        long raw = 0, aggregates = 0, decisions = 0, events = 0, web = 0;
        events += Delete("DELETE FROM events WHERE ts < $c;", EvidenceStore.ToMs(now - limits.EventRetention));
        var eventCount = store.Scalar<long>("SELECT COUNT(*) FROM events;");
        if (eventCount > limits.MaxEventRows)
            events += Delete("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY ts LIMIT $c);",
                eventCount - limits.MaxEventRows);
        var rawCutoff = EvidenceStore.ToMs(now - limits.RawRetention);
        raw += Delete("DELETE FROM auth_failures WHERE ts < $c;", rawCutoff);
        var count = store.Scalar<long>("SELECT COUNT(*) FROM auth_failures;");
        if (count > limits.MaxRawRows)
        {
            var boundary = store.Scalar<long>("SELECT ts FROM auth_failures ORDER BY ts LIMIT 1 OFFSET $n;", null,
                ("$n", count - limits.MaxRawRows));
            raw += Delete("DELETE FROM auth_failures WHERE ts < $c;", boundary);
            rawCutoff = Math.Max(rawCutoff, boundary);
        }
        // The IIS log evidence (ADR 0011) follows the same bounds: findings are detailed rows, the hourly
        // counts are aggregates, and a read position outlives its file only as long as the detailed rows.
        var webCutoff = EvidenceStore.ToMs(now - limits.RawRetention);
        web += Delete("DELETE FROM web_findings WHERE ts < $c;", webCutoff);
        var webCount = store.Scalar<long>("SELECT COUNT(*) FROM web_findings;");
        var webBounded = false;
        if (webCount > limits.MaxRawRows)
        {
            web += Delete("DELETE FROM web_findings WHERE id IN (SELECT id FROM web_findings ORDER BY ts LIMIT $c);", webCount - limits.MaxRawRows);
            webBounded = true;
        }
        WebEvidenceWriter.PrunePositions(store, webCutoff);
        var aggregateCutoff = EvidenceStore.ToMs(now - limits.AggregateRetention);
        aggregates += Delete("DELETE FROM hourly_sources WHERE hour < $c;", aggregateCutoff / 3_600_000);
        aggregates += Delete("DELETE FROM web_hourly_sites WHERE hour < $c;", aggregateCutoff / 3_600_000);
        aggregates += Delete("DELETE FROM web_hourly_sources WHERE hour < $c;", aggregateCutoff / 3_600_000);
        decisions += Delete("DELETE FROM decisions WHERE ts < $c;", aggregateCutoff);
        var host = HostFactsWriter.Prune(store, now);
        store.Execute("DELETE FROM coverage WHERE to_ts < $c;", null, ("$c", aggregateCutoff));
        store.Execute("PRAGMA incremental_vacuum;");
        // The file bound: drop the oldest tenth of the detailed rows until it fits, never the aggregates.
        for (var round = 0; round < 10 && store.SizeInBytes > limits.MaxBytes; round++)
        {
            var remaining = store.Scalar<long>("SELECT COUNT(*) FROM auth_failures;");
            var webRemaining = store.Scalar<long>("SELECT COUNT(*) FROM web_findings;");
            if (remaining == 0 && webRemaining == 0) break;
            if (remaining > 0)
            {
                var boundary = store.Scalar<long>("SELECT ts FROM auth_failures ORDER BY ts LIMIT 1 OFFSET $n;", null,
                    ("$n", Math.Max(1, remaining / 10) - 1)) + 1;
                raw += Delete("DELETE FROM auth_failures WHERE ts < $c;", boundary);
                rawCutoff = Math.Max(rawCutoff, boundary);
            }
            if (webRemaining > 0)
            {
                web += Delete("DELETE FROM web_findings WHERE id IN (SELECT id FROM web_findings ORDER BY ts LIMIT $c);",
                    Math.Max(1, webRemaining / 10));
                webBounded = true;
            }
            store.Execute("PRAGMA incremental_vacuum;");
        }
        if (web > 0)
        {
            // Where web findings now start, so a reader says "findings before this were pruned" instead of "none".
            // A bound on rows or on the file size cut later than the age did: findings start at the oldest one kept.
            var boundary = webBounded ? store.Scalar<long?>("SELECT MIN(ts) FROM web_findings;") ?? EvidenceStore.ToMs(now) : webCutoff;
            store.Execute("INSERT INTO meta(key, value) VALUES ($k, $v) ON CONFLICT(key) DO UPDATE SET value = excluded.value;", null,
                ("$k", WebEvidenceQueries.WebPrunedBeforeKey),
                ("$v", Math.Max(boundary, webCutoff).ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }
        var previous = RawPrunedBefore();
        if (raw > 0 || previous is null || EvidenceStore.ToMs(previous.Value) < rawCutoff)
            store.Execute("INSERT INTO meta(key, value) VALUES ($k, $v) ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
                null, ("$k", RawPrunedBeforeKey), ("$v", rawCutoff.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        return new(raw, aggregates, decisions, events, EvidenceStore.FromMs(rawCutoff)) { WebRowsDeleted = web, HostRowsDeleted = host };
    }

    internal DateTimeOffset? RawPrunedBefore() => EvidenceQueries.RawPrunedBefore(store);

    private long Delete(string sql, long cutoff)
    {
        using var command = store.Command(sql, null, ("$c", cutoff));
        return command.ExecuteNonQuery();
    }
}

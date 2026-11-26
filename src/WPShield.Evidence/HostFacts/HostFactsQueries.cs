using System.Text.Json;
using System.Text.Json.Nodes;

namespace WPShield.Evidence;

/// <summary>A point of the posture history: the "pools moved, week by week" gauge.</summary>
public sealed record PosturePoint(DateTimeOffset TakenAt, string Source, bool Complete, int? PoolsTotal, int? PoolsAdministrator);

/// <summary>One hour of health: CPU average and peak, minimum free memory, minimum free space per volume.</summary>
public sealed record HealthHour(DateTimeOffset Hour, long Samples, double? CpuAverage, double? CpuPeak, long? MemoryTotal,
    long? MemoryMinAvailable, IReadOnlyDictionary<string, long> VolumeMinFree);

/// <summary>An inventory change as stored. <see cref="Item"/> is a host detail: a name or a path.</summary>
public sealed record InventoryChangeRecord(DateTimeOffset At, string Kind, string Change, string Item, IReadOnlyList<string> Fields);

/// <summary>An overflow of inventory changes on one day: counted, not stored one by one.</summary>
public sealed record InventoryOverflow(DateTimeOffset Day, string Kind, long Count);

/// <summary>
/// The read API of the host facts (ADR 0013): fixed, parameterised SQL with bounded results, like every other
/// reader of the store. The CLI answers from it today; the desktop command center and the MCP tools follow.
/// </summary>
public sealed class HostFactsQueries
{
    public const int MaxRows = 1000;
    private readonly EvidenceStore store;

    public HostFactsQueries(EvidenceStore store) => this.store = store ?? throw new ArgumentNullException(nameof(store));

    /// <summary>The newest snapshot of one fact (and inventory kind), or <see langword="null"/> when none was ever taken.</summary>
    public HostFactReading? Latest(string fact, string? kind = null)
    {
        if (!HostFacts.IsFact(fact)) throw new ArgumentException($"Unknown host fact '{fact}'.", nameof(fact));
        if (fact == HostFacts.Inventory ? !HostFacts.IsInventoryKind(kind) : kind is not null)
            throw new ArgumentException("Only host_inventory takes a kind: accounts, services or tasks.", nameof(kind));
        using var command = store.Command("""
            SELECT fact, kind, ts, status, reason, remedy, payload FROM host_snapshots
            WHERE fact = $f AND kind = $k ORDER BY ts DESC, id DESC LIMIT 1;
            """, null, ("$f", fact), ("$k", kind ?? ""));
        using var reader = command.ExecuteReader();
        return reader.Read() ? Read(reader) : null;
    }

    /// <summary>
    /// The newest snapshot of every fact, in a fixed order; a fact never read is absent, which every surface
    /// shows as "no snapshot yet", never as empty.
    /// </summary>
    public IReadOnlyList<HostFactReading> LatestAll()
    {
        var result = new List<HostFactReading>();
        foreach (var fact in HostFacts.All)
        {
            if (fact == HostFacts.Inventory)
            {
                foreach (var kind in HostFacts.InventoryKinds)
                    if (Latest(fact, kind) is { } inventory) result.Add(inventory);
            }
            else if (Latest(fact) is { } snapshot) result.Add(snapshot);
        }
        return result;
    }

    /// <summary>Unexpected restarts recorded in a range, newest first.</summary>
    public IReadOnlyList<HostRestart> Restarts(DateTimeOffset from, DateTimeOffset to, int limit = 100)
    {
        if (to <= from) throw new ArgumentException("The range must end after it starts.");
        using var command = store.Command("""
            SELECT ts, detail, dedupe_key FROM events WHERE kind = $k AND ts >= $f AND ts < $t ORDER BY ts DESC LIMIT $n;
            """, null, ("$k", HostFacts.RestartKind), ("$f", EvidenceStore.ToMs(from)), ("$t", EvidenceStore.ToMs(to)),
            ("$n", Math.Clamp(limit, 1, MaxRows)));
        using var reader = command.ExecuteReader();
        var result = new List<HostRestart>();
        while (reader.Read())
        {
            var detail = JsonNode.Parse(reader.GetString(1)) as JsonObject ?? [];
            var ids = detail["events"] is JsonArray array
                ? array.Select(n => n is JsonValue v && v.TryGetValue<int>(out var id) ? id : 0).Where(id => id > 0).ToArray()
                : [];
            uint? code = detail["bugCheckCode"] is JsonValue c && c.TryGetValue<uint>(out var value) ? value : null;
            result.Add(new HostRestart(reader.IsDBNull(2) ? "" : reader.GetString(2), EvidenceStore.FromMs(reader.GetInt64(0)), ids, code));
        }
        return result;
    }

    /// <summary>
    /// Until when the collector's restart reader has read the System log, or <see langword="null"/> when it never
    /// has. A count of restarts is only a count once this is known: with no read, "no restart recorded" means
    /// "nobody looked", never "none" (ADR 0013, section 2).
    /// </summary>
    public DateTimeOffset? RestartsReadUntil()
    {
        var ms = store.Scalar<long?>("SELECT last_ts FROM collector_state WHERE channel = $c;", null, ("$c", HostFactsWriter.RestartChannel));
        return ms is null ? null : EvidenceStore.FromMs(ms.Value);
    }

    /// <summary>The posture snapshots in a range, oldest first: the history behind "pools moved: N of M".</summary>
    public IReadOnlyList<PosturePoint> PostureHistory(DateTimeOffset from, DateTimeOffset to, int limit = 500)
    {
        if (to <= from) throw new ArgumentException("The range must end after it starts.");
        using var command = store.Command("""
            SELECT ts, payload FROM host_snapshots WHERE fact = 'iis_posture' AND ts >= $f AND ts < $t AND payload IS NOT NULL
            ORDER BY ts LIMIT $n;
            """, null, ("$f", EvidenceStore.ToMs(from)), ("$t", EvidenceStore.ToMs(to)), ("$n", Math.Clamp(limit, 1, MaxRows)));
        using var reader = command.ExecuteReader();
        var result = new List<PosturePoint>();
        while (reader.Read())
        {
            var posture = (JsonNode.Parse(reader.GetString(1)) as JsonObject)?.Deserialize<HostPosture>(HostFacts.Json);
            if (posture is null) continue;
            result.Add(new(EvidenceStore.FromMs(reader.GetInt64(0)), posture.Source, posture.Complete, posture.PoolsTotal, posture.PoolsAdministrator));
        }
        return result;
    }

    /// <summary>Hourly health in a range, oldest first.</summary>
    public IReadOnlyList<HealthHour> HealthHourly(DateTimeOffset from, DateTimeOffset to)
    {
        if (to <= from) throw new ArgumentException("The range must end after it starts.");
        using var command = store.Command("""
            SELECT hour, samples, cpu_sum, cpu_samples, cpu_peak, memory_total, memory_min_available, volumes
            FROM host_health_hourly WHERE hour >= $f AND hour < $t ORDER BY hour LIMIT $n;
            """, null, ("$f", EvidenceStore.ToMs(from) / 3_600_000), ("$t", (EvidenceStore.ToMs(to) + 3_599_999) / 3_600_000), ("$n", 24 * 400));
        using var reader = command.ExecuteReader();
        var result = new List<HealthHour>();
        while (reader.Read())
        {
            var cpuSamples = reader.GetInt64(3);
            var volumes = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            if (JsonNode.Parse(reader.GetString(7)) is JsonObject map)
                foreach (var (name, value) in map)
                    if (value is JsonValue v && v.TryGetValue<long>(out var free)) volumes[name] = free;
            result.Add(new(EvidenceStore.FromMs(reader.GetInt64(0) * 3_600_000), reader.GetInt64(1),
                cpuSamples > 0 ? reader.GetDouble(2) / cpuSamples : null, reader.IsDBNull(4) ? null : reader.GetDouble(4),
                reader.IsDBNull(5) ? null : reader.GetInt64(5), reader.IsDBNull(6) ? null : reader.GetInt64(6), volumes));
        }
        return result;
    }

    /// <summary>Inventory changes in a range, newest first. Overflow days are returned by <see cref="InventoryOverflows"/>.</summary>
    public IReadOnlyList<InventoryChangeRecord> InventoryChanges(DateTimeOffset from, DateTimeOffset to, string? kind = null, int limit = 200)
    {
        if (to <= from) throw new ArgumentException("The range must end after it starts.");
        if (kind is not null && !HostFacts.IsInventoryKind(kind)) throw new ArgumentException("An inventory kind is accounts, services or tasks.", nameof(kind));
        using var command = store.Command($"""
            SELECT ts, subject, detail FROM events WHERE kind = $k AND ts >= $f AND ts < $t
            AND (dedupe_key IS NULL OR dedupe_key NOT LIKE 'overflow:%'){(kind is null ? "" : " AND subject = $s")}
            ORDER BY ts DESC LIMIT $n;
            """, null, ("$k", HostFacts.InventoryChangeKind), ("$f", EvidenceStore.ToMs(from)), ("$t", EvidenceStore.ToMs(to)),
            ("$s", kind), ("$n", Math.Clamp(limit, 1, MaxRows)));
        using var reader = command.ExecuteReader();
        var result = new List<InventoryChangeRecord>();
        while (reader.Read())
        {
            var detail = JsonNode.Parse(reader.GetString(2)) as JsonObject ?? [];
            var fields = detail["fields"] is JsonArray array
                ? array.Select(n => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null).OfType<string>().ToArray()
                : [];
            result.Add(new(EvidenceStore.FromMs(reader.GetInt64(0)), reader.GetString(1), Text(detail["change"]), Text(detail["item"]), fields));
        }
        return result;
    }

    public IReadOnlyList<InventoryOverflow> InventoryOverflows(DateTimeOffset from, DateTimeOffset to)
    {
        using var command = store.Command("""
            SELECT ts, subject, detail FROM events WHERE kind = $k AND ts >= $f AND ts < $t AND dedupe_key LIKE 'overflow:%'
            ORDER BY ts DESC LIMIT 400;
            """, null, ("$k", HostFacts.InventoryChangeKind), ("$f", EvidenceStore.ToMs(from)), ("$t", EvidenceStore.ToMs(to)));
        using var reader = command.ExecuteReader();
        var result = new List<InventoryOverflow>();
        while (reader.Read())
        {
            var detail = JsonNode.Parse(reader.GetString(2)) as JsonObject ?? [];
            var count = detail["overflow"] is JsonValue v && v.TryGetValue<long>(out var n) ? n : 0;
            var at = EvidenceStore.FromMs(reader.GetInt64(0));
            result.Add(new(new DateTimeOffset(at.UtcDateTime.Date, TimeSpan.Zero), reader.GetString(1), count));
        }
        return result;
    }

    /// <summary>
    /// The distinct account names attempted since a time, from the detailed failed logons. They are
    /// attacker-chosen text, already cleaned when stored; the collector compares them with local full names in
    /// memory for the full-name indicator and keeps only the count.
    /// </summary>
    public IReadOnlyList<string> AttemptedAccountNames(DateTimeOffset since, int limit = 50_000)
    {
        using var command = store.Command("SELECT DISTINCT account FROM auth_failures WHERE ts >= $f LIMIT $n;", null,
            ("$f", EvidenceStore.ToMs(since)), ("$n", Math.Clamp(limit, 1, 50_000)));
        using var reader = command.ExecuteReader();
        var result = new List<string>();
        while (reader.Read()) result.Add(reader.GetString(0));
        return result;
    }

    private static HostFactReading Read(Microsoft.Data.Sqlite.SqliteDataReader reader) => new(
        reader.GetString(0),
        reader.GetString(1) is { Length: > 0 } kind ? kind : null,
        EvidenceStore.FromMs(reader.GetInt64(2)),
        reader.GetString(3),
        reader.IsDBNull(4) ? null : reader.GetString(4),
        reader.IsDBNull(5) ? null : reader.GetString(5),
        reader.IsDBNull(6) ? null : JsonNode.Parse(reader.GetString(6)) as JsonObject);

    private static string Text(JsonNode? node) => node is JsonValue v && v.TryGetValue<string>(out var s) ? s : "";
}

using System.Globalization;
using System.Text.Json.Nodes;

namespace WPShield.Evidence;

/// <summary>
/// Writes host facts (ADR 0013) into the evidence store: snapshots, hourly health, unexpected restarts and
/// inventory changes. Only the collector's loop writes, plus one posture summary per manual audit.
/// </summary>
/// <remarks>
/// Everything is bounded here as well as in the readers: a payload is cleaned and kept under
/// <see cref="HostFacts.MaxPayloadBytes"/>, a status other than <c>ok</c> must say why and what to do, and
/// change events stop at <see cref="HostFacts.MaxChangeEventsPerDay"/> a day per kind, with the overflow counted.
/// </remarks>
public sealed class HostFactsWriter
{
    private const string RestartChannel = "host-restarts";
    private readonly EvidenceStore store;

    public HostFactsWriter(EvidenceStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (store.ReadOnly) throw new InvalidOperationException("A read-only evidence store cannot be written.");
        this.store = store;
    }

    /// <summary>Stores one snapshot. Returns it as stored: cleaned, and trimmed to the payload bound if it had to be.</summary>
    public HostFactReading Write(HostFactReading reading)
    {
        ArgumentNullException.ThrowIfNull(reading);
        if (!HostFacts.IsFact(reading.Fact)) throw new ArgumentException($"Unknown host fact '{reading.Fact}'.", nameof(reading));
        if (reading.Fact == HostFacts.Inventory ? !HostFacts.IsInventoryKind(reading.Kind) : reading.Kind is not null)
            throw new ArgumentException("Only host_inventory has a kind: accounts, services or tasks.", nameof(reading));
        if (!HostFactStatus.IsKnown(reading.Status)) throw new ArgumentException($"Unknown status '{reading.Status}'.", nameof(reading));
        if (reading.Status != HostFactStatus.Ok && (string.IsNullOrWhiteSpace(reading.Reason) || string.IsNullOrWhiteSpace(reading.Remedy)))
            throw new ArgumentException("A fact that is not ok says why and what to do: reason and remedy are required.", nameof(reading));

        var status = reading.Status;
        var reason = reading.Reason;
        var payload = reading.Payload is null ? null : (JsonObject)CleanNode(reading.Payload, 0)!;
        if (payload is not null && Trim(payload))
        {
            if (status == HostFactStatus.Ok) status = HostFactStatus.Partial;
            reason = reason is null ? "payload-bound" : reason + "; payload-bound";
        }
        var remedy = reading.Remedy ?? (reason is null ? null : "The snapshot was cut to its size bound; 'wpshield host --live' shows everything.");
        var stored = reading with
        {
            Status = status,
            Reason = reason is null ? null : EvidenceText.Clean(reason, 512),
            Remedy = remedy is null ? null : EvidenceText.Clean(remedy, 1024),
            Payload = payload
        };
        store.Execute("""
            INSERT INTO host_snapshots(fact, kind, ts, status, reason, remedy, payload)
            VALUES ($f, $k, $ts, $s, $r, $m, $p);
            """, null, ("$f", stored.Fact), ("$k", stored.Kind ?? ""), ("$ts", EvidenceStore.ToMs(stored.TakenAt)), ("$s", stored.Status),
            ("$r", stored.Reason), ("$m", stored.Remedy), ("$p", payload?.ToJsonString()));
        return stored;
    }

    /// <summary>Folds one health reading into its hour: CPU average and peak, minimum free memory and disk.</summary>
    public void RecordHealth(HostHealth health, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(health);
        var hour = EvidenceStore.ToMs(at) / 3_600_000;
        using var command = store.Command("""
            SELECT samples, cpu_sum, cpu_samples, cpu_peak, memory_total, memory_min_available, volumes
            FROM host_health_hourly WHERE hour = $h;
            """, null, ("$h", hour));
        long samples = 0, cpuSamples = 0;
        double cpuSum = 0;
        double? cpuPeak = null;
        long? memoryTotal = null, memoryMin = null;
        var volumes = new JsonObject();
        using (var reader = command.ExecuteReader())
        {
            if (reader.Read())
            {
                samples = reader.GetInt64(0);
                cpuSum = reader.GetDouble(1);
                cpuSamples = reader.GetInt64(2);
                cpuPeak = reader.IsDBNull(3) ? null : reader.GetDouble(3);
                memoryTotal = reader.IsDBNull(4) ? null : reader.GetInt64(4);
                memoryMin = reader.IsDBNull(5) ? null : reader.GetInt64(5);
                volumes = JsonNode.Parse(reader.GetString(6)) as JsonObject ?? [];
            }
        }
        samples++;
        if (health.CpuPercent is { } cpu && double.IsFinite(cpu))
        {
            cpuSum += cpu;
            cpuSamples++;
            cpuPeak = cpuPeak is null ? cpu : Math.Max(cpuPeak.Value, cpu);
        }
        memoryTotal = health.MemoryTotalBytes ?? memoryTotal;
        if (health.MemoryAvailableBytes is { } available) memoryMin = memoryMin is null ? available : Math.Min(memoryMin.Value, available);
        foreach (var volume in health.Volumes.Take(HostFacts.MaxVolumes))
        {
            var name = HostFacts.Clean(volume.Name);
            if (name.Length == 0) continue;
            var previous = volumes[name] is JsonValue v && v.TryGetValue<long>(out var free) ? free : (long?)null;
            if (previous is null && volumes.Count >= HostFacts.MaxVolumes) continue;
            volumes[name] = previous is null ? volume.FreeBytes : Math.Min(previous.Value, volume.FreeBytes);
        }
        store.Execute("""
            INSERT OR REPLACE INTO host_health_hourly(hour, samples, cpu_sum, cpu_samples, cpu_peak, memory_total, memory_min_available, volumes)
            VALUES ($h, $n, $cs, $cn, $cp, $mt, $mm, $v);
            """, null, ("$h", hour), ("$n", samples), ("$cs", cpuSum), ("$cn", cpuSamples), ("$cp", cpuPeak), ("$mt", memoryTotal),
            ("$mm", memoryMin), ("$v", volumes.ToJsonString()));
    }

    /// <summary>
    /// Records unexpected restarts, once each. A restart already stored is updated in place when a later read
    /// brings its bugcheck code (WER writes 1001 after Kernel-Power writes 41). Returns how many were new.
    /// </summary>
    public int RecordRestarts(IReadOnlyList<HostRestart> restarts)
    {
        ArgumentNullException.ThrowIfNull(restarts);
        var added = 0;
        foreach (var restart in restarts.Take(HostFacts.MaxRestartEvents))
        {
            var key = EvidenceText.Clean(restart.Key, 200);
            var exists = store.Scalar<long>("SELECT COUNT(*) FROM events WHERE kind = $k AND dedupe_key = $d;", null,
                ("$k", HostFacts.RestartKind), ("$d", key)) > 0;
            var detail = new JsonObject
            {
                ["events"] = new JsonArray([.. restart.EventIds.Take(8).Select(id => (JsonNode)JsonValue.Create(id))]),
                ["bugCheckCode"] = restart.BugCheckCode is { } code ? JsonValue.Create(code) : null,
                ["bugCheck"] = restart.BugCheck,
                ["recordedAtNextStart"] = true
            };
            store.Execute("""
                INSERT INTO events(ts, kind, source, address, subject, detail, dedupe_key)
                VALUES ($ts, $k, $s, NULL, 'unexpected-restart', $d, $key)
                ON CONFLICT(kind, dedupe_key) DO UPDATE SET detail = excluded.detail WHERE events.detail <> excluded.detail;
                """, null, ("$ts", EvidenceStore.ToMs(restart.At)), ("$k", HostFacts.RestartKind), ("$s", HostFacts.EventSource),
                ("$d", detail.ToJsonString()), ("$key", key));
            if (!exists) added++;
        }
        return added;
    }

    /// <summary>Where the restart reader stopped, so a later start reads only what is new.</summary>
    public DateTimeOffset? RestartsReadUntil()
    {
        var ms = store.Scalar<long?>("SELECT last_ts FROM collector_state WHERE channel = $c;", null, ("$c", RestartChannel));
        return ms is null ? null : EvidenceStore.FromMs(ms.Value);
    }

    public void SetRestartsReadUntil(DateTimeOffset until) =>
        store.Execute("""
            INSERT INTO collector_state(channel, last_record_id, last_ts) VALUES ($c, 0, $ts)
            ON CONFLICT(channel) DO UPDATE SET last_ts = excluded.last_ts;
            """, null, ("$c", RestartChannel), ("$ts", EvidenceStore.ToMs(until)));

    /// <summary>
    /// Records inventory changes as events, at most <see cref="HostFacts.MaxChangeEventsPerDay"/> a day per kind.
    /// Beyond that they are counted in one overflow event for the day, so a flood is visible and bounded.
    /// </summary>
    public (int Stored, int Overflow) RecordInventoryChanges(string kind, IReadOnlyList<InventoryChange> changes, DateTimeOffset at)
    {
        if (!HostFacts.IsInventoryKind(kind)) throw new ArgumentException("An inventory kind is accounts, services or tasks.", nameof(kind));
        ArgumentNullException.ThrowIfNull(changes);
        if (changes.Count == 0) return (0, 0);
        var day = new DateTimeOffset(at.UtcDateTime.Date, TimeSpan.Zero);
        var today = store.Scalar<long>("""
            SELECT COUNT(*) FROM events WHERE kind = $k AND subject = $s AND ts >= $f AND ts < $t
            AND (dedupe_key IS NULL OR dedupe_key NOT LIKE 'overflow:%');
            """, null, ("$k", HostFacts.InventoryChangeKind), ("$s", kind), ("$f", EvidenceStore.ToMs(day)), ("$t", EvidenceStore.ToMs(day.AddDays(1))));
        var room = (int)Math.Max(0, HostFacts.MaxChangeEventsPerDay - today);
        var stored = 0;
        foreach (var change in changes.Take(room))
        {
            var detail = new JsonObject
            {
                ["change"] = change.Change,
                ["item"] = HostFacts.Clean(change.Key),
                ["fields"] = new JsonArray([.. change.Fields.Take(3).Select(f => (JsonNode)JsonValue.Create(f))])
            };
            store.Execute("""
                INSERT INTO events(ts, kind, source, address, subject, detail, dedupe_key)
                VALUES ($ts, $k, $s, NULL, $sub, $d, NULL);
                """, null, ("$ts", EvidenceStore.ToMs(at)), ("$k", HostFacts.InventoryChangeKind), ("$s", HostFacts.EventSource),
                ("$sub", kind), ("$d", detail.ToJsonString()));
            stored++;
        }
        var overflow = changes.Count - stored;
        if (overflow > 0)
        {
            var key = string.Create(CultureInfo.InvariantCulture, $"overflow:{kind}:{day:yyyy-MM-dd}");
            var previous = store.Scalar<string?>("SELECT detail FROM events WHERE kind = $k AND dedupe_key = $d;", null,
                ("$k", HostFacts.InventoryChangeKind), ("$d", key));
            var counted = previous is not null && JsonNode.Parse(previous)?["overflow"] is JsonValue v && v.TryGetValue<long>(out var n) ? n : 0;
            var detail = new JsonObject { ["overflow"] = counted + overflow, ["bound"] = HostFacts.MaxChangeEventsPerDay };
            store.Execute("""
                INSERT INTO events(ts, kind, source, address, subject, detail, dedupe_key)
                VALUES ($ts, $k, $s, NULL, $sub, $d, $key)
                ON CONFLICT(kind, dedupe_key) DO UPDATE SET detail = excluded.detail, ts = excluded.ts;
                """, null, ("$ts", EvidenceStore.ToMs(at)), ("$k", HostFacts.InventoryChangeKind), ("$s", HostFacts.EventSource),
                ("$sub", kind), ("$d", detail.ToJsonString()), ("$key", key));
        }
        return (stored, overflow);
    }

    /// <summary>
    /// Applies the host-fact retention: the latest snapshot of every fact is always kept, posture snapshots for
    /// 400 days, other snapshots for 7, hourly health for 90. Events follow the store's event retention.
    /// </summary>
    internal static long Prune(EvidenceStore store, DateTimeOffset now)
    {
        long deleted = 0;
        deleted += Delete(store, """
            DELETE FROM host_snapshots WHERE fact <> 'iis_posture' AND ts < $c
            AND id NOT IN (SELECT MAX(id) FROM host_snapshots GROUP BY fact, kind);
            """, EvidenceStore.ToMs(now - HostFacts.SnapshotRetention));
        deleted += Delete(store, """
            DELETE FROM host_snapshots WHERE fact = 'iis_posture' AND ts < $c
            AND id NOT IN (SELECT MAX(id) FROM host_snapshots GROUP BY fact, kind);
            """, EvidenceStore.ToMs(now - HostFacts.PostureRetention));
        deleted += Delete(store, "DELETE FROM host_health_hourly WHERE hour < $c;",
            EvidenceStore.ToMs(now - HostFacts.HealthHourlyRetention) / 3_600_000);
        return deleted;
    }

    private static long Delete(EvidenceStore store, string sql, long cutoff)
    {
        using var command = store.Command(sql, null, ("$c", cutoff));
        return command.ExecuteNonQuery();
    }

    /// <summary>Every string in a payload cleaned and bounded, whatever its reader did; depth and arrays bounded too.</summary>
    private static JsonNode? CleanNode(JsonNode? node, int depth) => node switch
    {
        null => null,
        _ when depth > 6 => null,
        JsonObject o => new JsonObject(o.Take(200).Select(p => KeyValuePair.Create(EvidenceText.Clean(p.Key, 64), CleanNode(p.Value, depth + 1)))),
        JsonArray a => new JsonArray([.. a.Take(HostFacts.MaxInventoryItems).Select(v => CleanNode(v, depth + 1))]),
        JsonValue v when v.TryGetValue<string>(out var s) => JsonValue.Create(HostFacts.Clean(s)),
        _ => node.DeepClone()
    };

    /// <summary>Halves the largest arrays until the payload fits. Returns whether anything was cut.</summary>
    private static bool Trim(JsonObject payload)
    {
        var trimmed = false;
        for (var round = 0; round < 32 && System.Text.Encoding.UTF8.GetByteCount(payload.ToJsonString()) > HostFacts.MaxPayloadBytes; round++)
        {
            var largest = Arrays(payload).OrderByDescending(a => a.Count).FirstOrDefault();
            if (largest is null || largest.Count == 0)
            {
                foreach (var key in payload.Select(p => p.Key).ToArray()) payload.Remove(key);
                return true;
            }
            var keep = largest.Count / 2;
            while (largest.Count > keep) largest.RemoveAt(largest.Count - 1);
            trimmed = true;
        }
        return trimmed;
    }

    private static IEnumerable<JsonArray> Arrays(JsonNode node)
    {
        switch (node)
        {
            case JsonArray array:
                yield return array;
                foreach (var item in array.OfType<JsonNode>())
                    foreach (var inner in Arrays(item)) yield return inner;
                break;
            case JsonObject obj:
                foreach (var (_, value) in obj)
                    if (value is not null)
                        foreach (var inner in Arrays(value)) yield return inner;
                break;
        }
    }
}

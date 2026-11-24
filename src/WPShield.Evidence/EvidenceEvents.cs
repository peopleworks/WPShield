using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace WPShield.Evidence;

/// <summary>
/// Evidence of a kind the store has no dedicated table for: an HTTP attack the gateway refused, a SQL
/// Server login, an FTP logon. New kinds need no schema change.
/// </summary>
/// <param name="Kind">Lowercase, for example <c>http.request-refused</c> or <c>sql.login-failed</c>.</param>
/// <param name="Subject">What the event is about, such as a normalized path or an instance name. Cleaned and bounded.</param>
/// <param name="Detail">Small structured detail. String values are cleaned; the whole is bounded.</param>
/// <param name="DedupeKey">When set, a second event with the same kind and key is ignored.</param>
public sealed record EvidenceEvent(DateTimeOffset Timestamp, string Kind, string Source, string? Address, string Subject,
    JsonObject Detail, string? DedupeKey = null);

public sealed partial class EvidenceEvents
{
    public const int MaxDetailBytes = 4096;
    public const int MaxStringValue = 512;
    public const int MaxQueryRows = 1000;
    private readonly EvidenceStore store;

    public EvidenceEvents(EvidenceStore store) => this.store = store;

    /// <summary>Stores one event. Returns false when an event with the same kind and key already exists.</summary>
    public bool Append(EvidenceEvent evidence)
    {
        if (store.ReadOnly) throw new InvalidOperationException("A read-only evidence store cannot be written.");
        if (!Name().IsMatch(evidence.Kind)) throw new ArgumentException("A kind is lowercase letters, digits, '.' and '-', 40 at most.");
        if (!Name().IsMatch(evidence.Source)) throw new ArgumentException("A source is lowercase letters, digits, '.' and '-', 40 at most.");
        var detail = Clean(evidence.Detail);
        var json = detail.ToJsonString();
        if (json.Length > MaxDetailBytes) throw new ArgumentException($"An event's detail is at most {MaxDetailBytes} bytes.");
        var address = evidence.Address is null ? null
            : IPAddress.TryParse(evidence.Address, out var ip) ? (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString()
            : throw new ArgumentException("Not an IP address.", nameof(evidence));
        using var command = store.Command("""
            INSERT OR IGNORE INTO events(ts, kind, source, address, subject, detail, dedupe_key)
            VALUES ($ts, $kind, $source, $address, $subject, $detail, $key);
            """, null, ("$ts", EvidenceStore.ToMs(evidence.Timestamp)), ("$kind", evidence.Kind), ("$source", evidence.Source),
            ("$address", address), ("$subject", EvidenceText.Clean(evidence.Subject, 200)), ("$detail", json),
            ("$key", evidence.DedupeKey is null ? null : EvidenceText.Clean(evidence.DedupeKey, 200)));
        return command.ExecuteNonQuery() == 1;
    }

    public IReadOnlyList<EvidenceEvent> Query(string kind, DateTimeOffset from, DateTimeOffset to, int limit = 100, string? address = null)
    {
        if (to <= from) throw new ArgumentException("The range must end after it starts.");
        using var command = store.Command($"""
            SELECT ts, kind, source, address, subject, detail, dedupe_key FROM events
            WHERE kind = $kind AND ts >= $f AND ts < $t{(address is null ? "" : " AND address = $a")}
            ORDER BY ts DESC LIMIT $n;
            """, null, ("$kind", kind), ("$f", EvidenceStore.ToMs(from)), ("$t", EvidenceStore.ToMs(to)), ("$a", address),
            ("$n", Math.Clamp(limit, 1, MaxQueryRows)));
        using var reader = command.ExecuteReader();
        var result = new List<EvidenceEvent>();
        while (reader.Read())
            result.Add(new(EvidenceStore.FromMs(reader.GetInt64(0)), reader.GetString(1), reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3), reader.GetString(4),
                JsonNode.Parse(reader.GetString(5)) as JsonObject ?? [], reader.IsDBNull(6) ? null : reader.GetString(6)));
        return result;
    }

    /// <summary>Counts per kind in a range, so a reader can discover what kinds of evidence exist.</summary>
    public IReadOnlyList<(string Kind, long Count)> Kinds(DateTimeOffset from, DateTimeOffset to)
    {
        using var command = store.Command("SELECT kind, COUNT(*) FROM events WHERE ts >= $f AND ts < $t GROUP BY kind ORDER BY kind LIMIT 200;",
            null, ("$f", EvidenceStore.ToMs(from)), ("$t", EvidenceStore.ToMs(to)));
        using var reader = command.ExecuteReader();
        var result = new List<(string, long)>();
        while (reader.Read()) result.Add((reader.GetString(0), reader.GetInt64(1)));
        return result;
    }

    private static JsonObject Clean(JsonObject detail)
    {
        var copy = new JsonObject();
        foreach (var (key, value) in detail)
            copy[EvidenceText.Clean(key, 64)] = CleanNode(value, depth: 0);
        return copy;
    }

    private static JsonNode? CleanNode(JsonNode? node, int depth) => node switch
    {
        null => null,
        _ when depth > 4 => null,
        JsonObject o => new JsonObject(o.Select(p => KeyValuePair.Create(EvidenceText.Clean(p.Key, 64), CleanNode(p.Value, depth + 1)))),
        JsonArray a => new JsonArray(a.Take(50).Select(v => CleanNode(v, depth + 1)).ToArray()),
        JsonValue v when v.TryGetValue<string>(out var s) => JsonValue.Create(EvidenceText.Clean(s, MaxStringValue)),
        _ => node.DeepClone()
    };

    [GeneratedRegex("^[a-z0-9][a-z0-9.-]{0,39}$")]
    private static partial Regex Name();
}

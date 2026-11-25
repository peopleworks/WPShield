using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WPShield.Evidence;

/// <summary>When a changed setting takes effect. The service logs the moment it applies one.</summary>
public enum SettingEffect
{
    /// <summary>Read again at the next point that uses it (the next pruning pass, the next query).</summary>
    NextUse,
    /// <summary>Read only when the service starts. Changing it says so instead of pretending to reload.</summary>
    NextStart
}

/// <summary>One setting the store accepts. Anything not in <see cref="SettingCatalog"/> is refused.</summary>
public sealed record SettingDefinition(string Key, string Description, JsonNode Default, SettingEffect Effect,
    Func<JsonNode, string?> Validate);

public sealed record SettingValue(string Key, JsonNode Value, bool IsDefault, long Version, DateTimeOffset? UpdatedAt,
    string? UpdatedBy, SettingEffect Effect, string Description);

public sealed record SettingChange(string Key, string? OldValue, string? NewValue, DateTimeOffset At, string ChangedBy,
    string Reason, SettingEffect Effect);

/// <summary>
/// The settings the store can hold. Adding a setting is adding an entry here, with its type, bounds
/// and when it takes effect; the database needs no change. Unknown keys are refused so a typo never
/// becomes a setting that silently does nothing.
/// </summary>
public static class SettingCatalog
{
    public static readonly IReadOnlyDictionary<string, SettingDefinition> All = new[]
    {
        Int("retention.raw_days", "Days of detailed failed logons kept.", 14, 1, 90),
        Int("retention.aggregate_days", "Days of hourly aggregates and decisions kept.", 400, 30, 1000),
        Int("retention.event_days", "Days of other evidence events kept.", 90, 1, 400),
        Int("retention.max_megabytes", "Size the database file may reach before detailed rows are pruned.", 2048, 100, 20000),
        new SettingDefinition("attacks.default_range", "Range the attacks view opens with: 1h, 6h, 24h, 7d or 30d.",
            JsonValue.Create("24h"), SettingEffect.NextUse,
            node => node is JsonValue v && v.TryGetValue<string>(out var s) && s is "1h" or "6h" or "24h" or "7d" or "30d"
                ? null : "one of 1h, 6h, 24h, 7d, 30d"),
        new SettingDefinition("labels.addresses",
            "Names for known addresses and networks, for example your office or your own connection. Labels describe; they never allow or block.",
            new JsonObject(), SettingEffect.NextUse, ValidateLabels),
        new SettingDefinition("mcp.detailed_records",
            "Whether the MCP server may return single attempts and account names, or only aggregates. Answers leave the host.",
            JsonValue.Create(false), SettingEffect.NextStart,
            node => node is JsonValue v && v.TryGetValue<bool>(out _) ? null : "true or false"),
    }.Concat(Decisions.DefenseSettings.Definitions()).ToDictionary(d => d.Key, StringComparer.Ordinal);

    public const int MaxLabels = 1000;

    private static SettingDefinition Int(string key, string description, int value, int min, int max) =>
        new(key, description, JsonValue.Create(value), SettingEffect.NextUse,
            node => node is JsonValue v && v.TryGetValue<int>(out var n) && n >= min && n <= max
                ? null : $"a whole number from {min} to {max}");

    private static string? ValidateLabels(JsonNode node)
    {
        if (node is not JsonObject map) return "an object of address or network to label";
        if (map.Count > MaxLabels) return $"at most {MaxLabels} labels";
        foreach (var (key, value) in map)
        {
            if (!IsAddressOrNetwork(key)) return $"'{EvidenceText.Clean(key, 64)}' is not an IP address or network";
            if (value is not JsonValue v || !v.TryGetValue<string>(out var label) || label.Length is 0 or > 64)
                return "each label is text of 1 to 64 characters";
        }
        return null;
    }

    private static bool IsAddressOrNetwork(string text)
    {
        var slash = text.IndexOf('/');
        var address = slash < 0 ? text : text[..slash];
        if (!IPAddress.TryParse(address, out var ip) || ip.ToString() != address) return false;
        if (slash < 0) return true;
        var max = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        return int.TryParse(text[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var bits) && bits >= 0 && bits <= max;
    }
}

/// <summary>
/// Reads and changes settings. Every change is validated against the catalog, versioned, and recorded
/// in <c>settings_history</c> with who made it and why. Writing needs a store opened for writing, so
/// an elevated operator tool or the service. The desktop writes settings only when elevated, from its
/// Settings window and the Attacks view's Label and Allow actions; the MCP server only reads.
/// </summary>
public sealed class EvidenceSettings
{
    public const int MaxValueBytes = 64 * 1024;
    private readonly EvidenceStore store;

    public EvidenceSettings(EvidenceStore store) => this.store = store;

    public JsonNode Get(string key)
    {
        var definition = Definition(key);
        var stored = store.Scalar<string?>("SELECT value FROM settings WHERE key = $k;", null, ("$k", key));
        return stored is null ? definition.Default.DeepClone() : JsonNode.Parse(stored)!;
    }

    public T Get<T>(string key) => Get(key).GetValue<T>();

    public IReadOnlyList<SettingValue> List()
    {
        var stored = new Dictionary<string, (string Value, long Version, long At, string By)>();
        using (var command = store.Command("SELECT key, value, version, updated_ts, updated_by FROM settings;", null))
        using (var reader = command.ExecuteReader())
            while (reader.Read())
                stored[reader.GetString(0)] = (reader.GetString(1), reader.GetInt64(2), reader.GetInt64(3), reader.GetString(4));
        return SettingCatalog.All.Values.OrderBy(d => d.Key, StringComparer.Ordinal).Select(d =>
            stored.TryGetValue(d.Key, out var s)
                ? new SettingValue(d.Key, JsonNode.Parse(s.Value)!, false, s.Version, EvidenceStore.FromMs(s.At), s.By, d.Effect, d.Description)
                : new SettingValue(d.Key, d.Default.DeepClone(), true, 0, null, null, d.Effect, d.Description)).ToArray();
    }

    /// <summary>Validates and stores a value given as JSON text. Throws with the reason when it is refused.</summary>
    public SettingChange Set(string key, string json, string changedBy, string reason, DateTimeOffset? now = null)
    {
        var definition = Definition(key);
        if (json.Length > MaxValueBytes) throw new ArgumentException($"A setting value is at most {MaxValueBytes} bytes.", nameof(json));
        JsonNode? node;
        try { node = JsonNode.Parse(json); }
        catch (JsonException) { throw new ArgumentException($"{key}: not valid JSON.", nameof(json)); }
        if (node is null) throw new ArgumentException($"{key}: expected a value.", nameof(json));
        if (definition.Validate(node) is { } problem) throw new ArgumentException($"{key}: expected {problem}.", nameof(json));
        if (node is JsonObject labels && key == "labels.addresses")
            foreach (var name in labels.Select(p => p.Key).ToArray())
                labels[name] = EvidenceText.Clean(labels[name]!.GetValue<string>(), 64);
        return Write(definition, node.ToJsonString(), changedBy, reason, now ?? DateTimeOffset.UtcNow);
    }

    /// <summary>Removes the stored value, so the default applies again. Recorded like any change.</summary>
    public SettingChange Reset(string key, string changedBy, string reason, DateTimeOffset? now = null) =>
        Write(Definition(key), null, changedBy, reason, now ?? DateTimeOffset.UtcNow);

    public IReadOnlyList<SettingChange> History(string? key = null, int limit = 100)
    {
        using var command = store.Command($"""
            SELECT key, old_value, new_value, ts, changed_by, reason FROM settings_history
            {(key is null ? "" : "WHERE key = $k")} ORDER BY ts DESC, id DESC LIMIT $n;
            """, null, ("$k", key), ("$n", Math.Clamp(limit, 1, 1000)));
        using var reader = command.ExecuteReader();
        var result = new List<SettingChange>();
        while (reader.Read())
        {
            var effect = SettingCatalog.All.TryGetValue(reader.GetString(0), out var d) ? d.Effect : SettingEffect.NextUse;
            result.Add(new(reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetString(2),
                EvidenceStore.FromMs(reader.GetInt64(3)), reader.GetString(4), reader.GetString(5), effect));
        }
        return result;
    }

    /// <summary>The store's bounds as the retention settings currently say.</summary>
    public EvidenceLimits Limits() => new()
    {
        RawRetention = TimeSpan.FromDays(Get<int>("retention.raw_days")),
        AggregateRetention = TimeSpan.FromDays(Get<int>("retention.aggregate_days")),
        EventRetention = TimeSpan.FromDays(Get<int>("retention.event_days")),
        MaxBytes = Get<int>("retention.max_megabytes") * 1024L * 1024L
    };

    private SettingChange Write(SettingDefinition definition, string? value, string changedBy, string reason, DateTimeOffset now)
    {
        if (store.ReadOnly) throw new InvalidOperationException("Settings cannot be changed through a read-only store.");
        var who = EvidenceText.Clean(changedBy, 64);
        var why = EvidenceText.Clean(reason, 200);
        if (who.Length == 0 || why.Length == 0) throw new ArgumentException("A change needs who made it and why.");
        using var transaction = store.Connection.BeginTransaction();
        var old = store.Scalar<string?>("SELECT value FROM settings WHERE key = $k;", transaction, ("$k", definition.Key));
        var ts = EvidenceStore.ToMs(now);
        if (value is null)
            store.Execute("DELETE FROM settings WHERE key = $k;", transaction, ("$k", definition.Key));
        else
            store.Execute("""
                INSERT INTO settings(key, value, version, updated_ts, updated_by) VALUES ($k, $v, 1, $ts, $by)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, version = version + 1,
                    updated_ts = excluded.updated_ts, updated_by = excluded.updated_by;
                """, transaction, ("$k", definition.Key), ("$v", value), ("$ts", ts), ("$by", who));
        store.Execute("""
            INSERT INTO settings_history(key, old_value, new_value, ts, changed_by, reason) VALUES ($k, $o, $n, $ts, $by, $why);
            """, transaction, ("$k", definition.Key), ("$o", old), ("$n", value), ("$ts", ts), ("$by", who), ("$why", why));
        transaction.Commit();
        return new(definition.Key, old, value, now, who, why, definition.Effect);
    }

    private static SettingDefinition Definition(string key) =>
        SettingCatalog.All.TryGetValue(key, out var definition)
            ? definition
            : throw new KeyNotFoundException($"'{EvidenceText.Clean(key, 64)}' is not a setting this version knows.");
}

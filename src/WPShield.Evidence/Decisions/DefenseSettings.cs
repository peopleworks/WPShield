using System.Net;
using System.Text.Json.Nodes;

namespace WPShield.Evidence.Decisions;

/// <param name="Count">How many failures, names or addresses fire the rule.</param>
/// <param name="Window">Within how long.</param>
/// <param name="Duration">How long the decision lasts; zero for a report-only rule.</param>
public sealed record RuleSettings(int Count, TimeSpan Window, TimeSpan Duration);

/// <summary>
/// The engine's settings at one evaluation. A plain snapshot: the engine never reads the store, so the
/// collector reads these before every evaluation (<c>NextUse</c>) and hands them over.
/// </summary>
public sealed record DefenseOptions
{
    public RuleSettings RepeatedFailures { get; init; } = new(10, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(60));
    public RuleSettings NonexistentAccounts { get; init; } = new(4, TimeSpan.FromMinutes(10), TimeSpan.FromHours(6));
    public RuleSettings Network { get; init; } = new(8, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(60));
    public RuleSettings SharedAccount { get; init; } = new(10, TimeSpan.FromMinutes(10), TimeSpan.Zero);

    /// <summary>Addresses and networks never decided against (<c>defense.allow</c>).</summary>
    public IReadOnlyList<IPNetwork> Allow { get; init; } = [];

    /// <summary>Whether private ranges (RFC 1918, ULA, CGNAT) may be decided against.</summary>
    public bool IncludePrivate { get; init; }

    public static DefenseOptions Default { get; } = new();

    /// <summary>
    /// The current values, in one read of the store. A stored value the catalog would refuse - which the
    /// operator tool cannot write - falls back to that key's default rather than stopping the engine.
    /// </summary>
    public static DefenseOptions Read(EvidenceSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var values = settings.List().ToDictionary(v => v.Key, v => v.Value, StringComparer.Ordinal);
        JsonNode Value(string key)
        {
            var definition = SettingCatalog.All[key];
            return values.TryGetValue(key, out var value) && definition.Validate(value) is null ? value : definition.Default;
        }
        int Int(string key) => Value(key).GetValue<int>();
        RuleSettings Rule(string prefix, string count, bool blocks) => new(Int($"{prefix}.{count}"),
            TimeSpan.FromMinutes(Int($"{prefix}.window_minutes")),
            blocks ? TimeSpan.FromMinutes(Int($"{prefix}.block_minutes")) : TimeSpan.Zero);

        var allow = new List<IPNetwork>();
        foreach (var entry in Value(DefenseSettings.Allow).AsArray())
            if (entry is JsonValue v && v.TryGetValue<string>(out var text) && AddressRanges.TryParseCanonical(text, out var network))
                allow.Add(network);

        return new DefenseOptions
        {
            RepeatedFailures = Rule(DefenseSettings.FailuresPrefix, "count", blocks: true),
            NonexistentAccounts = Rule(DefenseSettings.NonexistentPrefix, "count", blocks: true),
            Network = Rule(DefenseSettings.NetworkPrefix, "count", blocks: true),
            SharedAccount = Rule(DefenseSettings.SharedAccountPrefix, "addresses", blocks: false),
            Allow = allow,
            IncludePrivate = Value(DefenseSettings.IncludePrivate).GetValue<bool>()
        };
    }
}

/// <summary>
/// The <c>defense.*</c> settings (ADR 0009, section 6): validated, audited and read at each evaluation,
/// except <c>defense.mode</c>, which is read when the service starts.
/// </summary>
public static class DefenseSettings
{
    public const string Mode = "defense.mode";
    public const string Allow = "defense.allow";
    public const string IncludePrivate = "defense.include_private";
    public const string FailuresPrefix = "defense.failures";
    public const string NonexistentPrefix = "defense.unknown_accounts";
    public const string NetworkPrefix = "defense.network";
    public const string SharedAccountPrefix = "defense.shared_account";

    /// <summary>The longest allow-list accepted.</summary>
    public const int MaxAllow = 1000;

    /// <summary>A window of at most one day; a block of at most seven days, the escalation's cap.</summary>
    public const int MaxWindowMinutes = 1440;
    public const int MaxBlockMinutes = 10_080;

    internal static IEnumerable<SettingDefinition> Definitions() =>
    [
        new(Mode,
            "What the decision engine does with a decision. Only monitor is accepted: every decision is recorded as would-block and " +
            "nothing is enforced. Block becomes selectable only when the enforcer of ADR 0006 exists and has passed its validation.",
            JsonValue.Create(DecisionActions.MonitorMode), SettingEffect.NextStart,
            node => node is JsonValue v && v.TryGetValue<string>(out var s) && s == DecisionActions.MonitorMode
                ? null : "monitor (the only mode until the enforcer of ADR 0006 exists)"),
        new(Allow,
            "Addresses and networks the decision engine never decides against, for example your office or your own connection. " +
            "Canonical text; no network wider than /16 (IPv4) or /48 (IPv6); no loopback, multicast or unspecified address.",
            new JsonArray(), SettingEffect.NextUse, ValidateAllow),
        new(IncludePrivate,
            "Whether the decision engine may decide against private ranges (RFC 1918, ULA fc00::/7, CGNAT 100.64.0.0/10). " +
            "False by default: on most hosts those are the operator's own networks.",
            JsonValue.Create(false), SettingEffect.NextUse,
            node => node is JsonValue v && v.TryGetValue<bool>(out _) ? null : "true or false"),
        Int($"{FailuresPrefix}.count", "HOST-AUTH-001: failed logons from one address that make a decision.", 10, 3, 100),
        Int($"{FailuresPrefix}.window_minutes", "HOST-AUTH-001: the window those failures are counted in, in minutes.", 10, 1, MaxWindowMinutes),
        Int($"{FailuresPrefix}.block_minutes", "HOST-AUTH-001: how long the decision lasts, in minutes; doubled for a repeat within 7 days.", 60, 1, MaxBlockMinutes),
        Int($"{NonexistentPrefix}.count", "HOST-AUTH-002: account names that do not exist, tried from one address, that make a decision.", 4, 2, 50),
        Int($"{NonexistentPrefix}.window_minutes", "HOST-AUTH-002: the window those names are counted in, in minutes.", 10, 1, MaxWindowMinutes),
        Int($"{NonexistentPrefix}.block_minutes", "HOST-AUTH-002: how long the decision lasts, in minutes; doubled for a repeat within 7 days.", 360, 1, MaxBlockMinutes),
        Int($"{NetworkPrefix}.count", "HOST-AUTH-003: different failing addresses of one /24 (IPv4) or /64 (IPv6) that make a decision about the network.", 8, 2, 64),
        Int($"{NetworkPrefix}.window_minutes", "HOST-AUTH-003: the window those addresses are counted in, in minutes.", 10, 1, MaxWindowMinutes),
        Int($"{NetworkPrefix}.block_minutes", "HOST-AUTH-003: how long the decision lasts, in minutes; doubled for a repeat within 7 days.", 60, 1, MaxBlockMinutes),
        Int($"{SharedAccountPrefix}.addresses", "HOST-AUTH-004: different addresses failing on one existing account that make a report. Never blocks.", 10, 2, 100),
        Int($"{SharedAccountPrefix}.window_minutes", "HOST-AUTH-004: the window those addresses are counted in, in minutes.", 10, 1, MaxWindowMinutes),
    ];

    private static SettingDefinition Int(string key, string description, int value, int min, int max) =>
        new(key, description, JsonValue.Create(value), SettingEffect.NextUse,
            node => node is JsonValue v && v.TryGetValue<int>(out var n) && n >= min && n <= max
                ? null : $"a whole number from {min} to {max}");

    private static string? ValidateAllow(JsonNode node)
    {
        const string Expected = "a list of addresses or networks, for example [\"198.51.100.7\", \"203.0.113.0/24\"]";
        if (node is not JsonArray list) return Expected;
        if (list.Count > MaxAllow) return $"at most {MaxAllow} entries";
        foreach (var entry in list)
        {
            if (entry is not JsonValue value || !value.TryGetValue<string>(out var text)) return Expected;
            var shown = EvidenceText.Clean(text, 64);
            if (!AddressRanges.TryParseCanonical(text, out var network))
                return $"canonical addresses or networks with no bit set after the prefix; '{shown}' is not one";
            var ipv4 = network.BaseAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
            if (network.PrefixLength < (ipv4 ? AddressRanges.MinIPv4Prefix : AddressRanges.MinIPv6Prefix))
                return $"networks no wider than /{AddressRanges.MinIPv4Prefix} (IPv4) or /{AddressRanges.MinIPv6Prefix} (IPv6); '{shown}' is wider";
            var address = network.BaseAddress;
            if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || IsMulticast(address))
                return $"no loopback, multicast or unspecified address, which the engine never decides against anyway; '{shown}' is one";
        }
        return null;
    }

    private static bool IsMulticast(IPAddress address) =>
        address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? address.GetAddressBytes()[0] is >= 224 and <= 239
            : address.IsIPv6Multicast;
}

using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace WPShield.Evidence;

/// <summary>
/// The <c>analyst.*</c> settings (ADR 0010, section 4): validated and audited like every other setting,
/// and read at each run. They hold only what is safe to show a model, because <c>list_settings</c>
/// returns every setting to one. A provider key is never a setting: it is read from the environment of
/// the account that runs the analyst, and nothing here can name it.
/// </summary>
public static partial class AnalystSettings
{
    public const string Enabled = "analyst.enabled";
    public const string Provider = "analyst.provider";
    public const string Model = "analyst.model";
    public const string Effort = "analyst.effort";
    public const string Language = "analyst.language";
    public const string RelayUrl = "analyst.relay_url";
    public const string DailyRuns = "analyst.daily_runs";
    public const string DailyInputTokens = "analyst.daily_input_tokens";

    public const string DefaultModel = "claude-opus-5-5";
    public const string DefaultEffort = "medium";

    /// <summary>The providers phase 1 offers. The empty string is "not chosen", the default.</summary>
    public static IReadOnlyList<string> Providers { get; } = ["anthropic", "relay"];

    public static IReadOnlyList<string> Efforts { get; } = ["low", "medium", "high", "xhigh", "max"];

    public static IReadOnlyList<string> Languages { get; } = ["es", "en"];

    internal static IEnumerable<SettingDefinition> Definitions() =>
    [
        new(Enabled, "Whether the optional AI analyst may run. Off by default: nothing leaves the host until this is true, a provider is chosen and its key is in the environment.",
            JsonValue.Create(false), SettingEffect.NextUse,
            node => node is JsonValue v && v.TryGetValue<bool>(out _) ? null : "true or false"),
        new(Provider, "Where the analyst sends the evidence it reads: anthropic or relay. Empty until chosen.",
            JsonValue.Create(""), SettingEffect.NextUse,
            node => Text(node) is { } s && (s.Length == 0 || Providers.Contains(s)) ? null : "anthropic or relay"),
        new(Model, "The model the analyst asks. The report names the model that actually answered.",
            JsonValue.Create(DefaultModel), SettingEffect.NextUse,
            node => Text(node) is { } s && ModelPattern().IsMatch(s) ? null : "a model name of letters, digits, '.', '-', '_' or ':'"),
        new(Effort, "How much the model thinks on each turn: low, medium, high, xhigh or max. Higher costs more.",
            JsonValue.Create(DefaultEffort), SettingEffect.NextUse,
            node => Text(node) is { } s && Efforts.Contains(s) ? null : "one of low, medium, high, xhigh, max"),
        new(Language, "The language the analyst writes in: es or en.",
            JsonValue.Create("en"), SettingEffect.NextUse,
            node => Text(node) is { } s && Languages.Contains(s) ? null : "es or en"),
        new(RelayUrl, "The PeopleWorks Relay's base address, https only, such as https://relay.example. Empty until set; there is no default host.",
            JsonValue.Create(""), SettingEffect.NextUse,
            node => Text(node) is { } s ? (s.Length == 0 ? null : ValidateRelayUrl(s)) : "an https address"),
        Bounded(DailyRuns, "Analyst runs allowed per UTC day. A run past it is refused, never shortened.", 10, 1, 1000),
        Bounded(DailyInputTokens, "Input tokens the analyst may spend per UTC day on a provider the operator pays. A run past it is refused, never shortened.",
            2_000_000, 10_000, 100_000_000),
    ];

    /// <summary>
    /// Why <paramref name="text"/> is not an acceptable Relay address, or null when it is. Only https,
    /// and no user name, password, query or fragment: a token written into the address would be kept in
    /// <c>settings_history</c> and returned to the model by <c>list_settings</c>.
    /// </summary>
    public static string? ValidateRelayUrl(string text)
    {
        if (text.Length > 200 || !Uri.TryCreate(text, UriKind.Absolute, out var uri)) return "an absolute https address of at most 200 characters";
        if (uri.Scheme != Uri.UriSchemeHttps) return "an https address: the evidence the analyst reads must not travel in clear text";
        if (uri.UserInfo.Length > 0) return "an address without a user name or password: the key comes from RELAY_API_KEY, never from the address";
        if (uri.Query.Length > 0 || uri.Fragment.Length > 0) return "an address without a query or fragment";
        if (uri.AbsolutePath.TrimEnd('/').EndsWith("/v1", StringComparison.OrdinalIgnoreCase))
            return "the relay's base address, without /v1 (the analyst adds /v1/messages itself)";
        return null;
    }

    private static string? Text(JsonNode node) => node is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    private static SettingDefinition Bounded(string key, string description, int value, int min, int max) =>
        new(key, description, JsonValue.Create(value), SettingEffect.NextUse,
            node => node is JsonValue v && v.TryGetValue<int>(out var n) && n >= min && n <= max
                ? null : $"a whole number from {min} to {max}");

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")]
    private static partial Regex ModelPattern();
}

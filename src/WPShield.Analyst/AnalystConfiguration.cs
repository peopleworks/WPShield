using System.Text.Json.Nodes;
using WPShield.Evidence;

namespace WPShield.Analyst;

/// <summary>The <c>analyst.*</c> settings at one moment, read in one pass of the evidence store.</summary>
internal sealed record AnalystConfiguration
{
    public bool Enabled { get; init; }

    /// <summary><c>anthropic</c>, <c>relay</c>, or empty when the operator has not chosen one.</summary>
    public string Provider { get; init; } = "";

    public string Model { get; init; } = AnalystSettings.DefaultModel;

    public string Effort { get; init; } = AnalystSettings.DefaultEffort;

    public string Language { get; init; } = "en";

    /// <summary>The Relay's base address, or null when none is set.</summary>
    public Uri? RelayUrl { get; init; }

    public int DailyRuns { get; init; } = 10;

    public long DailyInputTokens { get; init; } = 2_000_000;

    public bool Spanish => Language == "es";

    /// <summary>
    /// The current values. A stored value the catalog would refuse - which the operator tool cannot
    /// write - falls back to that key's default rather than to something the operator never chose.
    /// </summary>
    public static AnalystConfiguration Read(EvidenceSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var values = settings.List().ToDictionary(v => v.Key, v => v.Value, StringComparer.Ordinal);
        JsonNode Value(string key)
        {
            var definition = SettingCatalog.All[key];
            return values.TryGetValue(key, out var value) && definition.Validate(value) is null ? value : definition.Default;
        }
        var relay = Value(AnalystSettings.RelayUrl).GetValue<string>();
        return new AnalystConfiguration
        {
            Enabled = Value(AnalystSettings.Enabled).GetValue<bool>(),
            Provider = Value(AnalystSettings.Provider).GetValue<string>(),
            Model = Value(AnalystSettings.Model).GetValue<string>(),
            Effort = Value(AnalystSettings.Effort).GetValue<string>(),
            Language = Value(AnalystSettings.Language).GetValue<string>(),
            RelayUrl = relay.Length == 0 ? null : new Uri(relay, UriKind.Absolute),
            DailyRuns = Value(AnalystSettings.DailyRuns).GetValue<int>(),
            DailyInputTokens = Value(AnalystSettings.DailyInputTokens).GetValue<int>()
        };
    }
}

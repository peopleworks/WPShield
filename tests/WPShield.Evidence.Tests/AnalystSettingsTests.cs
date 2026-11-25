using System.Text.Json.Nodes;
using WPShield.Evidence;
using Xunit;

namespace WPShield.Evidence.Tests;

/// <summary>
/// The analyst.* settings (ADR 0010, section 4): off by default, no provider until one is chosen, no
/// default Relay host, https only, and nothing in them that could hold a key.
/// </summary>
public sealed class AnalystSettingsTests
{
    private static string? Validate(string key, string json) => SettingCatalog.All[key].Validate(JsonNode.Parse(json)!);

    [Fact]
    public void TheDefaultsKeepTheAnalystOffWithNothingChosen()
    {
        Assert.False(SettingCatalog.All[AnalystSettings.Enabled].Default.GetValue<bool>());
        Assert.Equal("", SettingCatalog.All[AnalystSettings.Provider].Default.GetValue<string>());
        Assert.Equal("", SettingCatalog.All[AnalystSettings.RelayUrl].Default.GetValue<string>());
        Assert.Equal("claude-opus-5-5", SettingCatalog.All[AnalystSettings.Model].Default.GetValue<string>());
        Assert.Equal("medium", SettingCatalog.All[AnalystSettings.Effort].Default.GetValue<string>());
        Assert.Equal(10, SettingCatalog.All[AnalystSettings.DailyRuns].Default.GetValue<int>());
        Assert.Equal(2_000_000, SettingCatalog.All[AnalystSettings.DailyInputTokens].Default.GetValue<int>());
        foreach (var definition in SettingCatalog.All.Values.Where(d => d.Key.StartsWith("analyst.", StringComparison.Ordinal)))
        {
            Assert.Null(definition.Validate(definition.Default));
            Assert.Equal(SettingEffect.NextUse, definition.Effect);
        }
    }

    [Fact]
    public void NoSettingCouldHoldAKey()
    {
        Assert.DoesNotContain(SettingCatalog.All.Keys, k => k.Contains("key", StringComparison.OrdinalIgnoreCase) ||
            k.Contains("token", StringComparison.OrdinalIgnoreCase) && !k.EndsWith("_tokens", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(AnalystSettings.Provider, "\"anthropic\"", true)]
    [InlineData(AnalystSettings.Provider, "\"relay\"", true)]
    [InlineData(AnalystSettings.Provider, "\"\"", true)]
    [InlineData(AnalystSettings.Provider, "\"openai\"", false)]
    [InlineData(AnalystSettings.Provider, "\"Anthropic\"", false)]
    [InlineData(AnalystSettings.Effort, "\"xhigh\"", true)]
    [InlineData(AnalystSettings.Effort, "\"max\"", true)]
    [InlineData(AnalystSettings.Effort, "\"extreme\"", false)]
    [InlineData(AnalystSettings.Language, "\"es\"", true)]
    [InlineData(AnalystSettings.Language, "\"fr\"", false)]
    [InlineData(AnalystSettings.Model, "\"claude-opus-5-5\"", true)]
    [InlineData(AnalystSettings.Model, "\"\"", false)]
    [InlineData(AnalystSettings.Model, "\"claude opus\"", false)]
    [InlineData(AnalystSettings.Enabled, "true", true)]
    [InlineData(AnalystSettings.Enabled, "\"yes\"", false)]
    [InlineData(AnalystSettings.DailyRuns, "1", true)]
    [InlineData(AnalystSettings.DailyRuns, "0", false)]
    [InlineData(AnalystSettings.DailyRuns, "1001", false)]
    [InlineData(AnalystSettings.DailyInputTokens, "9999", false)]
    [InlineData(AnalystSettings.DailyInputTokens, "100000000", true)]
    public void EachValueIsValidated(string key, string json, bool accepted)
    {
        Assert.Equal(accepted, Validate(key, json) is null);
    }

    [Theory]
    [InlineData("https://relay.example", true)]
    [InlineData("https://relay.example/", true)]
    [InlineData("https://relay.example/gateway", true)]
    [InlineData("http://relay.example", false)]
    [InlineData("https://user:pass@relay.example", false)]
    [InlineData("https://relay.example/?token=abc", false)]
    [InlineData("https://relay.example/#x", false)]
    [InlineData("https://relay.example/v1", false)]
    [InlineData("relay.example", false)]
    [InlineData("ftp://relay.example", false)]
    public void TheRelayAddressIsHttpsWithNoCredentialQueryOrVersionPath(string url, bool accepted)
    {
        Assert.Equal(accepted, AnalystSettings.ValidateRelayUrl(url) is null);
        Assert.Equal(accepted, Validate(AnalystSettings.RelayUrl, $"\"{url}\"") is null);
    }

    [Fact]
    public void AChangeIsValidatedAndAudited()
    {
        var directory = Path.Combine(Path.GetTempPath(), "wpshield-evidence-analyst-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            using var store = EvidenceStore.OpenForWriting(Path.Combine(directory, EvidenceStore.FileName));
            var settings = new EvidenceSettings(store);
            Assert.Throws<ArgumentException>(() => settings.Set(AnalystSettings.RelayUrl, "\"http://relay.example\"", "op", "try"));
            settings.Set(AnalystSettings.Enabled, "true", "op", "first run");
            var change = Assert.Single(settings.History(AnalystSettings.Enabled));
            Assert.Equal("op", change.ChangedBy);
            Assert.Equal("first run", change.Reason);
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch (IOException) { }
        }
    }
}

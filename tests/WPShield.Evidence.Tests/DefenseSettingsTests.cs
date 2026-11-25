using System.Text.Json.Nodes;
using WPShield.Evidence.Decisions;
using Xunit;

namespace WPShield.Evidence.Tests;

/// <summary>
/// The <c>defense.*</c> settings of ADR 0009, section 6: in the catalog, validated, audited, and read
/// into the snapshot the engine evaluates with.
/// </summary>
public sealed class DefenseSettingsTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);
    private readonly string directory = Path.Combine(Path.GetTempPath(), "wpshield-defense-tests", Guid.NewGuid().ToString("N"));

    public DefenseSettingsTests() => Directory.CreateDirectory(directory);

    public void Dispose()
    {
        try { Directory.Delete(directory, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private EvidenceStore Open() => EvidenceStore.OpenForWriting(Path.Combine(directory, EvidenceStore.FileName));

    public static TheoryData<string, int, int, int> Thresholds => new()
    {
        { "defense.failures.count", 10, 3, 100 },
        { "defense.failures.window_minutes", 10, 1, 1440 },
        { "defense.failures.block_minutes", 60, 1, 10080 },
        { "defense.unknown_accounts.count", 4, 2, 50 },
        { "defense.unknown_accounts.window_minutes", 10, 1, 1440 },
        { "defense.unknown_accounts.block_minutes", 360, 1, 10080 },
        { "defense.network.count", 8, 2, 64 },
        { "defense.network.window_minutes", 10, 1, 1440 },
        { "defense.network.block_minutes", 60, 1, 10080 },
        { "defense.shared_account.addresses", 10, 2, 100 },
        { "defense.shared_account.window_minutes", 10, 1, 1440 },
    };

    [Theory]
    [MemberData(nameof(Thresholds))]
    public void EachThresholdHasTheAdrDefaultAndItsBounds(string key, int fallback, int min, int max)
    {
        using var store = Open();
        var settings = new EvidenceSettings(store);

        Assert.Equal(fallback, settings.Get<int>(key));
        Assert.Equal(SettingEffect.NextUse, SettingCatalog.All[key].Effect);
        settings.Set(key, min.ToString(System.Globalization.CultureInfo.InvariantCulture), "test", "lowest", Now);
        settings.Set(key, max.ToString(System.Globalization.CultureInfo.InvariantCulture), "test", "highest", Now);
        Assert.Throws<ArgumentException>(() => settings.Set(key, (min - 1).ToString(System.Globalization.CultureInfo.InvariantCulture), "test", "too low"));
        Assert.Throws<ArgumentException>(() => settings.Set(key, (max + 1).ToString(System.Globalization.CultureInfo.InvariantCulture), "test", "too high"));
        Assert.Throws<ArgumentException>(() => settings.Set(key, "\"10\"", "test", "a string"));
        Assert.Throws<ArgumentException>(() => settings.Set(key, "2.5", "test", "not whole"));
        Assert.Equal(2, settings.History(key).Count);
    }

    [Fact]
    public void TheModeAcceptsOnlyMonitorAndTakesEffectAtTheNextStart()
    {
        using var store = Open();
        var settings = new EvidenceSettings(store);

        Assert.Equal("monitor", settings.Get<string>(DefenseSettings.Mode));
        Assert.Equal(SettingEffect.NextStart, SettingCatalog.All[DefenseSettings.Mode].Effect);
        var refused = Assert.Throws<ArgumentException>(() => settings.Set(DefenseSettings.Mode, "\"block\"", "test", "try block"));
        Assert.Contains("ADR 0006", refused.Message, StringComparison.Ordinal);
        Assert.Equal(SettingEffect.NextStart, settings.Set(DefenseSettings.Mode, "\"monitor\"", "test", "say it explicitly", Now).Effect);
    }

    [Fact]
    public void IncludePrivateIsABooleanAndFalseByDefault()
    {
        using var store = Open();
        var settings = new EvidenceSettings(store);

        Assert.False(settings.Get<bool>(DefenseSettings.IncludePrivate));
        settings.Set(DefenseSettings.IncludePrivate, "true", "test", "a lab host", Now);
        Assert.True(DefenseOptions.Read(settings).IncludePrivate);
        Assert.Throws<ArgumentException>(() => settings.Set(DefenseSettings.IncludePrivate, "\"yes\"", "test", "not a boolean"));
    }

    [Fact]
    public void TheAllowListAcceptsCanonicalAddressesAndNetworks()
    {
        using var store = Open();
        var settings = new EvidenceSettings(store);

        settings.Set(DefenseSettings.Allow, """["198.51.100.7", "203.0.113.0/24", "192.0.0.0/16", "2001:db8:5::/48", "2001:db8::17"]""",
            "test", "the office and the provider", Now);

        var allow = DefenseOptions.Read(settings).Allow.Select(AddressRanges.Text).ToArray();
        Assert.Equal(new[] { "198.51.100.7", "203.0.113.0/24", "192.0.0.0/16", "2001:db8:5::/48", "2001:db8::17" }, allow);
        var change = Assert.Single(settings.History(DefenseSettings.Allow));
        Assert.Equal("the office and the provider", change.Reason);
    }

    [Theory]
    [InlineData("""["203.0.113.7/24"]""", "no bit set after the prefix")]
    [InlineData("""["10.0.0.0/8"]""", "no wider than /16")]
    [InlineData("""["2001:db8::/32"]""", "no wider than /16 (IPv4) or /48 (IPv6)")]
    [InlineData("""["127.0.0.1"]""", "no loopback")]
    [InlineData("""["::1"]""", "no loopback")]
    [InlineData("""["224.0.0.1"]""", "multicast")]
    [InlineData("""["ff02::1"]""", "multicast")]
    [InlineData("""["0.0.0.0"]""", "unspecified")]
    [InlineData("""["::"]""", "unspecified")]
    [InlineData("""["::ffff:198.51.100.7"]""", "canonical")]
    [InlineData("""["010.0.0.1"]""", "canonical")]
    [InlineData("""["2001:DB8::1"]""", "canonical")]
    [InlineData("""["not-an-address"]""", "canonical")]
    [InlineData("""["198.51.100.0/024"]""", "canonical")]
    [InlineData("""[7]""", "a list of addresses or networks")]
    [InlineData("""{"198.51.100.7": true}""", "a list of addresses or networks")]
    [InlineData("\"198.51.100.7\"", "a list of addresses or networks")]
    public void TheAllowListRefusesAnythingElse(string json, string expected)
    {
        using var store = Open();
        var settings = new EvidenceSettings(store);

        var refused = Assert.Throws<ArgumentException>(() => settings.Set(DefenseSettings.Allow, json, "test", "refused"));

        Assert.Contains(expected, refused.Message, StringComparison.Ordinal);
        Assert.Empty(settings.History(DefenseSettings.Allow));
    }

    [Fact]
    public void TheAllowListIsBounded()
    {
        using var store = Open();
        var list = new JsonArray(Enumerable.Range(0, DefenseSettings.MaxAllow + 1)
            .Select(i => (JsonNode)JsonValue.Create($"2001:db8::{i:x}")!).ToArray());

        var refused = Assert.Throws<ArgumentException>(() =>
            new EvidenceSettings(store).Set(DefenseSettings.Allow, list.ToJsonString(), "test", "too many"));

        Assert.Contains("at most 1000 entries", refused.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheSnapshotReadsEveryThreshold()
    {
        using var store = Open();
        var settings = new EvidenceSettings(store);
        settings.Set("defense.failures.count", "5", "test", "t", Now);
        settings.Set("defense.failures.window_minutes", "30", "test", "t", Now);
        settings.Set("defense.failures.block_minutes", "120", "test", "t", Now);
        settings.Set("defense.unknown_accounts.count", "3", "test", "t", Now);
        settings.Set("defense.network.count", "16", "test", "t", Now);
        settings.Set("defense.shared_account.addresses", "20", "test", "t", Now);

        var options = DefenseOptions.Read(settings);

        Assert.Equal(new RuleSettings(5, TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(120)), options.RepeatedFailures);
        Assert.Equal(new RuleSettings(3, TimeSpan.FromMinutes(10), TimeSpan.FromHours(6)), options.NonexistentAccounts);
        Assert.Equal(new RuleSettings(16, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(60)), options.Network);
        Assert.Equal(new RuleSettings(20, TimeSpan.FromMinutes(10), TimeSpan.Zero), options.SharedAccount);
    }

    [Fact]
    public void TheDefaultsAreTheAdrs()
    {
        using var store = Open();

        Assert.Equal(DefenseOptions.Default, DefenseOptions.Read(new EvidenceSettings(store)) with { Allow = DefenseOptions.Default.Allow });
        Assert.Empty(DefenseOptions.Read(new EvidenceSettings(store)).Allow);
    }

    /// <summary>A value the operator tool would refuse did not come from it. The engine uses the default, never stops.</summary>
    [Fact]
    public void AStoredValueTheCatalogRefusesFallsBackToTheDefault()
    {
        using var store = Open();
        store.Execute("INSERT INTO settings(key, value, version, updated_ts, updated_by) VALUES ('defense.failures.count', '1', 1, 0, 'x');");
        store.Execute("INSERT INTO settings(key, value, version, updated_ts, updated_by) VALUES ('defense.allow', '[\"10.0.0.0/8\"]', 1, 0, 'x');");

        var options = DefenseOptions.Read(new EvidenceSettings(store));

        Assert.Equal(10, options.RepeatedFailures.Count);
        Assert.Empty(options.Allow);
    }

    [Fact]
    public void AddressRangesAreCanonicalAndCompareByOverlap()
    {
        Assert.True(AddressRanges.TryParseCanonical("203.0.113.0/24", out var network));
        Assert.True(AddressRanges.TryParseCanonical("203.0.113.9", out var single));
        Assert.True(AddressRanges.Overlaps(network, single));
        Assert.False(AddressRanges.TryParseCanonical("203.0.113.9/24", out _));
        Assert.Equal("203.0.113.0/24", AddressRanges.NetworkOf(System.Net.IPAddress.Parse("203.0.113.77")).ToString());
        Assert.Equal("2001:db8:1:2::/64", AddressRanges.NetworkOf(System.Net.IPAddress.Parse("2001:db8:1:2:3:4:5:6")).ToString());
        Assert.Equal(EvidenceQueries.Network("2001:db8:1:2:3:4:5:6"), AddressRanges.NetworkOf(System.Net.IPAddress.Parse("2001:db8:1:2:3:4:5:6")).ToString());
        Assert.Equal("203.0.113.9", AddressRanges.Text(single));
    }
}

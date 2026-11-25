using System.Text.Json;
using WPShield.Cli;
using WPShield.Evidence;

namespace WPShield.Cli.Tests;

/// <summary>
/// <c>wpshield settings</c>: reads never fall back to defaults when the store cannot be read, writes
/// are elevated, validated and audited, and no change ever claims to have been applied.
/// </summary>
public sealed class SettingsCommandTests : IDisposable
{
    private const string Operator = @"HOST\operator";
    private static readonly DateTimeOffset Now = EvidenceTestStore.Now;
    private readonly EvidenceTestStore store = new();

    public void Dispose() => store.Dispose();

    private (int Exit, string Output, string Error) Run(bool elevated, params string[] args)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var exit = SettingsCommand.Run(args, output, error, store.Path, () => elevated, () => Operator, () => Now);
        return (exit, output.ToString(), error.ToString());
    }

    private (int Exit, string Output, string Error) Run(params string[] args) => Run(true, args);

    private IReadOnlyList<SettingChange> History()
    {
        using var opened = EvidenceStore.OpenReadOnly(store.Path);
        return new EvidenceSettings(opened).History();
    }

    [Fact]
    public void List_ShowsEveryCatalogKeyWithWhereItsValueCameFromAndWhenItTakesEffect()
    {
        store.Setting("retention.raw_days", "30");

        var (exit, output, _) = Run("list");

        Assert.Equal(0, exit);
        foreach (var key in SettingCatalog.All.Keys) Assert.Contains(key, output, StringComparison.Ordinal);
        var raw = Assert.Single(output.Split(Environment.NewLine), l => l.StartsWith("retention.raw_days", StringComparison.Ordinal));
        Assert.Contains("v1 2026-11-23 12:00 UTC by test", raw, StringComparison.Ordinal);
        Assert.Contains("next start", Assert.Single(output.Split(Environment.NewLine), l => l.StartsWith("mcp.detailed_records", StringComparison.Ordinal)), StringComparison.Ordinal);
    }

    /// <summary>The allow-list is the first array setting: set from a file, refused when too wide, listed as a count.</summary>
    [Fact]
    public void TheAllowList_IsSetFromAFileRefusedWhenTooWideAndListedAsACount()
    {
        store.Write(_ => { });
        var file = Path.Combine(store.DirectoryPath, "allow.json");
        File.WriteAllText(file, """["198.51.100.7", "203.0.113.0/24"]""");

        var (exit, output, _) = Run("set", "defense.allow", "--value-file", file, "--reason", "the office");
        Assert.Equal(0, exit);
        Assert.Contains("""defense.allow is now ["198.51.100.7","203.0.113.0/24"]""", output, StringComparison.Ordinal);
        Assert.Contains("next use", output, StringComparison.Ordinal);

        Assert.Contains("[2 entries]", Assert.Single(Run("list").Output.Split(Environment.NewLine),
            l => l.StartsWith("defense.allow", StringComparison.Ordinal)), StringComparison.Ordinal);

        File.WriteAllText(file, """["10.0.0.0/8"]""");
        var refused = Assert.Throws<CliArgumentException>(() => Run("set", "defense.allow", "--value-file", file, "--reason", "too wide"));
        Assert.Contains("no wider than /16", refused.Message, StringComparison.Ordinal);
        Assert.Single(History(), h => h.Key == "defense.allow");
    }

    [Fact]
    public void TheDefenseMode_RefusesBlockAndSaysItTakesEffectAtTheNextStart()
    {
        store.Write(_ => { });

        Assert.Throws<CliArgumentException>(() => Run("set", "defense.mode", "block", "--reason", "try"));
        var (exit, output, _) = Run("set", "defense.mode", "monitor", "--reason", "explicit");

        Assert.Equal(0, exit);
        Assert.Contains("next time the process that reads it starts", output, StringComparison.Ordinal);
    }
    /// <summary>"Could not read the store" must never print the catalog defaults as if they were the settings.</summary>
    [Theory]
    [InlineData(true, 3)]
    [InlineData(false, 1)]
    public void ReadingAStoreThatCannotBeOpened_FailsInsteadOfShowingDefaults(bool elevated, int expected)
    {
        var (exit, output, error) = Run(elevated, "list");

        Assert.Equal(expected, exit);
        Assert.Empty(output);
        Assert.StartsWith("ERROR:", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Get_PrintsTheWholeValueItsDefaultAndItsEffect()
    {
        store.Setting("labels.addresses", """{"198.51.100.7":"Oficina de Hernández"}""");

        var (exit, output, _) = Run("get", "labels.addresses");

        Assert.Equal(0, exit);
        Assert.Contains("""Value         {"198.51.100.7":"Oficina de Hernández"}""", output, StringComparison.Ordinal);
        Assert.Contains("Default       {}", output, StringComparison.Ordinal);
        Assert.Contains("Takes effect  next use", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Get_InJson()
    {
        store.Write(_ => { });

        var (exit, output, _) = Run("get", "retention.raw_days", "--json");

        Assert.Equal(0, exit);
        using var json = JsonDocument.Parse(output);
        Assert.Equal(14, json.RootElement.GetProperty("value").GetInt32());
        Assert.True(json.RootElement.GetProperty("isDefault").GetBoolean());
        Assert.Equal("next use", json.RootElement.GetProperty("effect").GetString());
    }

    [Theory]
    [InlineData("get", "retention.rawdays")]
    [InlineData("history", "labels")]
    [InlineData("set", "retention.rawdays", "7", "--reason", "typo")]
    [InlineData("reset", "retention.rawdays", "--reason", "typo")]
    public void AnUnknownKey_IsRefusedWithTheKnownOnes(params string[] args)
    {
        store.Write(_ => { });

        var refusal = Assert.Throws<CliArgumentException>(() => Run(args));

        Assert.Contains("is not a setting this version knows", refusal.Message, StringComparison.Ordinal);
        Assert.Contains("retention.raw_days", refusal.Message, StringComparison.Ordinal);
        Assert.Contains("labels.addresses", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Set_IsStoredAuditedWithTheWindowsUserAndSaysItReloadedNothing()
    {
        store.Write(_ => { });

        var (exit, output, _) = Run("set", "retention.raw_days", "30", "--reason", "keep a month of detail");

        Assert.Equal(0, exit);
        Assert.Contains("retention.raw_days is now 30 (it was the default).", output, StringComparison.Ordinal);
        Assert.Contains(@"HOST\operator", output, StringComparison.Ordinal);
        Assert.Contains("Takes effect at its next use", output, StringComparison.Ordinal);
        Assert.Contains("This command reloaded nothing.", output, StringComparison.Ordinal);
        var change = Assert.Single(History());
        Assert.Equal(Operator, change.ChangedBy);
        Assert.Equal("keep a month of detail", change.Reason);
        Assert.Equal("30", change.NewValue);
    }

    [Fact]
    public void ASettingReadOnlyAtStart_SaysSo()
    {
        store.Write(_ => { });

        var (exit, output, _) = Run("set", "mcp.detailed_records", "true", "--reason", "allow single attempts");

        Assert.Equal(0, exit);
        Assert.Contains("Takes effect the next time the process that reads it starts", output, StringComparison.Ordinal);
        Assert.Contains("this command restarts nothing", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Set_WithoutElevation_ChangesNothing()
    {
        store.Write(_ => { });

        var (exit, output, error) = Run(elevated: false, "set", "retention.raw_days", "30", "--reason", "try");

        Assert.Equal(1, exit);
        Assert.Empty(output);
        Assert.Contains("elevated prompt", error, StringComparison.Ordinal);
        Assert.Empty(History());
    }

    /// <summary>The service owns the file. A settings tool that created it would guess at a schema.</summary>
    [Fact]
    public void Set_NeverCreatesTheStore()
    {
        var (exit, _, error) = Run("set", "retention.raw_days", "30", "--reason", "too early");

        Assert.Equal(3, exit);
        Assert.Contains("no evidence store", error, StringComparison.Ordinal);
        Assert.False(File.Exists(store.Path));
    }

    [Theory]
    [InlineData("retention.raw_days", "0", "a whole number from 1 to 90")]
    [InlineData("retention.raw_days", "\"thirty\"", "a whole number")]
    [InlineData("attacks.default_range", "2d", "one of 1h, 6h, 24h, 7d, 30d")]
    [InlineData("labels.addresses", """{"not-an-ip":"x"}""", "is not an IP address or network")]
    [InlineData("labels.addresses", "{", "not valid JSON")]
    [InlineData("mcp.detailed_records", "null", "not null")]
    public void AValueTheCatalogRefuses_IsRefusedBeforeElevationIsAskedAbout(string key, string value, string expected)
    {
        store.Write(_ => { });

        var refusal = Assert.Throws<CliArgumentException>(() => Run(elevated: false, "set", key, value, "--reason", "test"));

        Assert.Contains(expected, refusal.Message, StringComparison.Ordinal);
        Assert.Empty(History());
    }

    /// <summary>The service holds the store open while an operator changes a setting; SQLite serialises the two.</summary>
    [Fact]
    public void Set_WorksWhileTheServiceHoldsTheStoreOpen()
    {
        using var service = EvidenceStore.OpenForWriting(store.Path);
        new EvidenceWriter(service).Append([store.Failure(10, "203.0.113.10")]);

        var (exit, _, error) = Run("set", "retention.raw_days", "30", "--reason", "while the service runs");

        Assert.Equal(0, exit);
        Assert.Empty(error);
        Assert.Equal(30, new EvidenceSettings(service).Get<int>("retention.raw_days"));
    }

    [Fact]
    public void ATextSettingTakesABareWordBecausePowerShellDropsTheQuotes()
    {
        store.Write(_ => { });

        var (exit, output, _) = Run("set", "attacks.default_range", "7d", "--reason", "a week by default");

        Assert.Equal(0, exit);
        Assert.Contains("attacks.default_range is now \"7d\"", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Set_RequiresAReason()
    {
        store.Write(_ => { });

        var refusal = Assert.Throws<CliArgumentException>(() => Run("set", "retention.raw_days", "30"));

        Assert.Contains("--reason is required", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void OptionsMayComeBeforeTheActionAndAReasonMayHaveSpaces()
    {
        store.Write(_ => { });

        var (exit, _, _) = Run("--store", store.Path, "set", "retention.event_days", "30", "--reason", "a b c");

        Assert.Equal(0, exit);
        Assert.Equal("a b c", Assert.Single(History()).Reason);
    }

    [Fact]
    public void AFlagBeforeAPositionalDoesNotSwallowIt()
    {
        store.Write(_ => { });

        var (exit, output, _) = Run("--json", "get", "retention.raw_days");

        Assert.Equal(0, exit);
        using var json = JsonDocument.Parse(output);
        Assert.Equal("retention.raw_days", json.RootElement.GetProperty("key").GetString());
    }

    [Fact]
    public void Labels_CanBeSetFromAFile()
    {
        store.Write(_ => { });
        var file = Path.Combine(store.DirectoryPath, "labels.json");
        File.WriteAllText(file, """{"198.51.100.7":"My office","203.0.113.0/24":"Scanner network"}""");

        var (exit, output, _) = Run("set", "labels.addresses", "--value-file", file, "--reason", "name the office");

        Assert.Equal(0, exit);
        Assert.Contains("My office", output, StringComparison.Ordinal);
        using var opened = EvidenceStore.OpenReadOnly(store.Path);
        Assert.Equal("Scanner network", AddressLabels.Read(opened).For("203.0.113.9"));
    }

    [Fact]
    public void Reset_ReturnsToTheDefaultAndIsRecordedLikeAnyChange()
    {
        store.Setting("retention.raw_days", "30");

        var (exit, output, _) = Run("reset", "retention.raw_days", "--reason", "back to the default");

        Assert.Equal(0, exit);
        Assert.Contains("retention.raw_days is back to its default, 14 (it was 30).", output, StringComparison.Ordinal);
        var history = History();
        Assert.Equal(2, history.Count);
        Assert.Null(history[0].NewValue);
    }

    [Fact]
    public void History_ListsChangesWithWhoAndWhy()
    {
        store.Setting("retention.raw_days", "30");

        var (exit, output, _) = Run("history", "retention.raw_days");

        Assert.Equal(0, exit);
        Assert.Contains("retention.raw_days  default -> 30  by test: test fixture", output, StringComparison.Ordinal);
        Assert.Contains("labels.addresses has never been changed", Run("history", "labels.addresses").Output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("frobnicate")]
    [InlineData("list", "extra")]
    [InlineData("get")]
    [InlineData("set", "retention.raw_days")]
    [InlineData("reset", "retention.raw_days", "30", "--reason", "x")]
    [InlineData("list", "--reason", "x")]
    public void MalformedCommands_AreRefused(params string[] args)
    {
        store.Write(_ => { });

        Assert.Throws<CliArgumentException>(() => Run(args));
    }
}

using System.IO;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Data.Sqlite;
using WPShield.Evidence;
using Xunit;

namespace WPShield.Desktop.Tests;

/// <summary>
/// The settings window against a real evidence store in a temporary directory, and against a fake
/// one for a catalog key this build has never heard of. Synthetic RFC 5737 addresses only.
/// </summary>
public sealed class SettingsWindowTests
{
    private const string Operator = @"WPSHIELD-LAB\operator";
    private static readonly RemoteClient Console = RemoteClient.Failed(RemoteClient.NotRemote);

    private static string TempStore(Action<EvidenceStore>? fill = null, bool create = true)
    {
        var directory = Path.Combine(Path.GetTempPath(), "wpshield-desktop-settings-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, EvidenceStore.FileName);
        if (create)
        {
            using var store = EvidenceStore.OpenForWriting(path);
            fill?.Invoke(store);
        }
        return path;
    }

    private static void Remove(string path)
    {
        try { Directory.Delete(Path.GetDirectoryName(path)!, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private static SettingsWindow Window(string path, bool elevated = true, bool spanish = false, RemoteClient? remote = null) =>
        new(spanish, new EvidenceSettingsStore(path, () => elevated, () => Operator), () => remote ?? Console);

    private static JsonNode Stored(string path, string key)
    {
        using var store = EvidenceStore.OpenReadOnly(path);
        return new EvidenceSettings(store).Get(key);
    }

    [Fact]
    public Task EverySettingIsListedWithItsValueDefaultAndWhenItTakesEffect() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore(store => new EvidenceSettings(store).Set("retention.raw_days", "30", "LAB\\earlier", "a month of detail"));
            var window = Window(path);
            try
            {
                window.Show();
                await window.LoadAsync();
                Assert.Equal(Visibility.Collapsed, window.Banner.Visibility);
                var rows = window.Keys.Items.OfType<SettingRow>().ToArray();
                Assert.Equal(SettingCatalog.All.Keys.Order(StringComparer.Ordinal), rows.Select(r => r.Key));

                await window.Select("retention.raw_days");
                Assert.Equal("Detailed records kept (days)", window.DetailName.Text);
                Assert.Equal("30", window.CurrentValue.Text);
                Assert.Equal("14", window.DefaultValue.Text);
                Assert.Contains("LAB\\earlier", window.ChangedValue.Text, StringComparison.Ordinal);
                Assert.StartsWith("Next use", window.EffectValue.Text, StringComparison.Ordinal);
                Assert.Equal(Visibility.Visible, window.ValueEditor.Visibility);
                var change = Assert.IsType<SettingHistoryRow>(Assert.Single(window.HistoryRows.Items.Cast<object>()));
                Assert.Equal("a month of detail", change.Reason);
                Assert.Equal("default", change.Old);
                Assert.Equal("30", change.New);

                await window.Select("mcp.detailed_records");
                Assert.Equal(Visibility.Visible, window.ToggleEditor.Visibility);
                // Honest about a start-time setting: saving restarts nothing.
                Assert.Contains("restarts nothing", window.EffectValue.Text, StringComparison.Ordinal);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task SaveStaysDisabledWithoutAReasonAndRecordsWhoAndWhy() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore();
            var window = Window(path);
            try
            {
                window.Show();
                await window.LoadAsync();
                await window.Select("attacks.default_range");
                Assert.False(window.SaveButton.IsEnabled);
                window.ValueEditor.Text = "7d";
                Assert.False(window.SaveButton.IsEnabled);
                Assert.Contains("reason", (string)window.SaveButton.ToolTip, StringComparison.Ordinal);
                Assert.True(ToolTipService.GetShowOnDisabled(window.SaveButton));
                Assert.Equal(200, window.ReasonBox.MaxLength);
                window.ReasonBox.Text = "a week by default";
                Assert.True(window.SaveButton.IsEnabled);

                await window.SaveAsync();

                Assert.Equal("7d", Stored(path, "attacks.default_range").GetValue<string>());
                Assert.Contains("Saved", window.StatusText.Text, StringComparison.Ordinal);
                Assert.Contains(Operator, window.StatusText.Text, StringComparison.Ordinal);
                Assert.Contains("next use", window.StatusText.Text, StringComparison.Ordinal);
                Assert.Equal("\"7d\"", window.CurrentValue.Text);
                var change = Assert.IsType<SettingHistoryRow>(Assert.Single(window.HistoryRows.Items.Cast<object>()));
                Assert.Equal(Operator, change.Who);
                Assert.Equal("a week by default", change.Reason);
                Assert.Equal("", window.ReasonBox.Text);
                Assert.False(window.SaveButton.IsEnabled);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task TheCatalogsVerdictIsShownInlineAndBlocksSaving() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore();
            var window = Window(path, spanish: true);
            try
            {
                window.Show();
                await window.LoadAsync();
                await window.Select("retention.raw_days");
                window.ValueEditor.Text = "500";
                window.ReasonBox.Text = "más días";
                Assert.Equal(Visibility.Visible, window.ValidationText.Visibility);
                Assert.Contains("a whole number from 1 to 90", window.ValidationText.Text, StringComparison.Ordinal);
                Assert.False(window.SaveButton.IsEnabled);
                window.ValueEditor.Text = "60";
                Assert.Equal(Visibility.Collapsed, window.ValidationText.Visibility);
                Assert.True(window.SaveButton.IsEnabled);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task LabelsAreEditedAsATableAndMyConnectionAddsTheReportedAddress() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore(store => new EvidenceSettings(store).Set(AddressLabels.SettingKey, """{"203.0.113.0/24":"Scanner network"}""",
                "LAB\\earlier", "names"));
            var window = Window(path, remote: new RemoteClient("198.51.100.23", null));
            try
            {
                window.Show();
                await window.LoadAsync();
                await window.Select(AddressLabels.SettingKey);
                Assert.Equal(Visibility.Visible, window.AddressEditor.Visibility);
                Assert.Equal(Visibility.Visible, window.RowActions.Visibility);
                Assert.True(window.ConnectionButton.IsEnabled);
                Assert.Contains("reports", (string)window.ConnectionButton.ToolTip, StringComparison.Ordinal);

                window.AddConnection();
                var edit = window.Edit!;
                Assert.Equal("198.51.100.23", edit.Addresses[^1].Address);
                // A new row has no label yet: the catalog says so and Save waits.
                Assert.Contains("1 to 64 characters", window.ValidationText.Text, StringComparison.Ordinal);
                edit.Addresses[^1].Label = "My \u202Econnection";
                window.ReasonBox.Text = "name my own connection";
                Assert.True(window.SaveButton.IsEnabled);
                window.AddConnection();
                Assert.Equal(2, edit.Addresses.Count);

                await window.SaveAsync();

                var stored = Assert.IsType<JsonObject>(Stored(path, AddressLabels.SettingKey));
                Assert.Equal("Scanner network", stored["203.0.113.0/24"]!.GetValue<string>());
                // The store cleaned the label on write; the window shows what was stored, not what was typed.
                Assert.DoesNotContain("\u202E", stored["198.51.100.23"]!.GetValue<string>(), StringComparison.Ordinal);
                Assert.Equal(stored["198.51.100.23"]!.GetValue<string>(), window.Edit!.Addresses[1].Label);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task ResetNeedsAReasonAndBringsTheDefaultBack() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore(store => new EvidenceSettings(store).Set("retention.event_days", "30", "LAB\\earlier", "less"));
            var window = Window(path);
            try
            {
                window.Show();
                await window.LoadAsync();
                await window.Select("retention.event_days");
                Assert.False(window.ResetButton.IsEnabled);
                window.ReasonBox.Text = "back to the default";
                Assert.True(window.ResetButton.IsEnabled);

                await window.ResetAsync();

                Assert.Equal(90, Stored(path, "retention.event_days").GetValue<int>());
                Assert.Contains("back to its default", window.StatusText.Text, StringComparison.Ordinal);
                Assert.Contains("the default applies", window.ChangedValue.Text, StringComparison.Ordinal);
                Assert.Equal("default (reset)", window.HistoryRows.Items.OfType<SettingHistoryRow>().First().New);
                Assert.False(window.ResetButton.IsEnabled);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task WithoutElevationAReadableStoreIsShownReadOnly() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore();
            var window = Window(path, elevated: false, remote: new RemoteClient("192.0.2.44", null));
            try
            {
                window.Show();
                await window.LoadAsync();
                Assert.Equal(SettingsAccess.ReadOnly, window.Snapshot!.Access);
                Assert.Equal(Visibility.Visible, window.Banner.Visibility);
                Assert.Equal(Visibility.Visible, window.ElevateButton.Visibility);
                Assert.Contains("cannot change", window.BannerText.Text, StringComparison.Ordinal);

                await window.Select("attacks.default_range");
                Assert.Equal("\"24h\"", window.CurrentValue.Text);
                Assert.False(window.Editors.IsEnabled);
                Assert.False(window.ReasonBox.IsEnabled);
                window.Edit!.Text = "7d";
                window.Edit.Reason = "would be a change";
                Assert.False(window.SaveButton.IsEnabled);
                Assert.Contains("administrator", (string)window.SaveButton.ToolTip, StringComparison.Ordinal);
                await window.SaveAsync();
                Assert.Equal("24h", Stored(path, "attacks.default_range").GetValue<string>());

                await window.Select(AddressLabels.SettingKey);
                Assert.False(window.ConnectionButton.IsEnabled);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Theory]
    [InlineData(false, "not elevated")]
    [InlineData(true, "no está elevada")]
    public Task WithoutElevationAStoreThatCannotBeOpenedIsCouldNotLookNotDefaults(bool spanish, string words) =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore(create: false);
            var window = Window(path, elevated: false, spanish: spanish);
            try
            {
                window.Show();
                await window.LoadAsync();
                Assert.Equal(SettingsAccess.CouldNotLook, window.Snapshot!.Access);
                Assert.Contains(words, window.BannerText.Text, StringComparison.Ordinal);
                Assert.DoesNotContain("does not exist", window.BannerText.Text, StringComparison.Ordinal);
                Assert.Equal(Visibility.Visible, window.ElevateButton.Visibility);
                // Every key is still listed, with an unknown value - never its default.
                var rows = window.Keys.Items.OfType<SettingRow>().ToArray();
                Assert.Equal(SettingCatalog.All.Count, rows.Length);
                Assert.All(rows, r => Assert.Equal("—", r.Summary));
                await window.Select("retention.raw_days");
                Assert.StartsWith("—", window.CurrentValue.Text, StringComparison.Ordinal);
                Assert.Equal(Visibility.Collapsed, window.EditArea.Visibility);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task ElevatedWithoutAStoreItSaysWhichCommandCreatesItAndCreatesNothing() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore(create: false);
            var missingDirectory = Path.Combine(Path.GetDirectoryName(path)!, "evidence", EvidenceStore.FileName);
            var noDirectory = Window(missingDirectory);
            var noFile = Window(path);
            try
            {
                noDirectory.Show();
                await noDirectory.LoadAsync();
                Assert.Equal(SettingsAccess.NoDirectory, noDirectory.Snapshot!.Access);
                Assert.Contains("does not exist", noDirectory.BannerText.Text, StringComparison.Ordinal);
                Assert.Contains("'wpshield install'", noDirectory.BannerText.Text, StringComparison.Ordinal);
                Assert.Contains("creates nothing", noDirectory.BannerText.Text, StringComparison.Ordinal);
                Assert.Equal(Visibility.Collapsed, noDirectory.ElevateButton.Visibility);

                noFile.Show();
                await noFile.LoadAsync();
                Assert.Equal(SettingsAccess.NoStore, noFile.Snapshot!.Access);
                Assert.Contains("'wpshield install'", noFile.BannerText.Text, StringComparison.Ordinal);
                await noFile.Select("attacks.default_range");
                Assert.Equal(Visibility.Collapsed, noFile.EditArea.Visibility);

                // Even asked directly, the store door never creates the file or the folder.
                var store = new EvidenceSettingsStore(path, () => true, () => Operator);
                Assert.ThrowsAny<Exception>(() => store.Save("attacks.default_range", "\"7d\"", "why", default));
                Assert.ThrowsAny<Exception>(() => new EvidenceSettingsStore(missingDirectory, () => true, () => Operator)
                    .Reset("attacks.default_range", "why", default));
                Assert.False(File.Exists(path));
                Assert.False(Directory.Exists(Path.GetDirectoryName(missingDirectory)));
            }
            finally
            {
                noDirectory.Close();
                noFile.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task AChangeMadeElsewhereSinceTheReadIsNotOverwrittenAndTheEditStays() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore(store => new EvidenceSettings(store).Set(AddressLabels.SettingKey, """{"192.0.2.7":"Office"}""", "LAB\\earlier", "names"));
            var window = Window(path);
            try
            {
                window.Show();
                await window.LoadAsync();
                await window.Select(AddressLabels.SettingKey);
                window.Edit!.AddAddress("198.51.100.9");
                window.Edit.Addresses[^1].Label = "Home";
                window.ReasonBox.Text = "add home";

                using (var cli = EvidenceStore.OpenForWriting(path))
                    new EvidenceSettings(cli).Set(AddressLabels.SettingKey, """{"192.0.2.7":"Office","203.0.113.5":"Partner"}""", "LAB\\cli", "partner");

                await window.SaveAsync();

                Assert.Contains("Not saved", window.StatusText.Text, StringComparison.Ordinal);
                Assert.Contains("LAB\\cli", window.StatusText.Text, StringComparison.Ordinal);
                Assert.Contains("still here", window.StatusText.Text, StringComparison.Ordinal);
                Assert.Equal("Home", window.Edit!.Addresses[^1].Label);
                Assert.True(window.SaveButton.IsEnabled);
                var stored = Assert.IsType<JsonObject>(Stored(path, AddressLabels.SettingKey));
                Assert.Equal("Partner", stored["203.0.113.5"]!.GetValue<string>());
                Assert.False(stored.ContainsKey("198.51.100.9"));
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task AFailedSaveShowsTheReasonAndKeepsTheEdit() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var fake = new FakeStore { Fail = new SqliteException("database is locked", 5) };
            var window = new SettingsWindow(false, fake, () => Console);
            try
            {
                window.Show();
                await window.LoadAsync();
                await window.Select("defense.allow");
                window.Edit!.AddItem("192.0.2.0/24");
                window.ReasonBox.Text = "the lab";

                await window.SaveAsync();

                Assert.Contains("Not saved", window.StatusText.Text, StringComparison.Ordinal);
                Assert.Contains("SQLite error 5", window.StatusText.Text, StringComparison.Ordinal);
                Assert.Equal("192.0.2.0/24", Assert.Single(window.Edit!.Items).Value);
                Assert.True(window.SaveButton.IsEnabled);
            }
            finally { window.Close(); }
        });

    [Fact]
    public Task AKeyAddedToTheCatalogLaterIsListedAndEditableWithNoDesktopChange() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var fake = new FakeStore();
            var window = new SettingsWindow(true, fake, () => new RemoteClient("203.0.113.77", null));
            try
            {
                window.Show();
                await window.LoadAsync();
                await window.Select("defense.allow");
                Assert.Equal("defense.allow", window.DetailName.Text);
                Assert.Equal(FakeStore.Description, window.DetailDescription.Text);
                Assert.Equal(Visibility.Visible, window.ListEditor.Visibility);
                Assert.Equal(Visibility.Collapsed, window.AddressEditor.Visibility);
                Assert.StartsWith("Al próximo arranque", window.EffectValue.Text, StringComparison.Ordinal);

                window.AddConnection();
                Assert.Equal("203.0.113.77", Assert.Single(window.Edit!.Items).Value);
                window.ReasonBox.Text = "mi conexión";
                await window.SaveAsync();

                Assert.Equal(("defense.allow", """["203.0.113.77"]""", "mi conexión"), fake.Saved);
                Assert.Contains("Guardado", window.StatusText.Text, StringComparison.Ordinal);
                Assert.Contains("no reinicia nada", window.StatusText.Text, StringComparison.Ordinal);
            }
            finally { window.Close(); }
        });

    [Fact]
    public Task WithoutARemoteAddressTheButtonIsDisabledAndSaysWhy() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore();
            var console = Window(path);
            var ipv6 = Window(path, spanish: true, remote: RemoteClient.Failed(RemoteClient.Ipv6));
            try
            {
                console.Show();
                await console.LoadAsync();
                await console.Select(AddressLabels.SettingKey);
                Assert.False(console.ConnectionButton.IsEnabled);
                Assert.Contains("not a Remote Desktop session", (string)console.ConnectionButton.ToolTip, StringComparison.Ordinal);
                Assert.True(ToolTipService.GetShowOnDisabled(console.ConnectionButton));
                console.AddConnection();
                Assert.Empty(console.Edit!.Addresses);

                ipv6.Show();
                await ipv6.LoadAsync();
                await ipv6.Select(AddressLabels.SettingKey);
                Assert.False(ipv6.ConnectionButton.IsEnabled);
                Assert.Contains("IPv6", (string)ipv6.ConnectionButton.ToolTip, StringComparison.Ordinal);
            }
            finally
            {
                console.Close();
                ipv6.Close();
                Remove(path);
            }
        });

    /// <summary>A store whose catalog has a key this build of the desktop has never seen.</summary>
    private sealed class FakeStore : ISettingsStore
    {
        internal const string Description = "Addresses and networks the decision engine never blocks.";

        private static readonly SettingDefinition Allow = new("defense.allow", Description, new JsonArray(), SettingEffect.NextStart,
            node => node is JsonArray ? null : "a list of addresses");

        private SettingValue value = new("defense.allow", new JsonArray(), true, 0, null, null, SettingEffect.NextStart, Description);

        internal Exception? Fail { get; init; }

        internal (string Key, string Json, string Reason)? Saved { get; private set; }

        public string Path => @"C:\WPShield-test\evidence\wpshield-evidence.db";

        public IReadOnlyDictionary<string, SettingDefinition> Catalog { get; } =
            new Dictionary<string, SettingDefinition>(StringComparer.Ordinal) { [Allow.Key] = Allow };

        public SettingsSnapshot Read() => new(SettingsAccess.Writable, [value], null);

        public IReadOnlyList<SettingChange> History(string key) => [];

        public SettingChange Save(string key, string json, string reason, SettingStamp loaded)
        {
            if (Fail is not null) throw Fail;
            Saved = (key, json, reason);
            var at = DateTimeOffset.UtcNow;
            value = new(key, JsonNode.Parse(json)!, false, 1, at, Operator, SettingEffect.NextStart, Description);
            return new(key, null, json, at, Operator, reason, SettingEffect.NextStart);
        }

        public SettingChange Reset(string key, string reason, SettingStamp loaded) => throw new NotSupportedException();
    }
}

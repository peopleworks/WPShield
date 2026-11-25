using System.Net;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;
using WPShield.SecurityMonitor;
using Xunit;

namespace WPShield.Desktop.Tests;

/// <summary>
/// Label and Allow in the Attacks detail panel, against a real evidence store in a temporary directory.
/// Synthetic RFC 5737 addresses only.
/// </summary>
public sealed class AttackActionsTests
{
    private const string Operator = @"WPSHIELD-LAB\operator";
    private const string Address = "203.0.113.10";

    private sealed class NoWatch : IDisposable
    {
        public void Dispose() { }
    }

    private static AuthFailureSnapshot Snapshot(DateTimeOffset end, params AuthFailure[] failures) =>
        new(end.AddHours(-24), end, failures,
        [
            new(AuthFailureFeed.SecurityChannel, "read", null, null, end.AddDays(-3), failures.Length),
            new(AuthFailureFeed.RdpCoreChannel, "read", null, null, end.AddDays(-3), 0)
        ]);

    private static AuthFailure Failure(DateTimeOffset at, string account, string reason, long id) =>
        new(at, AttemptPairing.SecurityChannel, IPAddress.Parse(Address), null, account, reason, 3, id);

    private static AuthFailureSnapshot Guessing(DateTimeOffset end) => Snapshot(end,
        Failure(end.AddMinutes(-9), "ghost1", "unknown-account", 1), Failure(end.AddMinutes(-8), "ghost2", "unknown-account", 2),
        Failure(end.AddMinutes(-7), "ghost3", "unknown-account", 3), Failure(end.AddMinutes(-6), "admin", "bad-password", 4));

    private static string TempStore(Action<EvidenceStore, EvidenceWriter> fill)
    {
        var directory = Path.Combine(Path.GetTempPath(), "wpshield-desktop-action-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, EvidenceStore.FileName);
        using var store = EvidenceStore.OpenForWriting(path);
        var writer = new EvidenceWriter(store);
        writer.BeginCoverage(EvidenceWriter.RawSource, DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow);
        fill(store, writer);
        return path;
    }

    private static void Remove(string path)
    {
        try { Directory.Delete(Path.GetDirectoryName(path)!, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private static AttacksWindow Window(string path, bool elevated = true, bool spanish = false) =>
        new(spanish, Guessing, (_, _) => new NoWatch(), new EvidenceAttackStore(path, () => true),
            new EvidenceSettingsStore(path, () => elevated, () => Operator));

    private static JsonNode Stored(string path, string key)
    {
        using var store = EvidenceStore.OpenReadOnly(path);
        return new EvidenceSettings(store).Get(key);
    }

    private static void ChangeElsewhere(string path, string key, string json)
    {
        using var cli = EvidenceStore.OpenForWriting(path);
        new EvidenceSettings(cli).Set(key, json, @"WPSHIELD-LAB\cli", "changed elsewhere");
    }

    private static async Task<AttackSource> SelectAsync(AttacksWindow window)
    {
        window.Show();
        await window.LoadAsync();
        var row = window.Rows.Items.Cast<AttackSource>().Single(r => r.Address == Address);
        window.Rows.SelectedItem = row;
        return row;
    }

    [Theory]
    [InlineData(false, "administrator")]
    [InlineData(true, "administrador")]
    public Task WithoutElevationBothActionsAreDisabledAndSayWhy(bool spanish, string word) =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore((_, _) => { });
            var window = Window(path, elevated: false, spanish: spanish);
            try
            {
                await SelectAsync(window);
                Assert.False(window.LabelButton.IsEnabled);
                Assert.False(window.AllowButton.IsEnabled);
                Assert.Equal(Visibility.Visible, window.ActionNote.Visibility);
                Assert.Contains(word, window.ActionNote.Text, StringComparison.Ordinal);
                Assert.Contains(word, (string)window.AllowButton.ToolTip, StringComparison.Ordinal);
                Assert.True(ToolTipService.GetShowOnDisabled(window.AllowButton));

                await window.OpenEditorAsync(AddressAction.Allow);
                Assert.Equal(Visibility.Collapsed, window.ActionEditor.Visibility);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task WithoutASettingsStoreNothingCanBeChangedAndThePanelSaysSo() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore((_, _) => { });
            var window = new AttacksWindow(false, Guessing, (_, _) => new NoWatch(), new EvidenceAttackStore(path, () => true));
            try
            {
                await SelectAsync(window);
                Assert.False(window.LabelButton.IsEnabled);
                Assert.Contains("not available", window.ActionNote.Text, StringComparison.Ordinal);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task ALabelReplacesOnlyTheAddresssOwnEntryAndIsRecordedWithWhoAndWhy() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore((store, _) => new EvidenceSettings(store).Set(AddressLabels.SettingKey,
                """{"203.0.113.0/24":"Scanner network"}""", @"WPSHIELD-LAB\earlier", "names"));
            var window = Window(path);
            try
            {
                var row = await SelectAsync(window);
                Assert.Equal("Scanner network", row.Label);
                Assert.True(window.LabelButton.IsEnabled);

                await window.OpenEditorAsync(AddressAction.Label);
                Assert.Equal(Visibility.Visible, window.ActionEditor.Visibility);
                Assert.Equal(Visibility.Visible, window.LabelFields.Visibility);
                Assert.Contains("“Scanner network”, which stays as it is", window.ActionText.Text, StringComparison.Ordinal);
                Assert.Equal(64, window.LabelBox.MaxLength);
                window.LabelBox.Text = "Partner VPN";
                Assert.False(window.ActionSave.IsEnabled);
                Assert.Contains("reason", (string)window.ActionSave.ToolTip, StringComparison.Ordinal);
                window.ActionReason.Text = "a partner's VPN";
                Assert.True(window.ActionSave.IsEnabled);

                await window.SaveActionAsync();

                var labels = Assert.IsType<JsonObject>(Stored(path, AddressLabels.SettingKey));
                Assert.Equal("Partner VPN", labels[Address]!.GetValue<string>());
                Assert.Equal("Scanner network", labels["203.0.113.0/24"]!.GetValue<string>());
                Assert.Empty(Assert.IsType<JsonArray>(Stored(path, DefenseSettings.Allow)));
                using (var store = EvidenceStore.OpenReadOnly(path))
                {
                    var change = new EvidenceSettings(store).History(AddressLabels.SettingKey).First();
                    Assert.Equal((Operator, "a partner's VPN"), (change.ChangedBy, change.Reason));
                }
                Assert.Equal(Visibility.Collapsed, window.ActionEditor.Visibility);
                Assert.Contains("Saved", window.ActionStatus.Text, StringComparison.Ordinal);
                Assert.Contains(Operator, window.ActionStatus.Text, StringComparison.Ordinal);
                // Labels were read again: the row and the detail show the new one.
                Assert.Equal("Partner VPN", window.Rows.Items.Cast<AttackSource>().Single(r => r.Address == Address).Label);
                Assert.Equal("Partner VPN", window.DetailLabel.Text);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task AllowWarnsWithCountsAndWritesTheExactAddressNeverItsNetwork() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var now = DateTimeOffset.UtcNow;
            var path = TempStore((_, writer) =>
            {
                writer.RecordEngineStart(now.AddHours(-1));
                writer.RecordDecision(new(now.AddMinutes(-5), DecisionActions.WouldBlock, Address, DecisionRules.NonexistentAccounts,
                    DecisionActions.MonitorMode, "4 account names that do not exist", AttemptPairing.SecurityChannel, now.AddHours(6)));
            });
            var window = Window(path);
            try
            {
                await SelectAsync(window);
                Assert.True(window.AllowButton.IsEnabled);

                await window.OpenEditorAsync(AddressAction.Allow);
                Assert.Equal(Visibility.Collapsed, window.LabelFields.Visibility);
                Assert.Contains("the decision engine will never decide against this address", window.ActionText.Text, StringComparison.Ordinal);
                Assert.Contains("never its network", window.ActionText.Text, StringComparison.Ordinal);
                Assert.Equal(Visibility.Visible, window.ActionWarning.Visibility);
                Assert.Contains("3 of its 4 attempts named accounts that do not exist", window.ActionWarningText.Text, StringComparison.Ordinal);
                Assert.Contains("1 would-block decision is in force", window.ActionWarningText.Text, StringComparison.Ordinal);
                Assert.False(window.ActionSave.IsEnabled);
                window.ActionReason.Text = "my own connection";
                Assert.True(window.ActionSave.IsEnabled);

                await window.SaveActionAsync();

                var allow = Assert.IsType<JsonArray>(Stored(path, DefenseSettings.Allow));
                Assert.Equal([Address], allow.Select(e => e!.GetValue<string>()));
                Assert.Contains($"Saved: {Address} is on defense.allow", window.ActionStatus.Text, StringComparison.Ordinal);
                Assert.Contains("next evaluation", window.ActionStatus.Text, StringComparison.Ordinal);
                Assert.False(window.AllowButton.IsEnabled);
                Assert.Contains("already on the allow-list", window.ActionNote.Text, StringComparison.Ordinal);
                // The decision in force is not withdrawn: it ends at its expiry, and the column still says so.
                Assert.Equal("would block", window.Rows.Items.Cast<AttackSource>().Single(r => r.Address == Address).Decision);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task AChangeMadeElsewhereIsNotOverwrittenTheTextStaysAndASecondSaveKeepsBoth() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore((store, _) => new EvidenceSettings(store).Set(AddressLabels.SettingKey, """{"192.0.2.7":"Office"}""",
                @"WPSHIELD-LAB\earlier", "names"));
            var window = Window(path);
            try
            {
                await SelectAsync(window);
                await window.OpenEditorAsync(AddressAction.Label);
                window.LabelBox.Text = "Home";
                window.ActionReason.Text = "add home";
                ChangeElsewhere(path, AddressLabels.SettingKey, """{"192.0.2.7":"Office","198.51.100.5":"Partner"}""");

                await window.SaveActionAsync();

                Assert.Contains("Not saved", window.ActionStatus.Text, StringComparison.Ordinal);
                Assert.Contains(@"WPSHIELD-LAB\cli changed labels.addresses", window.ActionStatus.Text, StringComparison.Ordinal);
                Assert.Equal(Visibility.Visible, window.ActionEditor.Visibility);
                Assert.Equal("Home", window.LabelBox.Text);
                var between = Assert.IsType<JsonObject>(Stored(path, AddressLabels.SettingKey));
                Assert.Equal("Partner", between["198.51.100.5"]!.GetValue<string>());
                Assert.False(between.ContainsKey(Address));

                // Read again, so the second save is checked against the change it now includes.
                Assert.True(window.ActionSave.IsEnabled);
                await window.SaveActionAsync();

                var after = Assert.IsType<JsonObject>(Stored(path, AddressLabels.SettingKey));
                Assert.Equal(("Office", "Partner", "Home"),
                    (after["192.0.2.7"]!.GetValue<string>(), after["198.51.100.5"]!.GetValue<string>(), after[Address]!.GetValue<string>()));
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task AnAllowRefusedByAConflictIsNotAddedWhenTheOtherChangeAlreadyCoversIt() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore((_, _) => { });
            var window = Window(path);
            try
            {
                await SelectAsync(window);
                await window.OpenEditorAsync(AddressAction.Allow);
                window.ActionReason.Text = "my own connection";
                ChangeElsewhere(path, DefenseSettings.Allow, """["203.0.113.0/24"]""");

                await window.SaveActionAsync();

                Assert.Contains("Not saved", window.ActionStatus.Text, StringComparison.Ordinal);
                Assert.False(window.ActionSave.IsEnabled);
                Assert.Contains("already allowed by the entry 203.0.113.0/24", window.ActionValidation.Text, StringComparison.Ordinal);
                Assert.Equal(["203.0.113.0/24"], Assert.IsType<JsonArray>(Stored(path, DefenseSettings.Allow)).Select(e => e!.GetValue<string>()));
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });
}

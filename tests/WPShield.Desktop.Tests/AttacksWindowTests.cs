using System.Net;
using System.Windows;
using System.Windows.Controls;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;
using WPShield.SecurityMonitor;
using Xunit;

namespace WPShield.Desktop.Tests;

public sealed class AttacksWindowTests
{
    private static AuthFailureSnapshot Snapshot(DateTimeOffset end, string status, string? reason, params AuthFailure[] failures) =>
        new(end.AddHours(-24), end, failures,
        [
            new(AuthFailureFeed.SecurityChannel, status, reason, null, status == "unavailable" ? null : end.AddDays(-3), failures.Length),
            new(AuthFailureFeed.RdpCoreChannel, "read", null, null, end.AddDays(-3), 0)
        ]);

    private sealed class NoWatch : IDisposable
    {
        public void Dispose() { }
    }

    [Theory]
    [InlineData(true, "administrador")]
    [InlineData(false, "administrator")]
    public Task WithoutElevationItSaysItCouldNotLookInsteadOfShowingAQuietHost(bool spanish, string word) =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var window = new AttacksWindow(spanish, end => Snapshot(end, "unavailable", "access-denied"), (_, _) => new NoWatch());
            try
            {
                window.Show();
                await window.LoadAsync();
                Assert.Equal(Visibility.Visible, window.Banner.Visibility);
                Assert.Contains(word, window.BannerText.Text, StringComparison.OrdinalIgnoreCase);
                Assert.Equal(Visibility.Visible, window.ElevateButton.Visibility);
                // "0" would claim nobody tried; the cards must say nothing was read.
                Assert.Equal("—", window.AttemptsValue.Text);
                Assert.Equal("—", window.SourcesValue.Text);
            }
            finally { window.Close(); }
        });

    [Fact]
    public Task LiveFailuresAreAppliedAndShown() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            Action<AuthFailure>? push = null;
            var window = new AttacksWindow(false, end => Snapshot(end, "read", null), (onFailure, _) =>
            {
                push = onFailure;
                return new NoWatch();
            });
            try
            {
                window.Show();
                await window.LoadAsync();
                Assert.Equal(Visibility.Collapsed, window.Banner.Visibility);
                Assert.NotNull(push);
                push(new(DateTimeOffset.UtcNow, "security-4625", IPAddress.Parse("203.0.113.44"), 50000, "admin",
                    "unknown-account", 10, 1));
                await Task.Delay(1600);
                Assert.Equal(1, window.Board.Count);
                Assert.Equal("1", window.AttemptsValue.Text);
            }
            finally { window.Close(); }
        });

    private static string TempStore(Action<EvidenceStore>? fill)
    {
        var directory = Path.Combine(Path.GetTempPath(), "wpshield-desktop-window-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, EvidenceStore.FileName);
        if (fill is not null)
        {
            using var store = EvidenceStore.OpenForWriting(path);
            fill(store);
        }
        return path;
    }

    private static void Remove(string path)
    {
        try { Directory.Delete(Path.GetDirectoryName(path)!, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private static AuthFailure Failure(DateTimeOffset at, string ip, string account, long id) =>
        new(at, AttemptPairing.SecurityChannel, IPAddress.Parse(ip), null, account, "bad-password", 3, id);

    [Theory]
    [InlineData(true, "almacén de evidencia")]
    [InlineData(false, "evidence store")]
    public Task WithoutAStoreTheLongRangesAreDisabledAndSayWhy(bool spanish, string words) =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var window = new AttacksWindow(spanish, end => Snapshot(end, "read", null), (_, _) => new NoWatch());
            try
            {
                window.Show();
                await window.LoadAsync();
                Assert.False(window.RangeWeek.IsEnabled);
                Assert.False(window.RangeMonth.IsEnabled);
                Assert.Contains(words, (string)window.RangeWeek.ToolTip, StringComparison.Ordinal);
                // WPF shows no tooltip on a disabled control unless asked, and the chip must look disabled.
                Assert.True(ToolTipService.GetShowOnDisabled(window.RangeWeek));
                Assert.Contains(window.RangeWeek.Template.Triggers.OfType<Trigger>(),
                    t => t.Property == UIElement.IsEnabledProperty && Equals(t.Value, false));
                Assert.True(window.RangeDay.IsChecked);
            }
            finally { window.Close(); }
        });

    [Fact]
    public Task WithoutElevationTheLongRangesSayRunAsAdministrator() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore(null);
            var window = new AttacksWindow(false, end => Snapshot(end, "unavailable", "access-denied"), (_, _) => new NoWatch(),
                new EvidenceAttackStore(path, () => false));
            try
            {
                window.Show();
                await window.LoadAsync();
                Assert.False(window.RangeWeek.IsEnabled);
                Assert.Contains("run as administrator", (string)window.RangeMonth.ToolTip, StringComparison.Ordinal);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task TheWeekComesFromTheStoreWithLabelsAndTheShortRangesStayLive() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var now = DateTimeOffset.UtcNow;
            var path = TempStore(store =>
            {
                var writer = new EvidenceWriter(store);
                writer.BeginCoverage(EvidenceWriter.RawSource, now.AddDays(-8), now);
                writer.Append([Failure(now.AddDays(-3), "203.0.113.10", "admin", 1), Failure(now.AddDays(-2), "203.0.113.10", "sa", 2),
                    Failure(now.AddDays(-2), "203.0.113.11", "admin", 3), Failure(now.AddHours(-30), "198.51.100.7", "pedro", 4)]);
                new EvidenceSettings(store).Set(AddressLabels.SettingKey, """{"203.0.113.0/24":"Scanner network"}""", "test", "names");
            });
            var window = new AttacksWindow(false, end => Snapshot(end, "read", null), (_, _) => new NoWatch(),
                new EvidenceAttackStore(path, () => true));
            try
            {
                window.Show();
                await window.LoadAsync();
                Assert.True(window.RangeWeek.IsEnabled);
                Assert.Equal("0", window.AttemptsValue.Text);

                window.RangeWeek.IsChecked = true;
                await window.LoadStoredAsync();
                Assert.Equal("4", window.AttemptsValue.Text);
                Assert.Equal("3", window.SourcesValue.Text);
                var top = Assert.IsType<AttackSource>(window.Rows.Items[0]);
                Assert.Equal("Scanner network", top.Label);

                window.Rows.SelectedItem = top;
                await window.LoadStoredDetailAsync(top.Address);
                Assert.Equal("Scanner network", window.DetailLabel.Text);
                Assert.Equal(Visibility.Collapsed, window.DetailNoteBox.Visibility);
                Assert.Contains("admin", string.Join("|", window.DetailAccounts.ItemsSource.Cast<string>()), StringComparison.Ordinal);

                // 24 h is still the Security log, not the store.
                window.RangeDay.IsChecked = true;
                Assert.Equal("0", window.AttemptsValue.Text);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task AMonthFromAggregatesSaysNamesAreGoneAndOpensWithTheSettingsRange() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var now = DateTimeOffset.UtcNow;
            var path = TempStore(store =>
            {
                var writer = new EvidenceWriter(store);
                writer.BeginCoverage(EvidenceWriter.RawSource, now.AddDays(-31), now);
                writer.Append([Failure(now.AddDays(-20), "203.0.113.10", "admin", 1), Failure(now.AddDays(-20).AddMinutes(1), "203.0.113.10", "sa", 2)]);
                writer.Prune(now, new EvidenceLimits());
                new EvidenceSettings(store).Set("attacks.default_range", "\"30d\"", "test", "a month");
            });
            var window = new AttacksWindow(true, end => Snapshot(end, "read", null), (_, _) => new NoWatch(),
                new EvidenceAttackStore(path, () => true));
            try
            {
                window.Show();
                await window.LoadAsync();
                Assert.True(window.RangeMonth.IsChecked);
                await window.LoadStoredAsync();
                Assert.Equal("2", window.AttemptsValue.Text);
                var row = Assert.IsType<AttackSource>(window.Rows.Items[0]);
                Assert.Null(row.Accounts);

                window.Rows.SelectedItem = row;
                await window.LoadStoredDetailAsync(row.Address);
                Assert.Equal(Visibility.Visible, window.DetailNoteBox.Visibility);
                Assert.Contains("ya no se guardan", window.DetailNote.Text, StringComparison.Ordinal);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task TheDecisionColumnMarksSourcesInEveryRangeAndTheDetailListsTheirDecisions() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var now = DateTimeOffset.UtcNow;
            var path = TempStore(store =>
            {
                var writer = new EvidenceWriter(store);
                writer.BeginCoverage(EvidenceWriter.RawSource, now.AddDays(-8), now);
                writer.Append([Failure(now.AddDays(-2), "203.0.113.10", "admin", 1), Failure(now.AddDays(-2), "198.51.100.7", "pedro", 2)]);
                writer.RecordEngineStart(now.AddHours(-1));
                writer.RecordDecision(new(now.AddMinutes(-10), DecisionActions.WouldBlock, "203.0.113.10", DecisionRules.RepeatedFailures,
                    DecisionActions.MonitorMode, "10 failed logons in 4 minutes (threshold 10 in 10 minutes)", AttemptPairing.SecurityChannel,
                    now.AddMinutes(50)));
            });
            var window = new AttacksWindow(false, end => Snapshot(end, "read", null, Failure(end.AddHours(-1), "203.0.113.10", "admin", 9)),
                (_, _) => new NoWatch(), new EvidenceAttackStore(path, () => true));
            try
            {
                window.Show();
                await window.LoadAsync();
                // 24 h, from the Security log: the mark comes from the store all the same.
                Assert.Equal("would block", Assert.IsType<AttackSource>(window.Rows.Items[0]).Decision);
                Assert.Contains("decisions in force: 1 (Monitor: nothing is blocked)", window.Footer.Text, StringComparison.Ordinal);
                Assert.Equal("Decision", window.Rows.Columns[^2].Header);

                window.RangeWeek.IsChecked = true;
                await window.LoadStoredAsync();
                var rows = window.Rows.Items.Cast<AttackSource>().ToArray();
                Assert.Equal("would block", rows.Single(r => r.Address == "203.0.113.10").Decision);
                Assert.Equal("", rows.Single(r => r.Address == "198.51.100.7").Decision);

                var top = rows.Single(r => r.Address == "203.0.113.10");
                window.Rows.SelectedItem = top;
                await window.LoadStoredDetailAsync(top.Address);
                await window.LoadDecisionDetailAsync(top.Address);
                var line = Assert.Single(window.DetailDecisions.ItemsSource.Cast<string>());
                Assert.Contains("would block until", line, StringComparison.Ordinal);
                Assert.Contains("HOST-AUTH-001", line, StringComparison.Ordinal);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task WithoutAStoreTheDecisionColumnSaysNobodyCouldLook() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var window = new AttacksWindow(false, end => Snapshot(end, "read", null, Failure(end.AddHours(-1), "203.0.113.10", "admin", 9)),
                (_, _) => new NoWatch());
            try
            {
                window.Show();
                await window.LoadAsync();
                var row = Assert.IsType<AttackSource>(window.Rows.Items[0]);
                Assert.Equal("—", row.Decision);
                Assert.Contains("decisions: not read", window.Footer.Text, StringComparison.Ordinal);

                window.Rows.SelectedItem = row;
                Assert.Contains("nobody could look", Assert.Single(window.DetailDecisions.ItemsSource.Cast<string>()), StringComparison.Ordinal);
            }
            finally { window.Close(); }
        });
    [Fact]
    public Task AStoreThatRecordedNothingShowsADashNotZero() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore(_ => { });
            var window = new AttacksWindow(false, end => Snapshot(end, "read", null), (_, _) => new NoWatch(),
                new EvidenceAttackStore(path, () => true));
            try
            {
                window.Show();
                await window.LoadAsync();
                window.RangeWeek.IsChecked = true;
                await window.LoadStoredAsync();
                Assert.Equal("—", window.AttemptsValue.Text);
                Assert.Equal("—", window.SourcesValue.Text);
                Assert.Contains("No data", window.Empty.Text, StringComparison.Ordinal);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });
}

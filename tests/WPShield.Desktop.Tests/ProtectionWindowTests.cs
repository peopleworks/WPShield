using System.Windows;
using System.Windows.Controls;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;
using Xunit;

namespace WPShield.Desktop.Tests;

/// <summary>The Protection window against a real evidence store in a temporary directory. Synthetic RFC 5737 / 3849 addresses only.</summary>
public sealed class ProtectionWindowTests
{
    private static string TempStore(Action<EvidenceStore>? fill, bool create = true)
    {
        var directory = Path.Combine(Path.GetTempPath(), "wpshield-desktop-protection-tests", Guid.NewGuid().ToString("N"));
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

    private static DecisionRecord Decision(DateTimeOffset at, string action, string target, string rule, DateTimeOffset? until) =>
        new(at, action, target, rule, DecisionActions.MonitorMode, "8 different addresses of this network failed in 3 minutes", "security-4625", until);

    private static string Recording(DateTimeOffset now) => TempStore(store =>
    {
        var writer = new EvidenceWriter(store);
        writer.BeginCoverage(EvidenceWriter.RawSource, now.AddDays(-2), now);
        writer.RecordEngineStart(now.AddHours(-1));
        writer.RecordDecision(Decision(now.AddMinutes(-10), DecisionActions.WouldBlock, "203.0.113.0/24", DecisionRules.Network, now.AddMinutes(50)));
        writer.RecordDecision(Decision(now.AddMinutes(-5), DecisionActions.Protected, "198.51.100.7", DecisionRules.RepeatedFailures, now.AddMinutes(55)));
        writer.RecordDecision(Decision(now.AddMinutes(-3), DecisionActions.Refused, "203.0.113.9", DecisionRules.NonexistentAccounts, null));
        writer.RecordDecision(Decision(now.AddDays(-10), DecisionActions.WouldBlock, "2001:db8:5::17", DecisionRules.NonexistentAccounts,
            now.AddDays(-10).AddHours(6)));
        new EvidenceSettings(store).Set(AddressLabels.SettingKey, """{"203.0.113.0/24":"Scanner network"}""", "LAB\\earlier", "names");
    });

    [Fact]
    public Task BeforeTheFirstReadNothingIsClaimedNeitherAFailureNorAValue() =>
        DesktopDispatcher.RunAsync(() =>
        {
            var window = new ProtectionWindow(false, null, () => new ServiceReading(ServiceState.Running));
            try
            {
                Assert.Equal("Reading…", window.CollectorText.Text);
                Assert.Equal("Reading…", window.ServiceText.Text);
                Assert.Equal("Reading…", window.LogonStatus.Text);
                Assert.Equal(Visibility.Collapsed, window.Banner.Visibility);
                Assert.Equal("—", window.WouldBlockValue.Text);
                Assert.Equal("In force (—)", window.TabInForce.Content);
                Assert.Contains("Reading the evidence store", window.Empty.Text, StringComparison.Ordinal);
            }
            finally { window.Close(); }
            return Task.CompletedTask;
        });

    [Theory]
    [InlineData(false, "administrator", "Could not read the store", "not read")]
    [InlineData(true, "administrador", "No se pudo leer el almacén", "sin lectura")]
    public Task WithoutElevationEveryCountIsADashAndItOffersToReopenElevated(bool spanish, string word, string title, string chip) =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore(null, create: false);
            var window = new ProtectionWindow(spanish, new EvidenceProtectionStore(path, () => false), () => new ServiceReading(ServiceState.Running));
            try
            {
                window.Show();
                await window.LoadAsync();
                Assert.Equal(Visibility.Visible, window.Banner.Visibility);
                Assert.Contains(word, window.BannerText.Text, StringComparison.Ordinal);
                Assert.Equal(Visibility.Visible, window.ElevateButton.Visibility);
                Assert.Equal(title, window.CollectorText.Text);
                // Nobody could look: a dash, never a zero that would read as a quiet host.
                Assert.All(new[] { window.WouldBlockValue, window.ProtectedValue, window.RefusedValue, window.ReportValue },
                    v => Assert.Equal("—", v.Text));
                Assert.Contains("(—)", (string)window.TabInForce.Content, StringComparison.Ordinal);
                Assert.Contains("(—)", (string)window.TabMonth.Content, StringComparison.Ordinal);
                Assert.Equal(chip, window.LogonStatus.Text);
                Assert.Equal(Visibility.Visible, window.Empty.Visibility);
                Assert.Contains("—", window.ModeText.Text, StringComparison.Ordinal);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task ElevatedWithoutAStoreItNamesTheInstallAndOffersNoElevation() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = TempStore(null, create: false);
            var window = new ProtectionWindow(false, new EvidenceProtectionStore(path, () => true), () => new ServiceReading(ServiceState.NotInstalled));
            try
            {
                window.Show();
                await window.LoadAsync();
                Assert.Contains("'wpshield install'", window.BannerText.Text, StringComparison.Ordinal);
                Assert.Equal(Visibility.Collapsed, window.ElevateButton.Visibility);
                Assert.Equal("Windows service WPShield: not installed", window.ServiceText.Text);
                Assert.False(File.Exists(path));
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task AnOperatorSortAndSelectionSurviveARefresh() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = Recording(DateTimeOffset.UtcNow);
            var window = new ProtectionWindow(false, new EvidenceProtectionStore(path, () => true), () => new ServiceReading(ServiceState.Running));
            try
            {
                window.Show();
                await window.LoadAsync();
                window.SelectTab(DecisionTab.Month);
                Assert.Equal(4, window.Rows.Items.Count);

                await GridRefreshTests.ClickHeader(window.Rows, 0);
                window.Rows.SelectedItem = window.Rows.Items.Cast<ProtectionRow>().Single(r => r.Target == "203.0.113.9");
                await window.LoadAsync();

                // Targets sort as numbers: IPv4 before IPv6, a network where its first address would be.
                Assert.Equal(["198.51.100.7", "203.0.113.0/24", "203.0.113.9", "2001:db8:5::17"],
                    window.Rows.Items.Cast<ProtectionRow>().Select(r => r.Target));
                Assert.Equal(System.ComponentModel.ListSortDirection.Ascending, window.Rows.Columns[0].SortDirection);
                Assert.Equal("203.0.113.9", Assert.IsType<ProtectionRow>(window.Rows.SelectedItem).Target);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task ARecordingStoreShowsItsDecisionsInTabsWithSearch() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = Recording(DateTimeOffset.UtcNow);
            var window = new ProtectionWindow(false, new EvidenceProtectionStore(path, () => true), () => new ServiceReading(ServiceState.Running));
            try
            {
                window.Show();
                await window.LoadAsync();
                Assert.Equal(Visibility.Collapsed, window.Banner.Visibility);
                Assert.Equal("Recording", window.CollectorText.Text);
                Assert.Equal("Windows service WPShield: running", window.ServiceText.Text);
                Assert.Equal("Monitor - nothing is blocked", window.ModeText.Text);
                Assert.Equal("recording", window.LogonStatus.Text);
                Assert.Equal(("1", "1", "1", "0"), (window.WouldBlockValue.Text, window.ProtectedValue.Text, window.RefusedValue.Text, window.ReportValue.Text));
                Assert.Equal("In force (2)", window.TabInForce.Content);
                Assert.Equal("Last 24 h (3)", window.TabDay.Content);
                Assert.Equal("30 days (4)", window.TabMonth.Content);

                var rows = window.Rows.Items.Cast<ProtectionRow>().ToArray();
                // Newest first, as the store answers.
                Assert.Equal(["198.51.100.7", "203.0.113.0/24"], rows.Select(r => r.Target));
                Assert.Equal("Scanner network", rows[1].Label);
                Assert.Contains("Monitor: nothing is blocked", window.Footer.Text, StringComparison.Ordinal);

                window.Search.Text = "scanner";
                Assert.Equal("203.0.113.0/24", Assert.Single(window.Rows.Items.Cast<ProtectionRow>()).Target);
                window.Search.Text = "";

                window.SelectTab(DecisionTab.Month);
                Assert.Equal(DecisionTab.Month, window.Tab);
                Assert.Equal(4, window.Rows.Items.Count);
                window.Search.Text = "HOST-AUTH-002";
                Assert.Equal(2, window.Rows.Items.Count);
                Assert.Contains("of 4 records shown", window.Footer.Text, StringComparison.Ordinal);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task WithTheServiceStoppedARecordingStoreIsSaidToBeTheForegroundCollector() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var path = Recording(DateTimeOffset.UtcNow);
            var window = new ProtectionWindow(false, new EvidenceProtectionStore(path, () => true), () => new ServiceReading(ServiceState.Stopped));
            try
            {
                window.Show();
                await window.LoadAsync();
                Assert.Equal("Recording", window.CollectorText.Text);
                Assert.Equal("Windows service WPShield: stopped", window.ServiceText.Text);
                Assert.Contains("'wpshield evidence collect' running in the foreground", window.ServiceDetail.Text, StringComparison.Ordinal);
            }
            finally
            {
                window.Close();
                Remove(path);
            }
        });

    [Fact]
    public Task PlannedSensorsAndBlockAreDrawnDisabledAndSayWhy() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var window = new ProtectionWindow(false, null, () => throw new InvalidOperationException("synthetic"));
            try
            {
                window.Show();
                await window.LoadAsync();
                foreach (var chip in new FrameworkElement[] { window.SqlChip, window.GatewayChip, window.BlockChip })
                {
                    Assert.False(chip.IsEnabled);
                    Assert.True(ToolTipService.GetShowOnDisabled(chip));
                }
                Assert.Equal("planned", window.SqlStatus.Text);
                Assert.Contains("not recording", (string)window.GatewayChip.ToolTip, StringComparison.Ordinal);
                Assert.Contains("ADR 0006", (string)window.BlockChip.ToolTip, StringComparison.Ordinal);
                // A service controller that throws is "could not be read", and the store's state is still shown.
                Assert.Equal("Windows service WPShield: could not be read", window.ServiceText.Text);
                Assert.Equal(TimeSpan.FromSeconds(15), ProtectionWindow.RefreshInterval);
            }
            finally { window.Close(); }
        });
}

using System.IO;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;
using Xunit;

namespace WPShield.Desktop.Tests;

public sealed class CommandCenterTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 26, 12, 30, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Hour = Now.AddMinutes(-30);

    [Theory]
    [InlineData(false, "No snapshot yet", "Not configured", "Not measured yet")]
    [InlineData(true, "Aún sin instantánea", "Sin configurar", "Aún sin medición")]
    public Task EmptyStoreShowsGreyAndLocalizesUnavailablePanels(bool spanish, string missing, string analyst, string outbound) =>
        Verify(_ => { }, (view, _) =>
        {
            Assert.Equal(8, view.Tiles.Items.Count);
            Assert.All(view.Tiles.Items.Cast<CommandTile>(), tile => Assert.Equal(CommandTone.Grey, tile.Tone));
            Assert.StartsWith(missing, Tile(view, CommandSection.Health).Status, StringComparison.Ordinal);
            Assert.Equal(analyst, Tile(view, CommandSection.Analyst).Status);
            Assert.Equal(outbound, Tile(view, CommandSection.Outbound).Status);
            Assert.Equal(spanish ? "Sin datos" : "No data", Metric(Tile(view, CommandSection.Web), WebObservationIds.PhpOutsideEntryPoints).Value);
        }, spanish);

    [Fact]
    public Task StaleSnapshotKeepsTheReadTimeAndAge() =>
        Verify(store => new HostFactsWriter(store).Write(HostFactReading.Of(HostFacts.Health, null,
            Now.AddMinutes(-6), Health())), (view, _) =>
        {
            var tile = Tile(view, CommandSection.Health);
            Assert.Equal(CommandTone.Grey, tile.Tone);
            Assert.Contains("STALE · 6 min", tile.Status, StringComparison.Ordinal);
            Assert.Contains("12:24 UTC", tile.Status, StringComparison.Ordinal);
        });

    [Fact]
    public Task AnUnreadableFactShowsUnknownWithReasonAndRemedy() =>
        Verify(store => new HostFactsWriter(store).Write(HostFactReading.Failed(HostFacts.Posture, null,
            Now.AddMinutes(-1), HostFactStatus.NeedsElevation, "access-denied", "Run the collector elevated.")), (view, _) =>
        {
            var tile = Tile(view, CommandSection.Posture);
            Assert.StartsWith("Unknown", tile.Status, StringComparison.Ordinal);
            Assert.Equal(CommandTone.Grey, tile.Tone);
            Assert.Contains("access-denied", tile.Status, StringComparison.Ordinal);
            Assert.Contains("Run the collector elevated.", tile.Status, StringComparison.Ordinal);
            Assert.Equal("Unknown", Metric(tile, "Pools as administrator").Value);
            Assert.Null(tile.Progress);
        });

    [Theory]
    [InlineData(1, false, "Red", "1")]
    [InlineData(0, false, "Grey", "No data")]
    [InlineData(0, true, "Green", "0")]
    public Task WebObservationGreenRequiresEverySiteForTheWholeRange(long observations, bool fullCoverage, string tone, string value) =>
        Verify(store => SeedWeb(store, observations, fullCoverage), (view, _) =>
        {
            var tile = Tile(view, CommandSection.Web);
            var observation = Metric(tile, WebObservationIds.PhpOutsideEntryPoints);
            Assert.Equal(Enum.Parse<CommandTone>(tone), observation.Tone);
            Assert.Equal(value, observation.Value);
            Assert.Equal("2 / 2", Metric(tile, "Sites read").Value);
            Assert.Equal(fullCoverage ? "Full coverage" : "Partial coverage", tile.Status);
            var button = TileButton(view, tile);
            Assert.Equal(tone switch
            {
                "Red" => Color.FromRgb(179, 58, 58),
                "Green" => Color.FromRgb(86, 167, 142),
                _ => Color.FromRgb(207, 220, 226)
            }, Assert.IsType<SolidColorBrush>(button.BorderBrush).Color);
        });

    [Fact]
    public Task HealthShowsBugcheckCodesPatchFactsAndTrends() =>
        Verify(store =>
        {
            var facts = new HostFactsWriter(store);
            facts.Write(HostFactReading.Of(HostFacts.Health, null, Now, Health()));
            facts.RecordHealth(Health(), Now.AddHours(-2));
            facts.RecordHealth(Health(), Now.AddHours(-1));
            facts.RecordRestarts(
                [new("fixture-1", Now.AddDays(-3), [41, 1001], 0x133),
                 new("fixture-2", Now.AddDays(-5), [41, 1001], 0x133)]);
        }, (view, _) =>
        {
            var tile = Tile(view, CommandSection.Health);
            Assert.Equal("2 × 0x133 DPC_WATCHDOG_VIOLATION", Metric(tile, "Unexpected restarts · 30 d").Value);
            Assert.Equal("20348.1234", Metric(tile, "Windows build").Value);
            Assert.Equal("10.0.20348.1234", Metric(tile, "ntoskrnl.exe").Value);
            Assert.Contains("7 d ago", Metric(tile, "Last cumulative update").Value, StringComparison.Ordinal);
            Assert.All(new[] { "CPU", "Memory used", "Disk free" }, label => Assert.NotNull(Metric(tile, label).Trend));
        });

    [Fact]
    public Task PostureProgressMeasuresThePoolsThatNoLongerRunAsAdministrators() =>
        Verify(store =>
        {
            var facts = new HostFactsWriter(store);
            facts.Write(HostFactReading.Of(HostFacts.Posture, null, Now.AddDays(-1),
                new HostPosture("collector", true, [], 10, 9, true, 3, 2)));
            facts.Write(HostFactReading.Of(HostFacts.Posture, null, Now.AddMinutes(-5),
                new HostPosture("collector", true, [], 10, 6, false, 2, 1)));
        }, (view, _) =>
        {
            var tile = Tile(view, CommandSection.Posture);
            Assert.Equal("6 of 10", Metric(tile, "Pools as administrator").Value);
            Assert.Equal("No", Metric(tile, "Server-wide PHP").Value);
            Assert.Equal("2", Metric(tile, "Writable site folders").Value);
            Assert.NotNull(Metric(tile, "Pools as administrator").Trend);
            var progress = Assert.Single(Visuals<ProgressBar>(TileButton(view, tile)));
            Assert.Equal(0.4, progress.Value, 3);
        });

    [Fact]
    public Task ExposureRedRequiresAnOpenSensitivePortAndCleansNamesForDisplayAndTooltip() =>
        Verify(store => new HostFactsWriter(store).Write(HostFactReading.Of(HostFacts.Ports, null, Now,
            new HostPorts(
                [new("TCP", 445, "any", null, "invented\u001b[31m\u202e service.exe", null, ExposureVerdicts.OpenToAny, true),
                 new("TCP", 1433, "specific", "192.0.2.8", "synthetic-db.exe", null, ExposureVerdicts.Restricted, false),
                 new("TCP", 443, "any", null, "synthetic-web.exe", null, ExposureVerdicts.OpenToAny, false)], true))), (view, _) =>
        {
            var tile = Tile(view, CommandSection.Exposure);
            Assert.Contains(ExposureVerdicts.Source, tile.Status, StringComparison.Ordinal);
            var open = Assert.Single(tile.Metrics, m => m.Label.StartsWith("TCP 445", StringComparison.Ordinal));
            Assert.Equal(CommandTone.Red, open.Tone);
            Assert.Equal("Open to any address", open.Value);
            Assert.Contains("Restrict the firewall rule", open.Help, StringComparison.Ordinal);
            Assert.DoesNotContain(open.Label, char.IsControl);
            Assert.DoesNotContain('\u202e', open.Help);
            Assert.Contains("service.exe", open.Help, StringComparison.Ordinal);
            var restricted = Assert.Single(tile.Metrics, m => m.Label.StartsWith("TCP 1433", StringComparison.Ordinal));
            Assert.Equal(CommandTone.Neutral, restricted.Tone);
            Assert.Equal("Restricted", restricted.Value);
        });

    [Fact]
    public Task AttacksShowsRecordedCountsNetworksAndTheFullNameIndicator() =>
        Verify(store =>
        {
            var writer = new EvidenceWriter(store);
            writer.BeginCoverage(EvidenceWriter.RawSource, Now.AddDays(-7), Now);
            writer.Append([new AuthFailure(Now.AddMinutes(-2), AttemptPairing.SecurityChannel, IPAddress.Parse("203.0.113.7"),
                null, "fixture-account", "bad-password", 3, 1)]);
            writer.RecordEngineStart(Now.AddHours(-1));
            writer.RecordDecision(new(Now.AddMinutes(-5), DecisionActions.WouldBlock, "203.0.113.7", DecisionRules.RepeatedFailures,
                DecisionActions.MonitorMode, "synthetic test", AttemptPairing.SecurityChannel, Now.AddMinutes(10)));
            new HostFactsWriter(store).Write(HostFactReading.Of(HostFacts.Inventory, HostFacts.Accounts, Now, new HostAccounts([], true, 2)));
        }, (view, _) =>
        {
            var attacks = Tile(view, CommandSection.Attacks);
            Assert.Equal("1", Metric(attacks, "Failed attempts").Value);
            Assert.Equal("1", Metric(attacks, "Would block · Monitor").Value);
            Assert.Equal("203.0.113.0/24", Metric(attacks, "Most active network").Value);
            Assert.Equal("YES (2)", Metric(attacks, "Real account full names tried").Value);
        });

    [Fact]
    public Task HomeTilesAreClickableAndRefreshPausesWhenMinimized() =>
        Verify(_ => { }, (view, owner) =>
        {
            CommandSection? selected = null;
            view.OpenTile = tile => selected = tile.Section;
            TileButton(view, Tile(view, CommandSection.Web)).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Assert.Equal(CommandSection.Web, selected);
            Assert.True(view.Live);
            Assert.Equal(TimeSpan.FromSeconds(30), CommandCenterView.RefreshInterval);
            owner.WindowState = WindowState.Minimized;
            Assert.False(view.Live);
        });

    [Fact]
    public Task TheMainWindowStartsOnTheFirstNavigationEntry() =>
        DesktopDispatcher.RunAsync(() =>
        {
            var window = new ListenerWindow();
            try
            {
                var nav = Assert.IsType<StackPanel>(window.HomeButton.Parent);
                Assert.Same(window.HomeButton, nav.Children[0]);
                Assert.Equal(Visibility.Visible, window.Home.Visibility);
                Assert.Equal(Visibility.Collapsed, window.Listeners.Visibility);
            }
            finally { window.Close(); }
            return Task.CompletedTask;
        });

    [Fact]
    public Task ConfiguredAnalystMarksReportUsageUnavailable() =>
        Verify(store =>
        {
            var settings = new EvidenceSettings(store);
            settings.Set(AnalystSettings.Enabled, "true", "test", "synthetic configuration");
            settings.Set(AnalystSettings.Provider, "\"anthropic\"", "test", "synthetic configuration");
        }, (view, _) =>
        {
            var tile = Tile(view, CommandSection.Analyst);
            Assert.Equal(CommandTone.Grey, tile.Tone);
            Assert.Contains("not available in this view yet", tile.Status, StringComparison.Ordinal);
        });

    private static HostHealth Health() => new(Now.AddDays(-2), 172_800, 42, 1000, 420, [new("X:", 1000, 600, true)], 200,
        new HostPatchLevel("20348", 1234, "21H2", "10.0.20348.1234", true, "Cumulative Update (synthetic)", Now.AddDays(-7), 0));

    private static void SeedWeb(EvidenceStore store, long observations, bool fullCoverage)
    {
        var writer = new WebEvidenceWriter(store);
        writer.RecordSites([new(4, "blog.example", "collected", null, null, false, Now),
            new(7, "shop.example", "collected", null, null, false, Now)], Now);
        var coverage = new EvidenceWriter(store);
        coverage.BeginCoverage(WebEvidenceWriter.SensorSource, Hour.AddHours(-1), Now);
        coverage.BeginCoverage(WebEvidenceWriter.SiteSource(4), Hour.AddHours(-1), Now);
        coverage.BeginCoverage(WebEvidenceWriter.SiteSource(7), fullCoverage ? Hour.AddHours(-1) : Hour, Now);
        writer.Write(new WebBatch([], [new(4, Hour, 120, 0, 0, 0, observations, 0, 0, 200)], [], []));
    }

    private static CommandTile Tile(CommandCenterView view, CommandSection section) =>
        Assert.Single(view.Tiles.Items.Cast<CommandTile>(), tile => tile.Section == section);

    private static CommandMetric Metric(CommandTile tile, string label) => Assert.Single(tile.Metrics, metric => metric.Label == label);

    private static Button TileButton(CommandCenterView view, CommandTile tile)
    {
        view.UpdateLayout();
        var container = Assert.IsType<ContentPresenter>(view.Tiles.ItemContainerGenerator.ContainerFromItem(tile));
        return Assert.Single(Visuals<Button>(container));
    }

    private static IEnumerable<T> Visuals<T>(DependencyObject root) where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is T result) yield return result;
            foreach (var descendant in Visuals<T>(child)) yield return descendant;
        }
    }

    private static Task Verify(Action<EvidenceStore> seed, Action<CommandCenterView, Window> verify, bool spanish = false) =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var directory = Directory.CreateTempSubdirectory("wpshield-command-center-test-");
            var path = Path.Combine(directory.FullName, EvidenceStore.FileName);
            using (var store = EvidenceStore.OpenForWriting(path)) seed(store);
            var view = new CommandCenterView(spanish, new CommandCenterStore(path, () => true).Read, () => Now);
            var owner = new Window { Width = 1180, Height = 850, Content = view };
            try
            {
                owner.Show();
                await view.LoadAsync();
                verify(view, owner);
            }
            finally
            {
                owner.Close();
                directory.Delete(recursive: true);
            }
        });
}

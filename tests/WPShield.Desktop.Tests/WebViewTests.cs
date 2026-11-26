using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Data.Sqlite;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;
using WPShield.SecurityMonitor;
using Xunit;

namespace WPShield.Desktop.Tests;

public sealed class WebViewTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 25, 12, 30, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Hour = Now.AddMinutes(-30);
    private const string Address = "203.0.113.7";
    private const string OtherAddress = "198.51.100.9";

    [Theory]
    [InlineData(false, "No data", "access denied")]
    [InlineData(true, "Sin datos", "acceso denegado")]
    public Task CoverageNamesAnUnreadableSiteAndMarksUncoveredBuckets(bool spanish, string noData, string denied) =>
        Verify(Seed, async (window, _) =>
        {
            Assert.Contains("shop.example", window.WebCoverage.Text, StringComparison.Ordinal);
            Assert.Contains(denied, window.WebCoverage.Text, StringComparison.Ordinal);
            Assert.Contains("Grant log read access by hand.", window.WebCoverage.Text, StringComparison.Ordinal);
            Assert.Contains(noData, window.WebCoverage.Text, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("1 / 2", Card(window, spanish ? "Sitios leídos" : "Sites read").Value);
            Assert.Equal("24 h", window.RangeDay.Content);
            Assert.Equal(98, window.WebPlot.Children.Count);
            var gap = Assert.IsType<Grid>(window.WebPlot.Children[0]);
            Assert.Contains(noData, AutomationName(gap), StringComparison.OrdinalIgnoreCase);
            var covered = Assert.IsType<Grid>(window.WebPlot.Children[^2]);
            Assert.DoesNotContain(noData, AutomationName(covered), StringComparison.OrdinalIgnoreCase);

            window.RangeHour.IsChecked = true;
            await window.LoadWebAsync();
            Assert.Equal(60, window.WebPlot.Children.Count);
            Assert.Equal("12", Card(window, spanish ? "Peticiones" : "Requests").Value);

            window.WebSite.SelectedItem = Assert.Single(window.WebSite.Items.OfType<AttacksWindow.WebSiteChoice>(), site => site.Id == 7);
            await window.LoadWebAsync();
            Assert.Equal("—", Card(window, spanish ? "Peticiones" : "Requests").Value);
            Assert.Equal("0 / 1", Card(window, spanish ? "Sitios leídos" : "Sites read").Value);
            Assert.All(window.WebPlot.Children.Cast<Grid>(), cell => Assert.Contains(noData, AutomationName(cell), StringComparison.OrdinalIgnoreCase));
        }, spanish);

    [Fact]
    public Task PhpObservationUsesTheRedCardAndTheDecisionColumnIsEmpty() =>
        Verify(Seed, (window, _) =>
        {
            var card = Card(window, WebObservationIds.PhpOutsideEntryPoints);
            Assert.True(card.Alert);
            Assert.Equal("1", card.Value);
            Assert.Equal("6", Card(window, "Observations").Value);
            window.UpdateLayout();
            var presenter = Assert.IsType<ContentPresenter>(window.WebCards.ItemContainerGenerator.ContainerFromItem(card));
            presenter.ApplyTemplate();
            var border = Assert.IsType<Border>(VisualTreeHelper.GetChild(presenter, 0));
            Assert.Equal(Color.FromRgb(179, 58, 58), Assert.IsType<SolidColorBrush>(border.BorderBrush).Color);
            var decision = Assert.IsType<DataGridTextColumn>(window.WebRows.Columns[^2]);
            Assert.Null(decision.Binding);
            Assert.Contains("does not feed decisions", (string)Assert.IsType<TextBlock>(decision.Header).ToolTip, StringComparison.Ordinal);
            Assert.Contains("nothing is decided or blocked", window.WebFooter.Text, StringComparison.Ordinal);
            return Task.CompletedTask;
        });

    [Theory]
    [InlineData(false, "Last (UTC)")]
    [InlineData(true, "Último (UTC)")]
    public Task TheAddressTableFitsAtTheDefaultWidthAndShowsFullHeaderTooltips(bool spanish, string last) =>
        Verify(Seed, (window, _) =>
        {
            // The window is designed 1280 x 820, but Windows clamps a shown window to the desktop, and a CI
            // desktop can be narrower (1044 on the hosted runner). Lay the content out at the design size
            // explicitly, so the check measures the table rather than the machine that runs the test.
            window.UpdateLayout();
            var root = Assert.IsAssignableFrom<FrameworkElement>(window.Content);
            var design = new Size(DesignWidth - (window.ActualWidth - root.ActualWidth), DesignHeight - (window.ActualHeight - root.ActualHeight));
            for (var pass = 0; pass < 2; pass++)
            {
                root.Measure(design);
                root.Arrange(new Rect(design));
            }
            var scroll = Assert.IsType<ScrollViewer>(window.WebRows.Template.FindName("DG_ScrollViewer", window.WebRows));
            Assert.True(scroll.ViewportWidth > 0);
            Assert.Equal(Visibility.Collapsed, scroll.ComputedHorizontalScrollBarVisibility);
            Assert.Equal("XML-RPC POST", Assert.IsType<TextBlock>(window.WebRows.Columns[7].Header).ToolTip);
            Assert.Equal(last, Assert.IsType<TextBlock>(window.WebRows.Columns[^1].Header).ToolTip);
            return Task.CompletedTask;
        }, spanish);

    [Fact]
    public Task SiteFilterChangesTotalsSourcesAndCoverage() =>
        Verify(store => Seed(store, otherSiteRead: true), async (window, _) =>
        {
            Assert.Equal("21", Card(window, "Requests").Value);
            Assert.Equal(2, window.WebRows.Items.Count);
            window.WebSite.SelectedItem = Assert.Single(window.WebSite.Items.OfType<AttacksWindow.WebSiteChoice>(), site => site.Id == 7);
            await window.LoadWebAsync();

            Assert.Equal("9", Card(window, "Requests").Value);
            Assert.Equal("1 / 1", Card(window, "Sites read").Value);
            Assert.False(Card(window, WebObservationIds.PhpOutsideEntryPoints).Alert);
            var row = Assert.IsType<AttacksWindow.WebRow>(Assert.Single(window.WebRows.Items));
            Assert.Equal(OtherAddress, row.Source.Address);
            window.WebRows.SelectedItem = row;
            await window.LoadWebDetailAsync();
            Assert.Empty(window.WebDetailFindings.Items);

            window.Views.SelectedItem = window.AttackTab;
            await window.LoadAsync();
            Assert.True(window.RangeDay.IsChecked);
            Assert.Equal("Attacks", window.Heading.Text);
            window.OpenWebView();
            await window.LoadWebAsync();
            Assert.Equal("9", Card(window, "Requests").Value);
        });

    [Fact]
    public Task DetailDisplaysBoundedUntrustedPathsWithSiteStatusAndRule() =>
        Verify(store => Seed(store, path: "/example\u001b[31m\n\u202e/" + new string('x', 800)), async (window, _) =>
        {
            window.WebRows.SelectedIndex = 0;
            await window.LoadWebDetailAsync();

            var line = Assert.IsType<AttacksWindow.WebFindingLine>(Assert.Single(window.WebDetailFindings.Items));
            Assert.Contains("2026-11-25 12:15 UTC · blog.example · GET · 200", line.Context, StringComparison.Ordinal);
            Assert.Contains(WebObservationIds.PhpOutsideEntryPoints, line.Ids, StringComparison.Ordinal);
            Assert.DoesNotContain(line.Path, char.IsControl);
            Assert.DoesNotContain('\u202e', line.Path);
            Assert.EndsWith("…", line.Path, StringComparison.Ordinal);
            Assert.InRange(line.Path.Length, 1, 201);
            Assert.Contains(window.WebDetailRules.Items.Cast<string>(), text => text.Contains(WebObservationIds.PhpOutsideEntryPoints, StringComparison.Ordinal));
        });

    [Fact]
    public Task AnEmptyStoreKeepsTheCardsUnknown() =>
        Verify(_ => { }, (window, _) =>
        {
            Assert.All(window.WebCards.Items.Cast<AttacksWindow.WebCard>(), card => Assert.Equal("—", card.Value));
            Assert.Contains("No data", window.WebCoverage.Text, StringComparison.Ordinal);
            Assert.Contains("no site inventory", window.WebCoverage.Text, StringComparison.Ordinal);
            Assert.Empty(window.WebRows.Items);
            return Task.CompletedTask;
        });

    [Fact]
    public Task TheViewWaitsForSchemaOneMigrationThenReadsTheNewEvidenceAndOldLabels() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            using var fixture = new StoreFixture();
            using (var old = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = fixture.Path, Pooling = false }.ToString()))
            {
                old.Open();
                using var command = old.CreateCommand();
                command.CommandText = """
                    CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL CHECK (json_valid(value)), version INTEGER NOT NULL,
                        updated_ts INTEGER NOT NULL, updated_by TEXT NOT NULL);
                    INSERT INTO settings VALUES ('labels.addresses', '{"203.0.113.7":"Synthetic label"}', 1, 1764000000000, 'test');
                    PRAGMA user_version = 1;
                    """;
                command.ExecuteNonQuery();
            }
            var window = Open(fixture.Path, spanish: false);
            try
            {
                await window.LoadWebAsync();
                Assert.Contains("migrate", window.WebCoverage.Text, StringComparison.Ordinal);
                Assert.Equal("—", Card(window, "Requests").Value);
                Assert.Throws<InvalidDataException>(() => EvidenceStore.OpenReadOnly(fixture.Path));
                using (var migrated = EvidenceStore.OpenForWriting(fixture.Path)) Seed(migrated);

                await window.LoadWebAsync();
                Assert.Equal("12", Card(window, "Requests").Value);
                var row = Assert.IsType<AttacksWindow.WebRow>(Assert.Single(window.WebRows.Items));
                Assert.Equal("Synthetic label", row.Label);
            }
            finally { window.Close(); }
        });

    [Fact]
    public Task AddressActionsReuseTheAttacksEditorAndWriteAuditedSettings() =>
        Verify(Seed, async (window, path) =>
        {
            window.WebRows.SelectedIndex = 0;
            await window.LoadWebDetailAsync();
            Assert.True(window.LabelButton.IsEnabled);
            await window.OpenEditorAsync(AddressAction.Label);
            window.LabelBox.Text = "Synthetic partner";
            window.ActionReason.Text = "testing a label";
            await window.SaveActionAsync();

            Assert.Equal("Synthetic partner", window.DetailLabel.Text);
            await window.OpenEditorAsync(AddressAction.Allow);
            Assert.Contains("Only this exact address", window.ActionText.Text, StringComparison.Ordinal);
            window.ActionReason.Text = "testing an exact address";
            await window.SaveActionAsync();
            await window.LoadWebDetailAsync();

            using var store = EvidenceStore.OpenReadOnly(path);
            var settings = new EvidenceSettings(store);
            Assert.Equal("[\"203.0.113.7\"]", settings.Get(DefenseSettings.Allow).ToJsonString());
            Assert.Equal("testing an exact address", Assert.Single(settings.History(DefenseSettings.Allow, 5)).Reason);
            Assert.False(window.AllowButton.IsEnabled);
        });

    private static string AutomationName(DependencyObject item) => System.Windows.Automation.AutomationProperties.GetName(item);

    private const double DesignWidth = 1280;
    private const double DesignHeight = 820;

    private static AttacksWindow.WebCard Card(AttacksWindow window, string title) =>
        Assert.Single(window.WebCards.Items.Cast<AttacksWindow.WebCard>(), card => card.Title == title);

    private static Task Verify(Action<EvidenceStore> seed, Func<AttacksWindow, string, Task> verify, bool spanish = false) =>
        DesktopDispatcher.RunAsync(async () =>
        {
            using var fixture = new StoreFixture();
            using (var store = EvidenceStore.OpenForWriting(fixture.Path)) seed(store);
            var window = Open(fixture.Path, spanish);
            try
            {
                await window.LoadWebAsync();
                await verify(window, fixture.Path);
            }
            finally { window.Close(); }
        });

    private static AttacksWindow Open(string path, bool spanish)
    {
        var window = new AttacksWindow(spanish, end => new AuthFailureSnapshot(end.AddDays(-1), end, [],
            [new(AuthFailureFeed.SecurityChannel, "read", null, null, end.AddDays(-3), 0)]),
            (_, _) => new NoWatch(), null, new EvidenceSettingsStore(path, () => true, () => "test"),
            new EvidenceWebStore(path, () => true, () => Now));
        window.Live.IsChecked = false;
        window.Show();
        window.OpenWebView();
        return window;
    }

    private static void Seed(EvidenceStore store) => Seed(store, otherSiteRead: false);

    private static void Seed(EvidenceStore store, bool otherSiteRead = false, string path = "/sample.php")
    {
        var coverage = new EvidenceWriter(store);
        coverage.BeginCoverage(WebEvidenceWriter.SensorSource, Now.AddHours(-1), Now, "collected");
        coverage.BeginCoverage(WebEvidenceWriter.SiteSource(4), Now.AddHours(-1), Now, "collected");
        coverage.BeginCoverage(WebEvidenceWriter.SiteSource(7), Now.AddHours(-1), Now,
            otherSiteRead ? "collected" : "unavailable", otherSiteRead ? null : "access-denied");
        var writer = new WebEvidenceWriter(store);
        writer.RecordSites(
            [new(4, "blog.example", "collected", null, null, false, Now),
             new(7, "shop.example", otherSiteRead ? "collected" : "unavailable",
                 otherSiteRead ? null : "access-denied", otherSiteRead ? null : "Grant log read access by hand.", false, Now)], Now);
        var findingTime = Now.AddMinutes(-15);
        writer.Write(new WebBatch(
            [new(findingTime, 4, Address, "GET", path, 200, [new("WP-PATH-001", 100), new(WebObservationIds.PhpOutsideEntryPoints, 0)],
                "", true, false, null)],
            [new(4, Hour, 12, 2, 0, 1, 1, 3, 2, 100)],
            [new(4, Hour, Address, 12, 2, 1, 1, 3, 2, findingTime, findingTime, null)], []));
        if (!otherSiteRead) return;
        writer.Write(new WebBatch([], [new(7, Hour, 9, 3, 0, 0, 0, 1, 0, 100)],
            [new(7, Hour, OtherAddress, 9, 3, 0, 0, 1, 0, findingTime, findingTime, null)], []));
    }

    private sealed class NoWatch : IDisposable
    {
        public void Dispose() { }
    }

    private sealed class StoreFixture : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("wpshield-web-view-");

        internal string Path => System.IO.Path.Combine(directory.FullName, EvidenceStore.FileName);

        public void Dispose() => directory.Delete(recursive: true);
    }
}

using System.ComponentModel;
using System.Text;
using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using Xunit;

namespace WPShield.Desktop.Tests;

/// <summary>
/// The shared grid behaviour: a refresh keeps the operator's sort, arrows, selection and scroll position, and
/// "Export CSV…" writes exactly what the grid shows. Synthetic rows only.
/// </summary>
public sealed class GridRefreshTests
{
    internal sealed record Row(string Name, long Count, string Note);

    private static Row[] Rows(params (string Name, long Count)[] rows) => [.. rows.Select(r => new Row(r.Name, r.Count, "note " + r.Name))];

    /// <summary>Clicks a column header the way an operator does: through its automation peer, so the grid's own sort runs.</summary>
    internal static async Task ClickHeader(DataGrid grid, int index)
    {
        grid.UpdateLayout();
        // The grid's automation tree: the headers presenter lists one item per column, and invoking one is a click.
        var gridPeer = Assert.IsAssignableFrom<AutomationPeer>(UIElementAutomationPeer.CreatePeerForElement(grid));
        var headers = gridPeer.GetChildren().OfType<DataGridColumnHeadersPresenterAutomationPeer>().Single();
        var column = headers.GetChildren()[index];
        var invoke = Assert.IsAssignableFrom<IInvokeProvider>(column.GetPattern(PatternInterface.Invoke));
        invoke.Invoke();
        await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
    }

    internal static IEnumerable<T> Descendants<T>(DependencyObject root) where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is T match) yield return match;
            foreach (var deeper in Descendants<T>(child)) yield return deeper;
        }
    }

    private static (Window Window, DataGrid Grid) Host()
    {
        var grid = new DataGrid { AutoGenerateColumns = false, IsReadOnly = true, Height = 300, EnableRowVirtualization = true };
        grid.Columns.Add(new DataGridTextColumn { Header = new TextBlock { Text = "Nom.", ToolTip = "Nombre completo" }, Binding = new Binding(nameof(Row.Name)) });
        grid.Columns.Add(new DataGridTextColumn { Header = "Cuenta", Binding = new Binding(nameof(Row.Count)) });
        grid.Columns.Add(new DataGridTextColumn { Header = "Nota", Binding = new Binding(nameof(Row.Note)) });
        var window = new Window { Width = 600, Height = 400, Content = grid, ShowActivated = false };
        window.Show();
        return (window, grid);
    }

    private static string[] Names(DataGrid grid) => [.. grid.Items.Cast<Row>().Select(r => r.Name)];

    [Fact]
    public Task AnOperatorSortSurvivesARefreshAndAnEmptyStateInBetween() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var (window, grid) = Host();
            try
            {
                GridRefresh.Replace(grid, Rows(("b", 2), ("c", 3), ("a", 1)));
                await ClickHeader(grid, 0);
                Assert.Equal(["a", "b", "c"], Names(grid));
                Assert.Equal(ListSortDirection.Ascending, grid.Columns[0].SortDirection);

                GridRefresh.Replace(grid, Rows(("c", 30), ("a", 10), ("d", 40), ("b", 20)));
                Assert.Equal(["a", "b", "c", "d"], Names(grid));
                Assert.Equal(ListSortDirection.Ascending, grid.Columns[0].SortDirection);

                // "Not read" first, then rows again: the sort comes back with them.
                GridRefresh.Replace(grid, null);
                GridRefresh.Replace(grid, Rows(("z", 1), ("y", 2)));
                Assert.Equal(["y", "z"], Names(grid));
                Assert.Equal(ListSortDirection.Ascending, grid.Columns[0].SortDirection);

                // A second click is the grid's own toggle, and that survives too.
                await ClickHeader(grid, 0);
                GridRefresh.Replace(grid, Rows(("y", 2), ("z", 1), ("x", 3)));
                Assert.Equal(["z", "y", "x"], Names(grid));
                Assert.Equal(ListSortDirection.Descending, grid.Columns[0].SortDirection);
            }
            finally { window.Close(); }
        });

    [Fact]
    public Task TheDefaultSortShowsItsArrowUntilTheOperatorChoosesAnother() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var (window, grid) = Host();
            try
            {
                GridRefresh.SetDefaultSort(grid, new SortDescription(nameof(Row.Count), ListSortDirection.Descending),
                    new SortDescription(nameof(Row.Name), ListSortDirection.Ascending));
                GridRefresh.Replace(grid, Rows(("b", 5), ("a", 5), ("c", 9)));
                Assert.Equal(["c", "a", "b"], Names(grid));
                Assert.Equal(ListSortDirection.Descending, grid.Columns[1].SortDirection);
                Assert.Null(grid.Columns[0].SortDirection);

                await ClickHeader(grid, 2);
                GridRefresh.Replace(grid, Rows(("b", 5), ("a", 5), ("c", 9)));
                Assert.Equal(["a", "b", "c"], Names(grid));
                Assert.Null(grid.Columns[1].SortDirection);
                Assert.Equal(ListSortDirection.Ascending, grid.Columns[2].SortDirection);
            }
            finally { window.Close(); }
        });

    [Fact]
    public Task TheSelectedRowAndTheScrollPositionSurviveARefresh() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var (window, grid) = Host();
            try
            {
                var many = Enumerable.Range(0, 200).Select(i => ($"row-{i:D3}", (long)i)).ToArray();
                GridRefresh.Replace(grid, Rows(many), row => ((Row)row).Name);
                grid.UpdateLayout();
                grid.SelectedItem = grid.Items.Cast<Row>().Single(r => r.Name == "row-120");
                var scroll = Assert.IsType<ScrollViewer>(GridRefresh.ScrollViewerOf(grid));
                scroll.ScrollToVerticalOffset(100);
                grid.UpdateLayout();
                await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
                var offset = scroll.VerticalOffset;
                Assert.True(offset > 0);

                // New objects with the same keys and changed counts, as a Live refresh brings.
                GridRefresh.Replace(grid, Rows([.. many.Select(r => (r.Item1, r.Item2 + 1))]), row => ((Row)row).Name);
                grid.UpdateLayout();
                await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);

                Assert.Equal("row-120", Assert.IsType<Row>(grid.SelectedItem).Name);
                Assert.Equal(121, Assert.IsType<Row>(grid.SelectedItem).Count);
                Assert.Equal(offset, scroll.VerticalOffset);
            }
            finally { window.Close(); }
        });

    [Fact]
    public Task TheTableIsTheVisibleColumnsInOrderWithFullHeadersAndTheRowsInTheirSortedOrder() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var (window, grid) = Host();
            try
            {
                GridRefresh.Replace(grid, Rows(("b", 2), ("c", 3), ("a", 1)));
                await ClickHeader(grid, 1);
                await ClickHeader(grid, 1); // descending
                grid.Columns[2].Visibility = Visibility.Collapsed;

                var (headers, rows) = GridExport.Table(grid);

                Assert.Equal(["Nombre completo", "Cuenta"], headers);
                Assert.Equal(["c", "b", "a"], rows.Select(r => (string)r[0]!));
                Assert.Equal([3L, 2L, 1L], rows.Select(r => (long)r[1]!));
            }
            finally { window.Close(); }
        });

    [Fact]
    public Task ExportWritesOnlyTheChosenFileAndNeutralisesHostileText() =>
        DesktopDispatcher.RunAsync(() =>
        {
            var (window, grid) = Host();
            var directory = Directory.CreateTempSubdirectory("wpshield-grid-export-");
            var (choose, notify) = (GridExport.ChooseFile, GridExport.Notify);
            var messages = new List<(string Message, bool Error)>();
            try
            {
                GridRefresh.Replace(grid, new[]
                {
                    new Row("=HYPERLINK(\"http://198.51.100.1/x\",\"ok\")", 1, "+cmd|' /C calc'!A0"),
                    new Row("@SUM(1)", -2, "-2+3")
                });
                var path = Path.Combine(directory.FullName, "chosen.csv");
                string? suggested = null;
                GridExport.ChooseFile = (_, name, spanish) => { suggested = name; Assert.True(spanish); return path; };
                GridExport.Notify = (_, message, error) => messages.Add((message, error));

                Assert.Equal(path, GridExport.Export(grid, "web", spanish: true));

                Assert.Matches(@"^wpshield-web-\d{4}-\d{2}-\d{2}-\d{4}\.csv$", suggested!);
                Assert.Equal(["chosen.csv"], directory.GetFiles().Select(f => f.Name));
                var bytes = File.ReadAllBytes(path);
                Assert.Equal(new byte[] { 0xEF, 0xBB, 0xBF }, bytes[..3]);
                var lines = Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3).Split("\r\n");
                Assert.Equal("\"Nombre completo\",\"Cuenta\",\"Nota\"", lines[0]);
                Assert.Equal("\"'=HYPERLINK(\"\"http://198.51.100.1/x\"\",\"\"ok\"\")\",1,\"'+cmd|' /C calc'!A0\"", lines[1]);
                Assert.Equal("\"'@SUM(1)\",-2,\"'-2+3\"", lines[2]);
                Assert.False(Assert.Single(messages).Error);

                // Cancelled: nothing is written, and nothing is said.
                GridExport.ChooseFile = (_, _, _) => null;
                Assert.Null(GridExport.Export(grid, "web", spanish: false));
                Assert.Single(directory.GetFiles());
                Assert.Single(messages);
            }
            finally
            {
                (GridExport.ChooseFile, GridExport.Notify) = (choose, notify);
                window.Close();
                directory.Delete(recursive: true);
            }
            return Task.CompletedTask;
        });

    [Fact]
    public Task AFileThatCannotBeWrittenIsReportedNotThrown() =>
        DesktopDispatcher.RunAsync(() =>
        {
            var (window, grid) = Host();
            var (choose, notify) = (GridExport.ChooseFile, GridExport.Notify);
            var messages = new List<(string Message, bool Error)>();
            try
            {
                GridRefresh.Replace(grid, Rows(("a", 1)));
                GridExport.ChooseFile = (_, _, _) => Path.Combine(Path.GetTempPath(), "wpshield-missing-" + Guid.NewGuid().ToString("N"), "x.csv");
                GridExport.Notify = (_, message, error) => messages.Add((message, error));

                Assert.Null(GridExport.Export(grid, "attacks", spanish: false));
                Assert.True(Assert.Single(messages).Error);
                Assert.StartsWith("Could not export", messages[0].Message, StringComparison.Ordinal);
            }
            finally
            {
                (GridExport.ChooseFile, GridExport.Notify) = (choose, notify);
                window.Close();
            }
            return Task.CompletedTask;
        });

    [Fact]
    public Task AListViewExportsItsGridViewColumnsInOrder() =>
        DesktopDispatcher.RunAsync(() =>
        {
            var view = new GridView();
            view.Columns.Add(new GridViewColumn { Header = "Fuente", DisplayMemberBinding = new Binding(nameof(Row.Name)) });
            view.Columns.Add(new GridViewColumn { Header = "Cuenta", DisplayMemberBinding = new Binding(nameof(Row.Count)) });
            var list = new ListView { View = view, ItemsSource = Rows(("rdp", 2), ("iis", 7)) };
            var directory = Directory.CreateTempSubdirectory("wpshield-list-export-");
            var (choose, notify) = (GridExport.ChooseFile, GridExport.Notify);
            try
            {
                var path = Path.Combine(directory.FullName, "references.csv");
                GridExport.ChooseFile = (_, _, _) => path;
                GridExport.Notify = (_, _, _) => { };

                Assert.Equal(path, GridExport.Export(list, "audit-references", spanish: true));

                Assert.Equal("\"Fuente\",\"Cuenta\"\r\n\"rdp\",2\r\n\"iis\",7\r\n", File.ReadAllText(path, Encoding.UTF8));
            }
            finally
            {
                (GridExport.ChooseFile, GridExport.Notify) = (choose, notify);
                directory.Delete(recursive: true);
            }
            return Task.CompletedTask;
        });

    [Fact]
    public Task EveryGridOffersExportInItsContextMenuInTheWindowsLanguage() =>
        DesktopDispatcher.RunAsync(() =>
        {
            var grid = new DataGrid();
            var list = new ListView { View = new GridView() };
            GridExport.Attach(grid, "web", spanish: true);
            GridExport.Attach(list, "audit-references", spanish: false);

            Assert.Equal("Exportar CSV…", Assert.IsType<MenuItem>(Assert.Single(grid.ContextMenu!.Items)).Header);
            Assert.Equal("Export CSV…", Assert.IsType<MenuItem>(Assert.Single(list.ContextMenu!.Items)).Header);
            return Task.CompletedTask;
        });
}

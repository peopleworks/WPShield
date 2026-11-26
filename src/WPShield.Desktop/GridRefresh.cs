using System.Collections;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace WPShield.Desktop;

/// <summary>
/// Replaces a grid's rows on a refresh and keeps what the operator chose: the sort, the header arrows, the
/// selected row and the scroll position.
/// </summary>
/// <remarks>
/// <para>
/// A <see cref="DataGrid"/> forgets its sort when its <see cref="ItemsControl.ItemsSource"/> is replaced: the
/// new collection gets a new view with no sort, and the header arrows are cleared. Every grid here is rebuilt
/// on each Live tick, so a column the operator sorted snapped back within seconds. Every refresh goes through
/// <see cref="Replace"/>, which captures the sort before the rows change and restores it after.
/// </para>
/// <para>
/// The sort is also remembered per grid, because some refreshes pass through an empty or "not read" state
/// first: the rows go to nothing and come back. A grid that has no sort when the next rows arrive gets the
/// last sort it had - the grid's own header click can change the sort, but never clears it, so "no sort now"
/// can only mean "lost in a refresh".
/// </para>
/// </remarks>
internal static class GridRefresh
{
    private sealed class State
    {
        internal SortDescription[] Sorts = [];
        internal (string Path, ListSortDirection Direction)[] Arrows = [];
    }

    private static readonly ConditionalWeakTable<DataGrid, State> States = new();

    /// <summary>The sort a grid opens with, until the operator picks another. The first sort shows its arrow.</summary>
    internal static void SetDefaultSort(DataGrid grid, params SortDescription[] sorts)
    {
        ArgumentNullException.ThrowIfNull(grid);
        var state = States.GetOrCreateValue(grid);
        state.Sorts = sorts;
        state.Arrows = sorts.Length == 0 ? [] : [(sorts[0].PropertyName, sorts[0].Direction)];
        Apply(grid, state);
    }

    /// <summary>
    /// Shows <paramref name="rows"/> in <paramref name="grid"/>, keeping the sort and the scroll position, and
    /// the selected row when <paramref name="key"/> is given and a row with the same key is still there. A grid
    /// whose window restores its own selection passes no key.
    /// </summary>
    internal static void Replace(DataGrid grid, IEnumerable? rows, Func<object, object?>? key = null)
    {
        ArgumentNullException.ThrowIfNull(grid);
        var state = States.GetOrCreateValue(grid);
        Remember(grid);
        var selected = key is not null && grid.SelectedItem is { } item ? key(item) : null;
        var scroll = ScrollViewerOf(grid);
        var offset = scroll?.VerticalOffset ?? 0;

        grid.ItemsSource = rows;
        Apply(grid, state);

        if (selected is not null && rows is not null)
            grid.SelectedItem = rows.Cast<object>().FirstOrDefault(row => Equals(key!(row), selected));
        if (scroll is not null && offset > 0) scroll.ScrollToVerticalOffset(offset);
    }

    private static SortDescription[] Remember(DataGrid grid)
    {
        var state = States.GetOrCreateValue(grid);
        var current = grid.Items.SortDescriptions.ToArray();
        if (current.Length > 0)
        {
            state.Sorts = current;
            state.Arrows = [.. grid.Columns
                .Where(column => column.SortDirection is not null && !string.IsNullOrEmpty(column.SortMemberPath))
                .Select(column => (column.SortMemberPath, column.SortDirection!.Value))];
        }
        return state.Sorts;
    }

    private static void Apply(DataGrid grid, State state)
    {
        var items = grid.Items;
        if (!items.SortDescriptions.SequenceEqual(state.Sorts) && (grid.ItemsSource is null || items.CanSort))
        {
            using (items.DeferRefresh())
            {
                items.SortDescriptions.Clear();
                foreach (var sort in state.Sorts) items.SortDescriptions.Add(sort);
            }
        }
        foreach (var column in grid.Columns)
        {
            var arrow = state.Arrows.FirstOrDefault(a => a.Path == column.SortMemberPath);
            column.SortDirection = arrow.Path is null || string.IsNullOrEmpty(column.SortMemberPath) ? null : arrow.Direction;
        }
    }

    internal static ScrollViewer? ScrollViewerOf(DependencyObject root)
    {
        if (root is ScrollViewer viewer) return viewer;
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
            if (ScrollViewerOf(VisualTreeHelper.GetChild(root, i)) is { } found) return found;
        return null;
    }
}

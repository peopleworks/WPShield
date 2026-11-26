using System.Collections;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace WPShield.Desktop;

/// <summary>
/// Writes a table as CSV: UTF-8 with a byte order mark so Excel reads accents, RFC 4180 quoting, CRLF line
/// ends - and every text cell neutralised against formula injection.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why every text cell is treated as hostile.</b> The rows hold attacker-chosen text: request paths, the
/// account names an attacker tried, user agents, labels typed from evidence. A spreadsheet runs a cell that
/// starts with <c>=</c>, <c>+</c>, <c>-</c> or <c>@</c> as a formula, and a formula can fetch a URL or start a
/// program (<c>=HYPERLINK(...)</c>, <c>+cmd|' /C calc'!A0</c>). So a text cell is cleaned the way the window
/// cleans it (<see cref="DisplayText.Clean"/>: no control or format characters, bounded), and when it starts -
/// after any leading spaces - with one of those characters, a tab or a carriage return, or their full-width
/// forms, it gets a leading single quote, which spreadsheets read as "this is text".
/// </para>
/// <para>
/// <b>Decided by the column's type, never by the value.</b> Only a value whose type is a number, a date or a
/// boolean - WPShield's own counts and times, never text taken from a request - is written as it is. A text
/// column that happens to hold <c>-2+3</c> is still text, and is still neutralised.
/// </para>
/// </remarks>
internal static class CsvExport
{
    /// <summary>The longest text cell written; longer text ends in an ellipsis, as on screen.</summary>
    internal const int MaxCell = 4096;

    private static readonly char[] FormulaStarts = ['=', '+', '-', '@', '\t', '\r', '\n', '＝', '＋', '－', '＠'];

    internal static readonly Encoding Utf8WithBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: true);

    /// <summary>Writes the header row and the rows. The stream is left open.</summary>
    internal static void Write(Stream stream, IReadOnlyList<string> headers, IEnumerable<IReadOnlyList<object?>> rows)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(rows);
        using var writer = new StreamWriter(stream, Utf8WithBom, bufferSize: 16 * 1024, leaveOpen: true) { NewLine = "\r\n" };
        writer.WriteLine(string.Join(",", headers.Select(header => Text(header))));
        foreach (var row in rows) writer.WriteLine(string.Join(",", row.Select(Cell)));
    }

    /// <summary>One cell: a number, date or boolean as it is (invariant culture), anything else as neutralised, quoted text.</summary>
    internal static string Cell(object? value) => value switch
    {
        null => "",
        string text => Text(text),
        sbyte or byte or short or ushort or int or uint or long or ulong => Convert.ToString(value, CultureInfo.InvariantCulture)!,
        float number => float.IsFinite(number) ? number.ToString("R", CultureInfo.InvariantCulture) : "",
        double number => double.IsFinite(number) ? number.ToString("R", CultureInfo.InvariantCulture) : "",
        decimal number => number.ToString(CultureInfo.InvariantCulture),
        bool flag => flag ? "true" : "false",
        DateTimeOffset time => Time(time.UtcDateTime),
        DateTime time => Time(time.Kind == DateTimeKind.Local ? time.ToUniversalTime() : time),
        _ => Text(Convert.ToString(value, CultureInfo.InvariantCulture))
    };

    /// <summary>A time in UTC, with milliseconds only when it has them (audit references are told apart by them).</summary>
    private static string Time(DateTime utc) =>
        utc.ToString(utc.Millisecond == 0 ? "yyyy-MM-dd HH:mm:ss" : "yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);

    /// <summary>Text as a quoted RFC 4180 field: cleaned, bounded, and prefixed with a quote when a spreadsheet would read a formula.</summary>
    internal static string Text(string? value)
    {
        var clean = DisplayText.Clean(value, MaxCell);
        var first = clean.TrimStart(' ');
        if (first.Length > 0 && FormulaStarts.Contains(first[0])) clean = "'" + clean;
        return "\"" + clean.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
}

/// <summary>
/// "Export CSV…" on a grid: exactly the rows and columns the grid shows, in its current sort, with the
/// headers in the window's language. Only the file the operator chose is written - no temporary file, no copy.
/// </summary>
internal static class GridExport
{
    /// <summary>Asks where to save. Replaced in tests; the default is a save dialog that starts in Documents.</summary>
    internal static Func<Window?, string, bool, string?> ChooseFile { get; set; } = ShowSaveDialog;

    /// <summary>Tells the operator what happened. Replaced in tests; the default is a message box.</summary>
    internal static Action<Window?, string, bool> Notify { get; set; } = ShowMessage;

    /// <summary>The name a save dialog suggests, such as <c>wpshield-web-2026-11-26-1830.csv</c>.</summary>
    internal static string SuggestedName(string name, DateTime now) =>
        $"wpshield-{name}-{now.ToString("yyyy-MM-dd-HHmm", CultureInfo.InvariantCulture)}.csv";

    /// <summary>Adds "Export CSV…" to the grid's context menu.</summary>
    internal static void Attach(DataGrid grid, string name, bool spanish) => AttachMenu(grid, name, spanish, () => Table(grid));

    /// <summary>Adds "Export CSV…" to a list view whose view is a <see cref="GridView"/>.</summary>
    internal static void Attach(ListView list, string name, bool spanish) => AttachMenu(list, name, spanish, () => Table(list));

    private static void AttachMenu(Control control, string name, bool spanish, Func<(IReadOnlyList<string>, IReadOnlyList<IReadOnlyList<object?>>)> table)
    {
        var item = new MenuItem { Header = spanish ? "Exportar CSV…" : "Export CSV…" };
        item.Click += (_, _) => Export(Window.GetWindow(control), name, spanish, table);
        control.ContextMenu ??= new ContextMenu();
        control.ContextMenu.Items.Add(item);
    }

    /// <summary>Exports the grid now. Returns the path written, or null when nothing was written.</summary>
    internal static string? Export(DataGrid grid, string name, bool spanish) =>
        Export(Window.GetWindow(grid), name, spanish, () => Table(grid));

    /// <summary>Exports the list view now. Returns the path written, or null when nothing was written.</summary>
    internal static string? Export(ListView list, string name, bool spanish) =>
        Export(Window.GetWindow(list), name, spanish, () => Table(list));

    private static string? Export(Window? owner, string name, bool spanish,
        Func<(IReadOnlyList<string> Headers, IReadOnlyList<IReadOnlyList<object?>> Rows)> table)
    {
        var (headers, rows) = table();
        var path = ChooseFile(owner, SuggestedName(name, DateTime.Now), spanish);
        if (string.IsNullOrWhiteSpace(path)) return null;
        try
        {
            using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
                CsvExport.Write(stream, headers, rows);
            Notify(owner, spanish
                ? $"Se exportaron {rows.Count:N0} filas a {DisplayText.Clean(path, 260)}."
                : $"Exported {rows.Count:N0} rows to {DisplayText.Clean(path, 260)}.", false);
            return path;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or NotSupportedException or ArgumentException)
        {
            Notify(owner, (spanish ? "No se pudo exportar: " : "Could not export: ") + DisplayText.Clean(ex.Message, 300), true);
            return null;
        }
    }

    /// <summary>The visible columns, in display order, and the rows in the grid's current order.</summary>
    internal static (IReadOnlyList<string> Headers, IReadOnlyList<IReadOnlyList<object?>> Rows) Table(DataGrid grid)
    {
        ArgumentNullException.ThrowIfNull(grid);
        var columns = grid.Columns.Where(column => column.Visibility == Visibility.Visible).OrderBy(column => column.DisplayIndex).ToArray();
        var headers = columns.Select(column => HeaderText(column.Header)).ToArray();
        var rows = Rows(grid.Items).Select(item => (IReadOnlyList<object?>)[.. columns.Select(column => Value(item, PathOf(column)))]).ToArray();
        return (headers, rows);
    }

    /// <summary>The columns of a list view's <see cref="GridView"/>, in display order, and its rows in order.</summary>
    internal static (IReadOnlyList<string> Headers, IReadOnlyList<IReadOnlyList<object?>> Rows) Table(ListView list)
    {
        ArgumentNullException.ThrowIfNull(list);
        var columns = list.View is GridView view ? view.Columns.ToArray() : [];
        var headers = columns.Select(column => HeaderText(column.Header)).ToArray();
        var rows = Rows(list.Items).Select(item => (IReadOnlyList<object?>)[.. columns.Select(column =>
            Value(item, (column.DisplayMemberBinding as Binding)?.Path?.Path))]).ToArray();
        return (headers, rows);
    }

    private static IEnumerable<object> Rows(IEnumerable items) =>
        items.Cast<object>().Where(item => item != CollectionView.NewItemPlaceholder);

    /// <summary>A header as the operator reads it: a short header's tooltip holds the full title.</summary>
    internal static string HeaderText(object? header) => header switch
    {
        null => "",
        string text => text,
        TextBlock { ToolTip: string full } when full.Length > 0 => full,
        TextBlock block => block.Text,
        HeaderedContentControl control => HeaderText(control.Header),
        ContentControl control => HeaderText(control.Content),
        _ => Convert.ToString(header, CultureInfo.CurrentCulture) ?? ""
    };

    private static string? PathOf(DataGridColumn column) => column switch
    {
        DataGridBoundColumn { Binding: Binding binding } => binding.Path?.Path,
        _ => (column.ClipboardContentBinding as Binding)?.Path?.Path
    };

    /// <summary>
    /// The value a column shows, read from the row by its binding path (<c>Source.Requests</c>). The raw value,
    /// not the formatted text, so numbers and times stay numbers and times in a spreadsheet.
    /// </summary>
    internal static object? Value(object? item, string? path)
    {
        if (item is null || string.IsNullOrEmpty(path)) return null;
        var current = item;
        foreach (var part in path.Split('.'))
        {
            if (current is null) return null;
            var property = current.GetType().GetProperty(part, BindingFlags.Public | BindingFlags.Instance);
            if (property is null || property.GetIndexParameters().Length > 0) return null;
            current = property.GetValue(current);
        }
        return current;
    }

    private static string? ShowSaveDialog(Window? owner, string suggested, bool spanish)
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = spanish ? "Exportar CSV" : "Export CSV",
            FileName = suggested,
            DefaultExt = ".csv",
            Filter = (spanish ? "Archivos CSV" : "CSV files") + " (*.csv)|*.csv",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            OverwritePrompt = true,
            AddToRecent = false
        };
        return dialog.ShowDialog(owner) == true ? dialog.FileName : null;
    }

    private static void ShowMessage(Window? owner, string message, bool error)
    {
        var icon = error ? MessageBoxImage.Warning : MessageBoxImage.Information;
        if (owner is not null) MessageBox.Show(owner, message, "WPShield", MessageBoxButton.OK, icon);
        else MessageBox.Show(message, "WPShield", MessageBoxButton.OK, icon);
    }
}

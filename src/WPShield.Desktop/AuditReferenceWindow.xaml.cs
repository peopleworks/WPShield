using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Win32;
using WPShield.Cli;

namespace WPShield.Desktop;

public partial class AuditReferenceWindow : Window
{
    private readonly bool spanish;
    private readonly Action<string> writeClipboard;
    private readonly CancellationTokenSource lifetime = new();

    internal AuditReferenceWindow(bool spanish, Action<string>? writeClipboard = null)
    {
        this.spanish = spanish;
        this.writeClipboard = writeClipboard ?? Clipboard.SetText;
        InitializeComponent();
        Heading.Text = L("Audit references", "Referencias de auditoría");
        Title = "WPShield | " + Heading.Text;
        OpenButton.Content = L("_Open snapshot…", "_Abrir informe…");
        CopyButton.Content = L("Copy (Ctrl+C)", "Copiar (Ctrl+C)");
        SourceColumn.Header = L("Source", "Fuente");
        IdColumn.Header = L("Record ID / IIS line", "ID de registro / línea IIS");
        TimeColumn.Header = L("Event time (UTC)", "Hora del evento (UTC)");
        GridExport.Attach(Entries, "audit-references", spanish);
        PreviewLabel.Text = L("Clipboard preview", "Vista previa del portapapeles");
        CoverageLabel.Text = L("Open a saved WPShield snapshot for RDP, SQL Server or IIS.",
            "Abra un informe JSON de WPShield de RDP, SQL Server o IIS.");
    }

    private string L(string english, string es) => spanish ? es : english;

    private async void OpenFile(object sender, RoutedEventArgs e)
    {
        var picker = new OpenFileDialog
        {
            Filter = "JSON (*.json;*.jsonl)|*.json;*.jsonl|" + L("All files", "Todos los archivos") + "|*.*",
            Title = L("Open audit snapshot", "Abrir informe de auditoría"),
            AddToRecent = false
        };
        if (picker.ShowDialog(this) == true) await LoadSnapshotAsync(picker.FileName);
    }

    internal async Task LoadSnapshotAsync(string path)
    {
        var token = lifetime.Token;
        OpenButton.IsEnabled = false;
        Entries.ItemsSource = null;
        Preview.Text = CoverageLabel.Text = "";
        Status.Text = L("Reading snapshot…", "Leyendo el informe…");
        try
        {
            var result = await Task.Run(() => SavedAuditSnapshot.BrowseAsync(path, token), token);
            if (token.IsCancellationRequested) return;
            CoverageLabel.Text = L("Reported coverage", "Cobertura declarada") + "   " +
                string.Join("   ·   ", result.Coverage.Select(pair => $"{pair.Key.ToUpperInvariant()} — {CoverageText(pair.Value)}"));
            Entries.ItemsSource = result.Rows;
            if (result.Rows.Count > 0)
            {
                Entries.SelectedIndex = 0;
                Entries.UpdateLayout();
                (Entries.ItemContainerGenerator.ContainerFromIndex(0) as ListViewItem)?.Focus();
            }
            else Status.Text = L("This snapshot contains no references.", "El informe no contiene referencias.");
        }
        catch (OperationCanceledException)
        {
            if (!token.IsCancellationRequested) Status.Text = L("Reading exceeded five seconds.", "La lectura superó los cinco segundos.");
        }
        catch (SnapshotSizeException) { Status.Text = L("The file exceeds 8 MiB.", "El archivo supera los 8 MiB."); }
        catch (ReferenceLimitException) { Status.Text = L("More than 1,024 references.", "El informe supera las 1.024 referencias."); }
        catch (DuplicateAuditRowException) { Status.Text = L("Duplicate ID in one source.", "Hay un ID duplicado en una fuente."); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or System.Security.SecurityException)
        {
            Status.Text = L("Cannot read the selected file.", "No se pudo leer el archivo seleccionado.");
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or ArgumentException)
        {
            Status.Text = L("Expected one valid WPShield audit snapshot.", "Se esperaba un único informe de auditoría válido de WPShield.");
        }
        finally { if (!token.IsCancellationRequested) OpenButton.IsEnabled = true; }
    }

    private string CoverageText(string status) => status switch
    {
        "read" => L("read", "leída"),
        "limited" => L("partial", "parcial"),
        "unavailable" => L("unavailable", "no disponible"),
        _ => L("unknown", "desconocida")
    };

    private void SelectReference(object sender, SelectionChangedEventArgs e)
    {
        Preview.Text = (Entries.SelectedItem as AuditReferenceRow)?.Json ?? "";
        Status.Text = Entries.SelectedItem is null ? "" : L("Use the arrow keys to select a reference and Ctrl+C to copy.",
            "Use las flechas para seleccionar una referencia y Ctrl+C para copiarla.");
        CommandManager.InvalidateRequerySuggested();
    }

    private void CanCopy(object sender, CanExecuteRoutedEventArgs e) => e.CanExecute = Entries?.SelectedItem is AuditReferenceRow;

    private void CopyReference(object sender, ExecutedRoutedEventArgs e)
    {
        if (Entries.SelectedItem is not AuditReferenceRow row) return;
        try
        {
            writeClipboard(row.Json);
            Status.Text = L("Reference copied.", "Referencia copiada.");
        }
        catch (ExternalException) { Status.Text = L("Clipboard unavailable. Try again.", "Portapapeles no disponible. Vuelva a intentarlo."); }
        e.Handled = true;
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        lifetime.Cancel();
        lifetime.Dispose();
    }
}

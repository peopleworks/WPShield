using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Data.Sqlite;
using WPShield.Cli;
using WPShield.Evidence;

namespace WPShield.Desktop;

/// <summary>One entry of the settings list: a catalog key and, when the store was read, its value.</summary>
/// <remarks>A class, not a record: the list selects by reference, and two reads of the same unread key are equal records.</remarks>
internal sealed class SettingRow(string key, string name, string summary, SettingDefinition definition, SettingValue? value)
{
    public string Key { get; } = key;

    public string Name { get; } = name;

    public string Summary { get; } = summary;

    public SettingDefinition Definition { get; } = definition;

    public SettingValue? Value { get; } = value;
}

/// <summary>One change from <c>settings_history</c>, cleaned for display.</summary>
internal sealed record SettingHistoryRow(string When, string Who, string Old, string New, string Reason);

/// <summary>
/// The evidence store's settings (ADR 0007, amendment), listed from <see cref="SettingCatalog"/> and
/// edited in place, so no setting needs a JSON file or a path on the server.
/// </summary>
/// <remarks>
/// <para>
/// Every key in the catalog is listed, and its editor follows the shape of its default
/// (<see cref="SettingEditors"/>), so a key added to the catalog later appears and can be changed
/// without a change here. Whether a value is acceptable is the catalog's answer, shown as it gives it.
/// </para>
/// <para>
/// Writing is the exception ADR 0007 allows an elevated operator tool. Without elevation the window
/// is read-only and offers to reopen elevated; when the store does not exist it says so and creates
/// nothing, because the writer never creates the evidence directory. Each save opens the store for
/// writing only for that change, needs a reason, records the Windows user exactly as
/// <c>wpshield settings set</c> does, and says when the change takes effect instead of implying it
/// already has. A save that fails says why and leaves the edit in the window.
/// </para>
/// </remarks>
public partial class SettingsWindow : Window
{
    private static readonly JsonSerializerOptions Readable = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    private readonly bool spanish;
    private readonly ISettingsStore store;
    private readonly Func<OwnConnection> remote;
    private SettingsSnapshot? snapshot;
    private SettingRow? shown;
    private SettingEdit? edit;
    private OwnConnection connection = OwnConnection.None(OwnConnection.Unknown, "not-read");
    private Task? loading;
    private Task? historyRead;
    private bool filling;
    private bool busy;
    private bool closed;

    public SettingsWindow(bool spanish) : this(spanish,
        new EvidenceSettingsStore(EvidenceStore.DefaultPath, EvidenceAccess.IsElevated, EvidenceAccess.CurrentUser), OwnConnectionReader.Read)
    {
    }

    internal SettingsWindow(bool spanish, ISettingsStore store, Func<OwnConnection> remote)
    {
        this.spanish = spanish;
        this.store = store;
        this.remote = remote;
        InitializeComponent();
        Title = "WPShield | " + L("Settings", "Ajustes");
        SourceLabel.Text = L("Evidence store  /  settings", "Almacén de evidencia  /  ajustes");
        Heading.Text = L("Settings", "Ajustes");
        Subtitle.Text = L("Store: ", "Almacén: ") + DisplayText.Clean(store.Path, 200);
        RefreshButton.Content = L("Refresh", "Actualizar");
        ElevateButton.Content = L("Reopen as administrator", "Abrir como administrador");
        CurrentLabel.Text = L("Current value", "Valor actual");
        ChangedLabel.Text = L("Last changed", "Último cambio");
        DefaultLabel.Text = L("Default", "Por defecto");
        EffectLabel.Text = L("Takes effect", "Surte efecto");
        EditorLabel.Text = L("New value", "Valor nuevo");
        AddressHeader.Text = L("Address or network", "Dirección o red");
        LabelHeader.Text = L("Label", "Etiqueta");
        ToggleEditor.Content = L("On (true)", "Activado (true)");
        ReasonLabel.Content = L("_Reason for the change (required, recorded in the history)", "_Motivo del cambio (obligatorio, queda en el historial)");
        SaveButton.Content = L("Save", "Guardar");
        ResetButton.Content = L("Reset to default", "Volver al valor por defecto");
        ResetButton.ToolTip = L("Removes the stored value so the default applies again. Needs a reason too.",
            "Quita el valor guardado para que vuelva a regir el valor por defecto. También necesita un motivo.");
        ConnectionButton.Content = L("My current connection", "Mi conexión actual");
        JsonSwitch.Content = L("Edit as JSON", "Editar como JSON");
        JsonSwitch.ToolTip = L("Edits the value as JSON text. The same check decides whether it can be saved.",
            "Edita el valor como texto JSON. La misma comprobación decide si se puede guardar.");
        HistoryLabel.Text = L("History of this setting", "Historial de este ajuste");
        string[] headers = [L("When (UTC)", "Cuándo (UTC)"), L("Who", "Quién"), L("Old value", "Valor anterior"),
            L("New value", "Valor nuevo"), L("Reason", "Motivo")];
        for (var i = 0; i < headers.Length; i++) HistoryRows.Columns[i].Header = headers[i];
        RemoveText = L("Remove this row", "Quitar esta fila");
        ShowNothingSelected();
    }

    /// <summary>The name screen readers give each row's remove button.</summary>
    public string RemoveText { get; }

    internal SettingEdit? Edit => edit;

    internal SettingsSnapshot? Snapshot => snapshot;

    private bool Writable => snapshot?.Access == SettingsAccess.Writable && !busy;

    private string L(string english, string es) => spanish ? es : english;

    private async void OnLoaded(object sender, RoutedEventArgs e) => await LoadAsync();

    private async void OnRefresh(object sender, RoutedEventArgs e) => await LoadAsync();

    /// <summary>Every caller waits for the same read; a second click never starts a parallel one.</summary>
    internal Task LoadAsync() => loading is { IsCompleted: false } ? loading : loading = LoadCoreAsync();

    private async Task LoadCoreAsync()
    {
        if (closed) return;
        RefreshButton.IsEnabled = false;
        Footer.Text = L("Reading the settings…", "Leyendo los ajustes…");
        try
        {
            // The connection is read alongside the store: the session log may take up to two seconds.
            var own = Task.Run(ReadConnection);
            var read = await Task.Run(store.Read);
            connection = await own;
            if (closed) return;
            snapshot = read;
            ShowAccess(read);
            var values = read.Values.ToDictionary(v => v.Key, StringComparer.Ordinal);
            var rows = store.Catalog.Values.OrderBy(d => d.Key, StringComparer.Ordinal)
                .Select(d => Row(d, values.GetValueOrDefault(d.Key))).ToArray();
            var keep = shown?.Key;
            Keys.ItemsSource = rows;
            Keys.SelectedItem = rows.FirstOrDefault(r => r.Key == keep) ?? rows.FirstOrDefault();
            Footer.Text = read.Read
                ? L($"{rows.Length} settings, read {DateTimeOffset.UtcNow:HH:mm:ss} UTC.", $"{rows.Length} ajustes, leídos a las {DateTimeOffset.UtcNow:HH:mm:ss} UTC.")
                : L($"{rows.Length} settings this version knows. Their values were not read.",
                    $"{rows.Length} ajustes que conoce esta versión. Sus valores no se leyeron.");
            if (historyRead is not null) await historyRead;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            if (closed) return;
            Footer.Text = L("The settings could not be read: ", "No se pudieron leer los ajustes: ") +
                DisplayText.Clean(ex.GetType().Name + ": " + ex.Message, 200);
        }
        finally
        {
            RefreshButton.IsEnabled = true;
        }
    }

    /// <summary>The connection, or "unknown" with the reason: a failed read must never hide the settings.</summary>
    private OwnConnection ReadConnection()
    {
        try
        {
            return remote();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return OwnConnection.None(OwnConnection.Unknown, ex.GetType().Name);
        }
    }

    private SettingRow Row(SettingDefinition definition, SettingValue? value)
    {
        var summary = value is null
            ? "—"
            : value.IsDefault ? Short(value.Value) + "  ·  " + L("default", "por defecto") : Short(value.Value) + "  ·  " + L("changed", "cambiado");
        return new(definition.Key, SettingNames.Name(definition.Key, spanish), summary, definition, value);
    }

    /// <summary>Says what this window may do, and why not when it may not. Never shows a default as a value nobody read.</summary>
    private void ShowAccess(SettingsSnapshot read)
    {
        var directory = DisplayText.Clean(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(store.Path)), 200);
        var path = DisplayText.Clean(store.Path, 200);
        var (message, elevate) = read.Access switch
        {
            SettingsAccess.Writable => ("", false),
            SettingsAccess.ReadOnly => (L("This window is not running as administrator, so it shows the settings but cannot change them. " +
                    "Every change is recorded with the Windows user who made it.",
                    "Esta ventana no se ejecuta como administrador: muestra los ajustes pero no puede cambiarlos. " +
                    "Cada cambio queda registrado con el usuario de Windows que lo hizo."), true),
            SettingsAccess.CouldNotLook => (L("The evidence store admits only administrators and the WPShield service, and this window is not " +
                    "elevated, so it could not read the settings. The values below are unknown, not defaults.",
                    "El almacén de evidencia solo admite a administradores y al servicio WPShield, y esta ventana no está elevada, así que no " +
                    "pudo leer los ajustes. Los valores de abajo son desconocidos, no los valores por defecto."), true),
            SettingsAccess.NoDirectory => (L($"There is no evidence store on this server: the folder {directory} does not exist. " +
                    "'wpshield install' creates it with restricted permissions, and the WPShield service then creates the store. " +
                    "This window creates nothing.",
                    $"No hay almacén de evidencia en este servidor: la carpeta {directory} no existe. " +
                    "'wpshield install' la crea con permisos restringidos y luego el servicio WPShield crea el almacén. " +
                    "Esta ventana no crea nada."), false),
            SettingsAccess.NoStore => (L($"The evidence folder exists, but the store {path} does not: the WPShield service creates it once it " +
                    "runs. Install the service with 'wpshield install' and start it. This window creates nothing.",
                    $"La carpeta de evidencia existe, pero el almacén {path} no: lo crea el servicio WPShield cuando se ejecuta. " +
                    "Instale el servicio con 'wpshield install' e inícielo. Esta ventana no crea nada."), false),
            SettingsAccess.AccessDenied => (L("Access to the evidence store was denied although this window is elevated. Check the folder's " +
                    "permissions; 'wpshield install' sets them.",
                    "Se denegó el acceso al almacén de evidencia aunque esta ventana está elevada. Revise los permisos de la carpeta; " +
                    "'wpshield install' los establece."), false),
            SettingsAccess.Schema => (L("Another version of WPShield wrote the evidence store; use the desktop that came with the installed service.",
                    "Otra versión de WPShield escribió el almacén de evidencia; use el monitor que vino con el servicio instalado."), false),
            _ => (L("The evidence store could not be read: ", "No se pudo leer el almacén de evidencia: ") + (read.Problem ?? ""), false)
        };
        Banner.Visibility = message.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        BannerText.Text = message;
        ElevateButton.Visibility = elevate ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>Selects a key as a click would, and returns the read of its history.</summary>
    internal Task Select(string key)
    {
        Keys.SelectedItem = Keys.Items.OfType<SettingRow>().FirstOrDefault(r => r.Key == key);
        return historyRead ?? Task.CompletedTask;
    }

    private void OnSelected(object sender, SelectionChangedEventArgs e)
    {
        if (Keys.SelectedItem is SettingRow row) Show(row);
        else ShowNothingSelected();
    }

    private void ShowNothingSelected()
    {
        shown = null;
        if (edit is not null) edit.Edited -= OnEdited;
        edit = null;
        DetailPanel.Visibility = Visibility.Collapsed;
    }

    private void Show(SettingRow row)
    {
        var sameKey = shown?.Key == row.Key;
        shown = row;
        DetailPanel.Visibility = Visibility.Visible;
        DetailName.Text = row.Name;
        DetailKey.Text = DisplayText.Clean(row.Key, 80);
        DetailDescription.Text = SettingNames.Description(row.Key, row.Definition.Description, spanish);
        DefaultValue.Text = Pretty(row.Definition.Default);
        EffectValue.Text = SettingNames.Effect(row.Definition.Effect, spanish);
        var value = row.Value;
        CurrentValue.Text = value is null ? "— " + L("(not read)", "(no se leyó)") : Pretty(value.Value);
        ChangedValue.Text = value is null ? "—"
            : value.IsDefault ? L("Not set in the store: the default applies. The history below shows any earlier change.", "Sin valor guardado: rige el valor por defecto. El historial de abajo muestra los cambios anteriores.")
            : $"{DisplayText.Clean(value.UpdatedBy, 64)}  ·  {value.UpdatedAt?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)} UTC  ·  v{value.Version.ToString(CultureInfo.InvariantCulture)}";
        if (!sameKey) StatusText.Text = "";

        if (edit is not null) edit.Edited -= OnEdited;
        edit = value is null ? null : new SettingEdit(row.Definition, value.Value, spanish);
        EditArea.Visibility = edit is null ? Visibility.Collapsed : Visibility.Visible;
        if (edit is not null)
        {
            filling = true;
            try
            {
                ReasonBox.Text = "";
            }
            finally
            {
                filling = false;
            }
            ShowEditor();
            edit.Edited += OnEdited;
        }
        UpdateState();
        historyRead = LoadHistoryAsync(row);
    }

    /// <summary>Shows the editor the edit is using, filled with its value.</summary>
    private void ShowEditor()
    {
        if (edit is null) return;
        filling = true;
        try
        {
            var kind = edit.Kind;
            ToggleEditor.Visibility = kind == SettingEditorKind.Toggle ? Visibility.Visible : Visibility.Collapsed;
            ValueEditor.Visibility = kind is SettingEditorKind.Number or SettingEditorKind.Text or SettingEditorKind.Json
                ? Visibility.Visible : Visibility.Collapsed;
            AddressEditor.Visibility = kind == SettingEditorKind.AddressTable ? Visibility.Visible : Visibility.Collapsed;
            ListEditor.Visibility = kind == SettingEditorKind.StringList ? Visibility.Visible : Visibility.Collapsed;
            RowActions.Visibility = kind is SettingEditorKind.AddressTable or SettingEditorKind.StringList ? Visibility.Visible : Visibility.Collapsed;
            var json = kind == SettingEditorKind.Json;
            ValueEditor.AcceptsReturn = json;
            ValueEditor.TextWrapping = json ? TextWrapping.Wrap : TextWrapping.NoWrap;
            ValueEditor.MinHeight = json ? 120 : 0;
            ValueEditor.VerticalScrollBarVisibility = json ? ScrollBarVisibility.Auto : ScrollBarVisibility.Disabled;
            ValueEditor.Text = edit.Text;
            ToggleEditor.IsChecked = edit.Toggle;
            AddressRows.ItemsSource = edit.Addresses;
            ListRows.ItemsSource = edit.Items;
            AddRowButton.Content = kind == SettingEditorKind.AddressTable ? L("Add a row", "Añadir una fila") : L("Add an entry", "Añadir una entrada");
            EditorLabel.Text = kind == SettingEditorKind.Json ? L("New value (JSON)", "Valor nuevo (JSON)") : L("New value", "Valor nuevo");
            JsonSwitch.Visibility = edit.CanSwitchToJson ? Visibility.Visible : Visibility.Collapsed;
            JsonSwitch.IsChecked = edit.AsJson;
        }
        finally
        {
            filling = false;
        }
    }

    private void OnJsonSwitch(object sender, RoutedEventArgs e)
    {
        if (filling || edit is null) return;
        if (edit.TrySetJson(JsonSwitch.IsChecked == true))
        {
            ShowEditor();
            return;
        }
        filling = true;
        JsonSwitch.IsChecked = edit.AsJson;
        filling = false;
        StatusText.Text = edit.AsJson
            ? L("This JSON does not have the form of the table or list editor, or is not valid JSON. Correct it, or keep editing it as JSON.",
                "Este JSON no tiene la forma del editor de tabla o lista, o no es JSON válido. Corríjalo o siga editándolo como JSON.")
            : L("Correct the value first.", "Corrija primero el valor.");
    }

    private void OnEdited(object? sender, EventArgs e) => UpdateState();

    /// <summary>Redraws the catalog's verdict and what the buttons may do. The rules live in <see cref="SettingEdit"/>.</summary>
    internal void UpdateState()
    {
        if (edit is null || shown?.Value is not { } value) return;
        var writable = Writable;
        Editors.IsEnabled = writable;
        JsonSwitch.IsEnabled = writable;
        ReasonBox.IsEnabled = writable;
        var (_, problem) = edit.Proposed();
        ValidationText.Text = problem ?? "";
        ValidationText.Visibility = problem is null ? Visibility.Collapsed : Visibility.Visible;
        SaveButton.IsEnabled = edit.CanSave(writable);
        ResetButton.IsEnabled = edit.CanReset(writable, value.IsDefault);
        SaveButton.ToolTip = !writable ? NotWritable()
            : problem is not null ? L("Correct the value first.", "Corrija primero el valor.")
            : !edit.Changed ? L("Nothing has changed yet.", "Todavía no ha cambiado nada.")
            : !edit.HasReason ? L("Give a reason: every change is recorded with who made it and why.",
                "Indique un motivo: cada cambio queda registrado con quién lo hizo y por qué.")
            : L("Saves the value in the evidence store and records the change.", "Guarda el valor en el almacén de evidencia y registra el cambio.");
        ShowConnection(writable);
    }

    private string NotWritable() => busy
        ? L("Saving…", "Guardando…")
        : snapshot?.Access is SettingsAccess.ReadOnly or SettingsAccess.CouldNotLook
            ? L("Changing a setting needs administrator rights: reopen as administrator.",
                "Cambiar un ajuste requiere permisos de administrador: abra la ventana como administrador.")
            : L("The evidence store cannot be written; the notice above says why.",
                "No se puede escribir en el almacén de evidencia; el aviso de arriba explica por qué.");

    /// <summary>
    /// Enables "My current connection" only for the address this server sees for this session, and
    /// says why otherwise. The address the client reports about itself is mentioned, never offered.
    /// </summary>
    private void ShowConnection(bool writable)
    {
        var address = connection.Address;
        ConnectionButton.IsEnabled = writable && address is not null;
        var read = L($" Read at {connection.ReadAt:HH:mm:ss} UTC; Refresh reads again.",
            $" Leído a las {connection.ReadAt:HH:mm:ss} UTC; Actualizar vuelve a leer.");
        ConnectionButton.ToolTip = ConnectionText() + ClientNote() + read + (address is not null && !writable ? " " + NotWritable() : "");
    }

    private string ConnectionText()
    {
        var address = connection.Address;
        var peers = Peers();
        var why = connection.Problem is null ? "" : $" ({DisplayText.Clean(connection.Problem, 60)})";
        return connection.Code switch
        {
            OwnConnection.ThisSession => L($"Adds {address}: the address this server sees for this Remote Desktop session, connected now.",
                $"Añade {address}: la dirección que este servidor ve para esta sesión de Escritorio remoto, conectada ahora."),
            OwnConnection.OnlyConnection => L($"Adds {address}: the only Remote Desktop connection this server sees now. No logon record of " +
                    $"this session named an address{why}.",
                $"Añade {address}: la única conexión de Escritorio remoto que ve ahora este servidor. Ningún registro de inicio de sesión " +
                    $"de esta sesión indicaba una dirección{why}."),
            OwnConnection.NotRemote => L("This is not a Remote Desktop session, so there is no connection to add.",
                "Esta no es una sesión de Escritorio remoto, así que no hay conexión que añadir."),
            OwnConnection.Ambiguous => L($"This server sees several Remote Desktop connections ({peers}) and nothing says which one is this " +
                    "session, so none is filled in. Type the right one.",
                $"Este servidor ve varias conexiones de Escritorio remoto ({peers}) y nada indica cuál es esta sesión, así que no se " +
                    "rellena ninguna. Escriba la correcta."),
            OwnConnection.RecordNotConnected => L($"This session's logon record names {DisplayText.Clean(connection.Recorded, 64)}, but this " +
                    $"server sees no Remote Desktop connection from it now (a Remote Desktop Gateway, or an older record), so it is not filled " +
                    $"in. Connections now: {peers}. Type the address instead.",
                $"El registro de inicio de esta sesión indica {DisplayText.Clean(connection.Recorded, 64)}, pero este servidor no ve ahora " +
                    $"ninguna conexión de Escritorio remoto desde ella (una puerta de enlace de Escritorio remoto, o un registro antiguo), así " +
                    $"que no se rellena. Conexiones ahora: {peers}. Escriba la dirección."),
            OwnConnection.RecordLocal => L($"This session's logon record says LOCAL: it did not arrive over the network (the console, or a " +
                    $"virtual machine's session), so none of this server's Remote Desktop connections ({peers}) is it. Type the address instead.",
                $"El registro de inicio de esta sesión indica LOCAL: no llegó por la red (la consola, o la sesión de una máquina virtual), " +
                    $"así que ninguna de las conexiones de Escritorio remoto de este servidor ({peers}) es ella. Escriba la dirección."),
            OwnConnection.NoConnection => L("This server sees no established Remote Desktop connection now, so there is nothing to add. " +
                    "Type the address instead.",
                "Este servidor no ve ahora ninguna conexión de Escritorio remoto establecida, así que no hay nada que añadir. " +
                    "Escriba la dirección."),
            _ => connection.Problem == "session-type-unknown"
                ? L("Windows could not say whether this is a Remote Desktop session, so nothing is filled in. Type the address instead.",
                    "Windows no pudo indicar si esta es una sesión de Escritorio remoto, así que no se rellena nada. Escriba la dirección.")
                : L($"This server's Remote Desktop connections could not be read{why}, so nothing is filled in. Type the address instead.",
                    $"No se pudieron leer las conexiones de Escritorio remoto de este servidor{why}, así que no se rellena nada. " +
                    "Escriba la dirección.")
        };
    }

    /// <summary>The client's own report, only when it differs from what is offered, and only as an explanation.</summary>
    private string ClientNote()
    {
        var reported = connection.ClientReported;
        if (reported is null || reported == connection.Address) return "";
        return L($" Your client reports {DisplayText.Clean(reported, 64)}, often its private address behind NAT; that one is not used.",
            $" Su cliente comunica {DisplayText.Clean(reported, 64)}, a menudo su dirección privada detrás de NAT; esa no se usa.");
    }

    private string Peers()
    {
        if (connection.Peers.Count == 0) return L("none", "ninguna");
        var shown = string.Join(", ", connection.Peers.Take(10).Select(p => DisplayText.Clean(p, 64)));
        return connection.Peers.Count > 10 ? shown + L($" and {connection.Peers.Count - 10} more", $" y {connection.Peers.Count - 10} más") : shown;
    }
    private async Task LoadHistoryAsync(SettingRow row)
    {
        HistoryRows.ItemsSource = Array.Empty<SettingHistoryRow>();
        if (snapshot is not { Read: true })
        {
            HistoryEmpty.Text = L("The history was not read either.", "Tampoco se leyó el historial.");
            return;
        }
        HistoryEmpty.Text = L("Reading the history…", "Leyendo el historial…");
        try
        {
            var changes = await Task.Run(() => store.History(row.Key));
            if (closed || shown?.Key != row.Key) return;
            var rows = changes.Select(c => new SettingHistoryRow(
                c.At.ToUniversalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture),
                DisplayText.Clean(c.ChangedBy, 64),
                c.OldValue is null ? L("default", "por defecto") : Shown(c.OldValue),
                c.NewValue is null ? L("default (reset)", "por defecto (restablecido)") : Shown(c.NewValue),
                DisplayText.Clean(c.Reason, 200))).ToArray();
            HistoryRows.ItemsSource = rows;
            HistoryEmpty.Text = rows.Length == 0 ? L("Never changed in this store.", "Nunca se cambió en este almacén.") : "";
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            if (closed || shown?.Key != row.Key) return;
            HistoryEmpty.Text = L("The history could not be read: ", "No se pudo leer el historial: ") + DisplayText.Clean(ex.Message, 200);
        }
    }

    private void OnToggle(object sender, RoutedEventArgs e)
    {
        if (!filling && edit is not null) edit.Toggle = ToggleEditor.IsChecked == true;
    }

    private void OnValueText(object sender, TextChangedEventArgs e)
    {
        if (!filling && edit is not null) edit.Text = ValueEditor.Text;
    }

    private void OnReasonText(object sender, TextChangedEventArgs e)
    {
        if (!filling && edit is not null) edit.Reason = ReasonBox.Text;
    }

    private void OnAddRow(object sender, RoutedEventArgs e)
    {
        if (edit?.Kind == SettingEditorKind.AddressTable) edit.AddAddress();
        else edit?.AddItem();
    }

    private void OnRemoveAddress(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is AddressLabelRow row) edit?.Addresses.Remove(row);
    }

    private void OnRemoveItem(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is ListItemRow row) edit?.Items.Remove(row);
    }

    private void OnAddConnection(object sender, RoutedEventArgs e) => AddConnection();

    /// <summary>Adds a row with the address this server sees for this session. Never the client's own report.</summary>
    internal void AddConnection()
    {
        if (edit is null || connection.Address is not { } address || !Writable) return;
        var present = edit.Kind == SettingEditorKind.AddressTable
            ? edit.Addresses.Any(r => r.Address.Trim() == address)
            : edit.Items.Any(r => r.Value.Trim() == address);
        if (present)
        {
            StatusText.Text = L($"{address} is already here.", $"{address} ya está aquí.");
            return;
        }
        if (edit.Kind == SettingEditorKind.AddressTable) edit.AddAddress(address);
        else if (edit.Kind == SettingEditorKind.StringList) edit.AddItem(address);
        else return;
        StatusText.Text = L($"Added {address}, the address this server sees for this session. Give a reason, then save.",
            $"Se añadió {address}, la dirección que este servidor ve para esta sesión. Indique un motivo y guarde.");
    }

    private async void OnSave(object sender, RoutedEventArgs e) => await SaveAsync();

    private async void OnReset(object sender, RoutedEventArgs e) => await ResetAsync();

    /// <summary>Stores the edited value. On failure the edit stays in the window and the reason is shown.</summary>
    internal Task SaveAsync()
    {
        if (edit is null || shown?.Value is not { } value || !edit.CanSave(Writable)) return Task.CompletedTask;
        var json = edit.Proposed().Json!;
        var reason = edit.Reason.Trim();
        var stamp = SettingStamp.Of(value);
        var key = shown.Key;
        return ChangeAsync(() => store.Save(key, json, reason, stamp));
    }

    /// <summary>Removes the stored value so the default applies again. Needs a reason like any change.</summary>
    internal Task ResetAsync()
    {
        if (edit is null || shown?.Value is not { } value || !edit.CanReset(Writable, value.IsDefault)) return Task.CompletedTask;
        var reason = edit.Reason.Trim();
        var stamp = SettingStamp.Of(value);
        var key = shown.Key;
        return ChangeAsync(() => store.Reset(key, reason, stamp));
    }

    private async Task ChangeAsync(Func<SettingChange> change)
    {
        busy = true;
        UpdateState();
        StatusText.Text = L("Saving…", "Guardando…");
        string message;
        var saved = false;
        try
        {
            var done = await Task.Run(change);
            message = Saved(done);
            saved = true;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            message = Failure(ex);
        }
        finally
        {
            busy = false;
        }
        if (closed) return;
        // Reload after a save: the store cleans labels on write, and the history has a new row.
        if (saved) await LoadAsync();
        else UpdateState();
        StatusText.Text = message;
    }

    private string Saved(SettingChange change)
    {
        var now = change.NewValue is null ? L("back to its default", "vuelve a su valor por defecto") : L("now ", "ahora vale ") + Shown(change.NewValue, 80);
        var was = change.OldValue is null ? L("the default", "el valor por defecto") : Shown(change.OldValue, 80);
        var recorded = L($"Recorded in the settings history: {DisplayText.Clean(change.ChangedBy, 64)}, " +
            $"{change.At.ToUniversalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)} UTC.",
            $"Registrado en el historial de ajustes: {DisplayText.Clean(change.ChangedBy, 64)}, " +
            $"{change.At.ToUniversalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)} UTC.");
        var effect = change.Effect == SettingEffect.NextStart
            ? L("It takes effect the next time the process that reads it starts. Nothing running has changed, and this window restarts nothing.",
                "Surte efecto la próxima vez que arranque el proceso que lo lee. Nada de lo que está en marcha ha cambiado, y esta ventana no reinicia nada.")
            : L("It takes effect at its next use - the next pruning pass, query or view that reads it. Nothing was reloaded.",
                "Surte efecto en su próximo uso: la próxima poda, consulta o vista que lo lea. No se recargó nada.");
        return L($"Saved: {change.Key} is {now} (it was {was}). ", $"Guardado: {change.Key} {now} (antes: {was}). ") + recorded + " " + effect;
    }

    private string Failure(Exception ex)
    {
        var reason = ex switch
        {
            SettingConflictException conflict => conflict.Now.IsDefault
                ? L("it was reset to its default elsewhere after this window read it. Refresh to see that change, then edit again.",
                    "otra herramienta lo restableció después de que esta ventana lo leyera. Actualice para ver ese cambio y vuelva a editarlo.")
                : L($"{DisplayText.Clean(conflict.Now.UpdatedBy, 64)} changed it at {conflict.Now.UpdatedAt?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)} UTC, " +
                    "after this window read it. Refresh to see that change, then edit again.",
                    $"{DisplayText.Clean(conflict.Now.UpdatedBy, 64)} lo cambió a las {conflict.Now.UpdatedAt?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)} UTC, " +
                    "después de que esta ventana lo leyera. Actualice para ver ese cambio y vuelva a editarlo."),
            SqliteException sqlite => L($"the store could not be written (SQLite error {sqlite.SqliteErrorCode}: {DisplayText.Clean(sqlite.Message, 160)}). " +
                    "The service may have been holding it; try again.",
                    $"no se pudo escribir en el almacén (error de SQLite {sqlite.SqliteErrorCode}: {DisplayText.Clean(sqlite.Message, 160)}). " +
                    "Puede que el servicio lo estuviera usando; vuelva a intentarlo."),
            ArgumentException refused => L("the store refused the value: ", "el almacén rechazó el valor: ") + DisplayText.Clean(refused.Message, 200),
            EvidenceAccessException access => DisplayText.Clean(access.Message, 300),
            _ => DisplayText.Clean(ex.GetType().Name + ": " + ex.Message, 200)
        };
        return L("Not saved: ", "No se guardó: ") + reason + " " + L("Your edit is still here.", "Su cambio sigue aquí.");
    }

    private void OnElevate(object sender, RoutedEventArgs e)
    {
        try
        {
            var path = Environment.ProcessPath ?? throw new InvalidOperationException("no process path");
            Process.Start(new ProcessStartInfo(path)
            {
                UseShellExecute = true,
                Verb = "runas",
                Arguments = (spanish ? "--es" : "--en") + " --settings"
            });
            Application.Current.Shutdown();
        }
        catch (Win32Exception)
        {
            // The operator declined the elevation prompt; keep this window as it is.
            Footer.Text = L("Elevation was cancelled.", "Se canceló la elevación.");
        }
    }

    private void OnClosed(object? sender, EventArgs e) => closed = true;

    private string Short(JsonNode? node) => node switch
    {
        JsonObject map => map.Count == 1 ? L("1 entry", "1 entrada") : L($"{map.Count} entries", $"{map.Count} entradas"),
        JsonArray list => list.Count == 1 ? L("1 entry", "1 entrada") : L($"{list.Count} entries", $"{list.Count} entradas"),
        null => "—",
        _ => DisplayText.Clean(node.ToJsonString(Readable), 40)
    };

    private static string Pretty(JsonNode node) => DisplayText.Clean(node.ToJsonString(Readable), 600);

    /// <summary>A stored JSON value, readable: accented letters kept, control and format characters replaced.</summary>
    private static string Shown(string json, int max = 200)
    {
        try
        {
            return DisplayText.Clean(JsonNode.Parse(json)?.ToJsonString(Readable) ?? "null", max);
        }
        catch (JsonException)
        {
            return DisplayText.Clean(json, max);
        }
    }
}

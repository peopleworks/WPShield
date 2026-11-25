using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using WPShield.Evidence;

namespace WPShield.Desktop;

/// <summary>How a setting is edited, decided by the shape of its catalog default.</summary>
internal enum SettingEditorKind
{
    /// <summary>A JSON boolean.</summary>
    Toggle,
    /// <summary>A JSON number.</summary>
    Number,
    /// <summary>A JSON string.</summary>
    Text,
    /// <summary>A JSON object of address or network to text: the shape of <c>labels.addresses</c>.</summary>
    AddressTable,
    /// <summary>A JSON array of strings, such as a list of addresses.</summary>
    StringList,
    /// <summary>Any other shape, or a stored value that does not have its default's shape: edited as JSON text.</summary>
    Json
}

/// <summary>One row of the address table editor.</summary>
internal sealed class AddressLabelRow : Observable
{
    private string address;
    private string label;

    internal AddressLabelRow(string address = "", string label = "")
    {
        this.address = address;
        this.label = label;
    }

    public string Address { get => address; set => Set(ref address, value ?? ""); }

    public string Label { get => label; set => Set(ref label, value ?? ""); }
}

/// <summary>One row of the list editor.</summary>
internal sealed class ListItemRow : Observable
{
    private string value;

    internal ListItemRow(string value = "") => this.value = value;

    public string Value { get => value; set => Set(ref this.value, value ?? ""); }
}

internal abstract class Observable : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}

/// <summary>
/// The editors of the settings window, chosen from the catalog and nothing else, so a setting added
/// to <see cref="SettingCatalog"/> later is listed and editable without a change here.
/// </summary>
/// <remarks>
/// The desktop never decides whether a value is acceptable. Every editor turns what was typed into
/// the JSON text <see cref="EvidenceSettings.Set"/> will receive, parses that text again, and asks the
/// catalog's own <see cref="SettingDefinition.Validate"/>; the window shows the catalog's answer. The
/// only refusals of its own are the ones a JSON value cannot represent: two rows for one address
/// (an object has one entry per key, so one of them would silently disappear) and text that is not
/// JSON in the raw editor.
/// </remarks>
internal static class SettingEditors
{
    internal static SettingEditorKind KindFor(JsonNode defaultValue) => defaultValue switch
    {
        JsonValue value => value.GetValueKind() switch
        {
            JsonValueKind.True or JsonValueKind.False => SettingEditorKind.Toggle,
            JsonValueKind.Number => SettingEditorKind.Number,
            JsonValueKind.String => SettingEditorKind.Text,
            _ => SettingEditorKind.Json
        },
        JsonObject map when map.All(p => IsString(p.Value)) => SettingEditorKind.AddressTable,
        JsonArray list when list.All(IsString) => SettingEditorKind.StringList,
        _ => SettingEditorKind.Json
    };

    /// <summary>
    /// The default's editor, unless the current value does not have that shape - written by a newer
    /// build, or by hand - in which case it is edited as JSON rather than misread.
    /// </summary>
    internal static SettingEditorKind KindFor(JsonNode defaultValue, JsonNode? current)
    {
        var kind = KindFor(defaultValue);
        return current is null || Fits(kind, current) ? kind : SettingEditorKind.Json;
    }

    private static bool Fits(SettingEditorKind kind, JsonNode node) => kind switch
    {
        SettingEditorKind.Toggle => node is JsonValue v && v.GetValueKind() is JsonValueKind.True or JsonValueKind.False,
        SettingEditorKind.Number => node is JsonValue v && v.GetValueKind() == JsonValueKind.Number,
        SettingEditorKind.Text => IsString(node),
        SettingEditorKind.AddressTable => node is JsonObject map && map.All(p => IsString(p.Value)),
        SettingEditorKind.StringList => node is JsonArray list && list.All(IsString),
        _ => true
    };

    private static bool IsString(JsonNode? node) => node is JsonValue v && v.GetValueKind() == JsonValueKind.String;

    internal static IReadOnlyList<AddressLabelRow> Rows(JsonObject map) =>
        map.Select(p => new AddressLabelRow(p.Key, p.Value!.GetValue<string>())).ToArray();

    internal static IReadOnlyList<ListItemRow> Items(JsonArray list) =>
        list.Select(e => new ListItemRow(e!.GetValue<string>())).ToArray();

    /// <summary>
    /// The table as a JSON object, in row order. A row left entirely blank is not a row; a row with
    /// only one of its two cells is kept, so the catalog says what is missing. Returns the address
    /// that appears twice instead, because an object would keep only one of them.
    /// </summary>
    internal static (JsonObject? Value, string? Duplicate) Table(IEnumerable<AddressLabelRow> rows)
    {
        var map = new JsonObject();
        foreach (var row in rows)
        {
            var address = row.Address.Trim();
            var label = row.Label.Trim();
            if (address.Length == 0 && label.Length == 0) continue;
            if (map.ContainsKey(address)) return (null, address);
            map[address] = label;
        }
        return (map, null);
    }

    /// <summary>The list as a JSON array, in row order, blank rows left out.</summary>
    internal static JsonArray List(IEnumerable<ListItemRow> rows)
    {
        var list = new JsonArray();
        foreach (var row in rows)
        {
            var value = row.Value.Trim();
            if (value.Length > 0) list.Add(value);
        }
        return list;
    }

    /// <summary>
    /// What the catalog says about this exact JSON text: <see langword="null"/> when it would be
    /// accepted, otherwise the catalog's own description of what it expects.
    /// </summary>
    internal static string? Check(SettingDefinition definition, string json)
    {
        if (json.Length > EvidenceSettings.MaxValueBytes) return $"at most {EvidenceSettings.MaxValueBytes} bytes";
        JsonNode? node;
        try { node = JsonNode.Parse(json); }
        catch (JsonException) { return "valid JSON"; }
        return node is null ? "a value, not null" : definition.Validate(node);
    }
}

/// <summary>The edit of one setting: what the operator typed, the JSON it becomes, and whether it may be saved.</summary>
internal sealed class SettingEdit
{
    private readonly bool spanish;
    private bool toggle;
    private string text = "";
    private string reason = "";

    internal SettingEdit(SettingDefinition definition, JsonNode? current, bool spanish)
    {
        Definition = definition;
        this.spanish = spanish;
        Current = current;
        Kind = SettingEditors.KindFor(definition.Default, current);
        var value = current ?? definition.Default;
        CurrentJson = current?.ToJsonString();
        switch (Kind)
        {
            case SettingEditorKind.Toggle:
                toggle = value.GetValue<bool>();
                break;
            case SettingEditorKind.Number:
                text = value.ToJsonString();
                break;
            case SettingEditorKind.Text:
                text = value.GetValue<string>();
                break;
            case SettingEditorKind.AddressTable:
                foreach (var row in SettingEditors.Rows((JsonObject)value)) Addresses.Add(row);
                break;
            case SettingEditorKind.StringList:
                foreach (var row in SettingEditors.Items((JsonArray)value)) Items.Add(row);
                break;
            default:
                text = value.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
                break;
        }
        Addresses.CollectionChanged += OnRowsChanged;
        Items.CollectionChanged += OnRowsChanged;
        foreach (var row in Addresses) row.PropertyChanged += OnRowChanged;
        foreach (var row in Items) row.PropertyChanged += OnRowChanged;
    }

    /// <summary>Raised on every change to the value or the reason, so the window can redraw the checks.</summary>
    internal event EventHandler? Edited;

    internal SettingDefinition Definition { get; }

    internal SettingEditorKind Kind { get; }

    /// <summary>The value read from the store, or <see langword="null"/> when the store was not read.</summary>
    internal JsonNode? Current { get; }

    internal string? CurrentJson { get; }

    internal ObservableCollection<AddressLabelRow> Addresses { get; } = [];

    internal ObservableCollection<ListItemRow> Items { get; } = [];

    internal bool Toggle
    {
        get => toggle;
        set { toggle = value; OnEdited(); }
    }

    /// <summary>The text of the number, text and JSON editors.</summary>
    internal string Text
    {
        get => text;
        set { text = value ?? ""; OnEdited(); }
    }

    internal string Reason
    {
        get => reason;
        set { reason = value ?? ""; OnEdited(); }
    }

    internal bool HasReason => !string.IsNullOrWhiteSpace(reason);

    /// <summary>
    /// The JSON text the editor would store, or <see langword="null"/>, and why it would be refused:
    /// the catalog's own words, or what JSON cannot represent.
    /// </summary>
    internal (string? Json, string? Problem) Proposed()
    {
        string json;
        switch (Kind)
        {
            case SettingEditorKind.Toggle:
                json = toggle ? "true" : "false";
                break;
            case SettingEditorKind.Number:
                // Text that is not a JSON number goes to the catalog as text, so the catalog's own
                // sentence ("a whole number from 1 to 90") is what the operator reads.
                var trimmed = text.Trim();
                json = IsJsonNumber(trimmed) ? trimmed : JsonValue.Create(trimmed).ToJsonString();
                break;
            case SettingEditorKind.Text:
                json = JsonValue.Create(text.Trim()).ToJsonString();
                break;
            case SettingEditorKind.AddressTable:
                var (table, duplicate) = SettingEditors.Table(Addresses);
                if (table is null)
                    return (null, L($"'{DisplayText.Clean(duplicate, 64)}' appears in two rows; keep one.",
                        $"'{DisplayText.Clean(duplicate, 64)}' aparece en dos filas; deje una."));
                json = table.ToJsonString();
                break;
            case SettingEditorKind.StringList:
                json = SettingEditors.List(Items).ToJsonString();
                break;
            default:
                try
                {
                    var node = JsonNode.Parse(text);
                    if (node is null) return (null, L("Expected a value, not null.", "Se espera un valor, no null."));
                    json = node.ToJsonString();
                }
                catch (JsonException)
                {
                    return (null, L("This is not valid JSON.", "Esto no es JSON válido."));
                }
                break;
        }
        var problem = SettingEditors.Check(Definition, json);
        return (json, problem is null ? null : L("Expected ", "Se espera: ") + DisplayText.Clean(problem, 200) + ".");
    }

    /// <summary>Whether the value differs from the one read. Always true when nothing was read.</summary>
    internal bool Changed => Proposed().Json is { } json && json != CurrentJson;

    internal bool CanSave(bool writable) => writable && Current is not null && HasReason && Proposed() is { Json: not null, Problem: null } &&
        Changed;

    internal bool CanReset(bool writable, bool isDefault) => writable && Current is not null && !isDefault && HasReason;

    internal void AddAddress(string address = "")
    {
        var row = new AddressLabelRow(address);
        Addresses.Add(row);
    }

    internal void AddItem(string value = "") => Items.Add(new ListItemRow(value));

    private static bool IsJsonNumber(string text)
    {
        if (text.Length == 0) return false;
        try { return JsonNode.Parse(text) is JsonValue v && v.GetValueKind() == JsonValueKind.Number; }
        catch (JsonException) { return false; }
    }

    private void OnRowsChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        foreach (var row in e.NewItems?.OfType<INotifyPropertyChanged>() ?? []) row.PropertyChanged += OnRowChanged;
        foreach (var row in e.OldItems?.OfType<INotifyPropertyChanged>() ?? []) row.PropertyChanged -= OnRowChanged;
        OnEdited();
    }

    private void OnRowChanged(object? sender, PropertyChangedEventArgs e) => OnEdited();

    private void OnEdited() => Edited?.Invoke(this, EventArgs.Empty);

    private string L(string english, string es) => spanish ? es : english;
}

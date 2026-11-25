using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using WPShield.Evidence;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield settings</c> - the evidence store's settings (ADR 0007, amendment).
/// </summary>
/// <remarks>
/// <para>
/// <c>list</c>, <c>get</c> and <c>history</c> open the store read-only. <c>set</c> and <c>reset</c>
/// need elevation and go through <see cref="EvidenceSettings"/>, which validates against the catalog
/// and records who changed what and why. They never create or migrate the store: the service owns
/// the file, and a settings tool that created it would have to guess at a schema it does not own.
/// </para>
/// <para>
/// Nothing here applies a change. Each setting declares when it takes effect, and the command says
/// that instead of implying a reload - the configuration rule <c>AGENTS.md</c> states for files.
/// </para>
/// </remarks>
internal static class SettingsCommand
{
    public const string Help = """
        wpshield settings - read and change the evidence store's settings.

        Usage:
          wpshield settings list [--json]
          wpshield settings get <key> [--json]
          wpshield settings set <key> <value> --reason <text>
          wpshield settings set <key> --value-file <file.json> --reason <text>
          wpshield settings reset <key> --reason <text>
          wpshield settings history [<key>] [--json]

          Every form also takes --store <path>. Write the action, the key and the value first and
          the options after them.

        list, get and history open the store read-only. set and reset need an elevated prompt; they
        refuse a key this version does not know, validate the value, and record the change in the
        store's settings history with your Windows user name and the reason. set replaces the whole
        value: to add one label, get labels.addresses, edit it, and set all of it back.

        Values are JSON. A text setting also takes a bare word: 'set attacks.default_range 7d'.
        Windows PowerShell 5.1 drops the quotes inside an argument on its way to a program, so
        give an object such as labels.addresses in a file with --value-file (64 KB at most).

        This command applies nothing. Each setting says when it takes effect:
          next use     the next time something reads it (a pruning pass, a query, a view opening)
          next start   the next time the process that reads it starts

        Exit codes:
          0   done
          1   an argument was wrong, the key is unknown, the value was refused, or the store could
              not be opened (set and reset: not elevated)
          2   the store cannot be read by this build
          3   there is no evidence store
        """;

    private static readonly string[] ValueOptions = ["--store", "--reason", "--value-file"];

    private static readonly JsonSerializerOptions Readable = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    public static int Run(IReadOnlyList<string> args, TextWriter output, TextWriter error) =>
        Run(args, output, error, EvidenceStore.DefaultPath, EvidenceAccess.IsElevated, EvidenceAccess.CurrentUser, () => DateTimeOffset.UtcNow);

    internal static int Run(IReadOnlyList<string> args, TextWriter output, TextWriter error, string defaultStore,
        Func<bool> elevated, Func<string> user, Func<DateTimeOffset> now)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        var (positionals, options) = Split(args);
        options.RejectRepeated();
        if (options.Get("--json") is not null) throw new CliArgumentException("--json takes no value.");
        var action = positionals.Count > 0 ? positionals[0].Trim().ToLowerInvariant() : "list";
        try
        {
            return action switch
            {
                "list" => List(positionals, options, output, defaultStore, elevated),
                "get" => Get(positionals, options, output, defaultStore, elevated),
                "set" => Change(positionals, options, output, error, defaultStore, elevated, user, now, reset: false),
                "reset" => Change(positionals, options, output, error, defaultStore, elevated, user, now, reset: true),
                "history" => History(positionals, options, output, defaultStore, elevated),
                _ => throw new CliArgumentException(
                    $"Unknown settings action '{NetworkMonitorCommand.ConsoleLabel(action)}'. Use list, get, set, reset or history.")
            };
        }
        catch (EvidenceAccessException ex)
        {
            error.WriteLine("ERROR: " + ex.Message);
            return ex.ExitCode;
        }
        catch (Exception ex) when (ex is SqliteException or InvalidOperationException or InvalidCastException or JsonException)
        {
            error.WriteLine("ERROR: the evidence store could not be read: " + NetworkMonitorCommand.ConsoleLabel(ex.Message));
            return 2;
        }
    }

    /// <summary>
    /// Separates the action, key and value from the options. <see cref="CliOptions"/> skips positional
    /// tokens, but it would also take a positional after a bare flag as that flag's value, so only the
    /// options that take a value consume the token after them.
    /// </summary>
    private static (List<string> Positionals, CliOptions Options) Split(IReadOnlyList<string> args)
    {
        var positionals = new List<string>();
        var options = new List<string>();
        for (var i = 0; i < args.Count; i++)
        {
            var token = args[i];
            if (!token.StartsWith("--", StringComparison.Ordinal))
            {
                positionals.Add(token);
                continue;
            }
            options.Add(token);
            if (!token.Contains('=', StringComparison.Ordinal) && ValueOptions.Contains(token, StringComparer.OrdinalIgnoreCase) &&
                i + 1 < args.Count && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                options.Add(args[++i]);
        }
        return (positionals, CliOptions.Parse(options));
    }

    private static int List(List<string> positionals, CliOptions options, TextWriter output, string defaultStore, Func<bool> elevated)
    {
        options.RejectUnknown("--store", "--json");
        Positionals(positionals, 1, "settings list takes no key.");
        using var store = EvidenceAccess.OpenReadOnly(AttacksCommand.StorePath(options, defaultStore), elevated());
        var values = new EvidenceSettings(store).List();
        if (options.Has("--json"))
        {
            output.WriteLine(JsonSerializer.Serialize(values.Select(Dto).ToArray(), AttacksCommand.JsonOptions));
            return 0;
        }
        var rows = values.Select(v => new[]
        {
            v.Key, Short(v.Value), v.IsDefault ? "default" : Stored(v), EffectName(v.Effect)
        }).ToArray();
        var widths = Enumerable.Range(0, 4).Select(c => Math.Max(new[] { "KEY", "VALUE", "SET", "TAKES EFFECT" }[c].Length, rows.Max(r => r[c].Length))).ToArray();
        string Line(string[] cells) => string.Join("  ", cells.Select((cell, c) => c == cells.Length - 1 ? cell : cell.PadRight(widths[c]))).TrimEnd();
        output.WriteLine(Line(["KEY", "VALUE", "SET", "TAKES EFFECT"]));
        foreach (var row in rows) output.WriteLine(Line(row));
        output.WriteLine();
        output.WriteLine("'wpshield settings get <key>' shows a whole value and what it does. Changing one needs an elevated prompt.");
        return 0;
    }

    private static int Get(List<string> positionals, CliOptions options, TextWriter output, string defaultStore, Func<bool> elevated)
    {
        options.RejectUnknown("--store", "--json");
        Positionals(positionals, 2, "settings get takes exactly one key.");
        var key = Key(positionals.Count > 1 ? positionals[1] : null);
        using var store = EvidenceAccess.OpenReadOnly(AttacksCommand.StorePath(options, defaultStore), elevated());
        var value = new EvidenceSettings(store).List().Single(v => v.Key == key);
        if (options.Has("--json"))
        {
            output.WriteLine(JsonSerializer.Serialize(Dto(value), AttacksCommand.JsonOptions));
            return 0;
        }
        var definition = SettingCatalog.All[key];
        output.WriteLine(key);
        output.WriteLine("  Value         " + Show(value.Value));
        output.WriteLine("  Set           " + (value.IsDefault ? "never; this is the default" : Stored(value)));
        output.WriteLine("  Default       " + Show(definition.Default));
        output.WriteLine("  Takes effect  " + EffectName(value.Effect));
        output.WriteLine("  About         " + definition.Description);
        return 0;
    }

    private static int Change(List<string> positionals, CliOptions options, TextWriter output, TextWriter error, string defaultStore,
        Func<bool> elevated, Func<string> user, Func<DateTimeOffset> now, bool reset)
    {
        options.RejectUnknown(reset ? ["--store", "--reason"] : ["--store", "--reason", "--value-file"]);
        var key = Key(positionals.Count > 1 ? positionals[1] : null);
        var definition = SettingCatalog.All[key];
        string? json = null;
        if (reset)
            Positionals(positionals, 2, "settings reset takes exactly one key.");
        else if (options.Has("--value-file"))
        {
            Positionals(positionals, 2, "Give the value on the command line or with --value-file, not both.");
            json = ReadValueFile(options.Get("--value-file"));
        }
        else
        {
            if (positionals.Count != 3) throw new CliArgumentException("settings set takes a key and one value: settings set <key> <value> --reason <text>.");
            json = positionals[2];
        }
        var reason = options.Get("--reason");
        if (string.IsNullOrWhiteSpace(reason))
            throw new CliArgumentException("--reason is required: every change is recorded with who made it and why.");

        // The value is checked before elevation is asked about, so a quoting mistake is found first.
        var node = json is null ? null : Parse(definition, json);

        if (!elevated())
        {
            error.WriteLine("ERROR: changing a setting needs an elevated prompt. The evidence store admits only administrators and the");
            error.WriteLine("       WPShield service, and every change is recorded with the Windows user who made it.");
            return 1;
        }

        using var store = EvidenceAccess.OpenForSettings(AttacksCommand.StorePath(options, defaultStore), elevated: true);
        var settings = new EvidenceSettings(store);
        SettingChange change;
        try
        {
            change = node is null
                ? settings.Reset(key, user(), reason, now())
                : settings.Set(key, node.ToJsonString(), user(), reason, now());
        }
        catch (ArgumentException ex)
        {
            throw new CliArgumentException(NetworkMonitorCommand.ConsoleLabel(ex.Message));
        }
        var was = change.OldValue is null ? "the default" : Show(JsonNode.Parse(change.OldValue));
        output.WriteLine(change.NewValue is null
            ? $"{key} is back to its default, {Show(definition.Default)} (it was {was})."
            : $"{key} is now {Show(JsonNode.Parse(change.NewValue))} (it was {was}).");
        output.WriteLine($"Recorded in the settings history: {NetworkMonitorCommand.ConsoleLabel(change.ChangedBy)}, " +
            $"{change.At.ToUniversalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)} UTC, \"{NetworkMonitorCommand.ConsoleLabel(change.Reason)}\".");
        output.WriteLine(EffectSentence(change.Effect));
        return 0;
    }

    private static int History(List<string> positionals, CliOptions options, TextWriter output, string defaultStore, Func<bool> elevated)
    {
        options.RejectUnknown("--store", "--json");
        Positionals(positionals, 2, "settings history takes at most one key.");
        // A misspelt key would otherwise answer with an empty history, as if nothing had changed.
        var key = positionals.Count > 1 ? Key(positionals[1]) : null;
        using var store = EvidenceAccess.OpenReadOnly(AttacksCommand.StorePath(options, defaultStore), elevated());
        var changes = new EvidenceSettings(store).History(key);
        if (options.Has("--json"))
        {
            output.WriteLine(JsonSerializer.Serialize(changes.Select(c => new ChangeDto(c.Key, c.OldValue, c.NewValue, c.At,
                c.ChangedBy, c.Reason, EffectName(c.Effect))).ToArray(), AttacksCommand.JsonOptions));
            return 0;
        }
        if (changes.Count == 0)
        {
            output.WriteLine(key is null ? "No setting has been changed in this store." : $"{key} has never been changed in this store.");
            return 0;
        }
        foreach (var change in changes)
        {
            var from = change.OldValue is null ? "default" : Short(JsonNode.Parse(change.OldValue));
            var to = change.NewValue is null ? "default (reset)" : Short(JsonNode.Parse(change.NewValue));
            output.WriteLine($"{change.At.ToUniversalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)} UTC  {change.Key}  " +
                $"{from} -> {to}  by {NetworkMonitorCommand.ConsoleLabel(change.ChangedBy)}: {NetworkMonitorCommand.ConsoleLabel(change.Reason)}");
        }
        return 0;
    }

    private static string Key(string? key)
    {
        if (key is not null && SettingCatalog.All.ContainsKey(key)) return key;
        var known = string.Join(", ", SettingCatalog.All.Keys.Order(StringComparer.Ordinal));
        throw new CliArgumentException(key is null
            ? $"Name a setting. Known settings: {known}."
            : $"'{NetworkMonitorCommand.ConsoleLabel(key)}' is not a setting this version knows. Known settings: {known}.");
    }

    private static void Positionals(List<string> positionals, int max, string message)
    {
        if (positionals.Count > max) throw new CliArgumentException(message);
    }

    /// <summary>
    /// JSON, or a bare word for a text setting. The bare word exists because Windows PowerShell 5.1
    /// strips the quotes from <c>'"7d"'</c> before the program sees it.
    /// </summary>
    private static JsonNode Parse(SettingDefinition definition, string text)
    {
        if (text.Length > EvidenceSettings.MaxValueBytes)
            throw new CliArgumentException($"A setting value is at most {EvidenceSettings.MaxValueBytes} bytes.");
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(text);
        }
        catch (JsonException)
        {
            node = definition.Default.GetValueKind() == JsonValueKind.String && !string.IsNullOrWhiteSpace(text)
                ? JsonValue.Create(text.Trim())
                : throw new CliArgumentException($"{definition.Key}: the value is not valid JSON. Windows PowerShell 5.1 drops the quotes " +
                    "inside an argument; put the value in a file and pass --value-file, or escape each quote as \\\".");
        }
        if (node is null) throw new CliArgumentException($"{definition.Key}: expected a value, not null.");
        if (definition.Validate(node) is { } problem) throw new CliArgumentException($"{definition.Key}: expected {problem}.");
        return node;
    }

    private static string ReadValueFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new CliArgumentException("--value-file requires the path of a JSON file.");
        var file = new FileInfo(path);
        if (!file.Exists) throw new CliArgumentException($"--value-file: {NetworkMonitorCommand.ConsoleLabel(path)} does not exist.");
        if (file.Length > EvidenceSettings.MaxValueBytes)
            throw new CliArgumentException($"--value-file: a setting value is at most {EvidenceSettings.MaxValueBytes} bytes.");
        return File.ReadAllText(file.FullName);
    }

    internal static string EffectName(SettingEffect effect) => effect == SettingEffect.NextStart ? "next start" : "next use";

    internal static string EffectSentence(SettingEffect effect) => effect == SettingEffect.NextStart
        ? "Takes effect the next time the process that reads it starts. Nothing running has changed, and this command restarts nothing."
        : "Takes effect at its next use - the next pruning pass, query or view that reads it. This command reloaded nothing.";

    private static string Stored(SettingValue value) =>
        $"v{value.Version.ToString(CultureInfo.InvariantCulture)} " +
        $"{value.UpdatedAt?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)} UTC " +
        $"by {NetworkMonitorCommand.ConsoleLabel(value.UpdatedBy)}";

    /// <summary>Readable JSON with accented letters kept; control and format characters replaced.</summary>
    private static string Show(JsonNode? node) => node is null ? "null" : NetworkMonitorCommand.ConsoleLabel(node.ToJsonString(Readable));

    private static string Short(JsonNode? node)
    {
        if (node is JsonObject map)
            return map.Count == 1 ? "{1 entry}" : $"{{{map.Count.ToString(CultureInfo.InvariantCulture)} entries}}";
        if (node is JsonArray list && list.Count > 1)
            return $"[{list.Count.ToString(CultureInfo.InvariantCulture)} entries]";
        var text = Show(node);
        return text.Length <= 40 ? text : text[..37] + "...";
    }

    private static SettingDto Dto(SettingValue value) => new(value.Key, value.Value, value.IsDefault, value.Version, value.UpdatedAt,
        value.UpdatedBy, EffectName(value.Effect), value.Description);

    private sealed record SettingDto(string Key, JsonNode Value, bool IsDefault, long Version, DateTimeOffset? UpdatedAt, string? UpdatedBy,
        string Effect, string Description);

    private sealed record ChangeDto(string Key, string? OldJson, string? NewJson, DateTimeOffset At, string ChangedBy, string Reason, string Effect);
}

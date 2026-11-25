using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using WPShield.Cli;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;

namespace WPShield.Desktop;

/// <summary>The two changes the Attacks detail panel makes about the selected address.</summary>
internal enum AddressAction { Label, Allow }

/// <summary>
/// The changes the Attacks detail panel makes about one address - its label in <c>labels.addresses</c>
/// and its place on <c>defense.allow</c> - built from the stored value as it was read, one entry at a
/// time, and checked by the catalog before anything is written.
/// </summary>
/// <remarks>
/// <para>
/// A setting is replaced whole when it is saved, so each change starts from the stored JSON, never from
/// a matcher such as <see cref="AddressLabels"/>, and changes exactly one entry: the address's own. A
/// label the address inherits from a network entry is never edited from here, and Allow never writes a
/// network.
/// </para>
/// <para>
/// Allow loosens protection. The engine never decides against an allowed address, and a network decision
/// is stopped when any address in it is protected, so allowing one address also stops <c>HOST-AUTH-003</c>
/// for its /24 or /64. The confirmation says both, and warns with counts when the address is guessing
/// account names or has a would-block decision in force.
/// </para>
/// </remarks>
internal static class AddressActions
{
    internal const int MaxLabel = 64;
    internal const int MaxReason = 200;

    internal static string Key(AddressAction action) => action == AddressAction.Label ? AddressLabels.SettingKey : DefenseSettings.Allow;

    /// <summary>The address as the settings store keeps it, or <see langword="null"/> for text that is not one address.</summary>
    internal static string? Canonical(string? address) =>
        address is not null && !address.Contains('/', StringComparison.Ordinal) && IPAddress.TryParse(address.Trim(), out var ip)
            ? AddressRanges.Canonical(ip).ToString()
            : null;

    /// <summary>Why neither change can be made now, or <see langword="null"/> when both can. The Settings window's door decides.</summary>
    internal static string? Unavailable(SettingsSnapshot? snapshot, bool spanish) => snapshot?.Access switch
    {
        null => L(spanish, "Checking whether the evidence store can be changed…", "Comprobando si se puede cambiar el almacén de evidencia…"),
        SettingsAccess.Writable => null,
        SettingsAccess.ReadOnly or SettingsAccess.CouldNotLook => L(spanish,
            "Labelling or allowing an address needs administrator rights: reopen this window as administrator.",
            "Etiquetar o permitir una dirección requiere permisos de administrador: abra esta ventana como administrador."),
        SettingsAccess.NoDirectory or SettingsAccess.NoStore => L(spanish,
            "There is no evidence store on this server yet: install the service with 'wpshield install'. Nothing is created from here.",
            "Aún no hay almacén de evidencia en este servidor: instale el servicio con 'wpshield install'. Desde aquí no se crea nada."),
        SettingsAccess.AccessDenied => L(spanish,
            "Access to the evidence store was denied although this window is elevated; 'wpshield install' sets its permissions.",
            "Se denegó el acceso al almacén de evidencia aunque esta ventana está elevada; 'wpshield install' establece sus permisos."),
        SettingsAccess.Schema => L(spanish,
            "Another version of WPShield wrote the evidence store; use the desktop that came with the installed service.",
            "Otra versión de WPShield escribió el almacén de evidencia; use el monitor que vino con el servicio instalado."),
        _ => L(spanish, "The evidence store could not be read, so nothing can be changed from here. ",
            "No se pudo leer el almacén de evidencia, así que desde aquí no se puede cambiar nada. ") + DisplayText.Clean(snapshot.Problem, 200)
    };

    /// <summary>What a window without a settings store says: nothing can be changed, and why.</summary>
    internal static string NoStore(bool spanish) => L(spanish,
        "The evidence store is not available to this window, so nothing can be changed from here.",
        "El almacén de evidencia no está disponible para esta ventana, así que desde aquí no se puede cambiar nada.");

    /// <summary>The address's own label, when <c>labels.addresses</c> has an entry for exactly it.</summary>
    internal static string? OwnLabel(JsonNode? labels, string address) =>
        labels is JsonObject map && map[address] is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;

    /// <summary>
    /// <c>labels.addresses</c> with this address's own entry set or replaced and every other entry as it was,
    /// or <see langword="null"/> when the stored value is not an object this build can change one entry of.
    /// </summary>
    internal static JsonObject? WithLabel(JsonNode? labels, string address, string label)
    {
        if (labels is not null and not JsonObject) return null;
        var map = labels is JsonObject current ? (JsonObject)current.DeepClone() : new JsonObject();
        map[address] = label.Trim();
        return map;
    }

    /// <summary>The <c>defense.allow</c> entry that already covers the address, exactly or as a network.</summary>
    internal static string? AllowedBy(JsonNode? allow, string address)
    {
        if (allow is not JsonArray list || !IPAddress.TryParse(address, out var ip)) return null;
        ip = AddressRanges.Canonical(ip);
        foreach (var entry in list)
            if (entry is JsonValue value && value.TryGetValue<string>(out var text) && AddressRanges.TryParseCanonical(text, out var network) &&
                network.Contains(ip))
                return text;
        return null;
    }

    /// <summary>
    /// <c>defense.allow</c> with exactly this address added - never its network - or <see langword="null"/>
    /// when the stored value is not a list this build can add one entry to.
    /// </summary>
    internal static JsonArray? WithAllowed(JsonNode? allow, string address)
    {
        if (allow is not null and not JsonArray) return null;
        var list = allow is JsonArray current ? (JsonArray)current.DeepClone() : new JsonArray();
        list.Add(address);
        return list;
    }

    /// <summary>The catalog's verdict on a proposed value, in its own words; <see langword="null"/> when it is acceptable.</summary>
    internal static string? Check(AddressAction action, JsonNode proposed) => SettingCatalog.All[Key(action)].Validate(proposed);

    /// <summary>The would-block decisions in force about the address or its /24 or /64; <see langword="null"/> when they were not read.</summary>
    internal static int? WouldBlockInForce(ActiveDecisions? decisions, string address, DateTimeOffset now)
    {
        if (decisions is null) return null;
        var network = EvidenceQueries.Network(address);
        return decisions.Decisions.Count(d => d.Action == DecisionActions.WouldBlock && d.ExpiresAt > now &&
            (d.Target == address || d.Target == network));
    }

    /// <summary>What the label editor says before anything is typed.</summary>
    internal static string LabelIntro(string address, string? own, string inherited, bool spanish)
    {
        var now = own is not null
            ? L(spanish, $"Its label now is “{DisplayText.Clean(own, MaxLabel)}”; saving replaces it. ",
                $"Su etiqueta ahora es «{DisplayText.Clean(own, MaxLabel)}»; guardar la reemplaza. ")
            : inherited.Length > 0
                ? L(spanish, $"It has no label of its own; it shows its network's, “{inherited}”, which stays as it is. ",
                    $"No tiene etiqueta propia; muestra la de su red, «{inherited}», que queda como está. ")
                : "";
        return L(spanish, $"Sets the label of {address} in labels.addresses: this exact address only. ",
                $"Asigna la etiqueta de {address} en labels.addresses: solo esta dirección exacta. ") + now +
            L(spanish, "A label describes an address; it never allows or blocks one.",
                "Una etiqueta describe una dirección; nunca la permite ni la bloquea.");
    }

    /// <summary>The confirmation Allow shows. It says plainly what allowing an address gives up.</summary>
    internal static string AllowConfirmation(string address, bool spanish)
    {
        var network = EvidenceQueries.Network(address);
        return L(spanish,
            $"Allow {address}: the decision engine will never decide against this address. A rule that fires on it is recorded as " +
            $"protected instead of would block. A decision about a network stops when any address in it is protected, so none will be " +
            $"made about {network} (HOST-AUTH-003) either. Only this exact address is added to defense.allow, never its network. " +
            "It takes effect at the next evaluation; a decision already in force is not withdrawn and ends at its expiry. Monitor: nothing is blocked either way.",
            $"Permitir {address}: el motor de decisiones nunca decidirá contra esta dirección. Una regla que se active con ella queda " +
            $"registrada como protegida en lugar de bloquearía. Una decisión sobre una red se detiene cuando cualquier dirección de ella " +
            $"está protegida, así que tampoco se decidirá sobre {network} (HOST-AUTH-003). Solo se añade esta dirección exacta a " +
            "defense.allow, nunca su red. Surte efecto en la próxima evaluación; una decisión ya vigente no se retira y termina a su " +
            "vencimiento. Monitor: en ningún caso se bloquea nada.");
    }

    /// <summary>
    /// The warning Allow shows when the address behaves like an attacker: attempts on names that do not
    /// exist, or a would-block decision in force. <see langword="null"/> when there is neither. A count that could not
    /// be read is said, never left out: nobody could look is not "none".
    /// </summary>
    /// <param name="source">The address's row in the range shown, or <see langword="null"/> when it could not be read.</param>
    /// <param name="period">The range the counts come from, in words, such as "the last 24 hours".</param>
    internal static string? AllowWarning(AttackSource? source, int? wouldBlock, string period, bool spanish)
    {
        var parts = new List<string>();
        if (source is null)
            parts.Add(L(spanish, $"how many of its attempts in {period} named accounts that do not exist could not be read",
                $"no se pudo leer cuántos de sus intentos en {period} usaron cuentas que no existen"));
        else if (source is { UnknownAttempts: > 0 } s)
            parts.Add(L(spanish,
                $"in {period} {s.UnknownAttempts:N0} of its {s.Attempts:N0} attempts named accounts that do not exist - guessing names, which a colleague mistyping a password does not do",
                $"en {period} {s.UnknownAttempts:N0} de sus {s.Attempts:N0} intentos usaron cuentas que no existen: adivina nombres, algo que no hace un compañero que se equivoca de contraseña"));
        if (wouldBlock is int count and > 0)
            parts.Add(count == 1
                ? L(spanish, "1 would-block decision is in force about it or its network", "hay 1 decisión «bloquearía» vigente sobre ella o su red")
                : L(spanish, $"{count:N0} would-block decisions are in force about it or its network", $"hay {count:N0} decisiones «bloquearía» vigentes sobre ella o su red"));
        // Nobody could look is not "no decision": say so rather than staying quiet.
        else if (wouldBlock is null)
            parts.Add(L(spanish, "whether a decision is in force about it could not be read", "no se pudo leer si hay una decisión vigente sobre ella"));
        if (parts.Count == 0) return null;
        return L(spanish, "Look before you allow it: ", "Mire antes de permitirla: ") + string.Join(L(spanish, "; and ", "; y "), parts) + ".";
    }

    /// <summary>What a save that worked says: what is stored now, who it was recorded as, and when it takes effect.</summary>
    internal static string Saved(AddressAction action, string address, string? label, SettingChange change, bool spanish)
    {
        var recorded = L(spanish, $"Recorded in the settings history: {DisplayText.Clean(change.ChangedBy, 64)}, {Time(change.At)} UTC.",
            $"Registrado en el historial de ajustes: {DisplayText.Clean(change.ChangedBy, 64)}, {Time(change.At)} UTC.");
        return action == AddressAction.Label
            ? L(spanish, $"Saved: {address} is labelled “{DisplayText.Clean(label, MaxLabel)}”. ", $"Guardado: {address} tiene la etiqueta «{DisplayText.Clean(label, MaxLabel)}». ") +
              recorded + " " + L(spanish, "It shows wherever the address appears from the next read. A label never allows or blocks.",
                  "Aparece donde se muestre la dirección desde la próxima lectura. Una etiqueta nunca permite ni bloquea.")
            : L(spanish, $"Saved: {address} is on defense.allow. ", $"Guardado: {address} está en defense.allow. ") + recorded + " " +
              L(spanish, "It takes effect at the next evaluation. Nothing was reloaded, and a decision already in force is not withdrawn.",
                  "Surte efecto en la próxima evaluación. No se recargó nada, y una decisión ya vigente no se retira.");
    }

    /// <summary>What a save that failed says. The typed text stays in the editor either way.</summary>
    internal static string Failure(Exception error, string key, bool spanish)
    {
        var reason = error switch
        {
            SettingConflictException conflict => conflict.Now.IsDefault
                ? L(spanish, $"{key} was reset to its default elsewhere after this panel read it.",
                    $"otra herramienta restableció {key} después de que este panel lo leyera.")
                : L(spanish, $"{DisplayText.Clean(conflict.Now.UpdatedBy, 64)} changed {key} at {Time(conflict.Now.UpdatedAt)} UTC, after this panel read it.",
                    $"{DisplayText.Clean(conflict.Now.UpdatedBy, 64)} cambió {key} a las {Time(conflict.Now.UpdatedAt)} UTC, después de que este panel lo leyera."),
            SqliteException sqlite => L(spanish,
                $"the store could not be written (SQLite error {sqlite.SqliteErrorCode}: {DisplayText.Clean(sqlite.Message, 160)}). The service may have been holding it; try again.",
                $"no se pudo escribir en el almacén (error de SQLite {sqlite.SqliteErrorCode}: {DisplayText.Clean(sqlite.Message, 160)}). Puede que el servicio lo estuviera usando; vuelva a intentarlo."),
            ArgumentException refused => L(spanish, "the store refused the value: ", "el almacén rechazó el valor: ") + DisplayText.Clean(refused.Message, 200),
            EvidenceAccessException access => DisplayText.Clean(access.Message, 300),
            _ => DisplayText.Clean(error.GetType().Name + ": " + error.Message, 200)
        };
        var again = error is SettingConflictException
            ? L(spanish, " The panel has read it again, so what it shows now includes that change. Your text is still here: save again to apply it on top.",
                " El panel volvió a leerlo, así que lo que muestra ahora incluye ese cambio. Su texto sigue aquí: guarde de nuevo para aplicarlo encima.")
            : L(spanish, " Your text is still here.", " Su texto sigue aquí.");
        return L(spanish, "Not saved: ", "No se guardó: ") + reason + again;
    }

    private static string Time(DateTimeOffset? at) =>
        at?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) ?? "—";

    private static string L(bool spanish, string english, string es) => spanish ? es : english;
}

using WPShield.Evidence;

namespace WPShield.Desktop;

/// <summary>
/// The desktop's names and descriptions for the settings it knows. A setting it does not know - one
/// a newer catalog added - is shown with its key as the name and the catalog's own description, so
/// it is listed and editable before anyone translates it.
/// </summary>
internal static class SettingNames
{
    private static readonly Dictionary<string, (string Name, string Description, string Nombre, string Descripcion)> Known =
        new(StringComparer.Ordinal)
        {
            ["retention.raw_days"] = ("Detailed records kept (days)",
                "Days of detailed failed logons the store keeps: every attempt with its account name. Older periods keep hourly counts only.",
                "Registros detallados que se guardan (días)",
                "Días de inicios de sesión fallidos en detalle que guarda el almacén: cada intento con su cuenta. Los periodos más antiguos guardan solo recuentos por hora."),
            ["retention.aggregate_days"] = ("Hourly counts and decisions kept (days)",
                "Days of hourly aggregates and block decisions the store keeps.",
                "Recuentos por hora y decisiones que se guardan (días)",
                "Días de agregados por hora y de decisiones de bloqueo que guarda el almacén."),
            ["retention.event_days"] = ("Other evidence kept (days)",
                "Days of other evidence events the store keeps.",
                "Otra evidencia que se guarda (días)",
                "Días que el almacén guarda los demás eventos de evidencia."),
            ["retention.max_megabytes"] = ("Store size limit (MB)",
                "Size the database file may reach before its detailed rows are pruned. Hourly counts stay.",
                "Límite de tamaño del almacén (MB)",
                "Tamaño que puede alcanzar el archivo antes de podar sus filas detalladas. Los recuentos por hora se conservan."),
            ["attacks.default_range"] = ("Attacks view opens with",
                "Range the Attacks view and 'wpshield attacks' open with: 1h, 6h, 24h, 7d or 30d.",
                "La vista Ataques se abre con",
                "Rango con el que se abren la vista Ataques y 'wpshield attacks': 1h, 6h, 24h, 7d o 30d."),
            [AddressLabels.SettingKey] = ("Address labels",
                "Names for addresses and networks you know: your office, your own connection. Labels describe; they never allow or block.",
                "Etiquetas de direcciones",
                "Nombres para direcciones y redes que conoce: su oficina, su propia conexión. Las etiquetas describen; nunca permiten ni bloquean."),
            ["mcp.detailed_records"] = ("MCP answers include single records",
                "Whether 'wpshield mcp' may return single attempts and account names, or only aggregates. Answers leave the host. Read when the MCP server starts.",
                "Las respuestas MCP incluyen registros individuales",
                "Si 'wpshield mcp' puede devolver intentos individuales y nombres de cuenta, o solo agregados. Las respuestas salen del servidor. Se lee cuando arranca el servidor MCP."),
        };

    internal static bool IsKnown(string key) => Known.ContainsKey(key);

    internal static string Name(string key, bool spanish) =>
        Known.TryGetValue(key, out var known) ? spanish ? known.Nombre : known.Name : DisplayText.Clean(key, 80);

    internal static string Description(string key, string catalogDescription, bool spanish) =>
        Known.TryGetValue(key, out var known) ? spanish ? known.Descripcion : known.Description : DisplayText.Clean(catalogDescription, 400);

    internal static string Effect(SettingEffect effect, bool spanish) => effect == SettingEffect.NextStart
        ? spanish
            ? "Al próximo arranque: se aplica cuando vuelva a arrancar el proceso que lo lee. Guardar aquí no reinicia nada ni cambia lo que ya está en marcha."
            : "Next start: applies the next time the process that reads it starts. Saving here restarts nothing and changes nothing already running."
        : spanish
            ? "Al próximo uso: se aplica la próxima vez que algo lo lea (una poda, una consulta, una vista que se abre). Guardar aquí no recarga nada."
            : "Next use: applies the next time something reads it (a pruning pass, a query, a view opening). Saving here reloads nothing.";
}

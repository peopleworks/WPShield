namespace WPShield.Analyst;

/// <summary>
/// What leaves the host for each provider (ADR 0010, section 7), in the operator's language. Printed by
/// <c>wpshield analyst status</c>, so the operator reads it before the first run; the desktop shows the
/// same text before its first run.
/// </summary>
internal static class ProviderDisclosure
{
    /// <summary>The environment variable each provider's key is read from. Never a setting, an argument or a file.</summary>
    public static string? KeyVariable(string provider) => provider switch
    {
        "anthropic" => "ANTHROPIC_API_KEY",
        "relay" => "RELAY_API_KEY",
        _ => null
    };

    public static IReadOnlyList<string> Lines(string provider, Uri? relayUrl, bool detailedRecords, bool spanish)
    {
        if (provider is not ("anthropic" or "relay"))
            return [spanish
                ? "No hay proveedor elegido (analyst.provider), así que nada sale de este servidor."
                : "No provider is chosen (analyst.provider), so nothing leaves this host."];

        var lines = new List<string>
        {
            spanish
                ? "Lo que sale de este servidor cuando el analista se ejecuta:"
                : "What leaves this host when the analyst runs:",
            spanish
                ? "  - las instrucciones del analista, su pregunta y cada resultado de herramienta que el modelo pida;"
                : "  - the analyst's instructions, your question, and every tool result the model asks for;",
            spanish
                ? "  - en esos resultados: conteos, direcciones de origen y sus redes, cobertura, decisiones de bloqueo, ajustes y sus etiquetas de direcciones, que nombran sus propias direcciones;"
                : "  - in those results: counts, source addresses and their networks, coverage, block decisions, settings, and your address labels, which name your own addresses;",
            detailedRecords
                ? spanish
                    ? "  - los nombres de cuenta probados (entre ellos cuentas reales de este servidor), quién pidió cada decisión y quién cambió cada ajuste, porque mcp.detailed_records es true."
                    : "  - the account names tried (real accounts on this server among them), who requested each decision and who changed each setting, because mcp.detailed_records is true."
                : spanish
                    ? "  - ni nombres de cuenta ni registros sueltos: mcp.detailed_records es false."
                    : "  - no account names and no single records: mcp.detailed_records is false."
        };

        if (provider == "anthropic")
        {
            lines.Add(spanish
                ? "Va a Anthropic, bajo los términos de su cuenta de la API. La clave se lee de ANTHROPIC_API_KEY y no se envía a ningún otro sitio."
                : "It goes to Anthropic, under your API terms. The key is read from ANTHROPIC_API_KEY and is sent nowhere else.");
        }
        else
        {
            var where = relayUrl?.ToString() ?? (spanish ? "(analyst.relay_url sin definir)" : "(analyst.relay_url is not set)");
            lines.Add(spanish
                ? $"Va al Relay de PeopleWorks en {where}, cuyo servidor lo contesta con una terminal Claude Code y las herramientas locales de esa terminal."
                : $"It goes to the PeopleWorks Relay at {where}, whose host answers it with a Claude Code terminal and that terminal's own local tools.");
            lines.Add(spanish
                ? "Lo que un texto inyectado en la evidencia puede hacer que esa terminal haga lo decide la configuración del Relay, no WPShield."
                : "What text injected into the evidence could make that terminal do is decided by the Relay's configuration, not by WPShield.");
            lines.Add(spanish
                ? "La clave se lee de RELAY_API_KEY. Su costo se cuenta como cero aquí, porque WPShield no lo paga; las ejecuciones sí cuentan."
                : "The key is read from RELAY_API_KEY. Its cost is counted as zero here, because WPShield does not pay it; its runs still count.");
        }
        lines.Add(spanish
            ? "El analista solo lee y recomienda. Nunca bloquea, desbloquea ni cambia un ajuste."
            : "The analyst only reads and recommends. It never blocks, unblocks or changes a setting.");
        return lines;
    }
}

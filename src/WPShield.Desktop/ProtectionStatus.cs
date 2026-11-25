using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Text.Json.Nodes;
using WPShield.Cli;
using WPShield.Cli.Install;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;
using WPShield.SecurityMonitor;

namespace WPShield.Desktop;

/// <summary>
/// One read of the evidence store for the Protection window: what the collector vouched for lately, the
/// decisions in force and those of the last day and month, and the two settings the window shows.
/// </summary>
/// <param name="RecentCoverage">The failed-logon collector's coverage rows of every status that overlap the last minutes.</param>
/// <param name="DayCounts">Decision records per action in the last 24 hours, counted exactly.</param>
/// <param name="Day">The newest decision records of the last 24 hours, at most <see cref="EvidenceProtectionStore.Shown"/> plus one.</param>
/// <param name="DayCoverage">The collector's coverage of the last 24 hours (<see cref="CoverageReport"/> state).</param>
internal sealed record ProtectionRead(DateTimeOffset At, IReadOnlyList<EvidenceCoverage> RecentCoverage, ActiveDecisions Active,
    IReadOnlyDictionary<string, long> DayCounts, IReadOnlyDictionary<string, long> MonthCounts,
    IReadOnlyList<DecisionRecord> Day, IReadOnlyList<DecisionRecord> Month, string DayCoverage, string MonthCoverage,
    JsonNode? Mode, JsonNode? Labels);

/// <summary>The evidence store as the Protection window asks it: one read-only open per refresh, closed again at once.</summary>
internal interface IProtectionStore
{
    ProtectionRead Read(DateTimeOffset now);
}

internal sealed class EvidenceProtectionStore(string path, Func<bool> elevated) : IProtectionStore
{
    /// <summary>Rows a tab lists at most; one more is read to know that there were more.</summary>
    internal const int Shown = 500;

    public ProtectionRead Read(DateTimeOffset now)
    {
        using var store = EvidenceAccess.OpenReadOnly(path, elevated());
        var queries = new EvidenceQueries(store);
        var settings = new EvidenceSettings(store);
        var day = now.AddHours(-24);
        var month = now.AddDays(-30);
        // A record written in the same millisecond as 'now' still belongs to the range.
        var end = now.AddSeconds(1);
        return new(now,
            queries.Coverage(now - ProtectionStatus.RecentSpan, now).Where(c => c.Source == EvidenceWriter.RawSource).ToArray(),
            queries.ActiveDecisions(now),
            queries.DecisionCounts(day, end), queries.DecisionCounts(month, end),
            queries.Decisions(day, end, Shown + 1), queries.Decisions(month, end, Shown + 1),
            CoverageReport.Analyse(queries.Coverage(day, now), day, now).State,
            CoverageReport.Analyse(queries.Coverage(month, now), month, now).State,
            settings.Get(DefenseSettings.Mode), settings.Get(AddressLabels.SettingKey));
    }
}

/// <summary>The Windows service WPShield as the service controller reports it. Read only; nothing here starts or stops it.</summary>
internal enum ServiceState { Running, Stopped, Starting, Stopping, Paused, NotInstalled, Unknown }

internal sealed record ServiceReading(ServiceState State, string? Problem = null);

internal static class ServiceReader
{
    /// <summary>ERROR_SERVICE_DOES_NOT_EXIST: the one answer that means "not installed".</summary>
    private const int DoesNotExist = 1060;

    internal static ServiceReading Read()
    {
        try
        {
            using var controller = new ServiceController(Installer.ServiceName);
            return new(controller.Status switch
            {
                ServiceControllerStatus.Running => ServiceState.Running,
                ServiceControllerStatus.Stopped => ServiceState.Stopped,
                ServiceControllerStatus.StartPending or ServiceControllerStatus.ContinuePending => ServiceState.Starting,
                ServiceControllerStatus.StopPending => ServiceState.Stopping,
                ServiceControllerStatus.Paused or ServiceControllerStatus.PausePending => ServiceState.Paused,
                _ => ServiceState.Unknown
            });
        }
        catch (InvalidOperationException ex) when (ex.InnerException is Win32Exception { NativeErrorCode: DoesNotExist })
        {
            return new(ServiceState.NotInstalled);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
            // Refused or failed: "nobody could ask" is not "not installed".
            return new(ServiceState.Unknown, DisplayText.Clean(ex.InnerException?.Message ?? ex.Message, 120));
        }
    }
}

/// <summary>What the store says about the collector: recording, alive but blind, stopped, or not read.</summary>
internal enum CollectorState { Recording, Blind, Stopped, Unread }

/// <param name="LastRecorded">How far the collector's <c>collected</c> coverage reaches, if it ever recorded.</param>
/// <param name="Problems">The reasons of current coverage rows that are not <c>collected</c>, as the collector wrote them.</param>
internal sealed record CollectorReading(CollectorState State, DateTimeOffset? LastRecorded, IReadOnlyList<string> Problems);

/// <summary>Green is earned, amber needs a look, grey is nothing (or nobody could look).</summary>
internal enum Tone { Green, Amber, Grey }

internal sealed record StatusLine(string Title, string Detail, Tone Tone);

/// <summary>One sensor chip. A planned one is drawn dotted and disabled: it records nothing yet.</summary>
internal sealed record SensorChip(string Name, Tone Tone, string Status, string Tooltip, bool Planned = false);

internal enum DecisionTab { InForce, Day, Month }

/// <summary>One row of the decisions table, cleaned for display.</summary>
internal sealed record ProtectionRow(string Target, string Label, string Rule, string Action, string Reason, string Since, string Until)
{
    internal bool Matches(string query) => query.Length == 0 ||
        Target.Contains(query, StringComparison.OrdinalIgnoreCase) ||
        Label.Contains(query, StringComparison.OrdinalIgnoreCase) ||
        Rule.Contains(query, StringComparison.OrdinalIgnoreCase);
}

/// <param name="WouldBlock">Would-block decisions in force now.</param>
/// <param name="Protected">Protected records of the last 24 hours; likewise <paramref name="Refused"/> and <paramref name="Report"/>.</param>
internal sealed record ProtectionCounts(string WouldBlock, string Protected, string Refused, string Report);

/// <summary>
/// Everything the Protection window says, decided from one read of the store and one read of the service
/// controller, so it is tested without a window. Monitor only: nothing here blocks or offers to.
/// </summary>
/// <remarks>
/// <para>
/// <b>A dot is earned.</b> The logon sensor is green only when the store shows the collector recording
/// within <see cref="EvidenceQueries.CurrentAllowance"/>, amber when a collector is alive but blind or its
/// coverage reports a problem (with the remedy), and grey when nothing records or nobody could look.
/// </para>
/// <para>
/// <b>Nobody could look is "—", never 0.</b> A store that could not be read, or a period the collector did not
/// record, shows a dash. A readable store with nothing in force shows 0 and says why nothing can be.
/// </para>
/// <para>
/// <b>The service and the collector are separate facts.</b> <c>wpshield evidence collect</c> runs the same
/// collector in the foreground with the service stopped; the window says that instead of contradicting
/// the store.
/// </para>
/// </remarks>
internal static class ProtectionStatus
{
    /// <summary>How far back the coverage rows that decide "current" are read.</summary>
    internal static readonly TimeSpan RecentSpan = TimeSpan.FromMinutes(10);

    internal static CollectorReading Collector(ProtectionRead? read)
    {
        if (read is null) return new(CollectorState.Unread, null, []);
        var since = read.At - EvidenceQueries.CurrentAllowance;
        var problems = read.RecentCoverage
            .Where(c => c.Status != "collected" && c.To >= since && c.From <= read.At)
            .OrderBy(c => c.Status == "unavailable" ? 0 : 1).ThenByDescending(c => c.To)
            .Select(c => c.Reason ?? c.Status).Distinct(StringComparer.Ordinal).Take(3).ToArray();
        // "Recording" is the store's one definition, the same that decides what is in force.
        if (read.Active.CollectorCurrent) return new(CollectorState.Recording, read.Active.CollectedUntil, problems);
        return problems.Length > 0
            ? new(CollectorState.Blind, read.Active.CollectedUntil, problems)
            : new(CollectorState.Stopped, read.Active.CollectedUntil, []);
    }

    /// <summary>The collector's state in the header. When the store could not be read, the remedy is the banner's to give.</summary>
    internal static StatusLine CollectorLine(CollectorReading collector, bool spanish) =>
        collector.State switch
        {
            CollectorState.Recording => new(L(spanish, "Recording", "Registrando"),
                L(spanish, $"Failed logons are being recorded; the collector's coverage reaches {Time(collector.LastRecorded)} UTC.",
                    $"Se registran los inicios de sesión fallidos; la cobertura del recolector llega hasta {Time(collector.LastRecorded)} UTC."),
                Tone.Green),
            CollectorState.Blind => new(L(spanish, "Running, not recording", "En marcha, sin registrar"),
                L(spanish, $"A collector is running but cannot read what it records ({Describe(collector.Problems[0], spanish)}), so no failed logon is " +
                        "being recorded. The logon sensor below says how to fix it.",
                    $"Hay un recolector en marcha, pero no puede leer lo que registra ({Describe(collector.Problems[0], spanish)}), así que no se " +
                        "registra ningún inicio de sesión fallido. El sensor de inicios de sesión indica cómo resolverlo."),
                Tone.Amber),
            CollectorState.Stopped => new(collector.LastRecorded is { } last
                    ? L(spanish, $"Stopped - last recorded {Time(last)} UTC", $"Detenido: último registro {Time(last)} UTC")
                    : L(spanish, "Stopped - nothing recorded yet", "Detenido: aún no se registró nada"),
                L(spanish, "Nothing is recording now. The Attacks view draws this time as no data, never as a quiet host.",
                    "Ahora no se registra nada. La vista Ataques dibuja este tiempo como sin datos, nunca como un servidor tranquilo."),
                Tone.Grey),
            _ => new(L(spanish, "Could not read the store", "No se pudo leer el almacén"),
                L(spanish, "Nobody could look, so whether anything is recording is unknown - not stopped. The notice above says what to do.",
                    "Nadie pudo mirar, así que no se sabe si algo está registrando; no es lo mismo que detenido. El aviso de arriba indica qué hacer."),
                Tone.Amber)
        };

    /// <summary>What to do when the store could not be read. Each reason has its own remedy.</summary>
    internal static string StoreRemedy(EvidenceProblem? problem, string? message, bool spanish) => problem switch
    {
        EvidenceProblem.NotElevated => L(spanish,
            "The evidence store admits only administrators and the WPShield service, and this window is not elevated: reopen it as administrator. " +
            "Nothing was read, which is not the same as nothing recorded.",
            "El almacén de evidencia solo admite a administradores y al servicio WPShield, y esta ventana no está elevada: ábrala como " +
            "administrador. No se leyó nada, que no es lo mismo que no haber registrado nada."),
        EvidenceProblem.AccessDenied => L(spanish,
            "Access to the evidence store was denied although this window is elevated. Check the folder's permissions; 'wpshield install' sets them.",
            "Se denegó el acceso al almacén de evidencia aunque esta ventana está elevada. Revise los permisos de la carpeta; 'wpshield install' los establece."),
        EvidenceProblem.Missing => L(spanish,
            "There is no evidence store on this server: install the service with 'wpshield install' and start it. This window creates nothing.",
            "No hay almacén de evidencia en este servidor: instale el servicio con 'wpshield install' e inícielo. Esta ventana no crea nada."),
        EvidenceProblem.Schema => L(spanish,
            "Another version of WPShield wrote the evidence store; use the desktop that came with the installed service.",
            "Otra versión de WPShield escribió el almacén de evidencia; use el monitor que vino con el servicio instalado."),
        _ => L(spanish, "The evidence store could not be read: ", "No se pudo leer el almacén de evidencia: ") + DisplayText.Clean(message, 300)
    };

    /// <summary>The Windows service, beside the collector state and never contradicting it.</summary>
    internal static StatusLine ServiceLine(ServiceReading service, CollectorReading collector, bool spanish)
    {
        var state = service.State switch
        {
            ServiceState.Running => L(spanish, "running", "en ejecución"),
            ServiceState.Stopped => L(spanish, "stopped", "detenido"),
            ServiceState.Starting => L(spanish, "starting", "iniciándose"),
            ServiceState.Stopping => L(spanish, "stopping", "deteniéndose"),
            ServiceState.Paused => L(spanish, "paused", "en pausa"),
            ServiceState.NotInstalled => L(spanish, "not installed", "no instalado"),
            _ => L(spanish, "could not be read", "no se pudo leer")
        };
        var title = L(spanish, $"Windows service WPShield: {state}", $"Servicio de Windows WPShield: {state}");
        var absent = service.State is ServiceState.Stopped or ServiceState.NotInstalled;
        var writing = collector.State is CollectorState.Recording or CollectorState.Blind;
        var detail = (service.State, collector.State) switch
        {
            (ServiceState.Unknown, _) => L(spanish,
                $"The service controller could not be asked ({DisplayText.Clean(service.Problem, 120)}); the collector state comes from the store.",
                $"No se pudo consultar al administrador de servicios ({DisplayText.Clean(service.Problem, 120)}); el estado del recolector viene del almacén."),
            _ when absent && writing => L(spanish,
                "A collector is writing to the store without the service: 'wpshield evidence collect' running in the foreground, which stops " +
                    "when its window closes - or the service stopped within the last two minutes.",
                "Hay un recolector escribiendo en el almacén sin el servicio: 'wpshield evidence collect' en primer plano, que se detiene al " +
                    "cerrar su ventana, o el servicio se detuvo hace menos de dos minutos."),
            (ServiceState.Running, CollectorState.Recording) => L(spanish, "The service is the collector recording.",
                "El servicio es el recolector que está registrando."),
            (ServiceState.Running, CollectorState.Blind) => L(spanish, "Its collector is running blind; the logon sensor below says why.",
                "Su recolector funciona a ciegas; el sensor de inicios de sesión indica por qué."),
            (ServiceState.Running, CollectorState.Stopped) => L(spanish,
                "But the store shows nothing recorded now: its evidence collection may be switched off (Evidence:Enabled) or idle because the " +
                    "evidence folder is missing. The service log says which.",
                "Pero el almacén no muestra ningún registro ahora: puede que su recolección de evidencia esté desactivada (Evidence:Enabled) o " +
                    "inactiva porque falta la carpeta de evidencia. El registro del servicio indica cuál."),
            (ServiceState.Stopped, CollectorState.Stopped) => L(spanish, "Nothing records failed logons while it is stopped.",
                "Mientras está detenido, nada registra los inicios de sesión fallidos."),
            (ServiceState.NotInstalled, _) => L(spanish, "'wpshield install' installs it; the service creates the evidence store once it runs.",
                "'wpshield install' lo instala; el servicio crea el almacén de evidencia cuando se ejecuta."),
            _ => ""
        };
        var tone = service.State == ServiceState.Running && collector.State == CollectorState.Recording ? Tone.Green
            : service.State is ServiceState.Unknown or ServiceState.Starting or ServiceState.Stopping or ServiceState.Paused || writing ||
              (service.State == ServiceState.Running && collector.State == CollectorState.Stopped) ? Tone.Amber
            : Tone.Grey;
        return new(title, detail, tone);
    }

    /// <summary>The mode, from <c>defense.mode</c>. Block does not exist in this version and is never offered.</summary>
    internal static StatusLine ModeLine(ProtectionRead? read, bool spanish)
    {
        if (read is null)
            return new(L(spanish, "Mode: —", "Modo: —"),
                L(spanish, "defense.mode is read from the store, which could not be read. This version runs Monitor only.",
                    "defense.mode se lee del almacén, que no se pudo leer. Esta versión solo funciona en Monitor."), Tone.Grey);
        var stored = read.Mode is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;
        return new(L(spanish, "Monitor - nothing is blocked", "Monitor: no se bloquea nada"),
            stored == DecisionActions.MonitorMode
                ? L(spanish, "defense.mode is monitor: every decision is recorded as would block and nothing is enforced anywhere.",
                    "defense.mode es monitor: cada decisión queda registrada como bloquearía y no se aplica nada en ningún sitio.")
                : L(spanish, $"defense.mode holds '{DisplayText.Clean(stored ?? read.Mode?.ToJsonString(), 32)}', which this version does not run; its engine runs in Monitor.",
                    $"defense.mode contiene '{DisplayText.Clean(stored ?? read.Mode?.ToJsonString(), 32)}', que esta versión no ejecuta; su motor funciona en Monitor."),
            Tone.Green);
    }

    internal static string BlockNotAvailable(bool spanish) => L(spanish,
        "Block mode does not exist in this version. It needs the enforcer of ADR 0006, which has not passed its validation; defense.mode accepts only monitor.",
        "El modo Block no existe en esta versión. Necesita el aplicador de la ADR 0006, que no ha superado su validación; defense.mode solo acepta monitor.");

    /// <summary>The Windows logon sensor's chip: earned from the store, never toggled.</summary>
    internal static SensorChip Logons(CollectorReading collector, ServiceReading service, bool spanish)
    {
        var name = L(spanish, "Windows logons (Remote Desktop, SMB, network)", "Inicios de sesión de Windows (Escritorio remoto, SMB, red)");
        return collector.State switch
        {
            CollectorState.Recording when collector.Problems.Count == 0 => new(name, Tone.Green, L(spanish, "recording", "registrando"),
                L(spanish, $"Security 4625 and RdpCoreTS 140 recorded within the last two minutes: coverage reaches {Time(collector.LastRecorded)} UTC.",
                    $"Seguridad 4625 y RdpCoreTS 140 registrados en los dos últimos minutos: la cobertura llega hasta {Time(collector.LastRecorded)} UTC.")),
            CollectorState.Recording => new(name, Tone.Amber, L(spanish, "recording, with a problem", "registrando, con un problema"),
                L(spanish, "Recording, but coverage reports a problem: ", "Registrando, pero la cobertura indica un problema: ") + Problems(collector, service, spanish)),
            CollectorState.Blind => new(name, Tone.Amber, L(spanish, "configured but blind", "configurado pero a ciegas"),
                L(spanish, "Configured but blind: ", "Configurado pero a ciegas: ") + Problems(collector, service, spanish)),
            CollectorState.Stopped => new(name, Tone.Grey, L(spanish, "not recording", "sin registrar"),
                collector.LastRecorded is { } last
                    ? L(spanish, $"Nothing is recording; the last recorded moment is {Time(last)} UTC.", $"No se registra nada; el último momento registrado es {Time(last)} UTC.")
                    : L(spanish, "Nothing is recording, and nothing was ever recorded in this store.", "No se registra nada, y nunca se registró nada en este almacén.")),
            _ => new(name, Tone.Grey, L(spanish, "not read", "sin lectura"),
                L(spanish, "The evidence store could not be read, so nobody could look.", "No se pudo leer el almacén de evidencia, así que nadie pudo mirar."))
        };
    }

    private static string Problems(CollectorReading collector, ServiceReading service, bool spanish) =>
        string.Join(" ", collector.Problems.Select(p => Describe(p, spanish) + "." + (Remedy(p, service, spanish) is { } fix ? " " + fix : "")));

    /// <summary>A coverage reason as the collector writes it (<c>security-4625: access-denied</c>), in words.</summary>
    internal static string Describe(string reason, bool spanish)
    {
        var (channel, code) = Split(reason);
        var log = channel switch
        {
            AttemptPairing.SecurityChannel => L(spanish, "the Security log", "el registro de seguridad"),
            AttemptPairing.RdpChannel => L(spanish, "Remote Desktop's log (RdpCoreTS)", "el registro de Escritorio remoto (RdpCoreTS)"),
            _ => null
        };
        if (channel == "buffer-full")
            return L(spanish, $"a burst filled the pairing buffer and failed logons were not recorded ({DisplayText.Clean(code, 40)})",
                $"una ráfaga llenó el búfer de emparejamiento y no se registraron inicios de sesión fallidos ({DisplayText.Clean(code, 40)})");
        if (log is null) return DisplayText.Clean(reason, 120);
        return code switch
        {
            "access-denied" => L(spanish, $"{log} could not be read: access denied", $"no se pudo leer {log}: acceso denegado"),
            "channel-missing" => L(spanish, $"{log} is not present on this system", $"{log} no existe en este sistema"),
            "query-failed" => L(spanish, $"the query of {log} failed", $"falló la consulta de {log}"),
            "read-bound" => L(spanish, $"the catch-up read of {log} stopped at its bound", $"la lectura de recuperación de {log} se detuvo en su límite"),
            "log-starts-later" => L(spanish, $"{log} does not reach back further", $"{log} no llega más atrás"),
            _ => $"{log}: {DisplayText.Clean(code, 80)}"
        };
    }

    /// <summary>What fixes a coverage problem, given who is collecting. <see langword="null"/> when nothing needs fixing.</summary>
    internal static string? Remedy(string reason, ServiceReading service, bool spanish)
    {
        var (channel, code) = Split(reason);
        if (channel == "buffer-full") return null;
        var serviceFix = L(spanish, $@"Add NT SERVICE\WPShield to Event Log Readers and restart the service: {EvidenceCollector.EventLogReadersRemedy}",
            $@"Añada NT SERVICE\WPShield a Lectores del registro de eventos y reinicie el servicio: {EvidenceCollector.EventLogReadersRemedy}");
        var foregroundFix = L(spanish, "The collector running without the service cannot read it: run 'wpshield evidence collect' from an elevated prompt.",
            "El recolector que funciona sin el servicio no puede leerlo: ejecute 'wpshield evidence collect' desde una consola elevada.");
        return code switch
        {
            "access-denied" => service.State switch
            {
                ServiceState.Running or ServiceState.Starting => serviceFix,
                ServiceState.Stopped or ServiceState.NotInstalled => foregroundFix,
                _ => serviceFix + " " + L(spanish, "Or, for a foreground collector: ", "O, para un recolector en primer plano: ") + foregroundFix
            },
            "channel-missing" => L(spanish,
                "Nothing to fix: attempts are still counted from the Security log, but those only this log names lose their address.",
                "No hay nada que corregir: los intentos se siguen contando desde el registro de seguridad, pero los que solo nombra este registro pierden su dirección."),
            "query-failed" => L(spanish, "The collector tries again every 15 minutes; the service log has the details.",
                "El recolector lo vuelve a intentar cada 15 minutos; el registro del servicio tiene los detalles."),
            _ => null
        };
    }

    /// <summary>Sensors on the roadmap. Dotted and disabled: they record nothing, and the chip never pretends they do.</summary>
    internal static IReadOnlyList<SensorChip> Planned(bool spanish) =>
    [
        new(L(spanish, "SQL Server logins", "Inicios de sesión de SQL Server"), Tone.Grey, L(spanish, "planned", "planificado"),
            L(spanish, "Planned, not recording. 'wpshield network-monitor --sql-instance' reads one instance's login outcomes on demand; nothing records " +
                    "them into this store, so the decision engine does not see them. On the roadmap: M4 and the Windows service protection benchmark.",
                "Planificado, sin registrar. 'wpshield network-monitor --sql-instance' lee bajo demanda los resultados de inicio de sesión de una " +
                    "instancia; nada los registra en este almacén, así que el motor de decisiones no los ve. En la hoja de ruta: M4 y la evaluación " +
                    "de protección de servicios de Windows."), Planned: true),
        new(L(spanish, "Requests to the sites (gateway)", "Solicitudes a los sitios (gateway)"), Tone.Grey, L(spanish, "planned", "planificado"),
            L(spanish, "Planned, not recording. The gateway inspects requests and writes its own request evidence, but nothing records it into this " +
                    "store, so the decision engine does not see it. On the roadmap: M3 and M4.",
                "Planificado, sin registrar. El gateway inspecciona las solicitudes y escribe su propia evidencia, pero nada la registra en este " +
                    "almacén, así que el motor de decisiones no la ve. En la hoja de ruta: M3 y M4."), Planned: true)
    ];

    /// <summary>The big counts: would-block in force, and protected, refused and report in the last 24 hours.</summary>
    internal static ProtectionCounts Counts(ProtectionRead? read, DateTimeOffset now)
    {
        if (read is null) return new("—", "—", "—", "—");
        var truncated = read.Active.Truncated ? "+" : "";
        var wouldBlock = read.Active.Decisions.Count(d => d.Action == DecisionActions.WouldBlock && d.ExpiresAt > now);
        string Day(string action) => NoData(read, DecisionTab.Day) ? "—" : Number(read.DayCounts.GetValueOrDefault(action));
        return new(Number(wouldBlock) + truncated, Day(DecisionActions.Protected), Day(DecisionActions.Refused), Day(DecisionActions.Report));
    }

    /// <summary>A period nobody recorded holds no decisions because nobody decided, not because nothing happened.</summary>
    internal static bool NoData(ProtectionRead read, DecisionTab tab) => tab switch
    {
        DecisionTab.Day => read.DayCoverage == CoverageReport.None && read.DayCounts.Values.Sum() == 0,
        DecisionTab.Month => read.MonthCoverage == CoverageReport.None && read.MonthCounts.Values.Sum() == 0,
        _ => false
    };

    /// <summary>A tab's count: every record of the period, counted exactly, or "—" when nobody could look.</summary>
    internal static string TabCount(ProtectionRead? read, DecisionTab tab, DateTimeOffset now)
    {
        if (read is null || NoData(read, tab)) return "—";
        return tab switch
        {
            DecisionTab.InForce => Number(read.Active.Decisions.Count(d => d.ExpiresAt > now)) + (read.Active.Truncated ? "+" : ""),
            DecisionTab.Day => Number(read.DayCounts.Values.Sum()),
            _ => Number(read.MonthCounts.Values.Sum())
        };
    }

    internal static string TabTitle(DecisionTab tab, string count, bool spanish) => tab switch
    {
        DecisionTab.InForce => L(spanish, $"In force ({count})", $"Vigentes ({count})"),
        DecisionTab.Day => L(spanish, $"Last 24 h ({count})", $"Últimas 24 h ({count})"),
        _ => L(spanish, $"30 days ({count})", $"30 días ({count})")
    };

    /// <summary>The rows of a tab that match the search, newest first.</summary>
    internal static IReadOnlyList<ProtectionRow> Rows(ProtectionRead? read, DecisionTab tab, string query, bool spanish, DateTimeOffset now)
    {
        if (read is null) return [];
        var matcher = AddressLabels.From(read.Labels);
        IEnumerable<DecisionRecord> records = tab switch
        {
            DecisionTab.InForce => read.Active.Decisions.Where(d => d.ExpiresAt > now),
            DecisionTab.Day => read.Day.Take(EvidenceProtectionStore.Shown),
            _ => read.Month.Take(EvidenceProtectionStore.Shown)
        };
        return records.Select(d => new ProtectionRow(DisplayText.Clean(d.Target, 64), LabelOf(read.Labels, matcher, d.Target),
                DisplayText.Clean(d.RuleId, 16), AttackDecisions.Action(d.Action, spanish), DisplayText.Clean(d.Reason, 200),
                Time(d.Timestamp), d.ExpiresAt is { } until && d.Action != DecisionActions.Expire ? Time(until) : ""))
            .Where(r => r.Matches(query.Trim())).ToArray();
    }

    /// <summary>Whether a tab lists fewer records than its period holds.</summary>
    internal static bool Truncated(ProtectionRead read, DecisionTab tab) => tab switch
    {
        DecisionTab.InForce => read.Active.Truncated,
        DecisionTab.Day => read.Day.Count > EvidenceProtectionStore.Shown,
        _ => read.Month.Count > EvidenceProtectionStore.Shown
    };

    /// <summary>What the table says when it has no rows. Unread, unrecorded and empty never look alike.</summary>
    internal static string Empty(ProtectionRead? read, DecisionTab tab, bool searching, bool spanish)
    {
        if (read is null)
            return L(spanish, "Not read: the evidence store could not be read, so nobody could look.",
                "Sin lectura: no se pudo leer el almacén de evidencia, así que nadie pudo mirar.");
        if (searching) return L(spanish, "No decision matches the search.", "Ninguna decisión coincide con la búsqueda.");
        if (tab == DecisionTab.InForce)
            return read.Active.EngineStarted is null
                ? L(spanish, "Nothing is in force: the decision engine has never run on this store.",
                    "No hay nada vigente: el motor de decisiones nunca se ejecutó sobre este almacén.")
                : !read.Active.CollectorCurrent
                    ? L(spanish, "Nothing is in force: the service is not recording, and a decision never outlives the process that made it.",
                        "No hay nada vigente: el servicio no está registrando, y una decisión nunca sobrevive al proceso que la tomó.")
                    : L(spanish, "Nothing is in force.", "No hay nada vigente.");
        return NoData(read, tab)
            ? L(spanish, "No data: the service recorded nothing in this period. That is not the same as no decisions.",
                "Sin datos: el servicio no registró nada en este periodo. No es lo mismo que no haber decisiones.")
            : L(spanish, "No decisions in this period.", "Ninguna decisión en este periodo.");
    }

    /// <summary>
    /// The label of a decision's target. An address has its usual label. A network has its own entry's, or that
    /// of the narrowest entry containing all of it - never that of one address inside it.
    /// </summary>
    internal static string LabelOf(JsonNode? labels, AddressLabels matcher, string target)
    {
        if (!target.Contains('/', StringComparison.Ordinal)) return AttackBoard.LabelFor(matcher, target);
        if (!TryNetwork(target, out var network) || labels is not JsonObject map) return "";
        string? best = null;
        var bits = -1;
        foreach (var (key, value) in map.Take(SettingCatalog.MaxLabels))
        {
            if (!key.Contains('/', StringComparison.Ordinal) || value is not JsonValue text || !text.TryGetValue<string>(out var label)) continue;
            if (!TryNetwork(key, out var entry) || entry.BaseAddress.AddressFamily != network.BaseAddress.AddressFamily) continue;
            if (entry.PrefixLength > network.PrefixLength || !entry.Contains(network.BaseAddress) || entry.PrefixLength <= bits) continue;
            best = label;
            bits = entry.PrefixLength;
        }
        return DisplayText.Clean(best, 64);
    }

    /// <summary>A network written as the store writes one, with any host bits cleared as the labels' own matcher does.</summary>
    private static bool TryNetwork(string text, out IPNetwork network)
    {
        network = default;
        var slash = text.IndexOf('/', StringComparison.Ordinal);
        if (slash < 0 || !IPAddress.TryParse(text[..slash], out var address) ||
            !int.TryParse(text[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix)) return false;
        address = AddressRanges.Canonical(address);
        var max = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix > max) return false;
        var bytes = address.GetAddressBytes();
        for (var i = 0; i < bytes.Length; i++) bytes[i] &= (byte)(0xFF << (8 - Math.Clamp(prefix - i * 8, 0, 8)));
        network = new IPNetwork(new IPAddress(bytes), prefix);
        return true;
    }

    private static (string Channel, string Code) Split(string reason)
    {
        var colon = reason.IndexOf(": ", StringComparison.Ordinal);
        return colon < 0 ? (reason, "") : (reason[..colon], reason[(colon + 2)..]);
    }

    private static string Number(long value) => value.ToString("N0", CultureInfo.CurrentCulture);

    internal static string Time(DateTimeOffset? at) =>
        at?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) ?? "—";

    private static string L(bool spanish, string english, string es) => spanish ? es : english;
}

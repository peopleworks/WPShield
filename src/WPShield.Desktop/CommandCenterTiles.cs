using System.Globalization;
using System.Windows;
using System.Windows.Media;
using WPShield.Cli;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;

namespace WPShield.Desktop;

internal enum CommandSection { Protection, Attacks, Web, Health, Posture, Exposure, Analyst, Outbound }
internal enum CommandTone { Neutral, Grey, Green, Red }

internal sealed record CommandMetric(string Label, string Value, CommandTone Tone = CommandTone.Neutral,
    string? Tooltip = null, Geometry? Trend = null)
{
    public string Help => Tooltip ?? Value;
}

internal sealed record CommandTile(CommandSection Section, string Title, string Status, CommandTone Tone,
    IReadOnlyList<CommandMetric> Metrics, IReadOnlyList<CommandMetric>? Details = null, double? Progress = null);

/// <summary>Presentation of recorded evidence. Coverage determines whether zero and a green indicator are earned.</summary>
internal sealed class CommandCenterTiles(bool spanish)
{
    private string L(string en, string es) => spanish ? es : en;
    private string Unknown => L("Unknown", "Desconocido");
    private string NoData => L("No data", "Sin datos");
    private string StartCollector => L("Run 'wpshield evidence collect' on the IIS host as administrator.",
        "Ejecute 'wpshield evidence collect' como administrador en el servidor IIS.");
    private string Firewall => L(ExposureVerdicts.Source, "según las reglas del Firewall de Windows");

    internal IReadOnlyList<CommandTile> Build(CommandCenterRead? read) =>
        [Protection(read), Attacks(read), Web(read), Health(read), Posture(read), Exposure(read), Analyst(read), Outbound()];

    private CommandTile Protection(CommandCenterRead? read)
    {
        var title = "WPShield";
        var section = CommandSection.Protection;
        if (read is null) return new(section, title, NoData, CommandTone.Grey, []);
        var collector = read.Collector;
        var line = ProtectionStatus.CollectorLine(collector, spanish);
        var tone = collector.State switch
        {
            CollectorState.Recording when collector.Problems.Count == 0 => CommandTone.Green,
            CollectorState.Stopped when collector.LastRecorded is not null => CommandTone.Red,
            _ => CommandTone.Grey
        };
        var rdpProblem = collector.Problems.FirstOrDefault(p => p.StartsWith(AttemptPairing.RdpChannel + ":", StringComparison.Ordinal));
        var securityProblem = collector.Problems.FirstOrDefault(p => p.StartsWith(AttemptPairing.SecurityChannel + ":", StringComparison.Ordinal));
        var facts = read.Facts.OrderByDescending(f => f.TakenAt).FirstOrDefault();
        var freshFacts = IsFresh(facts, read.At);
        return new(section, title, line.Title, tone,
        [
            Sensor(L("Security", "Seguridad"), securityProblem, collector),
            Sensor("RDP", rdpProblem, collector),
            new("IIS", Sites(read.Web), read.Web.Complete ? CommandTone.Green : CommandTone.Grey),
            new(L("Host facts", "Datos del host"), facts is null ? L("No snapshot yet", "Aún sin instantánea") : Status(facts, read.At),
                freshFacts ? CommandTone.Green : CommandTone.Grey),
            new(L("Newest evidence", "Evidencia más reciente"), read.NewestRecord is { } at ? Age(read.At - at) : NoData,
                Tooltip: read.NewestRecord is { } time ? Time(time) : NoData)
        ]);
    }

    private CommandMetric Sensor(string name, string? problem, CollectorReading collector)
    {
        if (problem is not null)
            return new(name, Unknown, CommandTone.Grey, ProtectionStatus.Describe(problem, spanish));
        var current = collector.State == CollectorState.Recording;
        return new(name, current ? L("Reading", "Leyendo") : NoData, current ? CommandTone.Green : CommandTone.Grey);
    }

    private CommandTile Attacks(CommandCenterRead? read)
    {
        var title = L("RDP / SMB attacks", "Ataques RDP / SMB");
        if (read is null) return new(CommandSection.Attacks, title, NoData, CommandTone.Grey, []);
        var logons = read.Logons;
        var coverage = logons.HourCoverage.State;
        var coveredHours = logons.Week.Where(b => b.Covered).ToArray();
        var baseline = coveredHours.Length == 0 ? NoData : coveredHours.Average(b => b.Attempts).ToString("N1", CultureInfo.CurrentCulture);
        var active = logons.Active;
        var decisions = active.Decisions.Count(d => d.Action == DecisionActions.WouldBlock);
        var accountFact = read.Fact(HostFacts.Inventory, HostFacts.Accounts);
        var accounts = accountFact?.Value<HostAccounts>();
        var fullName = !IsFresh(accountFact, read.At) ? Unknown : accounts?.FullNameTargeted switch
        {
            true when accounts.FullNameMatches is { } n => L($"YES ({n:N0})", $"SÍ ({n:N0})"),
            false => L("No", "No"),
            _ => Unknown
        };
        var exactHour = logons.LastHour.Detailed && (coverage != CoverageReport.None || logons.LastHour.Attempts > 0);
        return new(CommandSection.Attacks, title, coverage == CoverageReport.Full ? L("Last hour · Windows logons", "Última hora · inicios de Windows")
            : L("Last hour · coverage incomplete", "Última hora · cobertura incompleta"),
            coverage == CoverageReport.Full ? CommandTone.Neutral : CommandTone.Grey,
        [
            new(L("Failed attempts", "Intentos fallidos"), exactHour ? Number(logons.LastHour.Attempts) : NoData),
            new(L("7-day hourly average", "Media por hora de 7 días"), baseline, Tooltip:
                L($"{coveredHours.Length} of 168 hours recorded", $"{coveredHours.Length} de 168 horas registradas")),
            new(L("Would block · Monitor", "Bloquearía · Monitor"),
                active.EngineStarted is null ? NoData : (active.Truncated ? "≥ " : "") + Number(decisions)),
            new(L("Most active network", "Red más activa"), logons.TopNetwork is { } network ? DisplayText.Clean(network, 64) : "—",
                Tooltip: L("Grouped from the top recorded source addresses in the last hour.", "Agrupada a partir de los principales orígenes registrados en la última hora.")),
            new(L("Real account full names tried", "Nombres completos de cuentas probados"), fullName,
                fullName == Unknown ? CommandTone.Grey : accounts?.FullNameTargeted == true ? CommandTone.Red : CommandTone.Neutral,
                Tooltip: Status(accountFact, read.At))
        ]);
    }

    private CommandTile Web(CommandCenterRead? read)
    {
        var title = "Web";
        if (read is null) return new(CommandSection.Web, title, NoData, CommandTone.Grey,
            [new(WebObservationIds.PhpOutsideEntryPoints, NoData, CommandTone.Grey)]);
        var web = read.Web;
        var observed = web.Summary.Observations;
        var tone = observed > 0 ? CommandTone.Red : web.Complete ? CommandTone.Green : CommandTone.Grey;
        var status = !web.HasData ? NoData : web.Complete ? L("Full coverage", "Cobertura completa") : L("Partial coverage", "Cobertura parcial");
        var from = web.Summary.HoursFrom;
        var rate = web.Complete ? (web.Summary.Requests / (read.At - from).TotalMinutes).ToString("N1", CultureInfo.CurrentCulture) : "—";
        return new(CommandSection.Web, title, status, tone,
        [
            new(L("Requests / minute", "Peticiones / minuto"), rate, Tooltip:
                L($"{web.Summary.Requests:N0} requests recorded since {Time(from)}", $"{web.Summary.Requests:N0} peticiones registradas desde {Time(from)}")),
            new(L("Rule findings", "Hallazgos de reglas"), web.HasData ? Number(web.Summary.Findings) : NoData),
            new("wp-login POST", web.HasData ? Number(web.Summary.LoginPosts) : NoData),
            new("XML-RPC POST", web.HasData ? Number(web.Summary.XmlrpcPosts) : NoData),
            new(WebObservationIds.PhpOutsideEntryPoints, observed > 0 || web.Complete ? Number(observed) : NoData, tone,
                L("2xx PHP responses outside WordPress entry points.", "Respuestas 2xx de PHP fuera de los puntos de entrada de WordPress.")),
            new(L("Sites read", "Sitios leídos"), Sites(web))
        ]);
    }

    private CommandTile Health(CommandCenterRead? read)
    {
        var title = L("Server health", "Salud del servidor");
        var reading = read?.Fact(HostFacts.Health);
        var now = read?.At ?? DateTimeOffset.UtcNow;
        var health = reading?.Value<HostHealth>();
        var status = Status(reading, now);
        var recent = read?.HealthHistory ?? [];
        var volumes = health?.Volumes.OrderByDescending(v => v.HoldsIisLogs == true)
            .ThenBy(v => Ratio(v.FreeBytes, v.TotalBytes) ?? 1).ToArray() ?? [];
        var disk = volumes.FirstOrDefault();
        var restarts = read?.Restarts ?? [];
        var restartCodes = restarts.GroupBy(r => r.BugCheck)
            .OrderByDescending(group => group.Count())
            .Select(group => $"{group.Count():N0} × {group.Key ?? L("code unknown", "código desconocido")}").ToArray();
        var patch = health?.Patch;
        var update = patch?.UpdateLogReadable == true
            ? patch.LastCumulativeUpdate is { } name
                ? DisplayText.Clean(name, HostPatchLevel.MaxTitleLength) + (patch.DaysSinceCumulativeUpdate(now) is { } days
                    ? L($" · {days:N0} d ago", $" · hace {days:N0} d") : "")
                : L("No cumulative update found in the retained log", "El log conservado no registra una actualización acumulativa")
            : Unknown;
        var metrics = new List<CommandMetric>
        {
            new(L("Uptime", "Tiempo activo"), health is null ? Unknown : Age(TimeSpan.FromSeconds(health.UptimeSeconds))),
            new("CPU", Percent(health?.CpuPercent / 100), Trend: HealthPlot(recent, now, h => h.CpuAverage / 100)),
            new(L("Memory used", "Memoria utilizada"), Percent(Used(health?.MemoryAvailableBytes, health?.MemoryTotalBytes)),
                Trend: HealthPlot(recent, now, h => Used(h.MemoryMinAvailable, h.MemoryTotal))),
            new(L("Disk free", "Disco libre"), disk is null ? Unknown : $"{Safe(disk.Name)} · {Percent(Ratio(disk.FreeBytes, disk.TotalBytes))}",
                Trend: disk is null ? null : HealthPlot(recent, now, h => h.VolumeMinFree.TryGetValue(disk.Name, out var bytes) ? Ratio(bytes, disk.TotalBytes) : null)),
            new(L("Unexpected restarts · 30 d", "Reinicios inesperados · 30 d"),
                restartCodes.Length > 0 ? string.Join(" · ", restartCodes) : NoData,
                restartCodes.Length > 0 && IsFresh(reading, now) ? CommandTone.Red : CommandTone.Grey,
                restartCodes.Length > 0 ? string.Join(Environment.NewLine, restartCodes) : L("No restart records. System log coverage is unknown.",
                    "Sin registros de reinicios. Se desconoce la cobertura del registro del sistema.")),
            new(L("Windows build", "Compilación de Windows"), Safe(patch?.Build)),
            new("ntoskrnl.exe", Safe(patch?.KernelVersion)),
            new(L("Last cumulative update", "Última actualización acumulativa"), update)
        };
        var details = new List<CommandMetric>(metrics);
        details.AddRange(volumes.Select(volume => new CommandMetric(L("Free on volume", "Libre en volumen"),
            $"{Safe(volume.Name)} · {Percent(Ratio(volume.FreeBytes, volume.TotalBytes))}")));
        details.AddRange(restarts.Select(restart => new CommandMetric(Time(restart.At), restart.BugCheck ?? Unknown)));
        return new(CommandSection.Health, title, status, IsFresh(reading, now) ? CommandTone.Neutral : CommandTone.Grey, metrics, details);
    }

    private CommandTile Posture(CommandCenterRead? read)
    {
        var title = L("IIS posture", "Postura de IIS");
        var reading = read?.Fact(HostFacts.Posture);
        var now = read?.At ?? DateTimeOffset.UtcNow;
        var posture = reading?.Value<HostPosture>();
        var valid = posture is { Complete: true, PoolsTotal: > 0, PoolsAdministrator: >= 0 } && posture.PoolsAdministrator <= posture.PoolsTotal;
        var progress = valid ? 1 - (double)posture!.PoolsAdministrator!.Value / posture.PoolsTotal!.Value : (double?)null;
        var count = valid ? L($"{posture!.PoolsAdministrator:N0} of {posture.PoolsTotal:N0}", $"{posture!.PoolsAdministrator:N0} de {posture.PoolsTotal:N0}") : Unknown;
        var points = read?.PostureHistory ?? [];
        var history = points.Select(p => (p.TakenAt,
            p.Complete && p.PoolsTotal > 0 ? Ratio(p.PoolsAdministrator, p.PoolsTotal) : null)).ToArray();
        var metrics = new CommandMetric[]
        {
            new(L("Pools as administrator", "Pools como administrador"), count,
                Tooltip: L("Progress measures the share of pools without administrator rights. Trend shows the administrator share over 30 days.",
                    "El avance mide la proporción de pools sin derechos de administrador. La tendencia muestra la proporción con esos derechos en 30 días."),
                Trend: Plot(history, now.AddDays(-30), now)),
            new(L("Server-wide PHP", "PHP a nivel de servidor"), Flag(posture?.PhpServerLevel)),
            new(L("Writable site folders", "Carpetas de sitio escribibles"), Count(posture?.WritableSiteFolders)),
            new(L("FTP overlaps", "Solapamientos con FTP"), Count(posture?.FtpOverlaps)),
            new(L("Last reading", "Última lectura"), reading is null ? NoData : Time(reading.TakenAt))
        };
        var details = metrics.Concat((posture?.Findings ?? []).Select(f => new CommandMetric(Safe(f.Id), Safe(f.Title))))
            .Concat(points.Select(p => new CommandMetric(Time(p.TakenAt),
                p.Complete ? $"{Count(p.PoolsAdministrator)} / {Count(p.PoolsTotal)}" : Unknown))).ToArray();
        var tone = !IsFresh(reading, now) || !valid ? CommandTone.Grey : progress == 1 ? CommandTone.Green : CommandTone.Neutral;
        return new(CommandSection.Posture, title, Status(reading, now), tone, metrics, details, progress);
    }

    private CommandTile Exposure(CommandCenterRead? read)
    {
        var title = L("Exposure", "Exposición");
        var reading = read?.Fact(HostFacts.Ports);
        var now = read?.At ?? DateTimeOffset.UtcNow;
        var ports = reading?.Value<HostPorts>();
        var fresh = IsFresh(reading, now);
        var canCallRed = reading is { Status: HostFactStatus.Ok or HostFactStatus.Partial } &&
            !IsStale(reading, now) && ports?.FirewallRead == true;
        var listeners = ports?.Listeners.Select(port =>
        {
            var verdict = ports.FirewallRead || port.Verdict == ExposureVerdicts.LocalOnly ? port.Verdict : ExposureVerdicts.Unknown;
            var red = canCallRed && ExposureVerdicts.IsRed(port.Protocol, port.Port, verdict);
            var process = DisplayText.Clean(port.Process, HostFacts.MaxNameLength);
            var label = $"{DisplayText.Clean(port.Protocol, 8)} {port.Port}" + (process.Length > 0 ? $" · {process}" : "");
            var value = Verdict(verdict);
            var address = DisplayText.Clean(port.Address, 64);
            var help = $"{label} · {value} · {Firewall}" + (address.Length > 0 ? $" · {address}" : "");
            if (red) help += " · " + L("Restrict the firewall rule to the addresses that need it.",
                "Restrinja la regla a las direcciones que la necesitan.");
            return new CommandMetric(label, value, red ? CommandTone.Red : !fresh || verdict == ExposureVerdicts.Unknown ? CommandTone.Grey : CommandTone.Neutral, help);
        }).OrderByDescending(row => row.Tone == CommandTone.Red).ToArray() ?? [];
        var tone = listeners.Any(row => row.Tone == CommandTone.Red) ? CommandTone.Red : fresh && ports?.FirewallRead == true ? CommandTone.Neutral : CommandTone.Grey;
        var status = Status(reading, now) + " · " + Firewall;
        var total = new CommandMetric(L("Listening endpoints", "Endpoints en escucha"), ports is null ? Unknown : Number(listeners.Length));
        return new(CommandSection.Exposure, title, status, tone, [total, .. listeners.Take(5)], [total, .. listeners]);
    }

    private string Verdict(string verdict) => verdict switch
    {
        ExposureVerdicts.OpenToAny => L("Open to any address", "Abierto a cualquier dirección"),
        ExposureVerdicts.Restricted => L("Restricted", "Restringido"),
        ExposureVerdicts.Blocked => L("Blocked", "Bloqueado"),
        ExposureVerdicts.LocalOnly => L("Local only", "Solo local"),
        _ => Unknown
    };

    private CommandTile Analyst(CommandCenterRead? read)
    {
        var status = read is null ? NoData : !read.AnalystConfigured ? L("Not configured", "Sin configurar")
            : L("Report usage is not available in this view yet", "El uso del analista aún no está disponible en esta vista");
        return new(CommandSection.Analyst, L("AI analyst", "Analista de IA"), status, CommandTone.Grey, []);
    }

    private CommandTile Outbound() => new(CommandSection.Outbound,
        L("Outbound from web processes", "Conexiones salientes de procesos web"),
        L("Not measured yet", "Aún sin medición"), CommandTone.Grey,
        [new(L("Sensor", "Sensor"), L("Deferred to its own ADR", "Pendiente de su propio ADR"))]);

    private string Status(HostFactReading? reading, DateTimeOffset now)
    {
        if (reading is null) return L("No snapshot yet", "Aún sin instantánea") + " · " + StartCollector;
        var status = reading.Status switch
        {
            HostFactStatus.Ok => "",
            HostFactStatus.Partial => L("Partial · ", "Parcial · "),
            _ => Unknown + " · "
        };
        if (IsStale(reading, now))
            status += L("STALE · ", "CADUCADA · ") + Age(now - reading.TakenAt) + " · ";
        status += Time(reading.TakenAt);
        if (reading.Status != HostFactStatus.Ok)
            status += $" · {DisplayText.Clean(reading.Reason, 256)} · {DisplayText.Clean(reading.Remedy, 500)}";
        return status;
    }

    private static bool IsFresh(HostFactReading? reading, DateTimeOffset now) =>
        reading is { Status: HostFactStatus.Ok } && !IsStale(reading, now);

    private static bool IsStale(HostFactReading reading, DateTimeOffset now) => now - reading.TakenAt > HostFacts.Cadence(reading.Fact);

    private string Sites(CommandWeb web) => web.Sites.Count == 0 ? NoData : $"{web.ReadSites:N0} / {web.Sites.Count:N0}";
    private string Flag(bool? value) => value is null ? Unknown : value.Value ? L("Yes", "Sí") : L("No", "No");
    private string Count(int? value) => value is { } n ? Number(n) : Unknown;
    private string Safe(string? value) => string.IsNullOrWhiteSpace(value) ? Unknown : DisplayText.Clean(value, HostFacts.MaxNameLength);
    private string Percent(double? value) => value is double n ? n.ToString("P0", CultureInfo.CurrentCulture) : Unknown;
    private static string Time(DateTimeOffset value) => value.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC";
    private static string Number(long value) => value.ToString("N0", CultureInfo.CurrentCulture);

    private static string Age(TimeSpan span)
    {
        span = span < TimeSpan.Zero ? TimeSpan.Zero : span;
        return span.TotalDays >= 1 ? $"{(int)span.TotalDays} d {span.Hours} h"
            : span.TotalHours >= 1 ? $"{(int)span.TotalHours} h {span.Minutes} min"
            : span.TotalMinutes >= 1 ? $"{span.Minutes} min" : $"{span.Seconds} s";
    }

    private static double? Ratio(long? value, long? total) =>
        value is >= 0 && total is > 0 ? Math.Clamp((double)value.Value / total.Value, 0, 1) : null;
    private static double? Used(long? free, long? total) => 1 - Ratio(free, total);

    private static Geometry? HealthPlot(IReadOnlyList<HealthHour> rows, DateTimeOffset now, Func<HealthHour, double?> value)
    {
        var hour = TimeSpan.FromHours(1);
        var end = new DateTimeOffset(now.UtcTicks - now.UtcTicks % hour.Ticks, TimeSpan.Zero);
        var start = end.AddHours(-23);
        var lookup = rows.ToDictionary(h => h.Hour);
        return Plot(Enumerable.Range(0, 24).Select(i =>
        {
            var at = start.AddHours(i);
            return (at, lookup.TryGetValue(at, out var sample) ? value(sample) : null);
        }), start, end);
    }

    // Fixed coordinates keep the shares comparable. Missing hours break the line.
    private static Geometry? Plot(IEnumerable<(DateTimeOffset At, double? Value)> values, DateTimeOffset start, DateTimeOffset end)
    {
        var geometry = new StreamGeometry();
        var hasData = false;
        using (var path = geometry.Open())
        {
            var joining = false;
            foreach (var (at, value) in values)
            {
                if (value is not double share || !double.IsFinite(share))
                {
                    joining = false;
                    continue;
                }
                var x = 1 + 98 * Math.Clamp((at - start).TotalSeconds / (end - start).TotalSeconds, 0, 1);
                var y = 1 + 16 * (1 - Math.Clamp(share, 0, 1));
                var point = new Point(x, y);
                if (!joining)
                {
                    path.BeginFigure(new Point(x - 0.5, y), false, false);
                    joining = true;
                }
                path.LineTo(point, true, false);
                hasData = true;
            }
        }
        geometry.Freeze();
        return hasData ? geometry : null;
    }
}

using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using WPShield.Evidence;
using WPShield.SecurityMonitor;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield host</c> - the host facts of ADR 0013: the snapshots the collector took, read-only, or with
/// <c>--live</c> a direct read that writes nothing.
/// </summary>
/// <remarks>
/// <para>
/// <b>Unknown is never shown as none.</b> A fact never read says "no snapshot yet"; one that could not be read
/// shows its status, reason and remedy; one older than three times its cadence is marked stale with its age.
/// </para>
/// <para>
/// <b>Names come from a host that may be compromised.</b> Service, task and site names are cleaned when stored
/// and again for the console.
/// </para>
/// </remarks>
internal static class HostCommand
{
    public const string Help = """
        wpshield host - what this server is: the host facts of ADR 0013, from the snapshots the evidence
        collector takes. Read-only; nothing on this server is changed.

        Usage: wpshield host [health|sites|posture|ports|sessions|inventory <accounts|services|tasks>]
                             [--all] [--live] [--json] [--store PATH]

          (no section)   One screen: every fact with its age and status.
          health         Uptime, unexpected restarts in 30 days with their bugcheck codes, CPU,
                         memory, free space per volume, the patch level, and how far back the
                         System, Security and Application logs reach.
          sites          IIS sites, bindings, pools and the pool identity type (never a password).
          posture        The latest audit summary and the history of "pools as an administrator".
          ports          Listeners with their owning program and an exposure verdict by the Windows
                         Firewall rules. Red: SMB, RPC, SQL Server, MySQL, PostgreSQL, VNC, WinRM open
                         to any address, each with the rules that open it. Never "reachable": other
                         network filters decide too.
          sessions       Current sessions and RDP logons of the last 7 days with their source address.
          inventory      Non-Microsoft accounts, services or tasks, and what changed. Arguments of
                         services and tasks are never stored or shown, only flags.
          --all          With 'ports': the rules behind every port open to any address, not only the
                         red ones. With 'inventory tasks': also the Microsoft tasks listed only
                         because they run a script host, which are otherwise folded into a count.
          --live         Read the host now instead of the snapshots, and write nothing. For when the
                         collector is not running. Run it elevated.
          --json         One JSON document on stdout. Errors go to stderr.
          --store PATH   The evidence store. Default: %ProgramData%\WPShield\evidence\wpshield-evidence.db

        The collector ('wpshield evidence collect') takes the snapshots: health every 5 minutes,
        sites, ports and sessions every 15, posture and inventory every 6 hours.

        Exit codes:
          0   answered
          1   an argument was wrong, or the store could not be opened (not elevated, access denied)
          2   the store cannot be read by this build, or no snapshot was ever taken
          3   there is no evidence store
        """;

    private static readonly string[] Sections = ["health", "sites", "posture", "ports", "sessions", "inventory"];
    private static readonly string[] Flags = ["--live", "--json", "--all"];
    private static readonly string[] Valued = ["--store"];
    internal const int RowsShown = 60;

    public static int Run(IReadOnlyList<string> args, TextWriter output, TextWriter error) =>
        Run(args, output, error, EvidenceStore.DefaultPath, EvidenceAccess.IsElevated, () => DateTimeOffset.UtcNow,
            () => new Host.CliHostFactSource());

    internal static int Run(IReadOnlyList<string> args, TextWriter output, TextWriter error, string defaultStore, Func<bool> elevated,
        Func<DateTimeOffset> now, Func<IHostFactSource> source)
    {
        ArgumentNullException.ThrowIfNull(args);
        var (section, kind, options) = Parse(args);
        var json = options.Has("--json");
        var live = options.Has("--live");
        var all = options.Has("--all");
        var path = AttacksCommand.StorePath(options, defaultStore);
        var at = now();

        if (live) return RunLive(section, kind, output, error, path, elevated, at, source(), json, all);

        EvidenceStore store;
        try
        {
            store = EvidenceAccess.OpenReadOnly(path, elevated());
        }
        catch (EvidenceAccessException ex)
        {
            error.WriteLine("ERROR: " + ex.Message);
            return ex.ExitCode;
        }
        using (store)
        {
            try
            {
                var queries = new HostFactsQueries(store);
                var snapshots = Select(queries, section, kind);
                if (json)
                {
                    output.WriteLine(Json(path, at, snapshots, queries, section, kind, live: false).ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
                }
                else
                {
                    Header(output, path, at, live: false);
                    Render(output, at, snapshots, queries, section, kind, live: false, all: all);
                }
                return snapshots.Count == 0 ? 2 : 0;
            }
            catch (SqliteException ex)
            {
                error.WriteLine("ERROR: the evidence store could not be read: " + NetworkMonitorCommand.ConsoleLabel(ex.Message));
                return 2;
            }
        }
    }

    internal static (string? Section, string? Kind, CliOptions Options) Parse(IReadOnlyList<string> args)
    {
        var positional = new List<string>();
        var named = new List<string>();
        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            if (arg.StartsWith("--", StringComparison.Ordinal))
            {
                named.Add(arg);
                if (Valued.Contains(arg, StringComparer.OrdinalIgnoreCase) && i + 1 < args.Count) named.Add(args[++i]);
                continue;
            }
            positional.Add(arg.Trim().ToLowerInvariant());
        }
        var options = CliOptions.Parse(named);
        options.RejectUnknown([.. Flags, .. Valued]);
        options.RejectRepeated();
        foreach (var flag in Flags)
            if (options.Get(flag) is not null) throw new CliArgumentException($"{flag} takes no value.");
        if (positional.Count > 2) throw new CliArgumentException("Usage: wpshield host [section] [kind]. Run 'wpshield host --help'.");
        var section = positional.Count > 0 ? positional[0] : null;
        if (section is not null && !Sections.Contains(section, StringComparer.Ordinal))
            throw new CliArgumentException($"Unknown section '{NetworkMonitorCommand.ConsoleLabel(section)}'. One of: {string.Join(", ", Sections)}.");
        string? kind = null;
        if (section == "inventory")
        {
            kind = positional.Count > 1 ? positional[1] : throw new CliArgumentException("inventory needs a kind: accounts, services or tasks.");
            if (!HostFacts.IsInventoryKind(kind)) throw new CliArgumentException("inventory needs a kind: accounts, services or tasks.");
        }
        else if (positional.Count > 1) throw new CliArgumentException("Only 'inventory' takes a second word.");
        if (options.Has("--all") && section != "ports" && !(section == "inventory" && kind == HostFacts.Tasks))
            throw new CliArgumentException("--all goes with 'ports' or 'inventory tasks'.");
        return (section, kind, options);
    }

    private static string? FactOf(string? section) => section switch
    {
        null => null,
        "health" => HostFacts.Health,
        "sites" => HostFacts.Sites,
        "posture" => HostFacts.Posture,
        "ports" => HostFacts.Ports,
        "sessions" => HostFacts.Sessions,
        _ => HostFacts.Inventory
    };

    private static IReadOnlyList<HostFactReading> Select(HostFactsQueries queries, string? section, string? kind)
    {
        if (section is null) return queries.LatestAll();
        var fact = FactOf(section)!;
        return queries.Latest(fact, fact == HostFacts.Inventory ? kind : null) is { } snapshot ? [snapshot] : [];
    }

    // ---------------------------------------------------------------------------------------------
    //  --live: a direct read, written nowhere
    // ---------------------------------------------------------------------------------------------

    private static int RunLive(string? section, string? kind, TextWriter output, TextWriter error, string path, Func<bool> elevated,
        DateTimeOffset at, IHostFactSource source, bool json, bool all)
    {
        if (!elevated())
            error.WriteLine("WARNING: not elevated. Several facts need it, and they are reported as needs-elevation rather than empty.");
        using var budget = new CancellationTokenSource(HostFacts.ReadBudget);
        var token = budget.Token;
        var fact = FactOf(section);
        var readings = new List<HostFactReading>();
        IReadOnlyList<HostRestart> restarts = [];

        HostFactReading Guard(string name, string? inventoryKind, Func<HostFactReading> read)
        {
            try { return read(); }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                return HostFactReading.Failed(name, inventoryKind, DateTimeOffset.UtcNow, HostFactStatus.Unreadable,
                    "read-failed: " + exception.GetType().Name, "Run it elevated; if it persists, the error type names the failing reader.");
            }
        }

        if (fact is null or HostFacts.Health)
        {
            readings.Add(Guard(HostFacts.Health, null, () => source.ReadHealth(path, token)));
            try
            {
                var restartReading = source.ReadRestarts(at - HostFacts.RestartWindow, token);
                restarts = [.. HostRestarts.Group(restartReading.Records).OrderByDescending(r => r.At)];
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                error.WriteLine("WARNING: unexpected restarts could not be read (" + exception.GetType().Name + ").");
            }
        }
        if (fact is null or HostFacts.Sites) readings.Add(Guard(HostFacts.Sites, null, () => source.ReadSites(token)));
        if (fact is null or HostFacts.Posture) readings.Add(Guard(HostFacts.Posture, null, () => source.ReadPosture(token)));
        if (fact is null or HostFacts.Ports) readings.Add(Guard(HostFacts.Ports, null, () => source.ReadPorts(token)));
        if (fact is null or HostFacts.Sessions)
            readings.Add(Guard(HostFacts.Sessions, null, () => source.ReadSessions(at - HostFacts.SessionWindow, token)));
        foreach (var inventoryKind in fact is null ? HostFacts.InventoryKinds : fact == HostFacts.Inventory ? [kind!] : [])
        {
            readings.Add(Guard(HostFacts.Inventory, inventoryKind, () =>
            {
                var reading = source.ReadInventory(inventoryKind, token);
                return inventoryKind == HostFacts.Accounts ? reading.WithFullNameIndicator(AttemptedNames(path, elevated(), at)) : reading.Reading;
            }));
        }

        if (json)
        {
            var document = Json(path, at, readings, null, section, kind, live: true);
            document["restarts"] = Restarts(restarts);
            output.WriteLine(document.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }
        else
        {
            Header(output, path, at, live: true);
            Render(output, at, readings, null, section, kind, live: true, liveRestarts: restarts, all: all);
        }
        return 0;
    }

    /// <summary>The attempted account names, for the full-name indicator of a live read; <see langword="null"/> when the store is unreadable.</summary>
    private static IReadOnlyList<string>? AttemptedNames(string path, bool elevated, DateTimeOffset at)
    {
        try
        {
            using var store = EvidenceAccess.OpenReadOnly(path, elevated);
            return new HostFactsQueries(store).AttemptedAccountNames(at - HostFacts.AttemptWindow);
        }
        catch (Exception exception) when (exception is EvidenceAccessException or SqliteException)
        {
            return null;
        }
    }

    // ---------------------------------------------------------------------------------------------
    //  Rendering
    // ---------------------------------------------------------------------------------------------

    private static void Header(TextWriter output, string path, DateTimeOffset at, bool live)
    {
        output.WriteLine();
        output.WriteLine(live
            ? "WPShield host facts - LIVE READ. Nothing was written to the store, and nothing on this server is changed."
            : "WPShield host facts - snapshots taken by the evidence collector (ADR 0013). Nothing on this server is changed.");
        output.WriteLine(live
            ? $"Read at          {Time(at)}"
            : $"Evidence store   {NetworkMonitorCommand.ConsoleLabel(path)} (read-only)    now {Time(at)}");
        output.WriteLine();
    }

    private static void Render(TextWriter output, DateTimeOffset at, IReadOnlyList<HostFactReading> snapshots, HostFactsQueries? queries,
        string? section, string? kind, bool live, IReadOnlyList<HostRestart>? liveRestarts = null, bool all = false)
    {
        var restarts = liveRestarts ?? queries?.Restarts(at - HostFacts.RestartWindow, at.AddSeconds(1)) ?? [];
        if (section is null)
        {
            foreach (var name in Rows())
            {
                var (fact, inventoryKind) = name;
                var snapshot = snapshots.FirstOrDefault(s => s.Fact == fact && s.Kind == inventoryKind);
                var label = (inventoryKind ?? fact).PadRight(16);
                if (snapshot is null)
                {
                    output.WriteLine($"  {label} no snapshot yet - the collector has not read it. Start 'wpshield evidence collect' elevated, or use --live.");
                    continue;
                }
                output.WriteLine($"  {label} {Status(snapshot, at, live)}  {Summary(snapshot, restarts, at)}");
                if (snapshot.Status != HostFactStatus.Ok) output.WriteLine($"  {"",-16} {Problem(snapshot)}");
            }
            output.WriteLine();
            output.WriteLine("Details: wpshield host health | sites | posture | ports | sessions | inventory <accounts|services|tasks>");
            return;
        }

        var reading = snapshots.FirstOrDefault();
        if (reading is null)
        {
            output.WriteLine($"  No snapshot of {(kind ?? FactOf(section))} yet - the collector has not read it. Start 'wpshield evidence collect' elevated, or use --live.");
            if (section == "health" && restarts.Count > 0) Restarts(output, restarts);
            return;
        }
        output.WriteLine($"  {(kind ?? reading.Fact)}  {Status(reading, at, live)}");
        if (reading.Status != HostFactStatus.Ok) output.WriteLine($"  {Problem(reading)}");
        output.WriteLine();
        switch (section)
        {
            case "health":
                Health(output, reading.Value<HostHealth>(), restarts, at);
                break;
            case "sites":
                Sites(output, reading.Value<HostSites>());
                break;
            case "posture":
                Posture(output, reading.Value<HostPosture>(), queries?.PostureHistory(at.AddDays(-400), at.AddSeconds(1)));
                break;
            case "ports":
                Ports(output, reading.Value<HostPorts>(), all);
                break;
            case "sessions":
                Sessions(output, reading.Value<HostSessions>());
                break;
            default:
                Inventory(output, reading, queries?.InventoryChanges(at.AddDays(-7), at.AddSeconds(1), kind), all);
                break;
        }
    }

    private static IEnumerable<(string Fact, string? Kind)> Rows()
    {
        foreach (var fact in HostFacts.All)
        {
            if (fact == HostFacts.Inventory)
                foreach (var kind in HostFacts.InventoryKinds) yield return (fact, kind);
            else yield return (fact, null);
        }
    }

    private static string Status(HostFactReading snapshot, DateTimeOffset at, bool live)
    {
        var age = live ? "live" : Age(at - snapshot.TakenAt) + " ago";
        var stale = !live && HostFacts.IsStale(snapshot.Fact, snapshot.TakenAt, at) ? " STALE" : "";
        return $"{snapshot.Status,-15} {age,-12}{stale}";
    }

    private static string Problem(HostFactReading snapshot) =>
        $"{Text(snapshot.Reason ?? "no reason recorded")}. {Text(snapshot.Remedy ?? "")}".Trim();

    internal static string Summary(HostFactReading snapshot, IReadOnlyList<HostRestart> restarts, DateTimeOffset now)
    {
        switch (snapshot.Fact)
        {
            case HostFacts.Health when snapshot.Value<HostHealth>() is { } h:
                var codes = restarts.Select(r => r.BugCheck ?? "no code").Distinct(StringComparer.Ordinal).Take(3).ToArray();
                return $"up {Age(TimeSpan.FromSeconds(h.UptimeSeconds))}; unexpected restarts in 30 days: {restarts.Count}" +
                       (codes.Length > 0 ? $" ({string.Join(", ", codes)})" : "") +
                       $"; CPU {(h.CpuPercent is { } cpu ? cpu.ToString("0", CultureInfo.InvariantCulture) + "%" : "unknown")}" +
                       $"; memory {Bytes(h.MemoryAvailableBytes)} free of {Bytes(h.MemoryTotalBytes)}" +
                       $"; build {Text(h.Patch?.Build ?? "unknown")}; last cumulative update: {LastCumulative(h.Patch, now, withTitle: false)}" +
                       (Hotfix(h.Patch) is { } hotfix ? $"; newest hotfix: {hotfix}" : "") +
                       $"; failed installs in 30 days: {(h.Patch is { UpdateLogReadable: true, FailedInstalls30Days: { } failed } ? failed.ToString(CultureInfo.InvariantCulture) : "unknown")}" +
                       (h.Logs?.FirstOrDefault(l => l.Log == "System") is { } system ? $"; System log reaches back {Reach(system, now)}" : "");
            case HostFacts.Sites when snapshot.Value<HostSites>() is { } s:
                var admin = s.Sites.Count(x => x.IdentityIsAdministrator == true);
                return $"{s.Sites.Count} sites, {s.Sites.Count(x => x.State.Equals("Started", StringComparison.OrdinalIgnoreCase))} started; " +
                       $"{admin} run in a pool with administrator rights";
            case HostFacts.Posture when snapshot.Value<HostPosture>() is { } p:
                return $"pools as an administrator: {Count(p.PoolsAdministrator)} of {Count(p.PoolsTotal)}; PHP at server level: " +
                       $"{(p.PhpServerLevel is null ? "unknown" : p.PhpServerLevel.Value ? "yes" : "no")}; writable site folders: {Count(p.WritableSiteFolders)}; " +
                       $"critical {p.Findings.Count(f => f.Severity == "critical")}, warnings {p.Findings.Count(f => f.Severity == "warn")} ({p.Source})";
            case HostFacts.Ports when snapshot.Value<HostPorts>() is { } ports:
                var red = ports.Listeners.Where(l => l.Red).Select(l => $"{l.Port}").Distinct().Take(8).ToArray();
                return $"{ports.Listeners.Count} listeners; open to any by the Windows Firewall rules: " +
                       $"{ports.Listeners.Count(l => l.Verdict == ExposureVerdicts.OpenToAny)}" +
                       (red.Length > 0 ? $"; RED: {string.Join(", ", red)}" : "; none red") +
                       (ports.FirewallRead ? "" : "; firewall policy not read");
            case HostFacts.Sessions when snapshot.Value<HostSessions>() is { } r:
                return $"{r.Current.Count} sessions ({r.Current.Count(c => c.State == "active")} active); {r.Recent.Count} RDP logons in 7 days " +
                       $"from {r.Recent.Select(x => x.Address).OfType<string>().Distinct().Count()} addresses";
            case HostFacts.Inventory when snapshot.Kind == HostFacts.Accounts && snapshot.Value<HostAccounts>() is { } a:
                return $"{a.Accounts.Count} accounts, {a.Accounts.Count(x => x.Enabled)} enabled, {a.Accounts.Count(x => x.Administrator == true)} administrators; " +
                       "attackers try a real account's full name: " +
                       (a.FullNameTargeted is null ? "unknown" : a.FullNameTargeted.Value ? $"YES ({a.FullNameMatches})" : "no");
            case HostFacts.Inventory when snapshot.Kind == HostFacts.Services && snapshot.Value<HostServices>() is { } sv:
                return $"{sv.Services.Count} non-Microsoft services; unsigned {sv.Services.Count(x => x.Signature == HostSignature.Unsigned)}; " +
                       $"flagged {sv.Services.Count(x => x.Flags.Any(f => f != CommandFlags.HasArguments))}" +
                       $"; automatic but not running {sv.Services.Count(x => x.Flags.Contains(ServiceStates.NotRunning))}" +
                       (sv.Services.Count(x => x.Flags.Contains(ServiceStates.Flapping)) is > 0 and var flapping ? $"; flapping {flapping}" : "");
            case HostFacts.Inventory when snapshot.Kind == HostFacts.Tasks && snapshot.Value<HostTasks>() is { } t:
                var grouped = t.Tasks.Count(TaskGroups.IsMicrosoftScriptHostOnly);
                return $"{t.Tasks.Count} tasks listed" + (grouped > 0 ? $" ({grouped} of them Microsoft tasks listed only for a script host)" : "") +
                       $"; unsigned {t.Tasks.Count(x => x.Signature == HostSignature.Unsigned)}; " +
                       $"flagged {t.Tasks.Count(x => x.Flags.Any(f => f != CommandFlags.HasArguments))}";
            default:
                return snapshot.Payload is null ? "nothing was read" : "";
        }
    }

    private static void Health(TextWriter output, HostHealth? health, IReadOnlyList<HostRestart> restarts, DateTimeOffset now)
    {
        if (health is not null)
        {
            var patch = health.Patch;
            output.WriteLine($"  OS build          {Text(patch?.Build ?? "unknown")}{(patch?.DisplayVersion is { } display ? $" ({Text(display)})" : "")}   (registry: CurrentBuild.UBR)");
            output.WriteLine($"  Kernel file       {Text(patch?.KernelVersion ?? "unknown")}   (ntoskrnl.exe ProductVersion){KernelNote(patch)}");
            output.WriteLine($"  Last cumulative   {LastCumulative(patch, now, withTitle: true)}");
            if (patch?.HotfixListRead is not null)
                output.WriteLine($"  Newest hotfix     {Hotfix(patch) ?? "unknown (the hotfix list could not be read)"}   (source: {HostPatchLevel.HotfixSource})");
            output.WriteLine($"  Failed installs   {(patch is { UpdateLogReadable: true, FailedInstalls30Days: { } failed } ? $"{failed} in the last 30 days" : "unknown (the Windows Update log could not be read)")}");
            output.WriteLine("                    Facts as Windows reports them. WPShield has no offline source of the latest build and never calls a host outdated.");
            output.WriteLine($"  Up since          {Time(health.LastBoot)} ({Age(TimeSpan.FromSeconds(health.UptimeSeconds))})");
            output.WriteLine($"  CPU               {(health.CpuPercent is { } cpu ? cpu.ToString("0.0", CultureInfo.InvariantCulture) + "%" : "unknown")}");
            output.WriteLine($"  Memory            {Bytes(health.MemoryAvailableBytes)} free of {Bytes(health.MemoryTotalBytes)}");
            foreach (var volume in health.Volumes)
                output.WriteLine($"  Volume {Text(volume.Name),-10} {Bytes(volume.FreeBytes)} free of {Bytes(volume.TotalBytes)}{(volume.HoldsIisLogs == true ? "  (IIS logs)" : "")}");
            output.WriteLine($"  Evidence store    {Bytes(health.StoreBytes)}");
            Logs(output, health.Logs, now);
            output.WriteLine();
        }
        Restarts(output, restarts);
    }

    /// <summary>
    /// The kernel file against the registry, as a plain fact: a revision a little below the UBR is normal, because not
    /// every cumulative update replaces ntoskrnl.exe.
    /// </summary>
    private static string KernelNote(HostPatchLevel? patch) => patch?.KernelRevisionDelta switch
    {
        null or 0 => "",
        < 0 => $"  - revision below the registry's UBR {patch.Ubr}: normal, because not every update replaces ntoskrnl.exe",
        _ => $"  - revision above the registry's UBR {patch.Ubr}"
    };

    /// <summary>The newest installed hotfix, when the fallback read one; <see langword="null"/> otherwise.</summary>
    private static string? Hotfix(HostPatchLevel? patch) => patch is not { HotfixListRead: true } ? null
        : patch.LastHotfixId is null && patch.LastHotfixInstalledOn is null ? "none listed"
        : (patch.LastHotfixId is { } id ? Text(id) : "an unnamed hotfix") +
          (patch.LastHotfixInstalledOn is { } on ? " installed " + on.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : " (no install date recorded)");

    private static void Logs(TextWriter output, IReadOnlyList<HostLogHorizon>? logs, DateTimeOffset now)
    {
        if (logs is null) return;
        foreach (var log in logs)
        {
            var label = $"{Text(log.Log)} log".PadRight(17);
            if (!log.Readable)
            {
                output.WriteLine($"  {label} unknown ({Text(log.Problem ?? "not read")})");
                continue;
            }
            var size = log.MaximumBytes is { } max ? Bytes(max) : "size unknown";
            var records = log.RecordCount is { } count ? $", {count.ToString("N0", CultureInfo.InvariantCulture)} records" : "";
            var dominant = log.DominantShare is { } share && log.DominantEventId is { } id
                ? $"; {(share * 100).ToString("0.0", CultureInfo.InvariantCulture)}% of the newest {(log.Sampled ?? 0).ToString("N0", CultureInfo.InvariantCulture)} records are {id} {Text(log.DominantProvider ?? "(no provider)")}"
                : "";
            output.WriteLine($"  {label} reaches back {Reach(log, now)} ({size}{records}){dominant}");
        }
        if (logs.FirstOrDefault(l => l.IsShort(now) == true) is { } shortest)
        {
            output.WriteLine("                    A log that reaches back less than a week loses the records of crashes and logons before anyone reads them.");
            output.WriteLine($"                    Its maximum size is set by hand, for example: wevtutil sl {Text(shortest.Log)} /ms:268435456 (256 MB).");
        }
    }

    private static string Reach(HostLogHorizon log, DateTimeOffset now) =>
        !log.Readable ? "unknown" : log.Reach(now) is { } reach ? Age(reach) : log.Sampled == 0 ? "nothing (the log is empty)" : "unknown";

    /// <summary>The newest successful cumulative update, or why it is not known. "Unknown" is never "none".</summary>
    private static string LastCumulative(HostPatchLevel? patch, DateTimeOffset now, bool withTitle)
    {
        if (patch is null || !patch.UpdateLogReadable) return "unknown (the Windows Update log could not be read)";
        if (patch.LastCumulativeUpdateAt is not { } at)
            return "not found in the Windows Update log" + (patch.UpdateLogStartsAt is { } from ? $" (it reaches back to {Time(from)})" : "");
        var days = patch.DaysSinceCumulativeUpdate(now) ?? 0;
        return $"{Time(at)}, {days} day{(days == 1 ? "" : "s")} ago" + (withTitle && patch.LastCumulativeUpdate is { } title ? $": {Text(title)}" : "");
    }

    private static void Restarts(TextWriter output, IReadOnlyList<HostRestart> restarts)
    {
        output.WriteLine($"  Unexpected restarts in the last 30 days: {restarts.Count}");
        foreach (var restart in restarts.Take(RowsShown))
            output.WriteLine($"    {Time(restart.At)}  events {string.Join("/", restart.EventIds)}  {restart.BugCheck ?? "no bugcheck code"}");
        if (restarts.Count > 0) output.WriteLine("    (The time is the next start, when Windows wrote the records.)");
    }

    private static void Sites(TextWriter output, HostSites? sites)
    {
        if (sites is null) return;
        output.WriteLine($"  {"ID",-6} {"STATE",-9} {"ADMIN",-6} {"IDENTITY",-24} {"POOL",-24} SITE");
        foreach (var site in sites.Sites.Take(RowsShown * 4))
            output.WriteLine($"  {site.Id,-6} {Text(site.State),-9} {Flag(site.IdentityIsAdministrator),-6} {Text(site.IdentityType),-24} {Text(site.Pool),-24} {Text(site.Name)}");
    }

    private static void Posture(TextWriter output, HostPosture? posture, IReadOnlyList<PosturePoint>? history)
    {
        if (posture is null) return;
        output.WriteLine($"  Pools as an administrator: {Count(posture.PoolsAdministrator)} of {Count(posture.PoolsTotal)}   (source: {posture.Source})");
        foreach (var finding in posture.Findings)
            output.WriteLine($"  {finding.Severity.ToUpperInvariant(),-9} {finding.Id,-9} {Text(finding.Title)}{(finding.Items > 0 ? $"  [{finding.Items} items]" : "")}");
        if (history is { Count: > 1 })
        {
            output.WriteLine();
            output.WriteLine("  History (pools as an administrator):");
            foreach (var point in history.TakeLast(12))
                output.WriteLine($"    {Time(point.TakenAt)}  {Count(point.PoolsAdministrator)} of {Count(point.PoolsTotal)}  ({point.Source})");
        }
        output.WriteLine();
        output.WriteLine("  The remedies are printed by 'wpshield audit'. Every one is a change made by hand.");
    }

    private static void Ports(TextWriter output, HostPorts? ports, bool all)
    {
        if (ports is null) return;
        output.WriteLine($"  Verdicts are {ExposureVerdicts.Source}; other network filters decide too, so a listener is never shown as \"reachable\".");
        output.WriteLine();
        output.WriteLine($"  {"",-4} {"PROTO",-5} {"PORT",-6} {"BINDING",-9} {"VERDICT",-12} PROGRAM");
        var hidden = 0;
        foreach (var listener in ports.Listeners.OrderByDescending(l => l.Red).ThenBy(l => l.Port).Take(RowsShown * 4))
        {
            output.WriteLine($"  {(listener.Red ? "RED" : ""),-4} {listener.Protocol,-5} {listener.Port,-6} {listener.Binding,-9} {listener.Verdict,-12} {Text(listener.Process ?? "unknown")}");
            if (listener.Verdict != ExposureVerdicts.OpenToAny) continue;
            if (!listener.Red && !all)
            {
                if (listener.OpenedBy is { Count: > 0 }) hidden++;
                continue;
            }
            output.WriteLine(listener.OpenedBy is { Count: > 0 } rules
                ? $"  {"",-4} opened by: {string.Join("; ", rules.Select(Text))}"
                : $"  {"",-4} opened by: unknown (this snapshot did not name the rules)");
        }
        if (ports.Listeners.Any(l => l.Red))
        {
            output.WriteLine();
            output.WriteLine("  Remedy for RED, by hand: restrict every rule named under the port to the addresses that need it (or close it).");
            output.WriteLine("  One allow rule is enough in the Windows Firewall, so a program rule open on any port overrides a port rule");
            output.WriteLine("  restricted by address. Never hide the port.");
        }
        if (hidden > 0)
            output.WriteLine($"  The rules behind the other {hidden} listener(s) open to any address: wpshield host ports --all");
    }

    private static void Sessions(TextWriter output, HostSessions? sessions)
    {
        if (sessions is null) return;
        output.WriteLine("  Current sessions:");
        foreach (var session in sessions.Current)
            output.WriteLine($"    {session.SessionId,-4} {session.State,-13} {Text(session.User)}  {(session.LogonTime is { } t ? "since " + Time(t) : "")}");
        output.WriteLine();
        output.WriteLine("  RDP logons and reconnections, last 7 days (address from LocalSessionManager):");
        foreach (var logon in sessions.Recent.Take(RowsShown))
            output.WriteLine($"    {Time(logon.At)}  {logon.Kind,-9}  {Text(logon.User)}  {logon.Address ?? "local"}");
    }

    private static void Inventory(TextWriter output, HostFactReading reading, IReadOnlyList<InventoryChangeRecord>? changes, bool all)
    {
        switch (reading.Kind)
        {
            case HostFacts.Accounts when reading.Value<HostAccounts>() is { } accounts:
                output.WriteLine($"  {"ENABLED",-8} {"ADMIN",-6} {"RDP",-6} {"PWD AGE",-8} {"LAST LOGON",-20} NAME");
                foreach (var a in accounts.Accounts.Take(RowsShown * 4))
                    output.WriteLine($"  {(a.Enabled ? "yes" : "no"),-8} {Flag(a.Administrator),-6} {Flag(a.RemoteDesktopUser),-6} {(a.PasswordAgeDays is { } d ? d + " d" : "?"),-8} {(a.LastLogon is { } l ? Time(l) : "never"),-20} {Text(a.Name)}");
                output.WriteLine();
                output.WriteLine("  Attackers try a real account's full name: " + (accounts.FullNameTargeted is null ? "unknown"
                    : accounts.FullNameTargeted.Value ? $"YES, {accounts.FullNameMatches} account(s). The names leaked from this server (its login screen or an intrusion)."
                    : "no") + " Full names are compared in memory and never stored.");
                break;
            case HostFacts.Services when reading.Value<HostServices>() is { } services:
                output.WriteLine($"  {"STATE",-9} {"START",-10} {"SIGNATURE",-12} {"ACCOUNT",-22} NAME / EXECUTABLE / FLAGS");
                foreach (var s in services.Services.Take(RowsShown * 4))
                    output.WriteLine($"  {s.State,-9} {s.StartMode,-10} {s.Signature,-12} {Text(s.Account),-22} {Text(s.Name)}  {Text(s.Executable ?? "?")}  {string.Join(" ", s.Flags)}");
                if (services.SignaturesNotChecked > 0) output.WriteLine($"  {services.SignaturesNotChecked} signatures not checked this time (budget); the next snapshot checks them.");
                if (services.Services.Any(s => s.Flags.Contains(ServiceStates.NotRunning) || s.Flags.Contains(ServiceStates.Flapping)))
                {
                    output.WriteLine();
                    output.WriteLine($"  {ServiceStates.NotRunning}: set to start automatically and not running (start pending, paused, or stopped after a failure in 24 h).");
                    output.WriteLine($"  {ServiceStates.Flapping}: {ServiceStates.FlappingThreshold} or more state changes (System event 7036) in the last hour. A service in a start");
                    output.WriteLine("  loop fills the System log and pushes out the records of crashes; stop it or fix it, by hand.");
                }
                break;
            case HostFacts.Tasks when reading.Value<HostTasks>() is { } tasks:
                output.WriteLine($"  {"STATE",-9} {"SIGNATURE",-12} {"RUNS AS",-22} TASK / EXECUTABLE / FLAGS");
                HostTask[] folded = all ? [] : [.. tasks.Tasks.Where(TaskGroups.IsMicrosoftScriptHostOnly)];
                foreach (var t in tasks.Tasks.Except(folded).Take(RowsShown * 4))
                    output.WriteLine($"  {t.State,-9} {t.Signature,-12} {Text(t.Principal),-22} {Text(t.Path)}  {Text(t.Executable ?? "?")}  {string.Join(" ", t.Flags)}");
                if (folded.Length > 0)
                {
                    output.WriteLine();
                    output.WriteLine($"  + {folded.Length} Microsoft task(s) under \\Microsoft\\Windows\\, signed by Microsoft, listed only because they run a script host");
                    output.WriteLine("    (rundll32, cmd, cscript...) with no flag but has-arguments. Still read and stored; wpshield host inventory tasks --all shows them.");
                }
                if (tasks.SignaturesNotChecked > 0) output.WriteLine($"  {tasks.SignaturesNotChecked} signatures not checked this time (budget); the next snapshot checks them.");
                break;
        }
        output.WriteLine();
        output.WriteLine("  Arguments are never stored or shown; flags say what they contained.");
        if (changes is null) return;
        output.WriteLine();
        output.WriteLine($"  Changes in the last 7 days: {changes.Count}");
        foreach (var change in changes.Take(RowsShown))
            output.WriteLine($"    {Time(change.At)}  {change.Change,-8} {Text(change.Item)}{(change.Fields.Count > 0 ? "  (" + string.Join(", ", change.Fields) + ")" : "")}");
    }

    // ---------------------------------------------------------------------------------------------
    //  JSON
    // ---------------------------------------------------------------------------------------------

    private static JsonObject Json(string path, DateTimeOffset at, IReadOnlyList<HostFactReading> snapshots, HostFactsQueries? queries,
        string? section, string? kind, bool live)
    {
        var document = new JsonObject
        {
            ["live"] = live,
            ["store"] = live ? null : path,
            ["now"] = at,
            ["section"] = section,
            ["kind"] = kind,
            ["exposureVerdictsAre"] = ExposureVerdicts.Source,
            ["snapshots"] = new JsonArray([.. snapshots.Select(s => (JsonNode)new JsonObject
            {
                ["fact"] = s.Fact,
                ["kind"] = s.Kind,
                ["takenAt"] = s.TakenAt,
                ["status"] = s.Status,
                ["reason"] = s.Reason,
                ["remedy"] = s.Remedy,
                ["stale"] = !live && HostFacts.IsStale(s.Fact, s.TakenAt, at),
                ["payload"] = s.Payload?.DeepClone()
            })])
        };
        if (queries is not null && (section is null or "health"))
            document["restarts"] = Restarts(queries.Restarts(at - HostFacts.RestartWindow, at.AddSeconds(1)));
        return document;
    }

    private static JsonArray Restarts(IReadOnlyList<HostRestart> restarts) =>
        new([.. restarts.Select(r => (JsonNode)new JsonObject
        {
            ["at"] = r.At,
            ["events"] = new JsonArray([.. r.EventIds.Select(id => (JsonNode)JsonValue.Create(id))]),
            ["bugCheckCode"] = r.BugCheckCode is { } code ? JsonValue.Create(code) : null,
            ["bugCheck"] = r.BugCheck
        })]);

    // ---------------------------------------------------------------------------------------------
    //  Formatting
    // ---------------------------------------------------------------------------------------------

    private static string Text(string text) => AuditCommand.Printable(NetworkMonitorCommand.ConsoleLabel(text));

    private static string Time(DateTimeOffset at) => at.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC";

    private static string Count(int? value) => value is null ? "unknown" : value.Value.ToString(CultureInfo.InvariantCulture);

    private static string Flag(bool? value) => value is null ? "?" : value.Value ? "yes" : "no";

    internal static string Age(TimeSpan age) =>
        age < TimeSpan.Zero ? "0 s"
        : age.TotalMinutes < 1 ? $"{(int)age.TotalSeconds} s"
        : age.TotalHours < 1 ? $"{(int)age.TotalMinutes} min"
        : age.TotalDays < 1 ? $"{(int)age.TotalHours} h"
        : $"{(int)age.TotalDays} d {age.Hours} h";

    private static string Bytes(long? bytes) => bytes switch
    {
        null => "unknown",
        >= 1L << 30 => (bytes.Value / (double)(1L << 30)).ToString("0.0", CultureInfo.InvariantCulture) + " GB",
        >= 1L << 20 => (bytes.Value / (double)(1L << 20)).ToString("0.0", CultureInfo.InvariantCulture) + " MB",
        _ => bytes.Value.ToString(CultureInfo.InvariantCulture) + " B"
    };
}

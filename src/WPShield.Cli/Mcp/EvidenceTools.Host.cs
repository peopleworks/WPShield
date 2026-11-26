using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using WPShield.Evidence;

namespace WPShield.Cli.Mcp;

/// <summary>
/// The host facts of ADR 0013 (<c>host_health</c>, <c>iis_sites</c>, <c>iis_posture</c>,
/// <c>listening_ports</c>, <c>rdp_sessions</c>, <c>host_inventory</c>): what this server is, as opposed to
/// who attacks it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Snapshots only.</b> Every answer comes from <see cref="HostFactsQueries"/>, the snapshots the collector
/// takes on its cadence. Nothing here reads the host, so nothing a model asks for makes WPShield probe the
/// server. Each answer starts with the snapshot it read: its read time, its age, whether it is stale, and its
/// status with the reason and remedy when it is not <c>ok</c>. A fact never read is <c>no-snapshot-yet</c> and
/// its values are <see langword="null"/>: unknown is never shown as none.
/// </para>
/// <para>
/// <b>The host's own names leave only with <c>mcp.host_details</c>,</b> a gate separate from
/// <c>mcp.detailed_records</c> because it releases different content: the server's map, not evidence
/// detail (ADR 0013, section 5). Without it an answer carries counts, statuses, verdicts, port numbers,
/// executable file names, restart times and bugcheck codes, and every site, pool, account, service and
/// task name, host name, path, local address and RDP source address is the plain string <c>withheld</c>.
/// With it, every such value is returned under <c>untrusted</c>: on a compromised host the attacker
/// chooses task names, service display names and executable paths. An executable's file name is always
/// returned, also under <c>untrusted</c>, because an exposure verdict means nothing without it.
/// </para>
/// </remarks>
internal sealed partial class EvidenceTools
{
    private const string Withheld = "withheld";

    private const string HostSnapshotsOnly =
        "Host facts are snapshots the WPShield collector took on its cadence (ADR 0013); this server never reads the host itself. Each snapshot says when it was read, whether it is stale and whether it could be read. A fact with no snapshot or an unreadable status is unknown, not empty.";

    private const string HostDetailsWithheld =
        "Names of sites, pools, accounts, services and tasks, host names, paths, local addresses and RDP source addresses are withheld: the operator has not enabled mcp.host_details. Counts, statuses, verdicts, port numbers, executable file names, restart times and bugcheck codes are complete.";

    private const string NoSnapshotRemedy =
        "Start the WPShield collector elevated ('wpshield evidence collect'): it takes this snapshot on its cadence. Until then this fact is unknown, not empty.";

    private static readonly string[] SessionRangeNames = ["24h", "7d"];

    // ---------------------------------------------------------------------------------------------
    //  host_health
    // ---------------------------------------------------------------------------------------------

    public ToolAnswer HostHealth() => Guard("host_health", () => HostAnswer("host_health", null, (store, host, body, notes) =>
    {
        var reading = host.Latest(HostFacts.Health);
        var readUntil = host.RestartsReadUntil();
        var restarts = host.Restarts(Now - HostFacts.RestartWindow, Now.AddSeconds(1), MaxLimit + 1);
        body["coverage"] = new JsonObject
        {
            ["snapshots"] = new JsonArray(SnapshotNode(HostFacts.Health, null, reading)),
            ["restarts_read_until"] = readUntil is { } until ? Iso(until) : null
        };
        body["detail"] = HostDetailStatement();
        var health = reading?.Value<HostHealth>();
        var hourly = host.HealthHourly(Now.AddHours(-24), Now);
        body["result"] = new JsonObject
        {
            ["read"] = health is not null,
            ["last_boot"] = health is null ? null : Iso(health.LastBoot),
            ["uptime_seconds"] = health?.UptimeSeconds,
            ["cpu_percent"] = health?.CpuPercent,
            ["memory_total_bytes"] = health?.MemoryTotalBytes,
            ["memory_available_bytes"] = health?.MemoryAvailableBytes,
            ["evidence_store_bytes"] = health?.StoreBytes,
            ["volumes"] = health is null ? null : new JsonArray(health.Volumes.Take(HostFacts.MaxVolumes).Select(v => (JsonNode)new JsonObject
            {
                ["volume"] = VolumeName(v.Name),
                ["total_bytes"] = v.TotalBytes,
                ["free_bytes"] = v.FreeBytes,
                ["holds_iis_logs"] = v.HoldsIisLogs
            }).ToArray()),
            ["patch_level"] = health is null ? null : PatchNode(health.Patch),
            ["unexpected_restarts"] = RestartsNode(restarts, readUntil),
            ["last_24_hours"] = new JsonArray(hourly.TakeLast(24).Select(h => (JsonNode)new JsonObject
            {
                ["hour"] = Iso(h.Hour),
                ["samples"] = h.Samples,
                ["cpu_average_percent"] = h.CpuAverage is { } average ? Math.Round(average, 1) : null,
                ["cpu_peak_percent"] = h.CpuPeak is { } peak ? Math.Round(peak, 1) : null,
                ["memory_min_available_bytes"] = h.MemoryMinAvailable
            }).ToArray())
        };
        if (health is not null && health.Patch is null)
            notes.Add("patch_level is null: this snapshot did not read the patch level, which is unknown, not missing.");
        notes.Add("An unexpected restart's time is the next start, when Windows wrote its records (events 41, 6008 and 1001). Restarts are counted from what the System log still held when the collector read it, so a cleared or rolled-over log can hide older ones.");
        notes.Add("patch_level holds what Windows reports about itself. WPShield has no offline source of the latest build and never calls a host outdated.");
    }));

    private JsonObject? PatchNode(HostPatchLevel? patch)
    {
        if (patch is null) return null;
        var readable = patch.UpdateLogReadable;
        return new JsonObject
        {
            ["build"] = patch.Build is { } build ? Code(build) : null,
            ["display_version"] = patch.DisplayVersion is { } display ? Code(display) : null,
            ["kernel_version"] = patch.KernelVersion is { } kernel ? Code(kernel) : null,
            ["kernel_revision_differs_from_registry"] = patch.KernelDiffersFromRegistry,
            ["update_log_readable"] = readable,
            ["last_cumulative_update"] = readable && patch.LastCumulativeUpdate is { } title ? Untrusted(title, HostPatchLevel.MaxTitleLength) : null,
            ["last_cumulative_update_at"] = readable && patch.LastCumulativeUpdateAt is { } at ? Iso(at) : null,
            ["days_since_cumulative_update"] = readable ? patch.DaysSinceCumulativeUpdate(Now) : null,
            ["failed_installs_30_days"] = readable ? patch.FailedInstalls30Days : null,
            ["update_log_starts_at"] = patch.UpdateLogStartsAt is { } from ? Iso(from) : null
        };
    }

    private static JsonObject RestartsNode(IReadOnlyList<HostRestart> restarts, DateTimeOffset? readUntil)
    {
        var known = readUntil is not null || restarts.Count > 0;
        var listed = restarts.Take(MaxLimit).ToArray();
        return new JsonObject
        {
            ["window_days"] = (int)HostFacts.RestartWindow.TotalDays,
            ["read"] = known,
            ["count"] = known ? listed.Length : null,
            ["by_bugcheck"] = new JsonArray(listed.GroupBy(r => r.BugCheckCode).OrderByDescending(g => g.Count()).Select(g => (JsonNode)new JsonObject
            {
                ["bugcheck_code"] = g.Key is { } code ? string.Create(CultureInfo.InvariantCulture, $"0x{code:X}") : null,
                ["bugcheck"] = g.Key is { } named ? BugChecks.Describe(named) : "no bugcheck code",
                ["restarts"] = g.Count()
            }).ToArray()),
            ["restarts"] = new JsonArray(listed.Take(DefaultLimit).Select(r => (JsonNode)new JsonObject
            {
                ["at"] = Iso(r.At),
                ["events"] = new JsonArray(r.EventIds.Take(8).Select(id => (JsonNode)JsonValue.Create(id)).ToArray()),
                ["bugcheck_code"] = r.BugCheckCode is { } code ? string.Create(CultureInfo.InvariantCulture, $"0x{code:X}") : null,
                ["bugcheck"] = r.BugCheck
            }).ToArray()),
            ["truncated"] = restarts.Count > MaxLimit || listed.Length > DefaultLimit
        };
    }

    // ---------------------------------------------------------------------------------------------
    //  iis_sites
    // ---------------------------------------------------------------------------------------------

    public ToolAnswer IisSites() => Guard("iis_sites", () => HostAnswer("iis_sites", null, (store, host, body, notes) =>
    {
        var reading = host.Latest(HostFacts.Sites);
        body["coverage"] = new JsonObject { ["snapshots"] = new JsonArray(SnapshotNode(HostFacts.Sites, null, reading)) };
        body["detail"] = HostDetailStatement();
        var sites = reading?.Value<HostSites>();
        var logs = new WebEvidenceQueries(store).Sites().ToDictionary(s => s.SiteId);
        body["result"] = sites is null ? new JsonObject { ["read"] = false } : new JsonObject
        {
            ["read"] = true,
            ["sites_total"] = sites.Sites.Count,
            ["started"] = sites.Sites.Count(s => s.State.Equals("Started", StringComparison.OrdinalIgnoreCase)),
            ["in_an_administrator_pool"] = sites.Sites.Count(s => s.IdentityIsAdministrator == true),
            ["administrator_unknown"] = sites.Sites.Count(s => s.IdentityIsAdministrator is null),
            ["identity_types"] = new JsonArray(sites.Sites.GroupBy(s => s.IdentityType, StringComparer.Ordinal)
                .OrderByDescending(g => g.Count()).Take(MaxLimit).Select(g => (JsonNode)new JsonObject
                {
                    ["identity_type"] = Code(g.Key),
                    ["sites"] = g.Count()
                }).ToArray()),
            ["sites"] = new JsonArray(sites.Sites.Take(MaxLimit).Select(s => (JsonNode)new JsonObject
            {
                ["site_id"] = s.Id,
                ["name"] = HostName(s.Name),
                ["state"] = Code(s.State),
                ["pool"] = HostName(s.Pool),
                ["identity_type"] = Code(s.IdentityType),
                ["identity_is_administrator"] = s.IdentityIsAdministrator,
                ["bindings"] = new JsonArray(s.Bindings.Take(DefaultLimit).Select(b => (JsonNode)new JsonObject
                {
                    ["protocol"] = Code(b.Protocol),
                    ["port"] = b.Port,
                    ["loopback"] = b.Loopback,
                    ["any_host_name"] = string.IsNullOrEmpty(b.Host),
                    ["host"] = string.IsNullOrEmpty(b.Host) ? null : HostName(b.Host)
                }).ToArray()),
                ["log"] = logs.TryGetValue(s.Id, out var log)
                    ? log.Status == "collected" ? "read" : log.Status == "ignored" ? "ignored" : "not-read"
                    : "not-known-to-the-web-sensor"
            }).ToArray()),
            ["truncated"] = sites.Sites.Count > MaxLimit
        };
        notes.Add("identity_type is the kind of identity a site's pool runs as (ApplicationPoolIdentity, SpecificUser, LocalSystem...). No password is ever read or stored.");
        notes.Add("identity_is_administrator null means unknown, never no. any_host_name true is a binding that answers every host name.");
        notes.Add("log is whether the IIS log sensor (ADR 0011) reads this site's log; web_summary has the reasons.");
    }));

    // ---------------------------------------------------------------------------------------------
    //  iis_posture
    // ---------------------------------------------------------------------------------------------

    public ToolAnswer IisPosture() => Guard("iis_posture", () => HostAnswer("iis_posture", null, (store, host, body, notes) =>
    {
        var reading = host.Latest(HostFacts.Posture);
        body["coverage"] = new JsonObject { ["snapshots"] = new JsonArray(SnapshotNode(HostFacts.Posture, null, reading)) };
        body["detail"] = HostDetailStatement();
        var posture = reading?.Value<HostPosture>();
        var history = host.PostureHistory(Now - HostFacts.PostureRetention, Now.AddSeconds(1));
        body["result"] = new JsonObject
        {
            ["read"] = posture is not null,
            ["source"] = posture is null ? null : Code(posture.Source),
            ["complete"] = posture?.Complete,
            ["pools_total"] = posture?.PoolsTotal,
            ["pools_as_administrator"] = posture?.PoolsAdministrator,
            ["php_mapped_at_server_level"] = posture?.PhpServerLevel,
            ["writable_site_folders"] = posture?.WritableSiteFolders,
            ["ftp_overlaps"] = posture?.FtpOverlaps,
            ["findings"] = posture is null ? null : new JsonArray(posture.Findings.Take(MaxLimit).Select(f => (JsonNode)new JsonObject
            {
                ["id"] = Code(f.Id),
                ["severity"] = Code(f.Severity),
                ["title"] = Untrusted(f.Title, 200),
                ["items"] = f.Items
            }).ToArray()),
            ["history"] = new JsonArray(history.TakeLast(DefaultLimit).Select(p => (JsonNode)new JsonObject
            {
                ["at"] = Iso(p.TakenAt),
                ["source"] = Code(p.Source),
                ["complete"] = p.Complete,
                ["pools_total"] = p.PoolsTotal,
                ["pools_as_administrator"] = p.PoolsAdministrator
            }).ToArray()),
            ["history_points"] = history.Count
        };
        notes.Add("The posture is the audit's summary: finding IDs, severities and counts, never names. source says whether the collector or a manual 'wpshield audit' recorded it.");
        notes.Add("The remedies are printed by 'wpshield audit', and every one is a change an operator makes by hand. This server cannot apply any.");
        if (posture is { Complete: false })
            notes.Add("complete is false: the audit could not look at everything (not elevated, or IIS unreadable), so its counts are a floor, not the state of the host.");
    }));

    // ---------------------------------------------------------------------------------------------
    //  listening_ports
    // ---------------------------------------------------------------------------------------------

    public ToolAnswer ListeningPorts() => Guard("listening_ports", () => HostAnswer("listening_ports", null, (store, host, body, notes) =>
    {
        var reading = host.Latest(HostFacts.Ports);
        body["coverage"] = new JsonObject { ["snapshots"] = new JsonArray(SnapshotNode(HostFacts.Ports, null, reading)) };
        body["detail"] = HostDetailStatement();
        var ports = reading?.Value<HostPorts>();
        var listeners = ports?.Listeners.OrderByDescending(l => l.Red).ThenBy(l => l.Port).ToArray() ?? [];
        body["result"] = ports is null ? new JsonObject { ["read"] = false, ["verdicts_are"] = ExposureVerdicts.Source } : new JsonObject
        {
            ["read"] = true,
            ["firewall_policy_read"] = ports.FirewallRead,
            ["verdicts_are"] = ExposureVerdicts.Source,
            ["listeners_total"] = listeners.Length,
            ["open_to_any"] = listeners.Count(l => l.Verdict == ExposureVerdicts.OpenToAny),
            ["restricted"] = listeners.Count(l => l.Verdict == ExposureVerdicts.Restricted),
            ["blocked"] = listeners.Count(l => l.Verdict == ExposureVerdicts.Blocked),
            ["local_only"] = listeners.Count(l => l.Verdict == ExposureVerdicts.LocalOnly),
            ["unknown"] = listeners.Count(l => l.Verdict == ExposureVerdicts.Unknown),
            ["red"] = listeners.Count(l => l.Red),
            ["listeners"] = new JsonArray(listeners.Take(MaxLimit).Select(l => (JsonNode)new JsonObject
            {
                ["protocol"] = Code(l.Protocol),
                ["port"] = l.Port,
                ["binding"] = Code(l.Binding),
                ["address"] = l.Address is null ? null : l.Binding == "specific" ? HostName(l.Address) : Address(l.Address),
                ["verdict"] = Code(l.Verdict),
                ["red"] = l.Red,
                ["process"] = FileName(l.Process),
                ["process_path"] = l.ProcessPath is null ? null : HostName(l.ProcessPath)
            }).ToArray()),
            ["truncated"] = listeners.Length > MaxLimit,
            ["red_remedy"] = listeners.Any(l => l.Red)
                ? "By hand: restrict the firewall rule to the addresses that need it, or close the port. Never hide it."
                : null
        };
        notes.Add("Verdicts are by the Windows Firewall rules. Other network filters decide too, so a listener is never reported as reachable, and unknown is not closed.");
        notes.Add("red marks SMB (139, 445), RPC (135), SQL Server (1433), MySQL (3306, 33060), PostgreSQL (5432), VNC (5900) and WinRM (5985, 5986) open to any address. Restricted to some addresses, they are not red.");
        if (ports is { FirewallRead: false })
            notes.Add("The firewall policy could not be read for this snapshot, so the verdicts are unknown rather than closed.");
    }));

    // ---------------------------------------------------------------------------------------------
    //  rdp_sessions
    // ---------------------------------------------------------------------------------------------

    public ToolAnswer RdpSessions(string? range = null) => Guard("rdp_sessions", () =>
    {
        var name = (range ?? "7d").Trim().ToLowerInvariant();
        if (!SessionRangeNames.Contains(name, StringComparer.Ordinal))
            throw new ToolArgumentException("range", "range is 24h or 7d: the snapshot holds the RDP logons of the last 7 days.", range);
        var period = new TimeRange(Now - (name == "24h" ? TimeSpan.FromHours(24) : HostFacts.SessionWindow), Now, name);
        return HostAnswer("rdp_sessions", period, (store, host, body, notes) =>
        {
            var reading = host.Latest(HostFacts.Sessions);
            body["coverage"] = new JsonObject { ["snapshots"] = new JsonArray(SnapshotNode(HostFacts.Sessions, null, reading)) };
            body["detail"] = HostDetailStatement();
            var sessions = reading?.Value<HostSessions>();
            if (sessions is null)
            {
                body["result"] = new JsonObject { ["read"] = false };
                return;
            }
            var logons = sessions.Recent.Where(l => l.At >= period.From && l.At <= period.To).OrderByDescending(l => l.At).ToArray();
            body["result"] = new JsonObject
            {
                ["read"] = true,
                ["current_sessions"] = sessions.Current.Count,
                ["active_sessions"] = sessions.Current.Count(s => s.State == "active"),
                ["sessions"] = new JsonArray(sessions.Current.Take(MaxLimit).Select(s => (JsonNode)new JsonObject
                {
                    ["session_id"] = s.SessionId,
                    ["state"] = Code(s.State),
                    ["user"] = HostName(s.User),
                    ["logon_time"] = s.LogonTime is { } at ? Iso(at) : null
                }).ToArray()),
                ["logons_in_range"] = logons.Length,
                ["logons"] = logons.Count(l => l.Kind == "logon"),
                ["reconnections"] = logons.Count(l => l.Kind == "reconnect"),
                ["distinct_users"] = logons.Select(l => l.User).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                ["distinct_source_addresses"] = logons.Select(l => l.Address).OfType<string>().Distinct(StringComparer.Ordinal).Count(),
                ["local_logons"] = logons.Count(l => l.Address is null),
                ["recent"] = new JsonArray(logons.Take(MaxLimit).Select(l => (JsonNode)new JsonObject
                {
                    ["at"] = Iso(l.At),
                    ["kind"] = Code(l.Kind),
                    ["user"] = HostName(l.User),
                    ["address"] = l.Address is null ? "local" : access.HostDetails ? Address(l.Address) : Withheld
                }).ToArray()),
                ["truncated"] = logons.Length > MaxLimit
            };
            notes.Add("Source addresses come from the LocalSessionManager log (events 21 and 25), never from the address a client reports about itself.");
            notes.Add("The snapshot holds the RDP logons of the 7 days before its read time; a logon after the read time is not here yet.");
        });
    });

    // ---------------------------------------------------------------------------------------------
    //  host_inventory
    // ---------------------------------------------------------------------------------------------

    public ToolAnswer HostInventory(string kind) => Guard("host_inventory", () =>
    {
        var parsed = kind?.Trim().ToLowerInvariant();
        if (!HostFacts.IsInventoryKind(parsed))
            throw new ToolArgumentException("kind", "kind is accounts, services or tasks.", kind);
        return HostAnswer("host_inventory", null, (store, host, body, notes) =>
        {
            var reading = host.Latest(HostFacts.Inventory, parsed);
            body["coverage"] = new JsonObject { ["snapshots"] = new JsonArray(SnapshotNode(HostFacts.Inventory, parsed, reading)) };
            body["detail"] = HostDetailStatement();
            var result = parsed switch
            {
                HostFacts.Accounts => AccountsNode(reading?.Value<HostAccounts>()),
                HostFacts.Services => ServicesNode(reading?.Value<HostServices>()),
                _ => TasksNode(reading?.Value<HostTasks>())
            };
            result["kind"] = parsed;
            result["changes_last_7_days"] = ChangesNode(host, parsed!);
            body["result"] = result;
            notes.Add("Only items that are not Microsoft's are listed; a Microsoft-signed item that runs a script host or carries a flag is listed too.");
            notes.Add("Arguments are never stored or returned. flags say what they contained: encoded-command, contains-url, user-writable-path, has-arguments.");
            if (parsed == HostFacts.Accounts)
                notes.Add("full_name_targeted says whether attackers tried a local account's full name. The collector compares the names in memory and stores only the yes or no and the count; null means it could not tell, never no.");
        });
    });

    private JsonObject AccountsNode(HostAccounts? accounts)
    {
        if (accounts is null) return new JsonObject { ["read"] = false };
        return new JsonObject
        {
            ["read"] = true,
            ["accounts_total"] = accounts.Accounts.Count,
            ["enabled"] = accounts.Accounts.Count(a => a.Enabled),
            ["administrators"] = accounts.Accounts.Count(a => a.Administrator == true),
            ["remote_desktop_users"] = accounts.Accounts.Count(a => a.RemoteDesktopUser == true),
            ["password_never_expires"] = accounts.Accounts.Count(a => a.PasswordNeverExpires),
            ["full_name_targeted"] = accounts.FullNameTargeted,
            ["full_name_matches"] = accounts.FullNameMatches,
            ["accounts"] = new JsonArray(accounts.Accounts.Take(MaxLimit).Select(a => (JsonNode)new JsonObject
            {
                ["name"] = HostName(a.Name),
                ["enabled"] = a.Enabled,
                ["administrator"] = a.Administrator,
                ["remote_desktop_user"] = a.RemoteDesktopUser,
                ["last_logon"] = a.LastLogon is { } at ? Iso(at) : null,
                ["password_age_days"] = a.PasswordAgeDays,
                ["password_never_expires"] = a.PasswordNeverExpires
            }).ToArray()),
            ["truncated"] = accounts.Accounts.Count > MaxLimit
        };
    }

    private JsonObject ServicesNode(HostServices? services)
    {
        if (services is null) return new JsonObject { ["read"] = false };
        var ordered = services.Services.OrderByDescending(s => Notable(s.Signature, s.Flags)).ToArray();
        return new JsonObject
        {
            ["read"] = true,
            ["services_total"] = ordered.Length,
            ["unsigned"] = ordered.Count(s => s.Signature == HostSignature.Unsigned),
            ["signatures_not_checked"] = services.SignaturesNotChecked,
            ["flagged"] = ordered.Count(s => Flagged(s.Flags)),
            ["services"] = new JsonArray(ordered.Take(MaxLimit).Select(s => (JsonNode)new JsonObject
            {
                ["name"] = HostName(s.Name),
                ["display_name"] = HostName(s.DisplayName),
                ["state"] = Code(s.State),
                ["start_mode"] = Code(s.StartMode),
                ["account_type"] = AccountType(s.Account),
                ["account"] = HostName(s.Account),
                ["executable"] = FileName(s.Executable),
                ["executable_path"] = s.Executable is null ? null : HostName(s.Executable),
                ["signature"] = Code(s.Signature),
                ["signer"] = s.Signer is null ? null : Untrusted(s.Signer, 128),
                ["flags"] = FlagsNode(s.Flags)
            }).ToArray()),
            ["truncated"] = ordered.Length > MaxLimit
        };
    }

    private JsonObject TasksNode(HostTasks? tasks)
    {
        if (tasks is null) return new JsonObject { ["read"] = false };
        var ordered = tasks.Tasks.OrderByDescending(t => Notable(t.Signature, t.Flags)).ToArray();
        return new JsonObject
        {
            ["read"] = true,
            ["tasks_total"] = ordered.Length,
            ["unsigned"] = ordered.Count(t => t.Signature == HostSignature.Unsigned),
            ["signatures_not_checked"] = tasks.SignaturesNotChecked,
            ["flagged"] = ordered.Count(t => Flagged(t.Flags)),
            ["tasks"] = new JsonArray(ordered.Take(MaxLimit).Select(t => (JsonNode)new JsonObject
            {
                ["task"] = HostName(t.Path),
                ["state"] = Code(t.State),
                ["runs_as_type"] = AccountType(t.Principal),
                ["runs_as"] = HostName(t.Principal),
                ["last_run"] = t.LastRun is { } last ? Iso(last) : null,
                ["next_run"] = t.NextRun is { } next ? Iso(next) : null,
                ["executable"] = FileName(t.Executable),
                ["executable_path"] = t.Executable is null ? null : HostName(t.Executable),
                ["signature"] = Code(t.Signature),
                ["signer"] = t.Signer is null ? null : Untrusted(t.Signer, 128),
                ["flags"] = FlagsNode(t.Flags)
            }).ToArray()),
            ["truncated"] = ordered.Length > MaxLimit
        };
    }

    private JsonObject ChangesNode(HostFactsQueries host, string kind)
    {
        var from = Now.AddDays(-7);
        var changes = host.InventoryChanges(from, Now.AddSeconds(1), kind, MaxLimit + 1);
        var overflows = host.InventoryOverflows(from, Now.AddSeconds(1)).Where(o => o.Kind == kind).ToArray();
        return new JsonObject
        {
            ["count"] = changes.Count,
            ["changes"] = new JsonArray(changes.Take(DefaultLimit).Select(c => (JsonNode)new JsonObject
            {
                ["at"] = Iso(c.At),
                ["change"] = Code(c.Change),
                ["item"] = HostName(c.Item),
                ["fields"] = new JsonArray(c.Fields.Take(8).Select(f => (JsonNode)Code(f)).ToArray())
            }).ToArray()),
            ["truncated"] = changes.Count > DefaultLimit,
            ["overflow_days"] = new JsonArray(overflows.Take(DefaultLimit).Select(o => (JsonNode)new JsonObject
            {
                ["day"] = Iso(o.Day),
                ["changes_counted_not_stored"] = o.Count
            }).ToArray())
        };
    }

    // ---------------------------------------------------------------------------------------------
    //  Host helpers
    // ---------------------------------------------------------------------------------------------

    private ToolAnswer HostAnswer(string tool, TimeRange? period, Action<EvidenceStore, HostFactsQueries, JsonObject, List<string>> fill) =>
        Answer(tool, period, (store, body, notes) =>
        {
            fill(store, new HostFactsQueries(store), body, notes);
            notes.Add(HostSnapshotsOnly);
            if (!access.HostDetails) notes.Add(HostDetailsWithheld);
        });

    /// <summary>The snapshot an answer read: when, how old, whether stale, and why it is not <c>ok</c>.</summary>
    private JsonObject SnapshotNode(string fact, string? kind, HostFactReading? reading)
    {
        var node = new JsonObject { ["fact"] = fact, ["kind"] = kind };
        if (reading is null)
        {
            node["state"] = "no-snapshot-yet";
            node["status"] = null;
            node["read_at"] = null;
            node["stale"] = null;
            node["remedy"] = NoSnapshotRemedy;
            return node;
        }
        node["state"] = "read";
        node["status"] = Code(reading.Status);
        node["read_at"] = Iso(reading.TakenAt);
        node["age_seconds"] = Math.Max(0L, (long)(Now - reading.TakenAt).TotalSeconds);
        node["cadence_seconds"] = (long)HostFacts.Cadence(fact).TotalSeconds;
        node["stale"] = HostFacts.IsStale(fact, reading.TakenAt, Now);
        node["reason"] = reading.Reason is null ? null : Code(reading.Reason);
        node["remedy"] = reading.Remedy is null ? null : Untrusted(reading.Remedy, 300);
        return node;
    }

    private JsonObject HostDetailStatement() => new()
    {
        ["host_details_allowed"] = access.HostDetails,
        ["host_details_allowed_by"] = "mcp.host_details, read when this server started"
    };

    /// <summary>A name or path of this host: the plain string <c>withheld</c>, or the value under <c>untrusted</c>.</summary>
    private JsonNode? HostName(string? value) =>
        value is null ? null : access.HostDetails ? Untrusted(value, HostFacts.MaxNameLength) : JsonValue.Create(Withheld);

    /// <summary>A drive letter names no one; any other volume name is a path, and a host detail.</summary>
    private JsonNode? VolumeName(string? name) =>
        name is not null && DriveLetter().IsMatch(name) ? JsonValue.Create(name) : HostName(name);

    /// <summary>An executable's file name without its folder, always under <c>untrusted</c>.</summary>
    private static JsonNode? FileName(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var cleaned = path.Trim().Trim('"');
        var slash = cleaned.LastIndexOfAny(['\\', '/']);
        var name = slash >= 0 ? cleaned[(slash + 1)..] : cleaned;
        return name.Length == 0 ? null : Untrusted(name, 128);
    }

    private static JsonArray FlagsNode(IReadOnlyList<string> flags) =>
        new(flags.Take(8).Select(f => (JsonNode)Code(f)).ToArray());

    private static bool Flagged(IReadOnlyList<string> flags) => flags.Any(f => f != CommandFlags.HasArguments);

    private static bool Notable(string signature, IReadOnlyList<string> flags) => signature == HostSignature.Unsigned || Flagged(flags);

    /// <summary>
    /// What kind of identity a service or task runs as, without naming it: a built-in or virtual account
    /// names no one, a named account is a host detail.
    /// </summary>
    internal static string AccountType(string? account)
    {
        if (string.IsNullOrWhiteSpace(account)) return "unknown";
        var name = account.Trim().ToLowerInvariant();
        return name switch
        {
            "localsystem" or "system" or @"nt authority\system" or "s-1-5-18" => "local-system",
            "localservice" or @"nt authority\localservice" or @"nt authority\local service" or "s-1-5-19" => "local-service",
            "networkservice" or @"nt authority\networkservice" or @"nt authority\network service" or "s-1-5-20" => "network-service",
            _ when name.StartsWith(@"nt service\", StringComparison.Ordinal) => "virtual-account",
            _ when name.StartsWith(@"iis apppool\", StringComparison.Ordinal) => "pool-identity",
            _ => "named-account"
        };
    }

    [GeneratedRegex(@"^[A-Za-z]:\\?$")]
    private static partial Regex DriveLetter();
}

using System.Runtime.InteropServices;
using System.Text;
using WPShield.Evidence;

namespace WPShield.Cli.Host;

/// <summary>
/// <c>listening_ports</c> (ADR 0013, section 1.1): every TCP and UDP listener, its owning executable, and an
/// exposure verdict "by the Windows Firewall rules". Read-only: the firewall policy is read through its COM
/// interface and nothing is ever set.
/// </summary>
internal static class HostPortsReader
{
    private const int MaxRules = 20_000;

    public static HostFactReading Read(CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var tables = LocalListenerInventory.ReadTables(LocalListenerInventory.ReadTcp, LocalListenerInventory.ReadUdp, null,
            new HashSet<int>(), null, ListenerOwners.Read, includeHints: false);
        if (tables.All(t => t.Status == "unavailable"))
        {
            var denied = tables.Any(t => t.Reason == "access-denied");
            return HostFactReading.Failed(HostFacts.Ports, null, now, denied ? HostFactStatus.NeedsElevation : HostFactStatus.Unreadable,
                "listener-tables: " + string.Join(", ", tables.Select(t => t.Reason).Distinct()),
                "The TCP and UDP listener tables could not be read. Run the collector elevated.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var (policy, firewallProblem) = ReadPolicy(cancellationToken);
        var paths = new Dictionary<uint, string?>();
        var devices = new Lazy<IReadOnlyList<ProcessImagePath.DosDevice>>(ProcessImagePath.DosDevices);
        var listeners = new List<HostListener>();
        var problems = new List<string>();
        if (firewallProblem is not null) problems.Add(firewallProblem);
        if (tables.Any(t => t.Status != "read")) problems.Add("listener-table-limited");
        if (tables.Any(t => t.OwnerReadFailed)) problems.Add("owners-unreadable");

        foreach (var (protocol, endpoint) in tables.SelectMany(t => t.Endpoints.Select(e => (t.Protocol, e))))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (listeners.Count >= HostFacts.MaxListeners)
            {
                problems.Add("listener-bound");
                break;
            }
            var binding = endpoint.Binding switch { "wildcard" => "any", "loopback" => "loopback", _ => "specific" };
            string? path = null;
            if (endpoint.Owner?.ProcessId is uint pid && !paths.TryGetValue(pid, out path))
                paths[pid] = path = ProcessImagePath.Read(pid, () => devices.Value);
            var verdict = ExposureVerdicts.Classify(protocol, endpoint.Port, binding, path, policy);
            var openedBy = verdict == ExposureVerdicts.OpenToAny ? ExposureVerdicts.OpenedBy(protocol, endpoint.Port, binding, path, policy) : null;
            listeners.Add(new HostListener(protocol, endpoint.Port, binding,
                binding == "any" ? null : HostFacts.Clean(endpoint.Address),
                path is null ? null : HostFacts.Clean(Path.GetFileName(path)), path is null ? null : HostFacts.Clean(path),
                verdict, ExposureVerdicts.IsRed(protocol, endpoint.Port, verdict), openedBy is { Count: > 0 } ? openedBy : null));
        }
        var value = new HostPorts(listeners, policy is not null);
        return problems.Count == 0
            ? HostFactReading.Of(HostFacts.Ports, null, now, value)
            : HostFactReading.Of(HostFacts.Ports, null, now, value, HostFactStatus.Partial, string.Join(", ", problems.Distinct()),
                "Verdicts that could not be decided read 'unknown', never 'closed'. Run the collector elevated to read owners and the firewall policy.");
    }

    /// <summary>The policy in force, or <see langword="null"/> and why.</summary>
    internal static (FirewallPolicy? Policy, string? Problem) ReadPolicy(CancellationToken cancellationToken)
    {
        try
        {
            var policy = ComLateBound.Create("HNetCfg.FwPolicy2");
            if (policy is null) return (null, "firewall-unavailable");
            var active = ComLateBound.GetInt(policy, "CurrentProfileTypes");
            int disabled = 0, allow = 0;
            foreach (var profile in new[] { 1, 2, 4 })
            {
                if (!ComLateBound.GetBool(policy, "FirewallEnabled", profile)) disabled |= profile;
                if (ComLateBound.GetInt(policy, "DefaultInboundAction", profile) == 1) allow |= profile;
            }
            var rules = new List<FirewallRule>();
            foreach (var rule in ComLateBound.Items(ComLateBound.Get(policy, "Rules")))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (rules.Count >= MaxRules) return (new FirewallPolicy(active, disabled, allow, rules), "firewall-rule-bound");
                if (ComLateBound.GetInt(rule, "Direction") != 1) continue;
                rules.Add(new FirewallRule(ComLateBound.GetBool(rule, "Enabled"), true, ComLateBound.GetInt(rule, "Action") == 1,
                    ComLateBound.GetInt(rule, "Protocol"), ComLateBound.GetString(rule, "LocalPorts"), ComLateBound.GetString(rule, "RemoteAddresses"),
                    ComLateBound.GetInt(rule, "Profiles"), ComLateBound.GetString(rule, "ApplicationName"), ComLateBound.GetString(rule, "Name"),
                    Optional(rule, "LocalAppPackageId"), Optional(rule, "LocalUserOwner")));
            }
            return (new FirewallPolicy(active, disabled, allow, rules), null);
        }
        catch (Exception exception) when (exception is COMException or UnauthorizedAccessException or InvalidCastException
            or MissingMethodException or MissingMemberException or FormatException or OverflowException)
        {
            return (null, "firewall-unreadable: " + exception.GetType().Name);
        }
    }

    /// <summary>
    /// A property only newer rule interfaces carry (<c>LocalAppPackageId</c> is INetFwRule3's). Missing reads as
    /// <see langword="null"/>, which scopes nothing - the open direction - rather than failing the whole policy.
    /// </summary>
    private static string? Optional(object rule, string property)
    {
        try
        {
            return ComLateBound.GetString(rule, property);
        }
        catch (Exception exception) when (exception is COMException or MissingMethodException or MissingMemberException)
        {
            return null;
        }
    }
}

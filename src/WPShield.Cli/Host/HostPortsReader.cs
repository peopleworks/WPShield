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
            if (endpoint.Owner?.ProcessId is uint pid && !paths.TryGetValue(pid, out path)) paths[pid] = path = ProcessPath(pid);
            var verdict = ExposureVerdicts.Classify(protocol, endpoint.Port, binding, path, policy);
            listeners.Add(new HostListener(protocol, endpoint.Port, binding,
                binding == "any" ? null : HostFacts.Clean(endpoint.Address),
                path is null ? null : HostFacts.Clean(Path.GetFileName(path)), path is null ? null : HostFacts.Clean(path),
                verdict, ExposureVerdicts.IsRed(protocol, endpoint.Port, verdict)));
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
            var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (type is null) return (null, "firewall-unavailable");
            dynamic policy = Activator.CreateInstance(type)!;
            int active = policy.CurrentProfileTypes;
            int disabled = 0, allow = 0;
            foreach (var profile in new[] { 1, 2, 4 })
            {
                if (!(bool)policy.FirewallEnabled[profile]) disabled |= profile;
                if ((int)policy.DefaultInboundAction[profile] == 1) allow |= profile;
            }
            var rules = new List<FirewallRule>();
            foreach (dynamic rule in policy.Rules)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (rules.Count >= MaxRules) return (new FirewallPolicy(active, disabled, allow, rules), "firewall-rule-bound");
                if ((int)rule.Direction != 1) continue;
                rules.Add(new FirewallRule((bool)rule.Enabled, true, (int)rule.Action == 1, (int)rule.Protocol,
                    rule.LocalPorts as string, rule.RemoteAddresses as string, (int)rule.Profiles, rule.ApplicationName as string));
            }
            return (new FirewallPolicy(active, disabled, allow, rules), null);
        }
        catch (Exception exception) when (exception is COMException or UnauthorizedAccessException or InvalidCastException
            or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            return (null, "firewall-unreadable: " + exception.GetType().Name);
        }
    }

    private static string? ProcessPath(uint pid)
    {
        if (pid == 4) return "System";
        var handle = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            var buffer = new StringBuilder(1024);
            var size = buffer.Capacity;
            return QueryFullProcessImageName(handle, 0, buffer, ref size) ? buffer.ToString(0, size) : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}

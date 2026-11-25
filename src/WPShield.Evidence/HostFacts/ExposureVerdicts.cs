using System.Globalization;

namespace WPShield.Evidence;

/// <summary>One inbound rule of the Windows Firewall, reduced to what the exposure verdict reads.</summary>
/// <param name="Protocol">IANA number: 6 TCP, 17 UDP, 256 any.</param>
/// <param name="LocalPorts">The rule's <c>LocalPorts</c> text: <c>*</c>, a list, ranges or keywords.</param>
/// <param name="RemoteAddresses">The rule's <c>RemoteAddresses</c> text; <c>*</c> is any.</param>
/// <param name="Profiles">The profile mask: 1 domain, 2 private, 4 public.</param>
/// <param name="Application">The program the rule is scoped to, or <see langword="null"/> for any.</param>
public sealed record FirewallRule(bool Enabled, bool Inbound, bool Allow, int Protocol, string? LocalPorts, string? RemoteAddresses,
    int Profiles, string? Application);

/// <summary>The firewall state that decides a verdict.</summary>
/// <param name="ActiveProfiles">The mask of the profiles in force now.</param>
/// <param name="Disabled">The mask of the profiles whose firewall is turned off.</param>
/// <param name="DefaultInboundAllow">The mask of the profiles whose default inbound action is allow.</param>
public sealed record FirewallPolicy(int ActiveProfiles, int Disabled, int DefaultInboundAllow, IReadOnlyList<FirewallRule> Rules);

/// <summary>
/// The exposure verdict of a listener, "by the Windows Firewall rules" (ADR 0013, section 1.1).
/// </summary>
/// <remarks>
/// <para>
/// <b>Never "reachable".</b> Other WFP filters and callouts sit in the same path and decide too: a network
/// filter driver, an endpoint product, a provider's edge firewall. A listener the rules admit is not proven
/// reachable, and the verdict is labelled with its source wherever it is shown.
/// </para>
/// <para>
/// <b>When unsure, the open direction.</b> A rule scoped to a program whose path could not be read is taken
/// to apply; a remote-address keyword that means the internet is taken as any. An exposure check that
/// guesses closed is the one that hides the open port.
/// </para>
/// </remarks>
public static class ExposureVerdicts
{
    public const string OpenToAny = "open-to-any";
    public const string Restricted = "restricted";
    public const string Blocked = "blocked";
    public const string LocalOnly = "local-only";
    public const string Unknown = "unknown";

    /// <summary>What every surface prints beside a verdict.</summary>
    public const string Source = "by the Windows Firewall rules";

    public const int ProtocolTcp = 6;
    public const int ProtocolUdp = 17;
    public const int ProtocolAny = 256;

    /// <summary>
    /// Services that must not be open to any address on an internet-facing server: SMB (139, 445), RPC (135),
    /// SQL Server (1433), MySQL (3306, 33060), PostgreSQL (5432), VNC (5900) and WinRM (5985, 5986). Restricted
    /// to some addresses, they are not red: the remedy is to restrict, never to hide.
    /// </summary>
    public static readonly IReadOnlySet<int> RedTcpPorts = new HashSet<int> { 135, 139, 445, 1433, 3306, 33060, 5432, 5900, 5985, 5986 };

    /// <summary>The dynamic RPC range a rule keyword <c>RPC</c> covers on Windows Server.</summary>
    private const int DynamicRpcFirst = 49152;

    public static bool IsRed(string protocol, int port, string verdict) =>
        verdict == OpenToAny && string.Equals(protocol, "TCP", StringComparison.OrdinalIgnoreCase) && RedTcpPorts.Contains(port);

    /// <summary>The verdict for one listener.</summary>
    /// <param name="protocol"><c>TCP</c> or <c>UDP</c>.</param>
    /// <param name="binding"><c>any</c>, <c>specific</c> or <c>loopback</c>.</param>
    /// <param name="processPath">The owning executable, or <see langword="null"/> when unknown.</param>
    /// <param name="policy">The firewall policy, or <see langword="null"/> when it could not be read.</param>
    public static string Classify(string protocol, int port, string binding, string? processPath, FirewallPolicy? policy)
    {
        if (binding == "loopback") return LocalOnly;
        if (policy is null) return Unknown;
        var active = policy.ActiveProfiles & 7;
        if (active == 0) return Unknown;
        // A profile in force with its firewall turned off admits everything on its interfaces.
        if ((policy.Disabled & active) != 0) return OpenToAny;

        var number = string.Equals(protocol, "TCP", StringComparison.OrdinalIgnoreCase) ? ProtocolTcp
            : string.Equals(protocol, "UDP", StringComparison.OrdinalIgnoreCase) ? ProtocolUdp : -1;
        var applicable = policy.Rules.Where(rule => rule.Enabled && rule.Inbound && (rule.Profiles & active) != 0
            && (rule.Protocol == ProtocolAny || rule.Protocol == number)
            && PortMatches(rule.LocalPorts, port)
            && ApplicationMatches(rule.Application, processPath)).ToArray();

        // Block wins over allow in the Windows Firewall.
        if (applicable.Any(rule => !rule.Allow && IsAnyRemote(rule.RemoteAddresses))) return Blocked;
        var allows = applicable.Where(rule => rule.Allow).ToArray();
        if (allows.Any(rule => IsAnyRemote(rule.RemoteAddresses))) return OpenToAny;
        if (allows.Length > 0) return Restricted;
        return (policy.DefaultInboundAllow & active) != 0 ? OpenToAny : Blocked;
    }

    /// <summary>Whether a rule's <c>LocalPorts</c> covers <paramref name="port"/>.</summary>
    public static bool PortMatches(string? localPorts, int port)
    {
        if (string.IsNullOrWhiteSpace(localPorts)) return true;
        foreach (var raw in localPorts.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Take(1000))
        {
            if (raw is "*" || raw.Equals("Any", StringComparison.OrdinalIgnoreCase)) return true;
            if (raw.Equals("RPC-EPMap", StringComparison.OrdinalIgnoreCase))
            {
                if (port == 135) return true;
                continue;
            }
            if (raw.Equals("RPC", StringComparison.OrdinalIgnoreCase))
            {
                if (port >= DynamicRpcFirst) return true;
                continue;
            }
            var dash = raw.IndexOf('-');
            if (dash > 0)
            {
                if (int.TryParse(raw.AsSpan(0, dash), NumberStyles.None, CultureInfo.InvariantCulture, out var first) &&
                    int.TryParse(raw.AsSpan(dash + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var last) &&
                    port >= first && port <= last)
                    return true;
                continue;
            }
            if (int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var single) && single == port) return true;
            // Other keywords (IPHTTPS, Teredo, mDNS, ...) name ports no listener here is assessed for.
        }
        return false;
    }

    /// <summary><c>*</c>, an empty list and the <c>Internet</c> keyword all admit any address on the internet.</summary>
    public static bool IsAnyRemote(string? remoteAddresses)
    {
        if (string.IsNullOrWhiteSpace(remoteAddresses)) return true;
        foreach (var raw in remoteAddresses.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Take(1000))
        {
            if (raw is "*" || raw.Equals("Any", StringComparison.OrdinalIgnoreCase) || raw.Equals("Internet", StringComparison.OrdinalIgnoreCase))
                return true;
            if (raw is "0.0.0.0/0" or "0.0.0.0-255.255.255.255" or "::/0") return true;
        }
        return false;
    }

    private static bool ApplicationMatches(string? application, string? processPath)
    {
        if (string.IsNullOrWhiteSpace(application) || application == "*") return true;
        // Unknown owner: the rule may well apply, and guessing "closed" is the direction that hides a port.
        if (processPath is null) return true;
        var expanded = Environment.ExpandEnvironmentVariables(application);
        return string.Equals(expanded, processPath, StringComparison.OrdinalIgnoreCase);
    }
}

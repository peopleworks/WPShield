using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Win32;

namespace WPShield.NetworkFilter;

/// <summary>
/// Refuses Block mode when it could lock the operator out (ADR 0006, section 3).
/// </summary>
/// <remarks>
/// <para>
/// On a remote server the RDP session used to fix a wrong block is the first thing a wrong block takes
/// away, and the only way back is the hosting provider's console. So Block mode does not start unless
/// the allow-list is non-empty and every address currently connected to the RDP port is on it. The
/// refusal names the addresses, so the operator can copy them into <c>--allow</c>.
/// </para>
/// <para>
/// The port is read from the registry, because it is the port the server actually listens on. A
/// guard that assumed 3389 would wave Block mode through on a host that moved RDP elsewhere.
/// </para>
/// </remarks>
public static class LockoutGuard
{
    public const int DefaultRdpPort = 3389;

    private const string RdpKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";

    public static LockoutGuardResult Evaluate(
        int rdpPort,
        IEnumerable<TcpConnectionSnapshot> established,
        IReadOnlyList<IpRange> allowList)
    {
        ArgumentNullException.ThrowIfNull(established);
        ArgumentNullException.ThrowIfNull(allowList);

        if (allowList.Count == 0)
        {
            return new LockoutGuardResult(
                false,
                [],
                "Block mode needs an allow-list. Name the addresses that must never be blocked - at least the " +
                "one you administer this server from - with --allow.");
        }

        var unlisted = established
            .Where(connection => connection.Local.Port == rdpPort)
            .Select(connection => Normalize(connection.Remote.Address))
            .Where(address => !IPAddress.IsLoopback(address))
            .Where(address => !allowList.Any(range => range.Contains(address)))
            .Distinct()
            .OrderBy(address => address.ToString(), StringComparer.Ordinal)
            .ToList();

        if (unlisted.Count > 0)
        {
            return new LockoutGuardResult(
                false,
                unlisted,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Block mode refused: {string.Join(", ", unlisted)} is connected to the RDP port ({rdpPort}) and is not on the allow-list. Add it with --allow, or you may lose this session."));
        }

        return new LockoutGuardResult(true, [], null);
    }

    /// <summary>The RDP listener's port, from <c>RDP-Tcp\PortNumber</c>; 3389 when it cannot be read.</summary>
    public static int ReadRdpPort()
    {
        if (!OperatingSystem.IsWindows())
        {
            return DefaultRdpPort;
        }

        using var key = Registry.LocalMachine.OpenSubKey(RdpKey);
        return key?.GetValue("PortNumber") is int port and > 0 and < 65536 ? port : DefaultRdpPort;
    }

    public static IReadOnlyList<TcpConnectionSnapshot> ReadEstablishedConnections() =>
        [
            .. IPGlobalProperties.GetIPGlobalProperties()
                .GetActiveTcpConnections()
                .Where(connection => connection.State == TcpState.Established)
                .Select(connection => new TcpConnectionSnapshot(connection.LocalEndPoint, connection.RemoteEndPoint)),
        ];

    private static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}

public readonly record struct TcpConnectionSnapshot(IPEndPoint Local, IPEndPoint Remote);

public sealed record LockoutGuardResult(bool MayBlock, IReadOnlyList<IPAddress> UnlistedRdpClients, string? Refusal);

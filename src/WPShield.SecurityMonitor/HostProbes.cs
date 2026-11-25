using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using WPShield.Evidence.Decisions;

namespace WPShield.SecurityMonitor;

/// <summary>
/// The host's facts the decision engine needs to know what it must never decide against (ADR 0009,
/// section 4): the addresses bound on this host, and who holds a Remote Desktop session right now.
/// </summary>
/// <remarks>
/// Both read and report; neither changes anything. A fact that cannot be read is reported as such
/// (<see langword="null"/>, or <see cref="RemoteDesktopSnapshot.Unreadable"/>), and the engine refuses
/// the decision: "nobody could look" is never turned into "nobody is there".
/// </remarks>
public static class HostProbes
{
    /// <summary>The probes the service uses.</summary>
    public static AddressProtection Protection() => new(OwnAddresses, RemoteDesktop);

    /// <summary>
    /// Every unicast address bound to any interface of this host, up or down: sites on a shared host call
    /// the host's own public address, and an interface that is down now may be up in a minute.
    /// </summary>
    public static IReadOnlyCollection<IPAddress>? OwnAddresses()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .SelectMany(adapter => adapter.GetIPProperties().UnicastAddresses)
                .Select(unicast => unicast.Address)
                .ToArray();
        }
        catch (NetworkInformationException)
        {
            return null;
        }
    }

    /// <summary>The remote addresses established to the Remote Desktop port, read from the port's registry value.</summary>
    public static RemoteDesktopSnapshot RemoteDesktop() => RemoteDesktopConnections.Read();
}

/// <summary>
/// Established TCP connections to this host's Remote Desktop listener, from the extended TCP table.
/// </summary>
/// <remarks>
/// <para>
/// The port is <c>RDP-Tcp\PortNumber</c>, the one the listener actually uses. It is never assumed to be
/// 3389: a guard that assumed it would see nobody connected on a host that moved Remote Desktop
/// elsewhere, which is the host where a lockout is hardest to undo. An unreadable port is an unreadable
/// answer.
/// </para>
/// <para>
/// Reading the table needs no elevation. Both address families are read; an IPv4 client of a dual-stack
/// socket is reported as the IPv4 address it is.
/// </para>
/// </remarks>
internal static class RemoteDesktopConnections
{
    internal const string RdpKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
    private const int MaxBytes = 4 * 1024 * 1024;
    private const uint InsufficientBuffer = 122;
    private const int OwnerPidConnections = 4;
    private const uint Established = 5;

    internal delegate uint ReadTable([Out] byte[] buffer, ref int size, int order, int family, int tableClass, int reserved);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetExtendedTcpTable([Out] byte[] buffer, ref int size, int order, int family, int tableClass, int reserved);

    /// <summary>The real table, for the test that reads a connection it opened itself.</summary>
    internal static readonly ReadTable Native = GetExtendedTcpTable;

    internal static RemoteDesktopSnapshot Read() => Read(ReadPort, Native);

    internal static RemoteDesktopSnapshot Read(Func<object?> port, ReadTable query)
    {
        object? value;
        try
        {
            value = port();
        }
        catch (Exception exception) when (exception is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return RemoteDesktopSnapshot.Unreadable("rdp-port-unreadable");
        }
        if (value is not int number || number is <= 0 or > 65535) return RemoteDesktopSnapshot.Unreadable("rdp-port-unreadable");

        var clients = new List<IPAddress>();
        foreach (var family in new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 })
        {
            var (remotes, problem) = EstablishedTo(number, family, query);
            if (problem is not null) return RemoteDesktopSnapshot.Unreadable(problem);
            clients.AddRange(remotes);
        }
        return RemoteDesktopSnapshot.Of(clients);
    }

    private static object? ReadPort()
    {
        using var key = Registry.LocalMachine.OpenSubKey(RdpKey);
        return key?.GetValue("PortNumber");
    }

    /// <summary>The remote addresses of established connections whose local port is <paramref name="port"/>.</summary>
    internal static (IReadOnlyList<IPAddress> Remotes, string? Problem) EstablishedTo(int port, AddressFamily family, ReadTable query)
    {
        var ipv6 = family == AddressFamily.InterNetworkV6;
        var size = 16 * 1024;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var buffer = new byte[size];
            uint error;
            try
            {
                error = query(buffer, ref size, 0, (int)family, OwnerPidConnections, 0);
            }
            catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
            {
                return ([], "query-failed");
            }
            if (error == InsufficientBuffer)
            {
                // The table grew between the two calls; ask again with what Windows says it needs.
                if (size <= buffer.Length || size > MaxBytes) return ([], "table-limit");
                continue;
            }
            if (error != 0) return ([], error == 5 ? "access-denied" : "query-failed");
            if (size < sizeof(uint) || size > buffer.Length) return ([], "invalid-table");
            return Decode(buffer.AsSpan(0, size), ipv6, port);
        }
        return ([], "table-limit");
    }

    /// <summary>MIB_TCPROW_OWNER_PID (24 bytes) and MIB_TCP6ROW_OWNER_PID (56 bytes); ports in network order.</summary>
    internal static (IReadOnlyList<IPAddress> Remotes, string? Problem) Decode(ReadOnlySpan<byte> table, bool ipv6, int port)
    {
        var stride = ipv6 ? 56 : 24;
        var count = BinaryPrimitives.ReadUInt32LittleEndian(table);
        table = table[sizeof(uint)..];
        if (count > table.Length / stride) return ([], "invalid-table");
        var remotes = new List<IPAddress>();
        for (var i = 0; i < count; i++)
        {
            var row = table.Slice(i * stride, stride);
            uint state;
            int localPort;
            IPAddress remote;
            if (ipv6)
            {
                localPort = BinaryPrimitives.ReadUInt16BigEndian(row[20..]);
                remote = new IPAddress(row.Slice(24, 16));
                state = BinaryPrimitives.ReadUInt32LittleEndian(row[48..]);
            }
            else
            {
                state = BinaryPrimitives.ReadUInt32LittleEndian(row);
                localPort = BinaryPrimitives.ReadUInt16BigEndian(row[8..]);
                remote = new IPAddress(row.Slice(12, 4));
            }
            if (state == Established && localPort == port) remotes.Add(AddressRanges.Canonical(remote));
        }
        return (remotes, null);
    }
}

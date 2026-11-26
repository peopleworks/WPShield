using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace WPShield.Cli;

internal sealed record ListenerOwner(DateTimeOffset ObservedAtUtc, uint? ProcessId, string? Reason);

internal static class ListenerOwners
{
    private const int MaxBytes = 1024 * 1024;
    private const uint InsufficientBuffer = 122;

    internal delegate uint ReadTable([Out] byte[] buffer, ref int size, int order, int family, int tableClass, int reserved);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetExtendedTcpTable([Out] byte[] buffer, ref int size, int order, int family, int tableClass, int reserved);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetExtendedUdpTable([Out] byte[] buffer, ref int size, int order, int family, int tableClass, int reserved);

    internal sealed record Sample(DateTimeOffset ObservedAtUtc, string? Error, Dictionary<IPEndPoint, uint?> Owners)
    {
        internal ListenerOwner For(IPEndPoint endpoint)
        {
            if (Error is not null) return new(ObservedAtUtc, null, Error);
            if (!Owners.TryGetValue(endpoint, out var pid)) return new(ObservedAtUtc, null, "not-observed");
            return pid switch
            {
                null => new(ObservedAtUtc, null, "ambiguous"),
                0 => new(ObservedAtUtc, null, "pid-unavailable"),
                _ => new(ObservedAtUtc, pid, null)
            };
        }
    }

    internal static Sample Read(string protocol, AddressFamily family, IReadOnlySet<IPEndPoint> selected) =>
        Read(protocol, family, selected, protocol == "TCP" ? GetExtendedTcpTable : GetExtendedUdpTable);

    internal static Sample Read(string protocol, AddressFamily family, IReadOnlySet<IPEndPoint> selected, ReadTable query)
    {
        var tcp = protocol == "TCP";
        var ipv6 = family == AddressFamily.InterNetworkV6;
        var size = 4096;
        var observed = DateTimeOffset.UtcNow;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var buffer = new byte[size];
            observed = DateTimeOffset.UtcNow;
            // TCP_TABLE_OWNER_PID_LISTENER = 3; UDP_TABLE_OWNER_PID = 1.
            uint error;
            try
            {
                error = query(buffer, ref size, 0, (int)family, tcp ? 3 : 1, 0);
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
            {
                return new(observed, "query-failed", []);
            }
            if (error == InsufficientBuffer)
            {
                if (size <= buffer.Length || size > MaxBytes) break;
                continue;
            }
            if (error != 0) return new(observed, error == 5 ? "access-denied" : "query-failed", []);
            if (size < sizeof(uint) || size > buffer.Length) return new(observed, "invalid-table", []);
            return Decode(buffer.AsSpan(0, size), tcp, ipv6, selected, observed);
        }
        return new(observed, "table-limit", []);
    }

    private static Sample Decode(ReadOnlySpan<byte> table, bool tcp, bool ipv6, IReadOnlySet<IPEndPoint> selected,
        DateTimeOffset observed)
    {
        // Windows MIB_{TCP,UDP}[6]ROW_OWNER_PID layouts. Each row ends with a native DWORD PID.
        var stride = (tcp, ipv6) switch { (true, true) => 56, (true, false) => 24, (false, true) => 28, _ => 12 };
        var count = BinaryPrimitives.ReadUInt32LittleEndian(table);
        table = table[sizeof(uint)..];
        if (count > table.Length / stride) return new(observed, "invalid-table", []);
        var owners = new Dictionary<IPEndPoint, uint?>();
        for (var i = 0; i < count; i++)
        {
            var row = table.Slice(i * stride, stride);
            var addressOffset = tcp && !ipv6 ? 4 : 0;
            // The scope ID is documented as network byte order, but Windows writes it in host order: measured in both the TCP
            // and UDP tables, a link-local listener on interface 5 carries 05 00 00 00, and IPGlobalProperties reports scope 5.
            var address = ipv6 ? new IPAddress(row[..16], BinaryPrimitives.ReadUInt32LittleEndian(row[16..])) :
                new IPAddress(row.Slice(addressOffset, 4));
            var port = BinaryPrimitives.ReadUInt16BigEndian(row[(ipv6 ? 20 : addressOffset + 4)..]);
            var endpoint = new IPEndPoint(address, port);
            if (!selected.Contains(endpoint)) continue;
            var pid = BinaryPrimitives.ReadUInt32LittleEndian(row[^4..]);
            if (!owners.TryAdd(endpoint, pid) && owners[endpoint] != pid) owners[endpoint] = null;
        }
        return new(observed, null, owners);
    }
}

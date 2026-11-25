using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;

namespace WPShield.Desktop;

/// <summary>
/// What this Remote Desktop session's client reports about itself: an address, or the reason there is
/// none. For information only - see <see cref="RemoteSession"/>.
/// </summary>
internal sealed record RemoteClient(string? Address, string? Problem)
{
    internal const string NotRemote = "not-remote";
    internal const string NotReported = "not-reported";
    internal const string Ipv6 = "ipv6-layout-unknown";
    internal const string OtherFamily = "not-ip";
    internal const string QueryFailed = "query-failed";

    internal static RemoteClient Failed(string problem) => new(null, problem);
}

/// <summary>
/// Whether the current session is a Remote Desktop session (<c>WTSClientProtocolType</c>), and the
/// address its client reports about itself (<c>WTSClientAddress</c> for <c>WTS_CURRENT_SESSION</c>).
/// </summary>
/// <remarks>
/// <para>
/// <b>The client-reported address is never offered as "My current connection".</b> Microsoft's
/// documentation of <c>WTS_CLIENT_ADDRESS</c> says the Remote Desktop client reports it itself: behind
/// NAT it is the client's private address, through a VPN it may be the only address the client has,
/// and through a Remote Desktop Gateway or the Store app there is none. It must not be used to
/// authenticate anyone. The settings window offers the address this server sees instead
/// (<see cref="ConnectionResolver"/>) and mentions this one only to explain a difference.
/// </para>
/// <para>
/// Never a guess. An IPv4 address is at offset 2 of the <c>Address</c> field, as the documentation
/// states. For IPv6 the same documentation contradicts itself on the offset, so an IPv6 value is
/// reported as unknown rather than read from a position that might be wrong. All zeros, a console
/// session or a failed call give nothing.
/// </para>
/// </remarks>
internal static class RemoteSession
{
    private const int WtsClientAddress = 14;
    private const int WtsClientProtocolType = 16;
    private const int CurrentSession = -1;
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int AfUnspec = 0;

    /// <summary>Size of <c>WTS_CLIENT_ADDRESS</c>: a 4-byte family and a 20-byte address.</summary>
    internal const int StructureSize = 24;

    [DllImport("wtsapi32.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);

    [DllImport("wtsapi32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void WTSFreeMemory(IntPtr memory);

    /// <summary>
    /// <see langword="true"/> for a Remote Desktop session, <see langword="false"/> for the console, and
    /// <see langword="null"/> when Windows could not say. Never throws.
    /// </summary>
    internal static bool? IsRemote()
    {
        try
        {
            var protocol = Query(WtsClientProtocolType);
            // 0 is the console session; 2 is RDP.
            return protocol is null || protocol.Length < 2 ? null : BinaryPrimitives.ReadUInt16LittleEndian(protocol) != 0;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            return null;
        }
    }

    /// <summary>The current session's client as the client reports itself. For information only. Never throws.</summary>
    internal static RemoteClient Current()
    {
        try
        {
            var protocol = Query(WtsClientProtocolType);
            if (protocol is null || protocol.Length < 2) return RemoteClient.Failed(RemoteClient.QueryFailed);
            // 0 is the console session; 2 is RDP.
            if (BinaryPrimitives.ReadUInt16LittleEndian(protocol) == 0) return RemoteClient.Failed(RemoteClient.NotRemote);
            var address = Query(WtsClientAddress);
            return address is null ? RemoteClient.Failed(RemoteClient.QueryFailed) : Parse(address);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            return RemoteClient.Failed(RemoteClient.QueryFailed);
        }
    }

    /// <summary>
    /// Reads a <c>WTS_CLIENT_ADDRESS</c>: a little-endian <c>DWORD</c> family, then 20 address bytes
    /// whose IPv4 value starts at offset 2.
    /// </summary>
    internal static RemoteClient Parse(ReadOnlySpan<byte> structure)
    {
        if (structure.Length < StructureSize) return RemoteClient.Failed(RemoteClient.QueryFailed);
        var family = BinaryPrimitives.ReadUInt32LittleEndian(structure);
        var address = structure.Slice(4, 20);
        switch (family)
        {
            case AfInet:
                var bytes = address.Slice(2, 4);
                if (!bytes.ContainsAnyExcept((byte)0)) return RemoteClient.Failed(RemoteClient.NotReported);
                return new(new IPAddress(bytes).ToString(), null);
            case AfInet6:
                return RemoteClient.Failed(address.ContainsAnyExcept((byte)0) ? RemoteClient.Ipv6 : RemoteClient.NotReported);
            case AfUnspec:
                return RemoteClient.Failed(RemoteClient.NotReported);
            default:
                return RemoteClient.Failed(RemoteClient.OtherFamily);
        }
    }

    private static byte[]? Query(int infoClass)
    {
        var buffer = IntPtr.Zero;
        try
        {
            if (!WTSQuerySessionInformationW(IntPtr.Zero, CurrentSession, infoClass, out buffer, out var size) || buffer == IntPtr.Zero ||
                size <= 0 || size > 4096)
                return null;
            var copy = new byte[size];
            Marshal.Copy(buffer, copy, 0, size);
            return copy;
        }
        finally
        {
            if (buffer != IntPtr.Zero) WTSFreeMemory(buffer);
        }
    }
}

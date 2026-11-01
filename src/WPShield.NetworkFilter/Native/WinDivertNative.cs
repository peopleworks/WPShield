using System.Runtime.InteropServices;

namespace WPShield.NetworkFilter.Native;

/// <summary>
/// Platform-invoke declarations for WinDivert 2.2, transcribed from <c>windivert.h</c>.
/// </summary>
/// <remarks>
/// <para>
/// Only what the filter uses is declared. <c>WinDivertSend</c> is absent on purpose: WPShield never
/// reinjects a packet, so there is no code path that could, and ADR 0006 section 1 depends on that
/// being structural rather than a convention.
/// </para>
/// <para>
/// Every import resolves <c>WinDivert.dll</c> from the assembly directory only. This process runs
/// elevated; a search that reached <c>PATH</c> or the working directory would load whatever a less
/// privileged user left there.
/// </para>
/// </remarks>
internal static class WinDivertNative
{
    private const string Library = "WinDivert.dll";

    public const int LayerNetwork = 0;

    public const ulong FlagSniff = 0x0001;
    public const ulong FlagDrop = 0x0002;
    public const ulong FlagRecvOnly = 0x0004;
    public const ulong FlagNoInstall = 0x0010;

    public const int ShutdownRecv = 0x1;
    public const int ShutdownBoth = 0x3;

    /// <summary><c>WINDIVERT_MTU_MAX</c>: the largest packet a receive can return.</summary>
    public const int MtuMax = 40 + 0xFFFF;

    /// <summary><c>WINDIVERT_FILTER_MAXLEN</c> in <c>windivert_device.h</c>: compiled objects per filter.</summary>
    public const int FilterMaxObjects = 256;

    public const short PriorityHighest = 30000;
    public const short PriorityLowest = -30000;

    [DllImport(Library, SetLastError = true, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    public static extern WinDivertSafeHandle WinDivertOpen(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        int layer,
        short priority,
        ulong flags);

    [DllImport(Library, SetLastError = true, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertRecv(
        WinDivertSafeHandle handle,
        [Out] byte[] packet,
        uint packetLength,
        out uint receivedLength,
        out WinDivertAddress address);

    [DllImport(Library, SetLastError = true, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertShutdown(WinDivertSafeHandle handle, int how);

    [DllImport(Library, SetLastError = true, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertClose(IntPtr handle);

    [DllImport(Library, SetLastError = true, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperCompileFilter(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        int layer,
        IntPtr compiledObject,
        uint compiledObjectLength,
        out IntPtr errorText,
        out uint errorPosition);

    [DllImport(Library, SetLastError = true, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperEvalFilter(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        byte[] packet,
        uint packetLength,
        ref WinDivertAddress address);
}

/// <summary>
/// <c>WINDIVERT_ADDRESS</c>: 80 bytes. A 64-bit timestamp, a 32-bit word of bitfields, a reserved
/// 32-bit word, and a 64-byte union of which only the network layer's two interface indexes are used.
/// </summary>
/// <remarks>
/// The bitfields are allocated from the least significant bit, as MSVC lays them out:
/// <c>Layer:8, Event:8, Sniffed:1, Outbound:1, Loopback:1, Impostor:1, IPv6:1, IPChecksum:1,
/// TCPChecksum:1, UDPChecksum:1, Reserved1:8</c>. Declaring this struct smaller than 80 bytes is the
/// defect the 2026-10-20 interop had: the driver writes 80 bytes into it regardless.
/// </remarks>
[StructLayout(LayoutKind.Explicit, Size = 80)]
internal struct WinDivertAddress
{
    public const int Size = 80;

    private const int OutboundBit = 17;
    private const int LoopbackBit = 18;
    private const int Ipv6Bit = 20;

    [FieldOffset(0)]
    public long Timestamp;

    [FieldOffset(8)]
    public uint Bits;

    [FieldOffset(12)]
    public uint Reserved2;

    [FieldOffset(16)]
    public uint InterfaceIndex;

    [FieldOffset(20)]
    public uint SubInterfaceIndex;

    public readonly int Layer => (int)(Bits & 0xFF);

    public readonly bool Outbound => (Bits & (1u << OutboundBit)) != 0;

    public readonly bool Loopback => (Bits & (1u << LoopbackBit)) != 0;

    public readonly bool IsIpv6 => (Bits & (1u << Ipv6Bit)) != 0;

    /// <summary>An address describing an inbound, non-loopback packet at the network layer.</summary>
    public static WinDivertAddress InboundNetwork(bool ipv6) => new()
    {
        Bits = (uint)WinDivertNative.LayerNetwork | (ipv6 ? 1u << Ipv6Bit : 0u),
    };
}

using System.Runtime.InteropServices;

namespace WPShield.NetworkFilter;

/// <summary>
/// Platform-invoke declarations for WinDivert.dll.
///
/// WinDivert is a user-mode packet filtering library: a signed system driver handles
/// packet capture and reinjection, while all filtering decisions run in this process.
/// The library is not bundled here; the WinDivert runtime must be installed on the
/// target machine before <see cref="WinDivertOpen"/> can succeed.
/// </summary>
internal static class WinDivertInterop
{
    private const string Dll = "WinDivert.dll";

    public const int WINDIVERT_LAYER_NETWORK = 0;
    public const int WINDIVERT_FLAG_SNIFF = 1;
    public const uint INVALID_HANDLE = 0xFFFFFFFF;

    [DllImport(Dll, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    public static extern IntPtr WinDivertOpen(
        string filter,
        int layer,
        int priority,
        uint flags);

    [DllImport(Dll, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    public static extern bool WinDivertRecv(
        IntPtr handle,
        IntPtr packet,
        int packetLen,
        out IntPtr addr,
        IntPtr overlapped);

    [DllImport(Dll, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    public static extern bool WinDivertSend(
        IntPtr handle,
        IntPtr packet,
        int packetLen,
        IntPtr addr,
        IntPtr overlapped);

    [DllImport(Dll, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    public static extern bool WinDivertClose(IntPtr handle);

    [DllImport(Dll, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    public static extern bool WinDivertGetParam(
        IntPtr handle,
        int param,
        out uint value);

    [DllImport(Dll, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    public static extern bool WinDivertSetParam(
        IntPtr handle,
        int param,
        uint value);

    public const int WINDIVERT_PARAM_QUEUE_LEN = 1;
    public const int WINDIVERT_PARAM_QUEUE_TIME = 2;
}

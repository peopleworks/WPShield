using Microsoft.Win32.SafeHandles;

namespace WPShield.NetworkFilter.Native;

/// <summary>
/// A WinDivert handle. Releasing it closes the handle, and closing it removes its filter from the
/// driver: that is the whole of ADR 0006's dead-man's switch. A block is never anything other than an
/// open handle owned by this process.
/// </summary>
internal sealed class WinDivertSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public WinDivertSafeHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle() => WinDivertNative.WinDivertClose(handle);
}

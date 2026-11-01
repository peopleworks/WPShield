using System.Runtime.InteropServices;
using WPShield.NetworkFilter.Native;

namespace WPShield.NetworkFilter;

/// <summary>
/// <see cref="IDivertDriver"/> over WinDivert 2.2.
/// </summary>
/// <remarks>
/// Handles are opened with <c>WINDIVERT_FLAG_NO_INSTALL</c> unless the operator passed
/// <c>--install-driver</c>: installing a kernel driver service is a change to the host, and
/// <c>AGENTS.md</c> keeps those to the ones the operator names.
/// </remarks>
public sealed class WinDivertDriver : IDivertDriver
{
    private readonly bool _mayInstallDriver;

    public WinDivertDriver(bool mayInstallDriver)
    {
        _mayInstallDriver = mayInstallDriver;
    }

    public IDivertHandle Open(string filter, DivertHandleKind kind, short priority)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filter);

        var flags = kind switch
        {
            DivertHandleKind.Observe => WinDivertNative.FlagSniff | WinDivertNative.FlagRecvOnly,
            DivertHandleKind.Drop => WinDivertNative.FlagDrop,
            _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown handle kind."),
        };

        if (!_mayInstallDriver)
        {
            flags |= WinDivertNative.FlagNoInstall;
        }

        var handle = InvokeLibrary(() => WinDivertNative.WinDivertOpen(filter, WinDivertNative.LayerNetwork, priority, flags));
        if (handle.IsInvalid)
        {
            try
            {
                var error = Marshal.GetLastPInvokeError();
                throw DivertDriverException.FromOpenFailure(error);
            }
            finally
            {
                handle.Dispose();
            }
        }

        return new WinDivertHandle(handle);
    }

    public FilterCompileResult Compile(string filter)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filter);

        var compiled = InvokeLibrary(() => WinDivertNative.WinDivertHelperCompileFilter(
            filter,
            WinDivertNative.LayerNetwork,
            IntPtr.Zero,
            0,
            out var errorText,
            out var errorPosition)
            ? FilterCompileResult.Success
            : new FilterCompileResult(
                false,
                errorText == IntPtr.Zero ? "unknown error" : Marshal.PtrToStringAnsi(errorText),
                (int)errorPosition));

        return compiled;
    }

    public bool Evaluate(string filter, byte[] packet, bool isIpv6)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filter);
        ArgumentNullException.ThrowIfNull(packet);

        var address = WinDivertAddress.InboundNetwork(isIpv6);
        return InvokeLibrary(() => WinDivertNative.WinDivertHelperEvalFilter(filter, packet, (uint)packet.Length, ref address));
    }

    private static T InvokeLibrary<T>(Func<T> call)
    {
        try
        {
            return call();
        }
        catch (DllNotFoundException exception)
        {
            throw new DivertDriverException(
                "WinDivert.dll was not found in the WPShield program directory. WPShield does not bundle " +
                "WinDivert: download the official 2.2.2 release, and copy WinDivert.dll and WinDivert64.sys " +
                "from its x64 folder next to wpshield.exe.",
                exception);
        }
        catch (EntryPointNotFoundException exception)
        {
            throw new DivertDriverException(
                "The WinDivert.dll next to wpshield.exe is not WinDivert 2.2. Replace it with the one from " +
                "the official 2.2.2 release.",
                exception);
        }
    }

    private sealed class WinDivertHandle : IDivertHandle
    {
        private readonly WinDivertSafeHandle _handle;

        public WinDivertHandle(WinDivertSafeHandle handle)
        {
            _handle = handle;
        }

        public int Receive(byte[] buffer)
        {
            ArgumentNullException.ThrowIfNull(buffer);

            if (WinDivertNative.WinDivertRecv(_handle, buffer, (uint)buffer.Length, out var length, out _))
            {
                return (int)length;
            }

            var error = Marshal.GetLastPInvokeError();
            if (error == DivertDriverException.ErrorNoData)
            {
                return 0;
            }

            throw new DivertDriverException($"WinDivert stopped delivering packets (Win32 error {error}).", error);
        }

        public void Shutdown()
        {
            if (!_handle.IsClosed)
            {
                _ = WinDivertNative.WinDivertShutdown(_handle, WinDivertNative.ShutdownBoth);
            }
        }

        public void Dispose() => _handle.Dispose();
    }
}

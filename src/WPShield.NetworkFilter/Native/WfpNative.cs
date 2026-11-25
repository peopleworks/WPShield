using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WPShield.NetworkFilter.Native;

// Layouts and constants from the Windows SDK (fwpmu.h, fwpmtypes.h and fwptypes.h).
internal static unsafe partial class WfpNative
{
    private const string Library = "fwpuclnt.dll";
    internal const uint DynamicSession = 1;
    internal const uint RpcAuthnWinnt = 10;
    internal const uint Block = 0x1001;
    internal const uint Ipv4Mask = 0x100;
    internal const uint Ipv6Mask = 0x101;
    internal const uint UInt32 = 3;
    internal const uint ByteArray16 = 11;
    internal const uint NotPersistentOrBootTime = 0;
    internal static readonly Guid ReceiveAcceptV4 = new("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
    internal static readonly Guid ReceiveAcceptV6 = new("a3b42c97-9f04-4672-b87e-cee9c483257f");
    internal static readonly Guid RemoteAddress = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    internal static readonly Guid SubLayerKey = new("93a54814-5f1d-44f3-b2ba-f4df18dfe12f");

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport(Library)]
    internal static partial uint FwpmEngineOpen0(nint serverName, uint authnService, nint authIdentity, in Session session, out EngineHandle engine);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport(Library)]
    internal static partial uint FwpmEngineClose0(nint engine);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport(Library)]
    internal static partial uint FwpmSubLayerAdd0(EngineHandle engine, in SubLayer subLayer, nint securityDescriptor);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport(Library)]
    internal static partial uint FwpmFilterAdd0(EngineHandle engine, in Filter filter, nint securityDescriptor, out ulong id);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport(Library)]
    internal static partial uint FwpmFilterDeleteById0(EngineHandle engine, ulong id);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport(Library)]
    internal static partial uint FwpmFilterCreateEnumHandle0(EngineHandle engine, in EnumTemplate template, out nint enumHandle);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport(Library)]
    internal static partial uint FwpmFilterEnum0(EngineHandle engine, nint enumHandle, uint requested, out nint entries, out uint returned);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport(Library)]
    internal static partial uint FwpmFilterDestroyEnumHandle0(EngineHandle engine, nint enumHandle);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport(Library)]
    internal static partial void FwpmFreeMemory0(ref nint memory);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport(Library)]
    internal static partial uint FwpmTransactionBegin0(EngineHandle engine, uint flags);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport(Library)]
    internal static partial uint FwpmTransactionCommit0(EngineHandle engine);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport(Library)]
    internal static partial uint FwpmTransactionAbort0(EngineHandle engine);

    internal sealed class EngineHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public EngineHandle() : base(ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle() => FwpmEngineClose0(handle) == 0;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct DisplayData
    {
        internal char* Name;
        internal char* Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Session
    {
        internal Guid Key;
        internal DisplayData Display;
        internal uint Flags;
        internal uint TransactionWaitMilliseconds;
        internal uint ProcessId;
        internal nint Sid;
        internal nint UserName;
        internal int KernelMode;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Blob
    {
        internal uint Size;
        internal nint Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SubLayer
    {
        internal Guid Key;
        internal DisplayData Display;
        internal uint Flags;
        internal nint ProviderKey;
        internal Blob ProviderData;
        internal ushort Weight;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Value
    {
        internal uint Type;
        internal nuint Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct V4AddressAndMask
    {
        internal uint Address;
        internal uint Mask;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct V6AddressAndMask
    {
        internal fixed byte Address[16];
        internal byte PrefixLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Condition
    {
        internal Guid FieldKey;
        internal uint MatchType;
        internal Value Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Action
    {
        internal uint Type;
        internal Guid FilterType;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct Context
    {
        [FieldOffset(0)] internal ulong Raw;
        [FieldOffset(0)] internal Guid ProviderContextKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Filter
    {
        internal Guid Key;
        internal DisplayData Display;
        internal uint Flags;
        internal nint ProviderKey;
        internal Blob ProviderData;
        internal Guid LayerKey;
        internal Guid SubLayerKey;
        internal Value Weight;
        internal uint ConditionCount;
        internal Condition* Conditions;
        internal Action Action;
        internal Context Context;
        internal nint Reserved;
        internal ulong Id;
        internal Value EffectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct EnumTemplate
    {
        internal nint ProviderKey;
        internal Guid LayerKey;
        internal uint EnumType;
        internal uint Flags;
        internal nint ProviderContextTemplate;
        internal uint ConditionCount;
        internal Condition* Conditions;
        internal uint ActionMask;
        internal nint CalloutKey;
    }
}

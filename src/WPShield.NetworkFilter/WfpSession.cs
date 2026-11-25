using WPShield.NetworkFilter.Native;

namespace WPShield.NetworkFilter;

internal interface IWfpSession : IDisposable
{
    ulong Add(IpRange range);
    bool Contains(ulong id, IpRange range);
    void Delete(ulong id);
    void Update(Action update);
}

internal sealed class WfpException(string message) : Exception(message);

internal sealed unsafe class WfpSession : IWfpSession
{
    private const uint EnumerationBatch = 64;
    private const int MaximumEnumerationBatches = 256;
    private const uint AccessDenied = 5;
    private const uint AlreadyExists = 0x80320009;
    private readonly WfpNative.EngineHandle _engine;

    private WfpSession(WfpNative.EngineHandle engine) => _engine = engine;

    internal static IWfpSession Open()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new WfpException("Windows Filtering Platform is available on Windows only.");
        }

        try
        {
            fixed (char* name = "WPShield network filter")
            {
                var display = new WfpNative.DisplayData { Name = name };
                var session = new WfpNative.Session
                {
                    Display = display,
                    Flags = WfpNative.DynamicSession,
                    TransactionWaitMilliseconds = 5000,
                };
                var result = WfpNative.FwpmEngineOpen0(0, WfpNative.RpcAuthnWinnt, 0, in session, out var engine);
                try
                {
                    Check(result, "Open dynamic session (FwpmEngineOpen0)");
                    var subLayer = new WfpNative.SubLayer
                    {
                        Display = display,
                        Key = WfpNative.SubLayerKey,
                        Weight = 0x100,
                    };
                    result = WfpNative.FwpmSubLayerAdd0(engine, in subLayer, 0);
                    if (result == AlreadyExists)
                    {
                        throw new WfpException("The WPShield WFP sublayer already exists. Stop the other WPShield network filter before retrying.");
                    }

                    Check(result, "Add dynamic sublayer (FwpmSubLayerAdd0)");
                    return new WfpSession(engine);
                }
                catch
                {
                    engine.Dispose();
                    throw;
                }
            }
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException)
        {
            throw new WfpException("The Windows Filtering Platform API could not be loaded from System32.");
        }
    }

    public ulong Add(IpRange range)
    {
        var ipv4 = default(WfpNative.V4AddressAndMask);
        var ipv6 = default(WfpNative.V6AddressAndMask);
        WfpNative.Condition condition;
        if (range.IsIpv6)
        {
            ipv6 = WfpFilterBuilder.Ipv6(range);
            condition = WfpFilterBuilder.Condition(range, &ipv6);
        }
        else
        {
            ipv4 = WfpFilterBuilder.Ipv4(range);
            condition = WfpFilterBuilder.Condition(range, &ipv4);
        }

        fixed (char* name = $"WPShield block {range}")
        {
            var filter = WfpFilterBuilder.Filter(range, &condition, name);
            Check(WfpNative.FwpmFilterAdd0(_engine, in filter, 0, out var id), "Add filter (FwpmFilterAdd0)");
            return id;
        }
    }

    public bool Contains(ulong id, IpRange range)
    {
        var template = new WfpNative.EnumTemplate { LayerKey = WfpFilterBuilder.Layer(range), ActionMask = uint.MaxValue };
        Check(WfpNative.FwpmFilterCreateEnumHandle0(_engine, in template, out var handle),
            "Create filter enumeration (FwpmFilterCreateEnumHandle0)");
        try
        {
            return FindFilter(handle, id, range);
        }
        finally
        {
            Check(WfpNative.FwpmFilterDestroyEnumHandle0(_engine, handle), "Close filter enumeration");
        }
    }

    private bool FindFilter(nint handle, ulong id, IpRange range)
    {
        for (var batch = 0; batch < MaximumEnumerationBatches; batch++)
        {
            var result = WfpNative.FwpmFilterEnum0(_engine, handle, EnumerationBatch, out var entries, out var count);
            try
            {
                Check(result, "Enumerate filters (FwpmFilterEnum0)");
                var filters = (WfpNative.Filter**)entries;
                for (var index = 0; index < count; index++)
                {
                    var filter = filters[index];
                    if (filter->Id == id)
                    {
                        return filter->SubLayerKey == WfpNative.SubLayerKey &&
                            filter->LayerKey == WfpFilterBuilder.Layer(range) &&
                            (filter->Flags & 3) == 0 &&
                            filter->Action.Type == WfpNative.Block &&
                            filter->ConditionCount == 1 && Matches(filter->Conditions, range);
                    }
                }

                if (count < EnumerationBatch)
                {
                    return false;
                }
            }
            finally
            {
                if (entries != 0)
                {
                    WfpNative.FwpmFreeMemory0(ref entries);
                }
            }
        }

        throw new WfpException("The WFP self-test reached the filter enumeration limit.");
    }

    private static bool Matches(WfpNative.Condition* condition, IpRange range)
    {
        if (condition->FieldKey != WfpNative.RemoteAddress || condition->MatchType != 0)
        {
            return false;
        }

        var value = condition->Value;
        if (range.IsIpv6)
        {
            var expected = WfpFilterBuilder.Ipv6(range);
            return value.Type switch
            {
                WfpNative.Ipv6Mask => ((WfpNative.V6AddressAndMask*)value.Data)->PrefixLength == expected.PrefixLength &&
                    new ReadOnlySpan<byte>((void*)value.Data, 16).SequenceEqual(new ReadOnlySpan<byte>(expected.Address, 16)),
                WfpNative.ByteArray16 when range.IsSingleAddress =>
                    new ReadOnlySpan<byte>((void*)value.Data, 16).SequenceEqual(new ReadOnlySpan<byte>(expected.Address, 16)),
                _ => false,
            };
        }

        var ipv4 = WfpFilterBuilder.Ipv4(range);
        return value.Type switch
        {
            WfpNative.Ipv4Mask => ((WfpNative.V4AddressAndMask*)value.Data)->Address == ipv4.Address &&
                ((WfpNative.V4AddressAndMask*)value.Data)->Mask == ipv4.Mask,
            WfpNative.UInt32 when range.IsSingleAddress => (uint)value.Data == ipv4.Address,
            _ => false,
        };
    }

    public void Delete(ulong id) => Check(WfpNative.FwpmFilterDeleteById0(_engine, id), "Delete filter (FwpmFilterDeleteById0)");

    public void Update(Action update)
    {
        Check(WfpNative.FwpmTransactionBegin0(_engine, 0), "Begin filter update");
        try
        {
            update();
            Check(WfpNative.FwpmTransactionCommit0(_engine), "Commit filter update");
        }
        catch
        {
            _ = WfpNative.FwpmTransactionAbort0(_engine);
            throw;
        }
    }

    public void Dispose() => _engine.Dispose();

    private static void Check(uint result, string operation)
    {
        if (result == 0)
        {
            return;
        }

        throw new WfpException(result == AccessDenied
            ? $"{operation} was denied by Windows (0x{result:X8}). Run as Administrator or check the WFP permissions of the current identity."
            : $"{operation} failed (0x{result:X8}).");
    }
}

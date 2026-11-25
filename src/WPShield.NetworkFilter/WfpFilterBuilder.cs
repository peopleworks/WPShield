using System.Buffers.Binary;
using WPShield.NetworkFilter.Native;

namespace WPShield.NetworkFilter;

internal static class WfpFilterBuilder
{
    internal static IpRange[] SelectBlocks(IEnumerable<IpRange> blocks, IReadOnlyList<IpRange> allowList) =>
        blocks.Where(block => !allowList.Any(allowed => allowed.Overlaps(block))).Distinct().ToArray();

    internal static WfpNative.V4AddressAndMask Ipv4(IpRange range) => new()
    {
        Address = BinaryPrimitives.ReadUInt32BigEndian(range.First.GetAddressBytes()),
        Mask = uint.MaxValue << (32 - range.PrefixLength),
    };

    internal static unsafe WfpNative.V6AddressAndMask Ipv6(IpRange range)
    {
        var value = new WfpNative.V6AddressAndMask { PrefixLength = (byte)range.PrefixLength };
        _ = range.First.TryWriteBytes(new Span<byte>(value.Address, 16), out _);
        return value;
    }

    internal static Guid Layer(IpRange range) => range.IsIpv6 ? WfpNative.ReceiveAcceptV6 : WfpNative.ReceiveAcceptV4;

    internal static unsafe WfpNative.Condition Condition(IpRange range, void* mask) => new()
    {
        FieldKey = WfpNative.RemoteAddress,
        MatchType = 0, // FWP_MATCH_EQUAL
        Value = new WfpNative.Value { Type = range.IsIpv6 ? WfpNative.Ipv6Mask : WfpNative.Ipv4Mask, Data = (nuint)mask },
    };

    internal static unsafe WfpNative.Filter Filter(IpRange range, WfpNative.Condition* condition, char* name) => new()
    {
        Key = Guid.NewGuid(),
        Display = new WfpNative.DisplayData { Name = name },
        Flags = WfpNative.NotPersistentOrBootTime,
        LayerKey = Layer(range),
        SubLayerKey = WfpNative.SubLayerKey,
        ConditionCount = 1,
        Conditions = condition,
        Action = new WfpNative.Action { Type = WfpNative.Block },
    };
}

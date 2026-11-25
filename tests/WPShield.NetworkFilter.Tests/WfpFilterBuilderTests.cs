using WPShield.NetworkFilter.Native;

namespace WPShield.NetworkFilter.Tests;

public sealed class WfpFilterBuilderTests
{
    [Theory]
    [InlineData("192.0.2.35", 0xC0000223u, 0xFFFFFFFFu)]
    [InlineData("198.51.100.0/24", 0xC6336400u, 0xFFFFFF00u)]
    public unsafe void Ipv4UsesWfpHostOrderAddressAndMask(string address, uint expectedAddress, uint expectedMask)
    {
        var range = Ranges.Block(address);
        var mask = WfpFilterBuilder.Ipv4(range);
        var condition = WfpFilterBuilder.Condition(range, &mask);
        var filter = WfpFilterBuilder.Filter(range, &condition, null);

        Assert.Equal(expectedAddress, mask.Address);
        Assert.Equal(expectedMask, mask.Mask);
        Assert.Equal(0x100u, condition.Value.Type);
        Assert.Equal((nuint)(&mask), condition.Value.Data);
        AssertFilter(filter, "e1cd9fe7-f4b5-4273-96c0-592e487b8650");
    }

    [Theory]
    [InlineData("2001:db8:abcd:ef00::/56", 56)]
    [InlineData("2001:db8:abcd:ef00::", 128)]
    public unsafe void Ipv6UsesNetworkBytesAndPrefixLength(string address, int prefix)
    {
        var range = Ranges.Block(address);
        var mask = WfpFilterBuilder.Ipv6(range);
        var condition = WfpFilterBuilder.Condition(range, &mask);
        var filter = WfpFilterBuilder.Filter(range, &condition, null);

        Assert.Equal(Convert.FromHexString("20010DB8ABCDEF000000000000000000"), new Span<byte>(mask.Address, 16).ToArray());
        Assert.Equal(prefix, mask.PrefixLength);
        Assert.Equal(0x101u, condition.Value.Type);
        Assert.Equal((nuint)(&mask), condition.Value.Data);
        AssertFilter(filter, "a3b42c97-9f04-4672-b87e-cee9c483257f");
    }

    [Fact]
    public void FiltersExcludeAnyOverlappingPrefixAndDeduplicate()
    {
        var allowed = Ranges.Allow("198.51.100.45");
        var excluded = Ranges.Block("198.51.100.0/24");
        var retained = Ranges.Block("203.0.113.4");

        Assert.Equal([retained], WfpFilterBuilder.SelectBlocks([excluded, retained, retained], [allowed]));
    }

    private static unsafe void AssertFilter(WfpNative.Filter filter, string layer)
    {
        Assert.NotEqual(Guid.Empty, filter.Key);
        Assert.Equal(Guid.Parse(layer), filter.LayerKey);
        Assert.Equal(WfpNative.SubLayerKey, filter.SubLayerKey);
        Assert.Equal(0u, filter.Flags);
        Assert.Equal(0x1001u, filter.Action.Type);
        Assert.Equal(1u, filter.ConditionCount);
        Assert.Equal(Guid.Parse("b235ae9a-1d64-49b8-a44c-5ff3d9095045"), filter.Conditions->FieldKey);
        Assert.Equal(0u, filter.Conditions->MatchType);
    }
}

using Xunit;

namespace WPShield.NetworkSensor.Tests;

public sealed class FlowInterfaceTests
{
    private static readonly FlowInterface First = new(@"\Device\NPF_{00000000-0000-0000-0000-000000000001}",
        "Example A", "Example adapter", true, true);
    private static readonly FlowInterface Second = First with
    {
        DeviceId = @"\Device\NPF_{00000000-0000-0000-0000-000000000002}",
        FriendlyName = "Example B"
    };

    [Fact]
    public void DeviceIdSurvivesRenameAndReorderingAndCannotFallBackToAnAlias()
    {
        var renamed = First with { FriendlyName = "Renamed" };
        var replacement = Second with { FriendlyName = First.DeviceId };
        Assert.Same(renamed, FlowInterface.Resolve([replacement, renamed], First.DeviceId.ToLowerInvariant()));
        var missing = Assert.Throws<InvalidOperationException>(() => FlowInterface.Resolve([replacement], First.DeviceId));
        Assert.Contains("unavailable", missing.Message);
    }

    [Fact]
    public void ExistingNamesAndDescriptionsMustResolveUniquely()
    {
        Assert.Same(First, FlowInterface.Resolve([First, Second], "example a"));
        Assert.Same(First, FlowInterface.Resolve([First], "example adapter"));
        var ambiguous = Assert.Throws<InvalidOperationException>(() => FlowInterface.Resolve([Second, First], "Example adapter"));
        Assert.Contains("ambiguous", ambiguous.Message);
    }
}

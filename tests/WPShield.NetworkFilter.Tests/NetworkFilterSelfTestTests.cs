namespace WPShield.NetworkFilter.Tests;

public sealed class NetworkFilterSelfTestTests
{
    [Fact]
    public void SelfTestAddsOnlyTheNonAllowListedProbeAndDeletesIt()
    {
        using var session = new FakeWfpSession();

        var result = NetworkFilterSelfTest.Run(session, [Ranges.Allow("192.0.2.0/24")]);

        Assert.True(result.Passed, result.Detail);
        Assert.Equal(Ranges.Block("198.51.100.1"), Assert.Single(session.Added));
        Assert.Single(session.Deleted);
        Assert.Empty(session.Filters);
    }

    [Fact]
    public void MissingReadbackFailsAndStillDeletesTheProbe()
    {
        using var session = new FakeWfpSession { EnumerationSucceeds = false };

        Assert.False(NetworkFilterSelfTest.Run(session, []).Passed);
        Assert.Single(session.Deleted);
        Assert.Empty(session.Filters);
    }

    [Fact]
    public void AProbeCannotUseAnAllowListedAddress()
    {
        using var session = new FakeWfpSession();

        Assert.False(NetworkFilterSelfTest.Run(session, [Ranges.Allow("0.0.0.0/0")]).Passed);
        Assert.Empty(session.Added);
    }
}

namespace WPShield.NetworkFilter.Tests;

public sealed class BlockSetTests
{
    private readonly ManualTimeProvider _time = new();

    private BlockSet Create(int capacity = 10, params string[] allow) =>
        new([.. allow.Select(Ranges.Allow)], capacity, _time);

    [Fact]
    public void AnAllowListedAddress_CanNeverEnter()
    {
        var set = Create(allow: "203.0.113.7");

        Assert.Equal(BlockAddOutcome.RefusedAllowListed, set.TryAdd(Ranges.Block("203.0.113.7"), "WP-NET-003", TimeSpan.FromHours(1)));
        Assert.Equal(BlockAddOutcome.RefusedAllowListed, set.TryAdd(Ranges.Block("203.0.113.0/24"), "operator", null));
        Assert.Equal(0, set.Count);
    }

    [Fact]
    public void ARangeContainingAnAllowListedAddress_IsRefused()
    {
        var set = Create(allow: "10.1.2.3");

        Assert.Equal(BlockAddOutcome.RefusedAllowListed, set.TryAdd(Ranges.Block("10.1.0.0/16"), "operator", null));
    }

    [Fact]
    public void ADynamicBlock_ExpiresAndChangesTheVersion()
    {
        var set = Create();
        Assert.Equal(BlockAddOutcome.Added, set.TryAdd(Ranges.Block("198.51.100.9"), "WP-SEC-002", TimeSpan.FromMinutes(60)));
        var version = set.Version;

        _time.Advance(TimeSpan.FromMinutes(59));
        Assert.Empty(set.RemoveExpired());
        _time.Advance(TimeSpan.FromMinutes(1));

        var expired = Assert.Single(set.RemoveExpired());
        Assert.Equal("198.51.100.9", expired.Range.ToString());
        Assert.Equal(0, set.Count);
        Assert.NotEqual(version, set.Version);
    }

    [Fact]
    public void ARepeatFinding_ExtendsTheBlockWithoutChangingTheVersion()
    {
        var set = Create();
        set.TryAdd(Ranges.Block("198.51.100.9"), "WP-SEC-002", TimeSpan.FromMinutes(60));
        var version = set.Version;

        _time.Advance(TimeSpan.FromMinutes(30));
        Assert.Equal(BlockAddOutcome.Extended, set.TryAdd(Ranges.Block("198.51.100.9"), "WP-SEC-002", TimeSpan.FromMinutes(60)));
        Assert.Equal(version, set.Version);

        _time.Advance(TimeSpan.FromMinutes(45));
        Assert.Empty(set.RemoveExpired());
    }

    [Fact]
    public void AnOperatorBlock_NeverExpires()
    {
        var set = Create();
        set.TryAdd(Ranges.Block("94.0.0.0/24"), "operator", null);

        _time.Advance(TimeSpan.FromDays(365));

        Assert.Empty(set.RemoveExpired());
        Assert.Equal(1, set.Count);
    }

    [Fact]
    public void AnAddressInsideAnOperatorRange_IsAlreadyBlocked()
    {
        var set = Create();
        set.TryAdd(Ranges.Block("94.0.0.0/24"), "operator", null);

        Assert.Equal(BlockAddOutcome.AlreadyBlocked, set.TryAdd(Ranges.Block("94.0.0.9"), "WP-NET-003", TimeSpan.FromMinutes(5)));
        Assert.Equal(1, set.Count);
    }

    [Fact]
    public void AFullSet_RefusesNewEntriesAndEvictsNothing()
    {
        var set = Create(capacity: 2);
        set.TryAdd(Ranges.Block("198.51.100.1"), "operator", null);
        set.TryAdd(Ranges.Block("198.51.100.2"), "WP-SEC-002", TimeSpan.FromMinutes(5));

        Assert.Equal(BlockAddOutcome.RefusedFull, set.TryAdd(Ranges.Block("198.51.100.3"), "WP-SEC-002", TimeSpan.FromMinutes(5)));
        Assert.Equal(["198.51.100.1", "198.51.100.2"], set.Snapshot().Select(entry => entry.Range.ToString()));
    }

    [Fact]
    public void TheSnapshot_IsOrderedByAddress()
    {
        var set = Create();
        set.TryAdd(Ranges.Block("198.51.100.20"), "operator", null);
        set.TryAdd(Ranges.Block("198.51.100.3"), "operator", null);
        set.TryAdd(Ranges.Block("2001:db8::1"), "operator", null);

        Assert.Equal(["198.51.100.3", "198.51.100.20", "2001:db8::1"], set.Snapshot().Select(entry => entry.Range.ToString()));
    }
}

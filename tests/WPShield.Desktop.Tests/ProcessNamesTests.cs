using Xunit;

namespace WPShield.Desktop.Tests;

public sealed class ProcessNamesTests
{
    private static readonly DateTimeOffset Sample = DateTimeOffset.UnixEpoch.AddDays(1);

    [Fact]
    public void ReadsEachProcessOnceAndKeepsUnreadableOnesUnnamed()
    {
        var calls = new List<uint>();
        var names = ProcessNames.Resolve([42u, 7u, 42u, 7u], id =>
        {
            calls.Add(id);
            return id == 42 ? new("sqlservr", Sample.AddSeconds(-1)) : null;
        });

        Assert.Equal([42u, 7u], calls);
        Assert.Equal(("sqlservr", null), ProcessNames.ForOwner(names, 42, Sample));
        Assert.Equal(("", "name-unavailable"), ProcessNames.ForOwner(names, 7, Sample));
    }

    [Fact]
    public void NamesThisProcess()
    {
        var observation = DateTimeOffset.UtcNow;
        var identity = Assert.IsType<ProcessNames.Identity>(ProcessNames.Read((uint)Environment.ProcessId));
        Assert.False(string.IsNullOrEmpty(identity.Name));
        Assert.True(identity.StartedAtUtc < observation);
    }

    [Fact]
    public void ReusedPidIsCheckedAgainstEachOwnerObservation()
    {
        var names = ProcessNames.Resolve([42u], _ => new("replacement", Sample));
        Assert.Equal(("", "start-not-before-sample"), ProcessNames.ForOwner(names, 42, Sample.AddTicks(-1)));
        Assert.Equal(("", "start-not-before-sample"), ProcessNames.ForOwner(names, 42, Sample));
        Assert.Equal(("replacement", null), ProcessNames.ForOwner(names, 42, Sample.AddTicks(1)));
    }

    [Fact]
    public void ReportsTheFirstPidSkippedByTheLookupLimit()
    {
        var ids = Enumerable.Range(1, 4097).Select(id => (uint)id);
        var names = ProcessNames.Resolve(ids, _ => null);
        Assert.Equal(4096, names.Count);
        Assert.Equal(("", "name-unavailable"), ProcessNames.ForOwner(names, 4096, Sample));
        Assert.Equal(("", "name-lookup-limit"), ProcessNames.ForOwner(names, 4097, Sample));
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(uint.MaxValue)]
    public void ImpossibleProcessIdsStayUnnamed(uint id) => Assert.Null(ProcessNames.Read(id));
}

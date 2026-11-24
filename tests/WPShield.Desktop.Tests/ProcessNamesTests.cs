using Xunit;

namespace WPShield.Desktop.Tests;

public sealed class ProcessNamesTests
{
    [Fact]
    public void ReadsEachProcessOnceAndKeepsUnreadableOnesUnnamed()
    {
        var calls = new List<uint>();
        var names = ProcessNames.Resolve([42u, 7u, 42u, 7u], id =>
        {
            calls.Add(id);
            return id == 42 ? "sqlservr" : null;
        });

        Assert.Equal([42u, 7u], calls);
        Assert.Equal("sqlservr", names[42]);
        Assert.Null(names[7]);
    }

    [Fact]
    public void NamesThisProcess() =>
        Assert.False(string.IsNullOrEmpty(ProcessNames.Read((uint)Environment.ProcessId)));

    [Theory]
    [InlineData(0u)]
    [InlineData(uint.MaxValue)]
    public void ImpossibleProcessIdsStayUnnamed(uint id) => Assert.Null(ProcessNames.Read(id));
}

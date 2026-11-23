using Xunit;

namespace WPShield.Desktop.Tests;

public sealed class ListenerRowTests
{
    private static readonly ListenerRow Row = new("TCP", "fe80::1%2", 1433, "IPv6", "ms-sql-s", 42, "42", "");

    [Theory]
    [InlineData(null, "", true)]
    [InlineData("UDP", "", false)]
    [InlineData("TCP", "FE80::1%2", true)]
    [InlineData("TCP", "SQL", true)]
    [InlineData("TCP", "1433", true)]
    [InlineData("TCP", "143", false)]
    [InlineData("TCP", "42", true)]
    public void FiltersObservedRows(string? protocol, string query, bool expected) =>
        Assert.Equal(expected, Row.Matches(protocol, query));

    [Fact]
    public void SelectionFollowsTheBindingAcrossOwnerChanges()
    {
        var unknownOwner = Row with { ProcessId = null, Owner = "—" };
        Assert.False(unknownOwner.Matches(null, "42"));
        Assert.Equal(Row.Key, unknownOwner.Key);
        Assert.NotEqual(Row.Key, (Row with { Protocol = "UDP" }).Key);
        Assert.NotEqual(Row.Key, (Row with { Address = "fe80::1%3" }).Key);
    }
}

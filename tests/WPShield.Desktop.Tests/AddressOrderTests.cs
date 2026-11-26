using Xunit;

namespace WPShield.Desktop.Tests;

public sealed class AddressOrderTests
{
    [Fact]
    public void AddressesSortAsNumbersNotAsText()
    {
        string[] shuffled = ["not an address", "2001:db8::1", "203.0.113.20", "203.0.113.0/24", "198.51.100.9", "203.0.113.7",
            "203.0.113.0/16", "203.0.113.0", "::ffff:192.0.2.1"];

        var sorted = shuffled.OrderBy(AddressOrder.Key, StringComparer.Ordinal).ToArray();

        Assert.Equal(["192.0.2.1 as mapped", "198.51.100.9", "203.0.113.0", "203.0.113.0/16", "203.0.113.0/24", "203.0.113.7",
            "203.0.113.20", "2001:db8::1", "not an address"],
            sorted.Select(s => s == "::ffff:192.0.2.1" ? "192.0.2.1 as mapped" : s));
    }

    [Fact]
    public void EmptyTextSortsLast()
    {
        Assert.True(string.CompareOrdinal(AddressOrder.Key("203.0.113.7"), AddressOrder.Key("")) < 0);
        Assert.True(string.CompareOrdinal(AddressOrder.Key("2001:db8::1"), AddressOrder.Key(null)) < 0);
    }
}

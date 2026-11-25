using System.Net;
using System.Text.Json.Nodes;
using WPShield.Evidence;
using Xunit;

namespace WPShield.Evidence.Tests;

public sealed class AddressLabelsTests
{
    private static AddressLabels Labels(string json) => AddressLabels.From(JsonNode.Parse(json));

    [Fact]
    public void AnExactAddressWinsOverTheLongestNetworkWhichWinsOverAShorterOne()
    {
        var labels = Labels("""{"203.0.113.0/16":"Provider","203.0.113.0/24":"Office network","203.0.113.7":"My office"}""");

        Assert.Equal("My office", labels.For("203.0.113.7"));
        Assert.Equal("Office network", labels.For("203.0.113.8"));
        Assert.Equal("Provider", labels.For("203.0.200.1"));
        Assert.Null(labels.For("198.51.100.1"));
    }

    [Fact]
    public void ANetworkWrittenWithHostBitsSetStillMatchesItsWholeNetwork()
    {
        // The catalog accepts "203.0.113.5/24"; System.Net.IPNetwork would refuse it, so this matcher masks.
        var labels = Labels("""{"203.0.113.5/24":"Scanner network"}""");

        Assert.Equal("Scanner network", labels.For("203.0.113.200"));
        Assert.Null(labels.For("203.0.114.1"));
    }

    [Fact]
    public void ZeroBitsMatchEveryAddressOfThatFamilyOnly()
    {
        var labels = Labels("""{"0.0.0.0/0":"Somewhere on IPv4"}""");

        Assert.Equal("Somewhere on IPv4", labels.For("192.0.2.1"));
        Assert.Null(labels.For("2001:db8::1"));
    }

    [Fact]
    public void IPv6NetworksAndMappedAddressesMatch()
    {
        var labels = Labels("""{"2001:db8:1::/48":"Lab","198.51.100.9":"Backup host"}""");

        Assert.Equal("Lab", labels.For("2001:db8:1:ffff::1"));
        Assert.Null(labels.For("2001:db8:2::1"));
        Assert.Equal("Backup host", labels.For(IPAddress.Parse("::ffff:198.51.100.9")));
    }

    [Fact]
    public void EntriesThisBuildCannotReadAreSkippedAndTextIsCleanedAgain()
    {
        var labels = Labels("""{"not-an-ip":"x","203.0.113.0/40":"y","192.0.2.1":5,"192.0.2.2":"Bad‮name","192.0.2.3":""}""");

        Assert.Equal(1, labels.Count);
        Assert.Equal("Bad�name", labels.For("192.0.2.2"));
        Assert.Null(labels.For("192.0.2.1"));
        Assert.Null(labels.For("not an address"));
        Assert.Same(AddressLabels.None, AddressLabels.From(JsonValue.Create(3)));
    }

    [Fact]
    public void LabelsAreReadFromTheStoreSetting()
    {
        var directory = Path.Combine(Path.GetTempPath(), "wpshield-evidence-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            using var store = EvidenceStore.OpenForWriting(Path.Combine(directory, EvidenceStore.FileName));
            Assert.Equal(0, AddressLabels.Read(store).Count);
            new EvidenceSettings(store).Set(AddressLabels.SettingKey, """{"198.51.100.7":"My office"}""", "test", "names");

            Assert.Equal("My office", AddressLabels.Read(store).For("198.51.100.7"));
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }
}

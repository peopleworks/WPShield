using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using Xunit;

namespace WPShield.Cli.Tests;

public sealed class LocalListenerInventoryTests
{
    private static (int Code, JsonElement Report) Inventory(Func<IPEndPoint[]> tcp, Func<IPEndPoint[]> udp, params string[] options)
    {
        using var output = new StringWriter();
        var code = LocalListenerInventory.Run(CliOptions.Parse(["--listeners", "--json", .. options]), output, tcp, udp);
        using var document = JsonDocument.Parse(output.ToString());
        return (code, document.RootElement.Clone());
    }

    [Fact]
    public void RecordsDistinctBindingsPerProtocolAndRefreshesAfterSocketDisappears()
    {
        IPEndPoint[] sockets = [new(IPAddress.Loopback, 443), new(IPAddress.IPv6Any, 443),
            new(IPAddress.Any, 443), new(IPAddress.Any, 443), new(IPAddress.Parse("192.0.2.1"), 1433)];
        var (code, first) = Inventory(() => sockets, () => [new(IPAddress.IPv6Loopback, 443)], "--ports", "443,443");
        Assert.Equal(0, code);
        Assert.Equal(443, Assert.Single(first.GetProperty("Ports").EnumerateArray()).GetInt32());
        var tcp = first.GetProperty("Tables")[0];
        Assert.Equal("TCP", tcp.GetProperty("Protocol").GetString());
        Assert.Equal(TimeSpan.Zero, tcp.GetProperty("ObservedAtUtc").GetDateTimeOffset().Offset);
        var endpoints = tcp.GetProperty("Endpoints").EnumerateArray().ToArray();
        Assert.All(endpoints, row => Assert.False(row.TryGetProperty("Owner", out _)));
        Assert.Equal(["wildcard", "loopback", "wildcard"], endpoints.Select(e => e.GetProperty("Binding").GetString()));
        Assert.Equal("::", endpoints[2].GetProperty("Address").GetString());
        var udp = first.GetProperty("Tables")[1];
        Assert.Equal("UDP", udp.GetProperty("Protocol").GetString());
        Assert.Equal("IPv6", udp.GetProperty("Endpoints")[0].GetProperty("Family").GetString());
        var (_, next) = Inventory(() => [sockets[3], sockets[4]], () => []);
        Assert.Empty(next.GetProperty("Ports").EnumerateArray());
        var nextTcp = next.GetProperty("Tables")[0].GetProperty("Endpoints");
        Assert.Equal(2, nextTcp.GetArrayLength());
        Assert.Equal("specific", nextTcp[1].GetProperty("Binding").GetString());
        Assert.DoesNotContain(nextTcp.EnumerateArray(), e => e.GetProperty("Binding").GetString() == "loopback");
    }

    [Theory]
    [InlineData(false, 2)]
    [InlineData(true, 1)]
    public void FailedTableKeepsItsReasonAndDoesNotHideTheOtherTable(bool bothFail, int expectedCode)
    {
        var (code, report) = Inventory(() => throw new NetworkInformationException(5),
            () => bothFail ? throw new NetworkInformationException(50) : []);
        Assert.Equal(expectedCode, code);
        var tables = report.GetProperty("Tables");
        Assert.Equal("access-denied", tables[0].GetProperty("Reason").GetString());
        Assert.Equal("unavailable", tables[0].GetProperty("Status").GetString());
        Assert.Equal(bothFail ? "unavailable" : "read", tables[1].GetProperty("Status").GetString());
        Assert.Equal(bothFail ? "query-failed" : null, tables[1].GetProperty("Reason").GetString());
        Assert.Empty(tables[1].GetProperty("Endpoints").EnumerateArray());
    }

    [Theory]
    [InlineData(4096, 0, "read")]
    [InlineData(4097, 2, "limited")]
    public void AppliesTheLimitPerProtocolAfterFiltering(int count, int expectedCode, string status)
    {
        var sockets = Enumerable.Range(1, count).Select(p => new IPEndPoint(IPAddress.Any, p)).ToArray();
        var (code, report) = Inventory(() => sockets, () => []);
        Assert.Equal(expectedCode, code);
        var tcp = report.GetProperty("Tables")[0];
        Assert.Equal(status, tcp.GetProperty("Status").GetString());
        Assert.Equal(4096, tcp.GetProperty("Endpoints").GetArrayLength());
        var (filteredCode, filtered) = Inventory(() => sockets, () => [], "--ports", count.ToString());
        Assert.Equal(0, filteredCode);
        Assert.Equal(count, filtered.GetProperty("Tables")[0].GetProperty("Endpoints")[0].GetProperty("Port").GetInt32());
    }

    [Fact]
    public void ConsoleNamesProtocolScopeAndReadStatusEvenWithNoRows()
    {
        using var output = new StringWriter();
        var code = LocalListenerInventory.Run(CliOptions.Parse(["--listeners", "--ports", "443"]),
            output, () => [new(IPAddress.IPv6Loopback, 443)], () => []);
        Assert.Equal(0, code);
        Assert.Contains("Ports: 443", output.ToString());
        Assert.Contains("IPv6  ::1  port 443  loopback", output.ToString());
        Assert.Contains("UDP  read  Endpoints shown: 0", output.ToString());
    }
}

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
        Assert.False(first.TryGetProperty("PortHintCatalog", out _));
        Assert.False(first.TryGetProperty("LocalAddress", out _));
        Assert.False(first.TryGetProperty("Protocol", out _));
        Assert.Equal(443, Assert.Single(first.GetProperty("Ports").EnumerateArray()).GetInt32());
        var tcp = first.GetProperty("Tables")[0];
        Assert.Equal("TCP", tcp.GetProperty("Protocol").GetString());
        Assert.Equal(TimeSpan.Zero, tcp.GetProperty("ObservedAtUtc").GetDateTimeOffset().Offset);
        var endpoints = tcp.GetProperty("Endpoints").EnumerateArray().ToArray();
        Assert.All(endpoints, row => Assert.False(row.TryGetProperty("Owner", out _)));
        Assert.All(endpoints, row => Assert.False(row.TryGetProperty("PortHints", out _)));
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
    public void SortsRetainedBindingsByPortFamilyNumericAddressAndScope()
    {
        string[] addresses = ["fe80::1%10", "192.0.2.10", "::10", "fe80::1%2", "::2", "192.0.2.2"];
        IPEndPoint[] sockets = [.. addresses.Select(a => new IPEndPoint(IPAddress.Parse(a), 443)), new(IPAddress.IPv6Loopback, 80)];
        var (_, report) = Inventory(() => sockets, () => []);
        var rows = report.GetProperty("Tables")[0].GetProperty("Endpoints").EnumerateArray();
        Assert.Equal(["::1", "192.0.2.2", "192.0.2.10", "::2", "::10", "fe80::1%2", "fe80::1%10"],
            rows.Select(row => row.GetProperty("Address").GetString()));
    }

    [Theory]
    [InlineData("127.0.0.1", "127.0.0.1")]
    [InlineData("0.0.0.0", "0.0.0.0")]
    [InlineData("::", "::")]
    [InlineData("FE80:0:0:0:0:0:0:1%2", "fe80::1%2")]
    [InlineData("fe80::1", "fe80::1")]
    public void MatchesTheExactBindingAndOnlyReadsTheSelectedProtocol(string filter, string canonical)
    {
        string[] ips = ["0.0.0.0", "::", "127.0.0.1", "::ffff:127.0.0.1", "fe80::1%2", "fe80::1%10", "fe80::1"];
        IPEndPoint[] udp = [.. ips.Select(a => new IPEndPoint(IPAddress.Parse(a), 443)), new(IPAddress.Parse(canonical), 80)];
        var (code, report) = Inventory(() => throw new InvalidOperationException(), () => udp,
            "--protocol", "uDp", "--local-address", filter, "--ports", "443");
        Assert.Equal(0, code);
        Assert.Equal(canonical, report.GetProperty("LocalAddress").GetString());
        Assert.Equal("UDP", report.GetProperty("Protocol").GetString());
        var table = Assert.Single(report.GetProperty("Tables").EnumerateArray());
        Assert.Equal("UDP", table.GetProperty("Protocol").GetString());
        var row = Assert.Single(table.GetProperty("Endpoints").EnumerateArray());
        Assert.Equal(canonical, row.GetProperty("Address").GetString());
        Assert.Equal(443, row.GetProperty("Port").GetInt32());
    }

    [Fact]
    public void FiltersBeforeTheLimitAndOwnerLookup()
    {
        var selected = new IPEndPoint(IPAddress.Loopback, 443);
        IPEndPoint[] sockets = [.. Enumerable.Range(1, 4097).Select(port => new IPEndPoint(IPAddress.Any, port)), selected];
        var args = CliOptions.Parse(["--listeners", "--protocol", "TCP", "--local-address", "127.0.0.1", "--owners"]);
        using var output = new StringWriter();
        var code = LocalListenerInventory.Run(args, output, () => sockets, () => throw new InvalidOperationException(),
            (protocol, _, endpoints) =>
            {
                Assert.Equal("TCP", protocol);
                Assert.Equal(selected, Assert.Single(endpoints));
                return new(DateTimeOffset.UnixEpoch, null, new() { [selected] = 42 });
            });
        Assert.Equal(0, code);
        Assert.Contains("PID 42", output.ToString());
    }

    [Theory]
    [InlineData(true, 1, "unavailable")]
    [InlineData(false, 0, "read")]
    public void ConsolePreservesTheScopeOfEmptyAndUnavailableTables(bool denied, int expected, string status)
    {
        var args = CliOptions.Parse(["--listeners", "--protocol", "tCp", "--local-address", "127.0.0.1"]);
        using var output = new StringWriter();
        var code = LocalListenerInventory.Run(args, output,
            () => denied ? throw new UnauthorizedAccessException() : [new(IPAddress.Any, 80)], () => throw new InvalidOperationException());
        Assert.Equal(expected, code);
        Assert.Contains("Local address: 127.0.0.1", output.ToString());
        Assert.Contains("Protocol: TCP", output.ToString());
        Assert.Contains($"TCP  {status}", output.ToString());
        Assert.Contains("Endpoints shown: 0", output.ToString());
    }

    [Theory]
    [InlineData("--protocol", null)]
    [InlineData("--protocol", "all")]
    [InlineData("--local-address", null)]
    [InlineData("--local-address", "server.example")]
    [InlineData("--local-address", "192.0.2.0/24")]
    [InlineData("--local-address", "127.1")]
    [InlineData("--local-address", "0x7f000001")]
    [InlineData("--local-address", "[::1]:443")]
    [InlineData("--local-address", "127.0.0.1%2")]
    [InlineData("--local-address", "fe80::1%Ethernet")]
    [InlineData("--local-address", "fe80::1%")]
    [InlineData("--local-address", "fe80::1%4294967296")]
    public void RejectsInvalidFiltersBeforeReadingWindows(string option, string? value)
    {
        string[] options = value is null ? [option] : [option, value];
        Assert.Throws<CliArgumentException>(() =>
            Inventory(() => throw new InvalidOperationException(), () => throw new InvalidOperationException(), options));
    }

    [Fact]
    public void OfflineHintsUseTransportAndPreserveEverySelectedRegistration()
    {
        IPEndPoint[] sockets = [new(IPAddress.IPv6Loopback, 465), new(IPAddress.Any, 55001)];
        var (code, report) = Inventory(() => sockets, () => sockets, "--port-hints");
        Assert.Equal(0, code);
        Assert.Equal("wpshield-iana-v1", report.GetProperty("PortHintCatalog").GetString());
        var tables = report.GetProperty("Tables");
        Assert.Equal(["submissions", "urd"], tables[0].GetProperty("Endpoints")[0].GetProperty("PortHints").EnumerateArray().Select(h => h.GetString()));
        Assert.Equal("igmpv3lite", Assert.Single(tables[1].GetProperty("Endpoints")[0].GetProperty("PortHints").EnumerateArray()).GetString());
        foreach (var table in tables.EnumerateArray())
        {
            var rows = table.GetProperty("Endpoints");
            Assert.Empty(rows[1].GetProperty("PortHints").EnumerateArray());
            Assert.False(rows[0].TryGetProperty("Owner", out _));
        }
    }

    [Fact]
    public void SharedListenerKeepsItsAmbiguousOwnerWithAKnownPortHint()
    {
        var shared = new IPEndPoint(IPAddress.Any, 1433);
        using var output = new StringWriter();
        var args = CliOptions.Parse(["--listeners", "--port-hints", "--owners", "--json"]);
        Assert.Equal(0, LocalListenerInventory.Run(args, output, () => [shared], () => [],
            (_, _, _) => new(DateTimeOffset.UnixEpoch, null, new() { [shared] = null })));
        using var doc = JsonDocument.Parse(output.ToString());
        var row = doc.RootElement.GetProperty("Tables")[0].GetProperty("Endpoints")[0];
        Assert.Equal("ms-sql-s", Assert.Single(row.GetProperty("PortHints").EnumerateArray()).GetString());
        Assert.Equal(JsonValueKind.Null, row.GetProperty("Owner").GetProperty("ProcessId").ValueKind);
        Assert.Equal("ambiguous", row.GetProperty("Owner").GetProperty("Reason").GetString());
    }

    [Fact]
    public void ConsoleShowsTheCatalogAndUnknownForAnUnlistedTransport()
    {
        using var output = new StringWriter();
        var args = CliOptions.Parse(["--listeners", "--port-hints", "--ports", "143"]);
        IPEndPoint[] sockets = [new(IPAddress.IPv6Any, 143)];
        Assert.Equal(0, LocalListenerInventory.Run(args, output, () => sockets, () => sockets));
        Assert.Contains("wpshield-iana-v1 (registry names only)", output.ToString());
        Assert.Contains("Port hints: imap", output.ToString());
        Assert.Contains("Port hints: unknown", output.ToString());
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

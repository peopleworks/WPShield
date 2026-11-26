using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Xunit;

namespace WPShield.Cli.Tests;

public sealed class ListenerOwnerTests
{
    [Theory]
    [InlineData("TCP", false, 24, 4, 8)]
    [InlineData("TCP", true, 56, 0, 20)]
    [InlineData("UDP", false, 12, 0, 4)]
    [InlineData("UDP", true, 28, 0, 20)]
    public void ReadsPidFromExactEndpointIncludingIpv6Scope(string protocol, bool ipv6, int stride, int addressOffset, int portOffset)
    {
        var address = IPAddress.Parse(ipv6 ? "fe80::1%9" : "192.0.2.1");
        var endpoint = new IPEndPoint(address, 43210);
        uint Query(byte[] buffer, ref int size, int order, int family, int tableClass, int reserved)
        {
            Assert.Equal((int)address.AddressFamily, family);
            Assert.Equal(protocol == "TCP" ? 3 : 1, tableClass);
            BinaryPrimitives.WriteUInt32LittleEndian(buffer, 1);
            var row = buffer.AsSpan(4, stride);
            address.GetAddressBytes().CopyTo(row[addressOffset..]);
            // Host order, as Windows writes it (not the network order its documentation states).
            if (ipv6) BinaryPrimitives.WriteUInt32LittleEndian(row[16..], 9);
            BinaryPrimitives.WriteUInt16BigEndian(row[portOffset..], 43210);
            BinaryPrimitives.WriteUInt32LittleEndian(row[^4..], 701);
            size = stride + 4;
            return 0;
        }
        var sample = ListenerOwners.Read(protocol, address.AddressFamily, new HashSet<IPEndPoint> { endpoint }, Query);
        Assert.Equal(701u, sample.For(endpoint).ProcessId);
        Assert.Null(sample.For(endpoint).Reason);
        if (ipv6) Assert.Equal("not-observed", sample.For(new(IPAddress.Parse("fe80::1%8"), 43210)).Reason);
    }

    [Theory]
    [InlineData(70u, 70u, 70u, null)]
    [InlineData(70u, 71u, null, "ambiguous")]
    [InlineData(0u, 70u, null, "ambiguous")]
    [InlineData(0u, 0u, null, "pid-unavailable")]
    public void SharedBindingsRequireOneNonzeroPid(uint first, uint second, uint? expected, string? reason)
    {
        var endpoint = new IPEndPoint(IPAddress.Loopback, 443);
        uint Query(byte[] buffer, ref int size, int order, int family, int tableClass, int reserved)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(buffer, 2);
            foreach (var (offset, pid) in new[] { (4, first), (16, second) })
            {
                endpoint.Address.GetAddressBytes().CopyTo(buffer, offset);
                BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset + 4), 443);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset + 8), pid);
            }
            size = 28;
            return 0;
        }
        var sample = ListenerOwners.Read("UDP", AddressFamily.InterNetwork, new HashSet<IPEndPoint> { endpoint }, Query);
        Assert.Equal(expected, sample.For(endpoint).ProcessId);
        Assert.Equal(reason, sample.For(endpoint).Reason);
    }

    [Theory]
    [InlineData(122u, 2000000, "table-limit")]
    [InlineData(0u, 8, "invalid-table")]
    [InlineData(5u, 0, "access-denied")]
    public void FailedOrIncompleteNativeDataNeverProducesAnOwner(uint result, int returnedSize, string reason)
    {
        uint Query(byte[] buffer, ref int size, int order, int family, int tableClass, int reserved)
        {
            size = returnedSize;
            BinaryPrimitives.WriteUInt32LittleEndian(buffer, uint.MaxValue);
            return result;
        }
        var endpoint = new IPEndPoint(IPAddress.Loopback, 443);
        var sample = ListenerOwners.Read("TCP", AddressFamily.InterNetwork, new HashSet<IPEndPoint> { endpoint }, Query);
        Assert.Equal(reason, sample.For(endpoint).Reason);
        Assert.Null(sample.For(endpoint).ProcessId);
    }

    [Theory]
    [InlineData(false, 2, null)]
    [InlineData(true, 3, "table-limit")]
    public void RetriesGrowingNativeTableWithinBudget(bool keepGrowing, int attempts, string? reason)
    {
        var calls = 0;
        uint Query(byte[] buffer, ref int size, int order, int family, int tableClass, int reserved)
        {
            calls++;
            if (calls == 1 || keepGrowing)
            {
                size *= 2;
                return 122;
            }
            size = sizeof(uint);
            return 0;
        }
        var sample = ListenerOwners.Read("TCP", AddressFamily.InterNetwork, new HashSet<IPEndPoint>(), Query);
        Assert.Equal(attempts, calls);
        Assert.Equal(reason, sample.Error);
    }

    [Fact]
    public void LaterSampleCannotReuseAnOldOwnerAfterProcessExit()
    {
        var endpoint = new IPEndPoint(IPAddress.Loopback, 443);
        var replacement = new IPEndPoint(IPAddress.Loopback, 1433);
        var time = DateTimeOffset.UnixEpoch;
        var records = new Dictionary<IPEndPoint, uint?> { [endpoint] = 701 };
        string Report()
        {
            using var output = new StringWriter();
            var code = LocalListenerInventory.Run(CliOptions.Parse(["--listeners", "--owners"]), output,
                () => [endpoint], () => [], (_, _, _) => new(time, null, records));
            Assert.Equal(0, code);
            return output.ToString();
        }
        Assert.Contains("PID 701", Report());
        records = new() { [replacement] = 701 };
        time = time.AddMinutes(1);
        Assert.Contains("PID unknown (not-observed)", Report());
    }

    [Fact]
    public void ReportPreservesInventoryWhenOwnerQueryFailsOrPortChangesBetweenReads()
    {
        var endpoint = new IPEndPoint(IPAddress.Loopback, 443);
        var now = DateTimeOffset.UtcNow;
        using var output = new StringWriter();
        var code = LocalListenerInventory.Run(CliOptions.Parse(["--listeners", "--owners", "--json"]), output,
            () => [endpoint], () => [endpoint], (protocol, family, selected) => protocol == "TCP"
                ? new(now, "access-denied", []) : new(now, null, new() { [new(IPAddress.Loopback, 1433)] = 701u }));
        using var document = JsonDocument.Parse(output.ToString());
        Assert.Equal(2, code);
        var tables = document.RootElement.GetProperty("Tables");
        foreach (var table in tables.EnumerateArray())
        {
            Assert.Equal("read", table.GetProperty("Status").GetString());
            var row = table.GetProperty("Endpoints")[0];
            Assert.Equal(endpoint.Port, row.GetProperty("Port").GetInt32());
            var owner = row.GetProperty("Owner");
            Assert.Equal(JsonValueKind.Null, owner.GetProperty("ProcessId").ValueKind);
            Assert.Equal(now, owner.GetProperty("ObservedAtUtc").GetDateTimeOffset());
            Assert.Equal(table.GetProperty("Protocol").GetString() == "TCP" ? "access-denied" : "not-observed",
                owner.GetProperty("Reason").GetString());
        }
    }
}

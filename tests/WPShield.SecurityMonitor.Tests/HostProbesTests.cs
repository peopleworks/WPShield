using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using WPShield.Evidence.Decisions;

namespace WPShield.SecurityMonitor.Tests;

/// <summary>
/// The host facts the decision engine refuses to decide without. A fact that cannot be read must come
/// back unreadable, never as an empty answer, and the Remote Desktop port is never assumed.
/// </summary>
public sealed class HostProbesTests
{
    /// <summary>
    /// The row layout is checked against Windows itself: a loopback connection this test opens on a dynamic
    /// port must be read back as established, from the remote address it really has.
    /// </summary>
    [Fact]
    public async Task AnEstablishedConnectionThisTestOpenedIsReadBackFromTheRealTable()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        using var accepted = await listener.AcceptTcpClientAsync();

        var (remotes, problem) = RemoteDesktopConnections.EstablishedTo(port, AddressFamily.InterNetwork, RemoteDesktopConnections.Native);
        var snapshot = RemoteDesktopConnections.Read(() => port, RemoteDesktopConnections.Native);

        Assert.Null(problem);
        Assert.Contains(IPAddress.Loopback, remotes);
        Assert.Null(snapshot.Problem);
        Assert.Equal(RemoteDesktopState.Connected, snapshot.For(AddressRanges.Single(IPAddress.Loopback)));
        Assert.Equal(RemoteDesktopState.NotConnected, snapshot.For(AddressRanges.Single(IPAddress.Parse("203.0.113.7"))));
    }

    [Fact]
    public async Task AnIPv6ConnectionIsReadBackToo()
    {
        if (!Socket.OSSupportsIPv6) return;
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var client = new TcpClient(AddressFamily.InterNetworkV6);
        await client.ConnectAsync(IPAddress.IPv6Loopback, port);
        using var accepted = await listener.AcceptTcpClientAsync();

        var (remotes, problem) = RemoteDesktopConnections.EstablishedTo(port, AddressFamily.InterNetworkV6, RemoteDesktopConnections.Native);

        Assert.Null(problem);
        Assert.Contains(IPAddress.IPv6Loopback, remotes);
    }

    [Fact]
    public void OnlyEstablishedConnectionsToTheRemoteDesktopPortCount()
    {
        var table = Ipv4Table(
            (5, 3390, "203.0.113.7"),
            (2, 3390, "0.0.0.0"),
            (8, 3390, "203.0.113.8"),
            (5, 443, "198.51.100.9"));

        var (remotes, problem) = RemoteDesktopConnections.Decode(table, ipv6: false, 3390);

        Assert.Null(problem);
        Assert.Equal(new[] { IPAddress.Parse("203.0.113.7") }, remotes);
    }

    [Fact]
    public void ATableThatClaimsMoreRowsThanItHoldsIsInvalid()
    {
        var table = Ipv4Table((5, 3390, "203.0.113.7"));
        BinaryPrimitives.WriteUInt32LittleEndian(table, 50);

        Assert.Equal("invalid-table", RemoteDesktopConnections.Decode(table, ipv6: false, 3390).Problem);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("3389")]
    [InlineData(0)]
    [InlineData(70000)]
    public void AnUnreadableOrImplausiblePortIsUnknownNever3389(object? value)
    {
        var queried = false;
        var snapshot = RemoteDesktopConnections.Read(() => value, (byte[] _, ref int _, int _, int _, int _, int _) =>
        {
            queried = true;
            return 0;
        });

        Assert.Null(snapshot.Clients);
        Assert.Equal("rdp-port-unreadable", snapshot.Problem);
        Assert.Equal(RemoteDesktopState.Unknown, snapshot.For(AddressRanges.Single(IPAddress.Parse("203.0.113.7"))));
        Assert.False(queried);
    }

    [Fact]
    public void ARegistryThatRefusesIsUnknown()
    {
        var snapshot = RemoteDesktopConnections.Read(() => throw new System.Security.SecurityException("synthetic"),
            (byte[] _, ref int _, int _, int _, int _, int _) => 0);

        Assert.Equal(RemoteDesktopState.Unknown, snapshot.For(AddressRanges.Single(IPAddress.Parse("203.0.113.7"))));
    }

    [Theory]
    [InlineData(5u, "access-denied")]
    [InlineData(87u, "query-failed")]
    public void ATableThatCannotBeReadIsUnknown(uint error, string problem)
    {
        var snapshot = RemoteDesktopConnections.Read(() => 3390, (byte[] _, ref int _, int _, int _, int _, int _) => error);

        Assert.Null(snapshot.Clients);
        Assert.Equal(problem, snapshot.Problem);
    }

    [Fact]
    public void ATableThatKeepsGrowingStopsAtItsBound()
    {
        var snapshot = RemoteDesktopConnections.Read(() => 3390, (byte[] buffer, ref int size, int _, int _, int _, int _) =>
        {
            size = buffer.Length * 2;
            return 122;
        });

        Assert.Equal("table-limit", snapshot.Problem);
    }

    [Fact]
    public void TheHostsOwnAddressesIncludeLoopback()
    {
        var own = HostProbes.OwnAddresses();

        Assert.NotNull(own);
        Assert.Contains(IPAddress.Loopback, own);
    }

    private static byte[] Ipv4Table(params (uint State, int LocalPort, string Remote)[] rows)
    {
        var table = new byte[4 + rows.Length * 24];
        BinaryPrimitives.WriteUInt32LittleEndian(table, (uint)rows.Length);
        for (var i = 0; i < rows.Length; i++)
        {
            var row = table.AsSpan(4 + i * 24, 24);
            BinaryPrimitives.WriteUInt32LittleEndian(row, rows[i].State);
            IPAddress.Loopback.GetAddressBytes().CopyTo(row[4..]);
            BinaryPrimitives.WriteUInt16BigEndian(row[8..], (ushort)rows[i].LocalPort);
            IPAddress.Parse(rows[i].Remote).GetAddressBytes().CopyTo(row[12..]);
            BinaryPrimitives.WriteUInt16BigEndian(row[16..], 50000);
        }
        return table;
    }
}

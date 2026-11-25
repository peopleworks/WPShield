using System.Diagnostics;
using System.Net;
using WPShield.Evidence.Decisions;
using Xunit;

namespace WPShield.Desktop.Tests;

/// <summary>
/// "My current connection": the address this server sees for the operator's own session, decided from
/// synthetic facts. RFC 5737 and RFC 3849 documentation addresses only.
/// </summary>
public sealed class OwnConnectionTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 21, 0, 0, TimeSpan.Zero);

    private static RemoteDesktopSnapshot Peers(params string[] addresses) => RemoteDesktopSnapshot.Of(addresses.Select(IPAddress.Parse));

    private static SessionRecord Record(string address, uint session = 3, int eventId = 21, double hoursAgo = 1) =>
        new(eventId, session, address, Now.AddHours(-hoursAgo));

    private static OwnConnection Resolve(SessionRecord? record, RemoteDesktopSnapshot snapshot, string? client = null, string? recordProblem = null) =>
        ConnectionResolver.Resolve(true, record, recordProblem, snapshot, client, Now);

    [Fact]
    public void TheSessionsOwnRecordWinsWhenItsAddressIsConnectedNow()
    {
        var own = Resolve(Record("203.0.113.40", eventId: 25), Peers("198.51.100.7", "203.0.113.40"), client: "192.0.2.10");

        Assert.Equal(OwnConnection.ThisSession, own.Code);
        Assert.Equal("203.0.113.40", own.Address);
        Assert.Equal("192.0.2.10", own.ClientReported);
        Assert.Equal(["198.51.100.7", "203.0.113.40"], own.Peers);
    }

    [Fact]
    public void TheClientsOwnReportIsNeverOffered()
    {
        // A colleague is connected from 198.51.100.7; this client reports 198.51.100.7 about itself.
        var ambiguous = Resolve(null, Peers("198.51.100.7", "203.0.113.40"), client: "198.51.100.7");
        Assert.Null(ambiguous.Address);
        Assert.Equal(OwnConnection.Ambiguous, ambiguous.Code);

        var notConnected = Resolve(Record("LOCAL"), Peers(), client: "192.0.2.10");
        Assert.Null(notConnected.Address);
        Assert.Equal(OwnConnection.NoConnection, notConnected.Code);
    }

    [Fact]
    public void WithoutARecordTheOnlyConnectionIsOfferedAndSeveralAreAmbiguous()
    {
        var only = Resolve(null, Peers("203.0.113.40"), recordProblem: "channel-missing");
        Assert.Equal(OwnConnection.OnlyConnection, only.Code);
        Assert.Equal("203.0.113.40", only.Address);
        Assert.Equal("channel-missing", only.Problem);

        var several = Resolve(Record("LOCAL"), Peers("203.0.113.40", "198.51.100.7"));
        Assert.Equal(OwnConnection.Ambiguous, several.Code);
        Assert.Null(several.Address);
        Assert.Equal(2, several.Peers.Count);

        Assert.Equal(OwnConnection.NoConnection, Resolve(null, Peers()).Code);
    }

    [Fact]
    public void ARecordWhoseAddressIsNotConnectedIsNotOfferedEvenWithOneConnection()
    {
        // Through a Remote Desktop Gateway the server sees the gateway, not the address the record names.
        var own = Resolve(Record("198.51.100.200"), Peers("203.0.113.1"));

        Assert.Equal(OwnConnection.RecordNotConnected, own.Code);
        Assert.Null(own.Address);
        Assert.Equal("198.51.100.200", own.Recorded);
        Assert.Equal(["203.0.113.1"], own.Peers);
    }

    [Fact]
    public void NotRemoteAndUnreadableFactsOfferNothing()
    {
        Assert.Equal(OwnConnection.NotRemote, ConnectionResolver.Resolve(false, Record("203.0.113.40"), null, Peers("203.0.113.40"), null, Now).Code);

        var unknownSession = ConnectionResolver.Resolve(null, Record("203.0.113.40"), null, Peers("203.0.113.40"), null, Now);
        Assert.Equal(OwnConnection.Unknown, unknownSession.Code);
        Assert.Null(unknownSession.Address);

        var unreadable = Resolve(Record("203.0.113.40"), RemoteDesktopSnapshot.Unreadable("rdp-port-unreadable"));
        Assert.Equal(OwnConnection.Unknown, unreadable.Code);
        Assert.Equal("rdp-port-unreadable", unreadable.Problem);
        Assert.Null(unreadable.Address);
    }

    [Theory]
    [InlineData("::ffff:192.0.2.55", "192.0.2.55", "192.0.2.55")]
    [InlineData("2001:db8::17", "2001:db8::17", "2001:db8::17")]
    [InlineData("2001:DB8:0::17%12", "2001:db8::17", "2001:db8::17")]
    public void ARecordAndATableRowCompareAsAddressesNotText(string recorded, string peer, string offered)
    {
        var own = Resolve(Record(recorded), Peers(peer));
        Assert.Equal(OwnConnection.ThisSession, own.Code);
        Assert.Equal(offered, own.Address);
    }

    [Theory]
    [InlineData("LOCAL")]
    [InlineData("")]
    [InlineData("not an address")]
    public void ARecordWithoutAnAddressIsNoRecord(string text) => Assert.Null(ConnectionResolver.Address(text));

    [Fact]
    public void RecordsAreReadInTheTemplateOrderUserSessionIdAddress()
    {
        var created = new DateTime(2026, 11, 24, 20, 0, 0, DateTimeKind.Utc);
        var record = SessionLog.Parse(25, ["LAB\\operator", 3u, "203.0.113.40"], created);

        Assert.NotNull(record);
        Assert.Equal(25, record.EventId);
        Assert.Equal(3u, record.SessionId);
        Assert.Equal("203.0.113.40", record.Address);
        Assert.Equal(new DateTimeOffset(created), record.At);

        Assert.Null(SessionLog.Parse(24, ["LAB\\operator", 3u, "203.0.113.40"], created));
        Assert.Null(SessionLog.Parse(21, ["LAB\\operator", 3u], created));
        Assert.Null(SessionLog.Parse(21, ["LAB\\operator", "203.0.113.40", 3u], created));
        Assert.Null(SessionLog.Parse(21, ["LAB\\operator", 3u, "203.0.113.40"], null));
    }

    [Fact]
    public void TheNewestRecordOfThisSessionSinceTheLastBootIsTheOneUsed()
    {
        var boot = Now.AddDays(-2);
        SessionRecord[] newestFirst =
        [
            Record("198.51.100.7", session: 4, hoursAgo: 1),
            Record("203.0.113.41", session: 3, eventId: 25, hoursAgo: 2),
            Record("203.0.113.40", session: 3, hoursAgo: 5)
        ];
        Assert.Equal("203.0.113.41", SessionLog.Newest(newestFirst, 3, boot)!.Address);
        Assert.Null(SessionLog.Newest(newestFirst, 9, boot));

        // Session numbers start again after a restart; a record from before it belongs to someone else.
        SessionRecord[] beforeBoot = [Record("198.51.100.7", session: 4, hoursAgo: 1), Record("203.0.113.40", session: 3, hoursAgo: 72)];
        Assert.Null(SessionLog.Newest(beforeBoot, 3, boot));
    }

    [Fact]
    public void ReadingThisMachineNeverThrows()
    {
        using var process = Process.GetCurrentProcess();
        var (record, problem) = SessionLog.Read((uint)process.SessionId, DateTimeOffset.MinValue);
        if (record is not null)
        {
            Assert.Equal((uint)process.SessionId, record.SessionId);
            Assert.Contains(record.EventId, new[] { 21, 25 });
            // The third property is the address: LOCAL for a console logon, an IP address otherwise.
            Assert.True(record.Address == "LOCAL" || IPAddress.TryParse(record.Address, out _), "unexpected address text");
        }
        else
        {
            Assert.True(problem is null or "log-limit" or "access-denied" or "channel-missing" or "query-failed", problem);
        }

        var own = OwnConnectionReader.Read();
        Assert.True(own.Address is null || own.Code is OwnConnection.ThisSession or OwnConnection.OnlyConnection);
    }
}

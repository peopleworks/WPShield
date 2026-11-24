using System.Net;
using WPShield.SecurityMonitor;
using Xunit;

namespace WPShield.Desktop.Tests;

public sealed class AttackBoardTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);

    private static AuthFailure Security(double minutesAgo, string? ip, string account = "admin",
        string reason = "bad-password", int type = 10, double seconds = 0) =>
        new(Now.AddMinutes(-minutesAgo).AddSeconds(seconds), "security-4625", ip is null ? null : IPAddress.Parse(ip),
            null, account, reason, type, 0);

    private static AuthFailure Rdp(double minutesAgo, string ip, double seconds = 0) =>
        new(Now.AddMinutes(-minutesAgo).AddSeconds(seconds), "rdpcorets-140", IPAddress.Parse(ip), null, "",
            "bad-credentials", 10, 0);

    [Fact]
    public void GroupsBySourceAndSortsByAttempts()
    {
        var board = new AttackBoard();
        board.Reset([Security(5, "203.0.113.1"), Security(4, "203.0.113.1"), Security(3, "203.0.113.1", "sa"),
            Security(2, "198.51.100.9")], Now.AddHours(-24));

        var view = board.View(Now, AttackRange.Day, "");

        Assert.Equal(4, view.Attempts);
        Assert.Equal(2, view.Sources);
        Assert.Equal("203.0.113.1", view.Rows[0].Address);
        Assert.Equal(3, view.Rows[0].Attempts);
        Assert.Equal(2, view.Rows[0].Accounts);
        Assert.Equal("admin", view.TopAccount);
    }

    [Fact]
    public void AnNlaPairIsCountedOnceAndKeepsTheAddress()
    {
        var board = new AttackBoard();
        board.Reset([Security(10, null, type: 3), Rdp(10, "203.0.113.5", seconds: 1)], Now.AddHours(-24));

        var view = board.View(Now, AttackRange.Day, "");

        Assert.Equal(1, view.Attempts);
        Assert.Equal(0, view.WithoutAddress);
        Assert.Equal("203.0.113.5", Assert.Single(view.Rows).Address);
    }

    [Fact]
    public void WhenBothRecordsCarryTheAddressThe4625WinsBecauseItNamesTheAccount()
    {
        var board = new AttackBoard();
        board.Add(Rdp(10, "203.0.113.6"));
        board.Add(Security(10, "203.0.113.6", "backup", seconds: 1));

        var view = board.View(Now, AttackRange.Day, "");

        Assert.Equal(1, view.Attempts);
        Assert.Equal("backup", view.TopAccount);
    }

    [Fact]
    public void ABurstIsNotCollapsedPairsMatchOneToOne()
    {
        var board = new AttackBoard();
        var burst = new List<AuthFailure>();
        for (var i = 0; i < 5; i++)
        {
            burst.Add(Security(10, null, type: 3, seconds: i * 0.2));
            burst.Add(Rdp(10, "203.0.113.7", seconds: i * 0.2 + 0.05));
        }
        board.Reset(burst, Now.AddHours(-24));

        Assert.Equal(5, board.View(Now, AttackRange.Day, "").Attempts);
    }

    [Fact]
    public void FailuresFarApartAreNotPaired()
    {
        var board = new AttackBoard();
        board.Reset([Security(10, null, type: 3), Rdp(20, "203.0.113.8")], Now.AddHours(-24));

        var view = board.View(Now, AttackRange.Day, "");

        Assert.Equal(2, view.Attempts);
        Assert.Equal(1, view.WithoutAddress);
    }

    [Fact]
    public void BucketsBeforeCoverageAreMarkedAsNoDataNotQuiet()
    {
        var board = new AttackBoard();
        board.Reset([Security(5, "203.0.113.1")], Now.AddMinutes(-30));

        var buckets = board.View(Now, AttackRange.Hour, "").Buckets;

        Assert.Equal(60, buckets.Count);
        Assert.All(buckets.Take(29), b => Assert.False(b.Covered));
        Assert.All(buckets.Skip(30), b => Assert.True(b.Covered));
        Assert.Equal(1, buckets.Sum(b => b.Total));
    }

    [Fact]
    public void SplitsBucketsIntoNonexistentAccountsAndTheRest()
    {
        var board = new AttackBoard();
        board.Reset([Security(1.5, "203.0.113.1", reason: "unknown-account"), Security(1.4, "203.0.113.1")], Now.AddHours(-24));

        var bucket = board.View(Now, AttackRange.Hour, "").Buckets.Single(b => b.Total > 0);

        Assert.Equal(1, bucket.UnknownAccount);
        Assert.Equal(1, bucket.Other);
    }

    [Fact]
    public void CountsOtherAttackersInTheSameNetwork()
    {
        var board = new AttackBoard();
        board.Reset([Security(5, "203.0.113.1"), Security(4, "203.0.113.2"), Security(3, "203.0.113.3"),
            Security(2, "198.51.100.1")], Now.AddHours(-24));

        var view = board.View(Now, AttackRange.Day, "");

        var row = view.Rows.Single(r => r.Address == "203.0.113.1");
        Assert.Equal("203.0.113.0/24", row.Network);
        Assert.Equal(2, row.Neighbors);
        Assert.Equal(0, view.Rows.Single(r => r.Address == "198.51.100.1").Neighbors);
        Assert.Equal("2001:db8:1:2::/64", AttackBoard.Network(IPAddress.Parse("2001:db8:1:2:3:4:5:6")));
    }

    [Theory]
    [InlineData("203.0.113", 1)]
    [InlineData("sqlsvc", 1)]
    [InlineData("203.0.113.0/24", 1)]
    [InlineData("192.0.2", 0)]
    public void SearchesByAddressAccountOrNetwork(string query, int rows)
    {
        var board = new AttackBoard();
        board.Reset([Security(5, "203.0.113.1", "sqlsvc"), Security(4, "198.51.100.1")], Now.AddHours(-24));

        Assert.Equal(rows, board.View(Now, AttackRange.Day, query).MatchingRows);
    }

    [Fact]
    public void RangeLimitsWhatIsCounted()
    {
        var board = new AttackBoard();
        board.Reset([Security(5, "203.0.113.1"), Security(120, "203.0.113.1"), Security(600, "203.0.113.1")], Now.AddHours(-24));

        Assert.Equal(1, board.View(Now, AttackRange.Hour, "").Attempts);
        Assert.Equal(2, board.View(Now, AttackRange.SixHours, "").Attempts);
        Assert.Equal(3, board.View(Now, AttackRange.Day, "").Attempts);
        Assert.Equal(1, board.View(Now, AttackRange.Day, "").LastHour);
    }

    [Fact]
    public void DetailListsAccountsNeighborsAndLatestFirst()
    {
        var board = new AttackBoard();
        board.Reset([Security(5, "203.0.113.1", "admin"), Security(4, "203.0.113.1", "admin"),
            Security(3, "203.0.113.1", "sa", "unknown-account"), Security(2, "203.0.113.9")], Now.AddHours(-24));

        var detail = board.Detail("203.0.113.1", Now, AttackRange.Day);

        Assert.NotNull(detail);
        Assert.Equal(("admin", 2), detail.Accounts[0]);
        Assert.Equal("sa", detail.Recent[0].Account);
        Assert.Equal(("203.0.113.9", 1), Assert.Single(detail.Neighbors));
        Assert.Equal(1.0 / 3, detail.Source.UnknownShare, 3);
        Assert.Null(board.Detail("192.0.2.1", Now, AttackRange.Day));
    }

    [Fact]
    public void MemoryIsBoundedAndCoverageMovesWithWhatWasDropped()
    {
        var board = new AttackBoard();
        board.Reset([], Now.AddHours(-24));
        for (var i = 0; i < AttackBoard.Capacity + 10; i++)
            board.Add(Security(600 - i * 0.005, "203.0.113.1"));

        Assert.Equal(AttackBoard.Capacity, board.Count);
        Assert.True(board.CoveredFrom > Now.AddHours(-24));
    }

    [Fact]
    public void LiveFailuresArriveOutOfOrderAndStillSort()
    {
        var board = new AttackBoard();
        board.Reset([], Now.AddHours(-24));
        board.Add(Security(1, "203.0.113.1", "late"));
        board.Add(Security(3, "203.0.113.1", "early"));

        var detail = board.Detail("203.0.113.1", Now, AttackRange.Hour);

        Assert.Equal("late", detail!.Recent[0].Account);
        Assert.Equal("early", detail.Recent[1].Account);
    }
}

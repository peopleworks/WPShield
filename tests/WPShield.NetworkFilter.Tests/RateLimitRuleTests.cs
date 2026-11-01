namespace WPShield.NetworkFilter.Tests;

public sealed class RateLimitRuleTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);

    private static NetworkInspectionContext Attempt(string source, DateTimeOffset at, int port = 443) => new()
    {
        SourceIp = source,
        DestinationIp = "192.0.2.1",
        SourcePort = 49152,
        DestinationPort = port,
        Protocol = "TCP",
        Timestamp = at,
    };

    private static NetworkInspectionResult Feed(RateLimitRule rule, string source, int attempts)
    {
        NetworkInspectionResult? last = null;
        for (var i = 0; i < attempts; i++)
        {
            last = rule.Inspect(Attempt(source, Start.AddMilliseconds(i)));
        }

        return last!;
    }

    [Fact]
    public void BelowTheThreshold_IsAllowWithScoreZero()
    {
        var result = Feed(new RateLimitRule(maxConnectionsPerMinute: 10), "198.51.100.7", 9);

        Assert.Equal("WP-NET-002", result.RuleId);
        Assert.Equal(0, result.Score);
        Assert.Equal(NetworkInspectionAction.Allow, result.Action);
    }

    [Theory]
    [InlineData(10, 60, NetworkInspectionAction.Observe)]
    [InlineData(20, 80, NetworkInspectionAction.Block)]
    [InlineData(40, 100, NetworkInspectionAction.Block)]
    public void AtEachMultipleOfTheThreshold_TheScoreRises(int attempts, int score, NetworkInspectionAction action)
    {
        var result = Feed(new RateLimitRule(maxConnectionsPerMinute: 10), "198.51.100.7", attempts);

        Assert.Equal(score, result.Score);
        Assert.Equal(action, result.Action);
        Assert.Equal("198.51.100.7", result.Evidence["source_ip"]);
    }

    [Fact]
    public void AttemptsOlderThanAMinute_StopCounting()
    {
        var rule = new RateLimitRule(maxConnectionsPerMinute: 10);
        for (var i = 0; i < 9; i++)
        {
            rule.Inspect(Attempt("198.51.100.7", Start));
        }

        var later = rule.Inspect(Attempt("198.51.100.7", Start.AddMinutes(2)));

        Assert.Equal(1, later.Evidence["attempts_last_minute"]);
    }

    [Fact]
    public void Sources_AreCountedSeparately()
    {
        var rule = new RateLimitRule(maxConnectionsPerMinute: 10);
        Feed(rule, "198.51.100.7", 10);

        Assert.Equal(0, rule.Inspect(Attempt("198.51.100.8", Start)).Score);
    }

    [Fact]
    public void AFloodOfForgedSources_IsBoundedByEvictingTheOldest()
    {
        var rule = new RateLimitRule(maxConnectionsPerMinute: 2, maximumSources: 100);
        rule.Inspect(Attempt("198.51.100.1", Start));

        for (var i = 0; i < 5_000; i++)
        {
            rule.Inspect(Attempt($"10.{i / 250}.{i % 250}.1", Start));
        }

        Assert.Equal(1, rule.Inspect(Attempt("198.51.100.1", Start)).Evidence["attempts_last_minute"]);
    }
}

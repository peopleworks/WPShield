using System.Net;
using System.Reflection;
using WPShield.WebEvidence;
using Xunit;

namespace WPShield.WebEvidence.Tests;

/// <summary>A W3C line is read by the positions its own directive names, and only the mapped fields are decoded.</summary>
public sealed class W3cParsingTests
{
    private static readonly DateTimeOffset Now = SensorHarness.Now;

    private static W3cFieldMap Map(string fields = W3c.Fields) => W3cFieldMap.Parse(W3c.Bytes(fields), out _)!;

    [Fact]
    public void TheDirectiveDecidesTheColumnsNotAnAssumedOrder()
    {
        // The same request, two field orders: the answer is the same.
        const string shuffled = "#Fields: c-ip time date cs-uri-stem sc-status cs-method cs(User-Agent)";
        var map = W3cFieldMap.Parse(W3c.Bytes(shuffled), out var problem);
        Assert.Null(problem);

        var parsed = W3cLineParser.TryParse(W3c.Bytes("203.0.113.7 08:15:00 2026-11-25 /index.php 200 GET Mozilla/5.0+(x)"), map!, out var request);

        Assert.Equal(W3cLineProblem.None, parsed);
        Assert.Equal(IPAddress.Parse("203.0.113.7"), request!.Address);
        Assert.Equal(new DateTimeOffset(2026, 11, 25, 8, 15, 0, TimeSpan.Zero), request.Timestamp);
        Assert.Equal("/index.php", request.Stem);
        Assert.Equal("GET", request.Method);
        Assert.Equal("Mozilla/5.0 (x)", request.UserAgent);
    }

    [Theory]
    [InlineData("#Fields: date time cs-method cs-uri-stem sc-status", "missing-field: c-ip")]
    [InlineData("#Fields: date time c-ip cs-method sc-status", "missing-field: cs-uri-stem")]
    [InlineData("#Fields: time c-ip cs-method cs-uri-stem sc-status", "missing-field: date")]
    public void ADirectiveWithoutARequiredFieldIsAProblemNotAGuess(string directive, string expected)
    {
        Assert.Null(W3cFieldMap.Parse(W3c.Bytes(directive), out var problem));
        Assert.Equal(expected, problem);
    }

    [Fact]
    public void ThePlusSignIsReadBackAsTheSpaceIisWroteItFor()
    {
        var line = W3c.Line(Now, "GET", "/wp-content/uploads/shell.php+", "203.0.113.7", 200).TrimEnd();

        W3cLineParser.TryParse(W3c.Bytes(line), Map(), out var request);

        Assert.Equal("/wp-content/uploads/shell.php ", request!.Stem);
    }

    [Theory]
    [InlineData("2026-11-25 12:00:00 192.0.2.10 GET /index.php - 443 - 203.0.113.7 agent - 200 0 0 1234 400")] // a column short
    [InlineData("2026-11-25 12:00:00 192.0.2.10 GET /index.php - 443 - not-an-ip agent - 200 0 0 1234 400 15")]
    [InlineData("2026-13-25 12:00:00 192.0.2.10 GET /index.php - 443 - 203.0.113.7 agent - 200 0 0 1234 400 15")]
    [InlineData("2026-11-25 12:00:00 192.0.2.10 G<T /index.php - 443 - 203.0.113.7 agent - 200 0 0 1234 400 15")]
    [InlineData("2026-11-25 12:00:00 192.0.2.10 GET index.php - 443 - 203.0.113.7 agent - 200 0 0 1234 400 15")]
    [InlineData("2026-11-25 12:00:00 192.0.2.10 GET /index.php - 443 - 203.0.113.7 agent - 20x 0 0 1234 400 15")]
    public void AMalformedLineIsCountedNeverHalfRead(string line)
    {
        Assert.Equal(W3cLineProblem.Malformed, W3cLineParser.TryParse(W3c.Bytes(line), Map(), out var request));
        Assert.Null(request);
    }

    [Fact]
    public void CommentsAreNotRequests()
    {
        Assert.Equal(W3cLineProblem.Comment, W3cLineParser.TryParse(W3c.Bytes("#Software: Microsoft Internet Information Services 10.0"), Map(), out _));
        Assert.Equal(W3cLineProblem.Comment, W3cLineParser.TryParse([], Map(), out _));
    }

    [Fact]
    public void AnIPv6ClientAndAnIPv4MappedOneAreRead()
    {
        W3cLineParser.TryParse(W3c.Bytes(W3c.Line(Now, "GET", "/", "2001:db8::7", 200).TrimEnd()), Map(), out var v6);
        W3cLineParser.TryParse(W3c.Bytes(W3c.Line(Now, "GET", "/", "::ffff:203.0.113.7", 200).TrimEnd()), Map(), out var mapped);

        Assert.Equal(IPAddress.Parse("2001:db8::7"), v6!.Address);
        Assert.Equal(IPAddress.Parse("203.0.113.7"), mapped!.Address);
    }

    /// <summary>
    /// The query, the referer and the user name have no place to go: the map has no member for them and the
    /// parsed request has no property that could hold them.
    /// </summary>
    [Fact]
    public void NoMemberExistsForTheQueryTheRefererOrTheUserName()
    {
        string[] forbidden = ["query", "referer", "referrer", "user", "username"];
        var members = typeof(W3cRequest).GetProperties().Select(p => p.Name)
            .Concat(typeof(W3cFieldMap).GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic).Select(p => p.Name))
            .Select(n => n.ToLowerInvariant()).ToArray();

        Assert.DoesNotContain(members, m => forbidden.Any(f => m == f || (m.Contains(f, StringComparison.Ordinal) && m != "useragent")));
    }
}

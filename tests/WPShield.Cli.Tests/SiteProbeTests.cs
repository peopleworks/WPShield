using WPShield.Cli.Enable;

namespace WPShield.Cli.Tests;

/// <summary>
/// The decision <c>enable</c> reverts on, stated directly rather than reproduced with a live server.
/// </summary>
public sealed class SiteProbeTests
{
    private const string Url = "https://example.test/";

    /// <summary>
    /// The hole. <c>421 Misdirected Request</c> is what the WPShield gateway answers for a Host it
    /// has no site for, and it used to land in the "not a 5xx, not a redirect, so the site answered"
    /// branch — so putting IIS in front of a gateway that did not know the site produced a 421 to
    /// every visitor while the verb reported success and reverted nothing.
    /// </summary>
    [Fact]
    public void A_421_is_a_failure_because_it_is_the_gateway_refusing_to_own_the_host()
    {
        var verdict = SiteProbe.Classify(421, hop: 0, Url);

        Assert.NotNull(verdict);
        Assert.False(verdict!.Healthy);
        Assert.Contains("421", verdict.Detail);
        Assert.Contains("no site for", verdict.Detail);
    }

    [Theory]
    [InlineData(500)]
    [InlineData(502)]
    [InlineData(503)]
    public void A_5xx_is_a_failure(int status)
    {
        var verdict = SiteProbe.Classify(status, hop: 0, Url);

        Assert.NotNull(verdict);
        Assert.False(verdict!.Healthy);
    }

    [Theory]
    [InlineData(200)]
    [InlineData(204)]
    [InlineData(401)] // a site behind auth is still a site that answered
    [InlineData(403)]
    [InlineData(404)]
    public void Anything_else_that_settles_is_the_site_answering(int status)
    {
        var verdict = SiteProbe.Classify(status, hop: 0, Url);

        Assert.NotNull(verdict);
        Assert.True(verdict!.Healthy);
    }

    [Theory]
    [InlineData(301)]
    [InlineData(302)]
    [InlineData(307)]
    [InlineData(308)]
    public void A_redirect_is_not_a_verdict_yet_so_the_hop_is_followed(int status)
    {
        // Null means "keep going" - the hop limit, not this method, is what catches a loop.
        Assert.Null(SiteProbe.Classify(status, hop: 0, Url));
    }

    [Fact]
    public void The_healthy_detail_counts_requests_not_hops()
    {
        Assert.Contains("after 1 request(s)", SiteProbe.Classify(200, hop: 0, Url)!.Detail);
        Assert.Contains("after 3 request(s)", SiteProbe.Classify(200, hop: 2, Url)!.Detail);
    }
}

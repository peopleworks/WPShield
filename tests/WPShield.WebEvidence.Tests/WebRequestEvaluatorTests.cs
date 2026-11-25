using System.Net;
using WPShield.Evidence;
using WPShield.Rules.WordPress;
using WPShield.WebEvidence;
using Xunit;

namespace WPShield.WebEvidence.Tests;

/// <summary>
/// The gateway's rules run on logged requests, and the observations see what no path rule can: the
/// status code. Paths are synthetic; no payload exists here, only names.
/// </summary>
public sealed class WebRequestEvaluatorTests
{
    private readonly WebRequestEvaluator evaluator = new();

    private static W3cRequest Request(string stem, int status = 200, string method = "GET") =>
        new(SensorHarness.Now, IPAddress.Parse("203.0.113.7"), 443, method, stem, status, 0, 0, 400, 15, "agent");

    [Fact]
    public void TheSensorRunsExactlyTheGatewaysCatalog()
    {
        Assert.Equal(RequestPathRuleCatalog.Create().Select(r => r.GetType()), evaluator.Rules.Select(r => r.GetType()));
    }

    [Fact]
    public void APhpFileUnderUploadsIsTheRuleTheGatewayWouldApply()
    {
        var result = evaluator.Evaluate(4, Request("/wp-content/uploads/2026/11/x.php"));

        Assert.Contains(result.Rules, hit => hit.Id == "WP-PATH-001" && hit.Score == 100);
        Assert.True(result.Stored);
        Assert.Equal("/wp-content/uploads/2026/11/x.php", result.Path);
    }

    [Fact]
    public void ATrailingSpaceLoggedAsPlusStillReachesTheRule()
    {
        // IIS logs "shell.php%20" as "shell.php+"; Windows opens shell.php.
        var result = evaluator.Evaluate(4, Request("/wp-content/uploads/shell.php "));

        Assert.Contains(result.Rules, hit => hit.Id == "WP-PATH-001");
    }

    [Fact]
    public void TheSecondDecodeViewStillApplies()
    {
        // A double-encoded request reaches the log once decoded, exactly as it reaches the gateway.
        var result = evaluator.Evaluate(4, Request("/wp-content/uploads/%2e%2e/%2e%2e/x.php"));

        Assert.NotEmpty(result.Rules);
    }

    [Theory]
    [InlineData("/wp-content/plugins/synthetic-addon/admin/modules.php", "POST", 200, true)]
    [InlineData("/wp-content/themes/synthetic/template-a.php", "GET", 200, true)]
    [InlineData("/wp-includes/customize/class-synthetic-section.php", "POST", 200, true)]
    [InlineData("/wp-content/plugins/synthetic-addon/wp-login.php", "POST", 200, true)] // an entry-point name under wp-content is not one
    [InlineData("/shell.php/logo.jpg", "GET", 200, true)] // path-info executes shell.php
    [InlineData("/index.php", "GET", 200, false)]
    [InlineData("/blog/wp-login.php", "POST", 200, false)]
    [InlineData("/wp-admin/admin-ajax.php", "POST", 200, false)]
    [InlineData("/wp-admin/network/sites.php", "GET", 200, false)]
    [InlineData("/xmlrpc.php", "POST", 200, false)]
    [InlineData("/wp-content/plugins/synthetic-addon/admin/modules.php", "POST", 404, false)] // it did not answer
    [InlineData("/wp-content/plugins/synthetic-addon/style.css", "GET", 200, false)]
    public void PhpThatAnsweredOutsideTheEntryPointsIsObserved(string stem, string method, int status, bool observed)
    {
        Assert.Equal(observed, evaluator.Evaluate(4, Request(stem, status, method)).PhpOutsideEntryPoints);
    }

    [Fact]
    public void AnObservationIsEvidenceOnlyAndScoresNothing()
    {
        var result = evaluator.Evaluate(4, Request("/wp-content/plugins/synthetic-addon/admin/modules.php", 200, "POST"));

        Assert.Empty(result.Rules);
        Assert.True(result.Stored);
        var hit = Assert.Single(result.Hits);
        Assert.Equal(WebObservationIds.PhpOutsideEntryPoints, hit.Id);
        Assert.Equal(0, hit.Score);
    }

    [Theory]
    [InlineData("/wp-login.php", "POST", true, false)]
    [InlineData("/blog/wp-login.php", "POST", true, false)]
    [InlineData("/wp-login.php", "GET", false, false)]
    [InlineData("/xmlrpc.php", "POST", false, true)]
    [InlineData("/wp-content/plugins/x/xmlrpc.php", "POST", false, false)]
    public void LoginAndXmlRpcPostsAreCounted(string stem, string method, bool login, bool xmlrpc)
    {
        var result = evaluator.Evaluate(4, Request(stem, 200, method));

        Assert.Equal(login, result.LoginPost);
        Assert.Equal(xmlrpc, result.XmlrpcPost);
    }

    [Fact]
    public void ARouteThatOnlyLooksAdministrativeIsNothing()
    {
        foreach (var stem in new[] { "/admin", "/login", "/dashboard", "/signin", "/" })
        {
            var result = evaluator.Evaluate(4, Request(stem));
            Assert.False(result.Stored, stem);
        }
    }
}

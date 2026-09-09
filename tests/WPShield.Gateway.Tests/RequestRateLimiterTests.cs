using Microsoft.Extensions.Configuration;
using WPShield.Core;

namespace WPShield.Gateway.Tests;

/// <summary>
/// The HTTP half of brute-force defence, decided by ADR 0002 and measured before it was designed:
/// 40,779 requests to <c>wp-login.php</c> in thirty days across two sites.
/// </summary>
public sealed class RequestRateLimiterTests
{
    private const string Site = "site-one";
    private const string Client = "203.0.113.5";

    [Fact]
    public void Evaluate_AllowsUpToThePermitLimitAndRefusesTheNextOne()
    {
        using var limiter = Create(permitLimit: 3);

        for (var attempt = 1; attempt <= 3; attempt++)
        {
            Assert.Null(limiter.Evaluate(Site, Client, "/wp-login.php"));
        }

        var exceeded = limiter.Evaluate(Site, Client, "/wp-login.php");

        Assert.NotNull(exceeded);
        Assert.Equal("wordpress-login", exceeded.RuleId);
        Assert.Equal(3, exceeded.PermitLimit);
    }

    /// <summary>
    /// The reason this limiter is targeted rather than global. One WordPress page view is dozens of
    /// asset requests, and a budget that counted them would throttle readers instead of attackers.
    /// </summary>
    [Fact]
    public void Evaluate_IgnoresPathsNoRuleNames()
    {
        using var limiter = Create(permitLimit: 2);

        for (var attempt = 0; attempt < 50; attempt++)
        {
            Assert.Null(limiter.Evaluate(Site, Client, "/wp-content/themes/x/style.css"));
        }
    }

    /// <summary>
    /// The trap this design exists to avoid. Behind IIS every request arrives from the same local
    /// proxy, so a limiter partitioned on the connecting peer would put the whole internet in one
    /// bucket: the eleventh visitor of the day would be refused, and a brute force would look
    /// exactly like a busy afternoon.
    /// </summary>
    [Fact]
    public void Evaluate_GivesEachClientItsOwnBudget()
    {
        using var limiter = Create(permitLimit: 2);

        Assert.Null(limiter.Evaluate(Site, "198.51.100.1", "/wp-login.php"));
        Assert.Null(limiter.Evaluate(Site, "198.51.100.1", "/wp-login.php"));
        Assert.NotNull(limiter.Evaluate(Site, "198.51.100.1", "/wp-login.php"));

        Assert.Null(limiter.Evaluate(Site, "198.51.100.2", "/wp-login.php"));
    }

    [Fact]
    public void Evaluate_GivesEachSiteItsOwnBudget()
    {
        using var limiter = Create(permitLimit: 1);

        Assert.Null(limiter.Evaluate("site-one", Client, "/wp-login.php"));
        Assert.NotNull(limiter.Evaluate("site-one", Client, "/wp-login.php"));

        Assert.Null(limiter.Evaluate("site-two", Client, "/wp-login.php"));
    }

    /// <summary>
    /// A free doubling for anyone who notices, if the two spellings were separate partitions.
    /// </summary>
    [Fact]
    public void Evaluate_TreatsATrailingSlashAsTheSamePath()
    {
        using var limiter = Create(permitLimit: 2);

        Assert.Null(limiter.Evaluate(Site, Client, "/wp-login.php"));
        Assert.Null(limiter.Evaluate(Site, Client, "/wp-login.php/"));
        Assert.NotNull(limiter.Evaluate(Site, Client, "/wp-login.php"));
    }

    [Fact]
    public void Evaluate_MatchesThePathWithoutRegardToCase()
    {
        using var limiter = Create(permitLimit: 1);

        Assert.Null(limiter.Evaluate(Site, Client, "/wp-login.php"));
        Assert.NotNull(limiter.Evaluate(Site, Client, "/WP-Login.PHP"));
    }

    [Fact]
    public void Evaluate_DoesNothingWhenTheLimiterIsOff()
    {
        using var limiter = new RequestRateLimiter(new RateLimitOptions { Enabled = false });

        Assert.False(limiter.IsActive);
        for (var attempt = 0; attempt < 100; attempt++)
        {
            Assert.Null(limiter.Evaluate(Site, Client, "/wp-login.php"));
        }
    }

    // =================================================================================
    //  Configuration.
    // =================================================================================

    /// <summary>
    /// The same binder trap that stopped the gateway from starting when
    /// <see cref="GatewayOptions.Urls"/> carried a non-empty default: a configured array is appended
    /// to the code default rather than replacing it. Here it would silently double every rule.
    /// </summary>
    [Fact]
    public void Bind_DoesNotAppendConfiguredRulesToTheCodeDefault()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Gateway:RateLimit:Enabled"] = "true",
                ["Gateway:RateLimit:Rules:0:Id"] = "wordpress-login",
                ["Gateway:RateLimit:Rules:0:Paths:0"] = "/wp-login.php",
                ["Gateway:RateLimit:Rules:0:PermitLimit"] = "10",
                ["Gateway:RateLimit:Rules:0:WindowSeconds"] = "300"
            })
            .Build();

        var options = configuration.GetSection("Gateway").Get<GatewayOptions>();

        Assert.NotNull(options);
        var rule = Assert.Single(options.RateLimit.Rules);
        Assert.Equal("/wp-login.php", Assert.Single(rule.Paths));
    }

    [Fact]
    public void RateLimit_DefaultsToOffWithNoRulesInCode()
    {
        var options = new RateLimitOptions();

        Assert.False(options.Enabled);
        Assert.Empty(options.Rules);
    }

    [Fact]
    public void Validate_RejectsARuleWithNoPaths()
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => ValidateWith(new RateLimitRuleOptions { Id = "empty", Paths = [] }));

        Assert.Contains("can never fire", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_RejectsARuleWithNoId()
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => ValidateWith(new RateLimitRuleOptions { Id = "  ", Paths = ["/wp-login.php"] }));

        Assert.Contains("non-empty Id", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("wp-login.php")]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_RejectsAPathThatIsNotRooted(string path)
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => ValidateWith(new RateLimitRuleOptions { Id = "one", Paths = [path] }));

        Assert.Contains("must begin with '/'", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Zero would refuse every request to those paths, including the operator's own login, and it
    /// would do it the moment the site went to Block.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(RateLimitOptions.AbsoluteMaximumPermitLimit + 1)]
    public void Validate_RejectsAnOutOfRangePermitLimit(int permitLimit)
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => ValidateWith(new RateLimitRuleOptions
            {
                Id = "one",
                Paths = ["/wp-login.php"],
                PermitLimit = permitLimit
            }));

        Assert.Contains("PermitLimit", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(RateLimitOptions.AbsoluteMaximumWindowSeconds + 1)]
    public void Validate_RejectsAnOutOfRangeWindow(int windowSeconds)
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => ValidateWith(new RateLimitRuleOptions
            {
                Id = "one",
                Paths = ["/wp-login.php"],
                WindowSeconds = windowSeconds
            }));

        Assert.Contains("WindowSeconds", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_RejectsTwoRulesClaimingTheSamePath()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ValidateWith(
            new RateLimitRuleOptions { Id = "first", Paths = ["/wp-login.php"] },
            new RateLimitRuleOptions { Id = "second", Paths = ["/wp-login.php"] }));

        Assert.Contains("both list", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_RejectsTwoRulesWithTheSameId()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ValidateWith(
            new RateLimitRuleOptions { Id = "same", Paths = ["/wp-login.php"] },
            new RateLimitRuleOptions { Id = "SAME", Paths = ["/xmlrpc.php"] }));

        Assert.Contains("more than one rule with Id", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_AcceptsTheShippedShape()
    {
        ValidateWith(new RateLimitRuleOptions
        {
            Id = "wordpress-login",
            Paths = ["/wp-login.php", "/xmlrpc.php"],
            PermitLimit = 10,
            WindowSeconds = 300
        });
    }

    /// <summary>An off limiter is never validated, so a disabled misconfiguration cannot stop a start.</summary>
    [Fact]
    public void Validate_IgnoresRulesWhenTheLimiterIsOff()
    {
        var options = new GatewayOptions
        {
            Urls = ["http://127.0.0.1:10000"],
            RateLimit = new RateLimitOptions
            {
                Enabled = false,
                Rules = [new RateLimitRuleOptions { Id = "", Paths = [] }]
            }
        };

        GatewayConfigurationValidator.Validate(options, [CreateSite()]);
    }

    private static RequestRateLimiter Create(int permitLimit)
    {
        return new RequestRateLimiter(new RateLimitOptions
        {
            Enabled = true,
            Rules =
            [
                new RateLimitRuleOptions
                {
                    Id = "wordpress-login",
                    Paths = ["/wp-login.php", "/xmlrpc.php"],
                    PermitLimit = permitLimit,
                    WindowSeconds = 300
                }
            ]
        });
    }

    private static void ValidateWith(params RateLimitRuleOptions[] rules)
    {
        var options = new GatewayOptions
        {
            Urls = ["http://127.0.0.1:10000"],
            RateLimit = new RateLimitOptions { Enabled = true, Rules = rules }
        };

        GatewayConfigurationValidator.Validate(options, [CreateSite()]);
    }

    private static SiteOptions CreateSite()
    {
        return new SiteOptions
        {
            Id = "site-one",
            Hosts = ["example.test"],
            Destination = new Uri("http://127.0.0.1:51001"),
            Mode = ProtectionMode.Monitor,
            ObserveThreshold = 30,
            BlockThreshold = 80
        };
    }
}

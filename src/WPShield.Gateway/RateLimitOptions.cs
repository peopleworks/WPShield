namespace WPShield.Gateway;

/// <summary>
/// Bounds for the request rate limiter, bound from <c>Gateway:RateLimit</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Rate limiting here is targeted, not global, and that is the whole design.</b> A single
/// WordPress page view is dozens of requests — stylesheets, scripts, fonts, images — so a limit
/// applied to every request either has to be set so high that it stops nothing, or it throttles
/// ordinary visitors. The traffic this exists for does not look like that: two sites on one host
/// recorded <b>40,779 requests to <c>wp-login.php</c> in thirty days</b>, from more than sixty
/// addresses, and every one of them went to the same handful of paths.
/// </para>
/// <para>
/// So the operator names the paths. A rule that fires on more than the operator wrote is a
/// false-positive machine, and a rate limiter producing false positives on a login form locks out
/// the person trying to fix it.
/// </para>
/// <para>
/// See <c>docs/en/adr/0002-host-level-brute-force-defence.md</c>, which decided that the HTTP half
/// of brute-force defence stays inside WPShield. This is that half.
/// </para>
/// </remarks>
public sealed class RateLimitOptions
{
    /// <summary>The most rules one gateway will carry, so a configuration mistake is bounded.</summary>
    public const int AbsoluteMaximumRules = 32;

    public const int AbsoluteMaximumPermitLimit = 100_000;
    public const int AbsoluteMaximumWindowSeconds = 24 * 60 * 60;
    public const int AbsoluteMaximumPathsPerRule = 32;

    /// <summary>
    /// Whether the limiter runs at all. Off in code, on in the shipped <c>appsettings.json</c>,
    /// following <c>Logging:File:Enabled</c>: the test host supplies configuration in memory and
    /// gets the code default, a deployment reads the shipped file.
    /// </summary>
    public bool Enabled { get; init; }

    /// <summary>
    /// The rules, each naming its own paths and its own budget.
    /// </summary>
    /// <remarks>
    /// <b>Empty by default, and every array default in this file must stay empty.</b>
    /// <c>ConfigurationBinder</c> appends to an array property that already holds a value rather than
    /// replacing it. <see cref="GatewayOptions.Urls"/> defaulted to the same address the shipped
    /// configuration set, which produced two identical listeners and a gateway that could not start
    /// at all. A non-empty default here would duplicate every shipped rule instead.
    /// </remarks>
    public RateLimitRuleOptions[] Rules { get; init; } = [];
}

/// <summary>
/// One budget, and the paths it applies to.
/// </summary>
public sealed class RateLimitRuleOptions
{
    /// <summary>
    /// The identifier that appears in the log. Not <c>required</c> on purpose: the configuration
    /// binder's message for a missing required property names the type, while
    /// <c>GatewayConfigurationValidator</c> can name the setting an operator has to edit.
    /// </summary>
    public string Id { get; init; } = string.Empty;

    /// <summary>
    /// Request paths this rule covers, matched whole and case-insensitively against the decoded
    /// path — never against a raw request target.
    /// </summary>
    /// <remarks>
    /// Whole-path matching rather than a prefix or a suffix. <c>/wp-login.php</c> means that path,
    /// and a WordPress installed under <c>/blog</c> is configured as <c>/blog/wp-login.php</c>.
    /// Matching more than the operator wrote is how a limiter starts refusing traffic nobody asked
    /// it to look at.
    /// </remarks>
    public string[] Paths { get; init; } = [];

    /// <summary>How many requests one client may make to those paths inside the window.</summary>
    public int PermitLimit { get; init; } = 10;

    /// <summary>The length of the fixed window, in seconds.</summary>
    public int WindowSeconds { get; init; } = 300;
}

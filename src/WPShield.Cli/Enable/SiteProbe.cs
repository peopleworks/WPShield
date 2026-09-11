using System.Globalization;
using System.Net;

namespace WPShield.Cli.Enable;

/// <summary>
/// Asks a site whether it still works, and is the reason automating this is safer than doing it by
/// hand.
/// </summary>
/// <remarks>
/// <para>
/// A person types a rewrite rule, saves, and finding out whether the site broke requires them to
/// check, notice, diagnose which change did it, and undo the right one under pressure. This closes
/// that window: the request happens immediately after the change and the revert happens before the
/// command returns.
/// </para>
/// <para>
/// <b>Redirects are followed by hand, with a hop limit.</b> The failure this exists to catch is
/// <c>ERR_TOO_MANY_REDIRECTS</c> — WordPress seeing plain HTTP behind an HTTPS site and redirecting
/// to itself forever. An automatic redirect follower reports that as an exception whose message
/// varies by platform; counting hops reports it as what it is.
/// </para>
/// <para>
/// <b>A 421 is a failure, not an answer.</b> That is the gateway's own "I have no site for this
/// Host", so it means the request arrived and WPShield refused to own it — the site is down. See
/// <see cref="Classify"/>; reading it as healthy was a real hole.
/// </para>
/// <para>
/// It records the status line and nothing else. No body, no headers beyond it — the same rule
/// everything in this project that writes evidence follows.
/// </para>
/// </remarks>
internal sealed class SiteProbe : ISiteProbe
{
    /// <summary>
    /// Enough hops for a legitimate canonical redirect or two, few enough that a loop is obvious.
    /// </summary>
    private const int MaximumHops = 5;

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Turns one status code into a verdict, or <see langword="null"/> to follow a redirect.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Pure, so the decision this verb reverts on can be stated in a test rather than reproduced with
    /// a live server.
    /// </para>
    /// <para>
    /// <b>421 is a failure, and reading it as one is the whole point of this method existing.</b>
    /// <c>421 Misdirected Request</c> is what the WPShield gateway answers for a <c>Host</c> it has no
    /// site for. It used to fall into the "not a 5xx, not a redirect, so the site answered" branch,
    /// which meant putting IIS in front of a gateway that did not know the site produced a 421 to
    /// every visitor while this verb reported <i>enabled and verified</i> and reverted nothing. It is
    /// the one status code that is strictly more suspicious after this change than before it: nothing
    /// else returns 421 in this path, so seeing one means the request reached the gateway and the
    /// gateway refused to own it.
    /// </para>
    /// </remarks>
    internal static SiteHealth? Classify(int status, int hop, string url)
    {
        if (status == 421)
        {
            return new SiteHealth(
                false,
                $"HTTP 421 from {url}. That is WPShield answering for a host it has no site for, so the " +
                "request reached the gateway and the gateway refused to own it.");
        }

        if (status >= 500)
        {
            return new SiteHealth(false, $"HTTP {status} from {url}");
        }

        if (status is < 300 or >= 400)
        {
            return new SiteHealth(true, $"HTTP {status} after {hop + 1} request(s)");
        }

        return null;
    }

    public SiteHealth Check(string publicHost)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(publicHost);

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,

            // The site's certificate is not what is being tested, and a host that answers its own
            // name with a name-mismatched certificate is a pre-existing condition rather than
            // something this change caused. Refusing here would revert a change that worked.
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };

        using var client = new HttpClient(handler) { Timeout = Timeout };

        var url = $"https://{publicHost}/";
        var seen = new List<string>();

        try
        {
            for (var hop = 0; hop < MaximumHops; hop++)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                using var response = client.Send(request);

                var status = (int)response.StatusCode;
                seen.Add(status.ToString(CultureInfo.InvariantCulture));

                if (Classify(status, hop, url) is { } verdict)
                {
                    return verdict;
                }

                var location = response.Headers.Location;
                if (location is null)
                {
                    return new SiteHealth(false, $"HTTP {status} with no Location header");
                }

                url = location.IsAbsoluteUri ? location.ToString() : new Uri(new Uri(url), location).ToString();
            }

            return new SiteHealth(
                false,
                $"the site redirected {MaximumHops} times without settling ({string.Join(" -> ", seen)}). " +
                "That is the shape of a WordPress site that has not been told the original request was HTTPS.");
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            return new SiteHealth(false, $"the site could not be reached: {exception.Message}");
        }
    }
}

internal interface ISiteProbe
{
    SiteHealth Check(string publicHost);
}

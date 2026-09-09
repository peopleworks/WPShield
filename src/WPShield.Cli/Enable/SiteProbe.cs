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

                if (status >= 500)
                {
                    return new SiteHealth(false, $"HTTP {status} from {url}");
                }

                if (status is < 300 or >= 400)
                {
                    return new SiteHealth(true, $"HTTP {status} after {hop + 1} request(s)");
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

using System.Net;
using WPShield.Core;

namespace WPShield.Gateway;

public static class GatewayConfigurationValidator
{
    private static readonly HashSet<string> SupportedSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        Uri.UriSchemeHttp,
        Uri.UriSchemeHttps
    };

    private static readonly string[] ReservedDocumentationDomains =
    [
        "example.com",
        "example.net",
        "example.org"
    ];

    public static void Validate(GatewayOptions gatewayOptions, IReadOnlyList<SiteOptions> sites)
    {
        ArgumentNullException.ThrowIfNull(gatewayOptions);
        ArgumentNullException.ThrowIfNull(sites);

        var listeners = ValidateListeners(gatewayOptions.Urls);
        ValidateRequestLimits(gatewayOptions);

        if (sites.Count == 0)
        {
            throw new InvalidOperationException("At least one site must be configured.");
        }

        _ = new SiteResolver(sites);
        ValidateNoPartiallyAppliedOverlay(sites);

        foreach (var site in sites)
        {
            ValidateDestination(site, listeners);
        }
    }

    /// <summary>
    /// Fails closed when real hostnames appear alongside the documentation placeholders that ship in
    /// <c>appsettings.json</c>.
    /// </summary>
    /// <remarks>
    /// JSON configuration providers merge arrays element by element instead of replacing them, and
    /// this applies to the nested <c>Hosts</c> array as well as to <c>Sites</c>. An operator overlay
    /// that declares fewer sites, or fewer hosts within a site, silently leaves the surplus shipped
    /// example entries active and routable. Mixed placeholder and real hostnames is the exact
    /// signature of that mistake, so the gateway refuses to start rather than serve a site table the
    /// operator did not intend. A configuration made entirely of placeholders is the untouched
    /// demonstration configuration and remains allowed.
    /// </remarks>
    private static void ValidateNoPartiallyAppliedOverlay(IReadOnlyList<SiteOptions> sites)
    {
        var placeholders = new List<string>();
        var realHostCount = 0;

        foreach (var site in sites)
        {
            foreach (var host in site.Hosts)
            {
                if (string.IsNullOrWhiteSpace(host))
                {
                    continue;
                }

                if (IsDocumentationHost(host))
                {
                    placeholders.Add($"{site.Id}:{host.Trim()}");
                }
                else
                {
                    realHostCount++;
                }
            }
        }

        if (placeholders.Count == 0 || realHostCount == 0)
        {
            return;
        }

        throw new InvalidOperationException(
            "Configuration mixes real hostnames with the documentation placeholders shipped in " +
            $"appsettings.json: {string.Join(", ", placeholders)}. JSON configuration merges arrays " +
            "element by element, so a local overlay that declares fewer sites, or fewer hosts inside " +
            "a site, leaves the surplus example entries active and routable. Declare every site and " +
            "every host explicitly in appsettings.Local.json. See docs/en/operator-configuration.md.");
    }

    /// <summary>
    /// Identifies hostnames reserved for documentation by RFC 2606, which is what the shipped
    /// example configuration uses. The <c>.test</c> label is deliberately excluded because the
    /// synthetic integration suite uses it for genuine, intentional test hosts.
    /// </summary>
    private static bool IsDocumentationHost(string host)
    {
        var value = host.Trim().TrimEnd('.');

        if (value.Equals("example", StringComparison.OrdinalIgnoreCase) ||
            value.EndsWith(".example", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        foreach (var reserved in ReservedDocumentationDomains)
        {
            if (value.Equals(reserved, StringComparison.OrdinalIgnoreCase) ||
                value.EndsWith($".{reserved}", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static void ValidateRequestLimits(GatewayOptions options)
    {
        if (options.MaximumRequestBytes <= 0 ||
            options.MaximumRequestBytes > GatewayOptions.AbsoluteMaximumRequestBytes)
        {
            throw new InvalidOperationException(
                $"Gateway:MaximumRequestBytes must be between 1 and {GatewayOptions.AbsoluteMaximumRequestBytes} bytes.");
        }
    }

    private static IReadOnlyList<Uri> ValidateListeners(string[]? urls)
    {
        if (urls is null || urls.Length == 0)
        {
            throw new InvalidOperationException("Gateway:Urls must contain at least one loopback URL.");
        }

        var listeners = new List<Uri>(urls.Length);
        foreach (var url in urls)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var listener) ||
                !SupportedSchemes.Contains(listener.Scheme) ||
                !IPAddress.TryParse(listener.Host.Trim('[', ']'), out var address) ||
                !IPAddress.IsLoopback(address))
            {
                throw new InvalidOperationException(
                    $"M1 laboratory gateway may listen only on a loopback HTTP or HTTPS IP. Invalid URL: '{url}'.");
            }

            listeners.Add(listener);
        }

        return listeners;
    }

    private static void ValidateDestination(SiteOptions site, IReadOnlyList<Uri> listeners)
    {
        var destination = site.Destination;
        if (destination is null || !destination.IsAbsoluteUri || !SupportedSchemes.Contains(destination.Scheme))
        {
            throw new InvalidOperationException(
                $"Site '{site.Id}' destination must use an absolute HTTP or HTTPS URI.");
        }

        if (!destination.IsLoopback)
        {
            throw new InvalidOperationException(
                $"Site '{site.Id}' destination must remain on loopback during M1.");
        }

        if (listeners.Any(listener => listener.Port == destination.Port))
        {
            throw new InvalidOperationException(
                $"Site '{site.Id}' destination must not point back to a WPShield listener.");
        }
    }
}

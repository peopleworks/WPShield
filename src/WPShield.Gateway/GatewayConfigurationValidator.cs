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

    public static void Validate(GatewayOptions gatewayOptions, IReadOnlyList<SiteOptions> sites)
    {
        ArgumentNullException.ThrowIfNull(gatewayOptions);
        ArgumentNullException.ThrowIfNull(sites);

        var listeners = ValidateListeners(gatewayOptions.Urls);

        if (sites.Count == 0)
        {
            throw new InvalidOperationException("At least one site must be configured.");
        }

        _ = new SiteResolver(sites);

        foreach (var site in sites)
        {
            ValidateDestination(site, listeners);
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

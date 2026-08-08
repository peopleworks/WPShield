namespace WPShield.Core;

public sealed class SiteResolver
{
    private readonly IReadOnlyDictionary<string, SiteOptions> _sitesByHost;

    public SiteResolver(IEnumerable<SiteOptions> sites)
    {
        ArgumentNullException.ThrowIfNull(sites);

        var map = new Dictionary<string, SiteOptions>(StringComparer.OrdinalIgnoreCase);
        foreach (var site in sites)
        {
            Validate(site);
            foreach (var host in site.Hosts)
            {
                var normalizedHost = NormalizeHost(host);
                if (normalizedHost.Length == 0)
                {
                    throw new ArgumentException($"Site '{site.Id}' contains an empty host.");
                }

                if (!map.TryAdd(normalizedHost, site))
                {
                    throw new InvalidOperationException($"Host '{host}' is assigned more than once.");
                }
            }
        }

        _sitesByHost = map;
    }

    public SiteOptions? Resolve(string host)
    {
        if (string.IsNullOrWhiteSpace(host)) return null;
        return _sitesByHost.GetValueOrDefault(NormalizeHost(host));
    }

    private static string NormalizeHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host)) return string.Empty;

        var value = host.Trim();
        if (value.StartsWith('['))
        {
            var closingBracket = value.IndexOf(']');
            if (closingBracket > 0)
            {
                return value[1..closingBracket].TrimEnd('.');
            }
        }

        var colon = value.LastIndexOf(':');
        if (colon > 0 && value.IndexOf(':') == colon && value[(colon + 1)..].All(char.IsDigit))
        {
            value = value[..colon];
        }

        return value.TrimEnd('.');
    }

    private static void Validate(SiteOptions site)
    {
        if (string.IsNullOrWhiteSpace(site.Id)) throw new ArgumentException("Site Id is required.");
        if (site.Hosts is null || site.Hosts.Length == 0 || site.Hosts.All(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException($"Site '{site.Id}' requires at least one non-empty host.");
        }

        if (site.BlockThreshold < site.ObserveThreshold) throw new ArgumentException($"Site '{site.Id}' has invalid thresholds.");
    }
}

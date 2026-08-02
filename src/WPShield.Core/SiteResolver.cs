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
                if (!map.TryAdd(NormalizeHost(host), site))
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
        var value = host.Trim();
        var colon = value.LastIndexOf(':');
        return colon > -1 && value[(colon + 1)..].All(char.IsDigit)
            ? value[..colon]
            : value;
    }

    private static void Validate(SiteOptions site)
    {
        if (string.IsNullOrWhiteSpace(site.Id)) throw new ArgumentException("Site Id is required.");
        if (site.Hosts is null || site.Hosts.Length == 0) throw new ArgumentException($"Site '{site.Id}' requires at least one host.");
        if (site.BlockThreshold < site.ObserveThreshold) throw new ArgumentException($"Site '{site.Id}' has invalid thresholds.");
    }
}

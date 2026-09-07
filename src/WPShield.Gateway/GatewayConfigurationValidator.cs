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

    /// <summary>
    /// Validates the gateway and site configuration, taking the multipart bounds from
    /// <see cref="GatewayOptions.Multipart"/>.
    /// </summary>
    public static void Validate(GatewayOptions gatewayOptions, IReadOnlyList<SiteOptions> sites)
    {
        ArgumentNullException.ThrowIfNull(gatewayOptions);

        Validate(gatewayOptions, gatewayOptions.Multipart, sites);
    }

    /// <summary>
    /// Validates the gateway configuration against an explicitly supplied set of multipart bounds.
    /// </summary>
    /// <remarks>
    /// The overload exists because <c>GatewayApplication.Build</c> binds <c>Gateway:Multipart</c>
    /// separately from <c>Gateway</c> and should validate exactly the instance it goes on to use,
    /// rather than a second binding that could differ. The two-argument overload above delegates
    /// here with <see cref="GatewayOptions.Multipart"/>, so a caller that never heard of multipart
    /// inspection still gets the full check.
    /// </remarks>
    public static void Validate(
        GatewayOptions gatewayOptions,
        MultipartInspectionOptions multipartOptions,
        IReadOnlyList<SiteOptions> sites)
    {
        ArgumentNullException.ThrowIfNull(gatewayOptions);
        ArgumentNullException.ThrowIfNull(multipartOptions);
        ArgumentNullException.ThrowIfNull(sites);

        var listeners = ValidateListeners(gatewayOptions.Urls);
        ValidateRequestLimits(gatewayOptions);
        ValidateTrustedProxies(gatewayOptions.TrustedProxies);
        ValidateMultipartInspection(multipartOptions);

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

    /// <summary>
    /// Rejects a <c>Gateway:TrustedProxies</c> entry that is not an exact IP address.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Throw rather than skip.</b> Every other setting in this file bounds a resource; this one
    /// decides whose forwarding headers become authoritative, so an entry that does not parse is the
    /// one case where continuing is worse than not starting. Skipping it silently would leave a
    /// gateway that appears configured for the production traffic path, attributes every visitor to
    /// the proxy, and says nothing — and the operator's evidence about who attacked them would be
    /// wrong for as long as it took to notice.
    /// </para>
    /// <para>
    /// The three rejected shapes each get their own message because they are three different
    /// mistakes. A CIDR range is a deliberate refusal rather than a missing feature; a hostname
    /// cannot be trusted because the peer address is what the connection reports and no lookup
    /// happens on the request path; an empty entry is almost always a stray comma in JSON.
    /// </para>
    /// </remarks>
    private static void ValidateTrustedProxies(string[]? trustedProxies)
    {
        if (trustedProxies is null)
        {
            return;
        }

        for (var index = 0; index < trustedProxies.Length; index++)
        {
            var entry = trustedProxies[index];
            var setting = $"Gateway:TrustedProxies:{index}";

            if (string.IsNullOrWhiteSpace(entry))
            {
                throw new InvalidOperationException(
                    $"{setting} is empty. Remove the entry rather than leaving a blank one, which " +
                    "reads as a configured trusted proxy that can never match.");
            }

            var value = entry.Trim();

            if (value.Contains('/', StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"{setting} ('{value}') is a CIDR range. Gateway:TrustedProxies accepts exact IP " +
                    "addresses only. These entries decide whose X-Forwarded-For and X-Forwarded-Proto " +
                    "headers WPShield honors, and a range written one bit too wide grants that to " +
                    "hosts the operator never intended. List each proxy address explicitly.");
            }

            if (!IPAddress.TryParse(value, out _))
            {
                throw new InvalidOperationException(
                    $"{setting} ('{value}') is not an IP address. Gateway:TrustedProxies is matched " +
                    "against the peer address of the connection, which is a number and never a name, " +
                    "so a hostname can never match and no lookup is performed on the request path.");
            }
        }
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

    /// <summary>
    /// Rejects <c>Gateway:Multipart</c> values outside the bounds the gateway will actually honor.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Throw, do not clamp.</b> This repository has both precedents — <c>MaximumRequestBytes</c>
    /// throws, <c>ActivityTimeoutSeconds</c> is silently <c>Math.Clamp</c>ed — and throwing is the
    /// right one here because every value below is a safety ceiling. An operator who writes
    /// <c>MaximumFileCount: 100000</c> and silently receives 100 has been told nothing, and
    /// configuration that appears to do something it does not is the failure this project refuses
    /// to ship. <see cref="MultipartInspectionReader"/> clamps again at the point of use, so an
    /// options instance built directly in code cannot lift a ceiling by skipping this method; that
    /// second clamp is a backstop, not the operator-facing contract.
    /// </para>
    /// <para>
    /// The <see cref="MultipartInspectionOptions.MinimumSampleBytes"/> floor is the one bound that
    /// is not a resource control. It is a cross-agent contract recorded in
    /// <c>docs/en/m2-content-rules-design.md</c>: below 512 bytes the text-versus-binary
    /// classification degrades and the <c>%PDF-</c> tolerance disappears, so a number that reads
    /// like a performance knob would quietly disable <c>FILE-TYPE-001</c> and <c>PHP-CONTENT-002</c>
    /// while the configuration still said <c>Enabled: true</c>.
    /// </para>
    /// <para>
    /// <see cref="MultipartInspectionOptions.Enabled"/> is deliberately not validated. Turning
    /// inspection off is a supported operator decision — the escape hatch if inspection is ever
    /// implicated in an incident — and the startup log, not a validation failure, is where it
    /// belongs.
    /// </para>
    /// <para>
    /// <b>A sample larger than <see cref="GatewayOptions.MaximumRequestBytes"/> is not rejected
    /// here, and that was a decision rather than an omission.</b> It looks like nonsense and it is
    /// certainly over-specified, but it is harmless: the reader fills whatever the body actually
    /// contains and stops, so the only effect is that the configured sample size can never be
    /// reached. Meanwhile a deliberately tiny <c>MaximumRequestBytes</c> is a legitimate
    /// configuration — this repository's own request-limit tests run the gateway with a 16-byte
    /// limit — and failing startup would turn a no-op over-specification into an outage. The
    /// combination is reported instead: <c>GatewayApplication</c> logs it at Warning during
    /// startup, which tells the operator without refusing to run.
    /// </para>
    /// </remarks>
    private static void ValidateMultipartInspection(MultipartInspectionOptions options)
    {
        if (options.MaximumFileCount <= 0 ||
            options.MaximumFileCount > MultipartInspectionOptions.AbsoluteMaximumFileCount)
        {
            throw new InvalidOperationException(
                "Gateway:Multipart:MaximumFileCount must be between 1 and " +
                $"{MultipartInspectionOptions.AbsoluteMaximumFileCount}.");
        }

        if (options.MaximumFieldCount <= 0 ||
            options.MaximumFieldCount > MultipartInspectionOptions.AbsoluteMaximumFieldCount)
        {
            throw new InvalidOperationException(
                "Gateway:Multipart:MaximumFieldCount must be between 1 and " +
                $"{MultipartInspectionOptions.AbsoluteMaximumFieldCount}.");
        }

        if (options.MaximumPartHeaderBytes <= 0 ||
            options.MaximumPartHeaderBytes > MultipartInspectionOptions.AbsoluteMaximumPartHeaderBytes)
        {
            throw new InvalidOperationException(
                "Gateway:Multipart:MaximumPartHeaderBytes must be between 1 and " +
                $"{MultipartInspectionOptions.AbsoluteMaximumPartHeaderBytes}.");
        }

        if (options.SampleBytes < MultipartInspectionOptions.MinimumSampleBytes ||
            options.SampleBytes > MultipartInspectionOptions.AbsoluteMaximumSampleBytes)
        {
            throw new InvalidOperationException(
                $"Gateway:Multipart:SampleBytes must be between {MultipartInspectionOptions.MinimumSampleBytes} " +
                $"and {MultipartInspectionOptions.AbsoluteMaximumSampleBytes}.");
        }

        if (options.ReadTimeoutSeconds <= 0 ||
            options.ReadTimeoutSeconds > MultipartInspectionOptions.AbsoluteMaximumReadTimeoutSeconds)
        {
            throw new InvalidOperationException(
                "Gateway:Multipart:ReadTimeoutSeconds must be between 1 and " +
                $"{MultipartInspectionOptions.AbsoluteMaximumReadTimeoutSeconds}.");
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

        // Under the traffic path in ADR 0001, IIS keeps the public ports and WPShield forwards to a
        // *private* loopback binding of the same site. Ports 80 and 443 are by definition the public
        // ones, so a destination on either is always the wrong binding - and it fails in a way that
        // is hard to read: an operator who writes 443 here is sending cleartext HTTP at a listener
        // expecting TLS, and gets a connection error that says nothing about the real mistake.
        //
        // Every other check above passes for that value. It is loopback, and it is not a listener
        // port. Without this one, the gateway starts, reports itself healthy, and fails only when a
        // real request arrives - which under this design means it fails on the live site.
        if (destination.Port is 80 or 443)
        {
            throw new InvalidOperationException(
                $"Site '{site.Id}' destination points at loopback port {destination.Port}, which is a public IIS " +
                "port. The destination is the private loopback binding WPShield forwards to, such as " +
                "http://127.0.0.1:8081, and it must be a binding added for this purpose rather than the one " +
                "serving the internet. See docs/en/adr/0001-production-traffic-path.md.");
        }
    }
}

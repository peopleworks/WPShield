using System.Text.Json;

namespace WPShield.Cli.Enable;

/// <summary>
/// What the installed gateway has been told to resolve, read from its own configuration.
/// </summary>
/// <remarks>
/// <para>
/// <b>This exists because of a hole in <c>enable</c> that could have taken a live site down while
/// reporting success.</b> The gateway answers <c>421 Misdirected Request</c> for a <c>Host</c> it has
/// no site for. Put IIS in front of a gateway that does not know the site and every visitor gets a
/// 421 — and <see cref="SiteProbe"/> read a 421 as "the site answered", so the verb would have
/// reverted nothing and printed <i>enabled and verified</i>.
/// </para>
/// <para>
/// The check is made from configuration rather than by asking the gateway, because it has to happen
/// <b>before</b> anything is changed. There is no request that can ask a running gateway "would you
/// resolve this host" without first pointing traffic at it, which is the very thing being guarded.
/// </para>
/// <para>
/// Hosts are collected from the shipped <c>appsettings.json</c> and the operator's
/// <c>appsettings.Local.json</c> together. That is a deliberate over-approximation: the overlay
/// merges into the array by position, so reasoning about which shipped entry survives is exactly the
/// kind of subtlety this check should not depend on. A real public host only ever appears because an
/// operator put it there, so the union cannot produce the false <i>pass</i> that would matter.
/// </para>
/// </remarks>
internal interface IGatewayFacts
{
    /// <summary>Every <c>Host</c> value the gateway's configuration names, across both files.</summary>
    IReadOnlyList<string> KnownHosts { get; }

    /// <summary>
    /// Where the configuration was read from, for the refusal message to name. Null when no
    /// installation could be found.
    /// </summary>
    string? ConfigurationDirectory { get; }

    /// <summary>Whether <paramref name="host"/> is one the gateway would resolve.</summary>
    bool Knows(string host);
}

internal sealed class GatewayFacts : IGatewayFacts
{
    private readonly HashSet<string> _hosts;

    private GatewayFacts(HashSet<string> hosts, string? directory)
    {
        _hosts = hosts;
        ConfigurationDirectory = directory;
    }

    public IReadOnlyList<string> KnownHosts => [.. _hosts.Order(StringComparer.OrdinalIgnoreCase)];

    public string? ConfigurationDirectory { get; }

    public bool Knows(string host) =>
        !string.IsNullOrWhiteSpace(host) && _hosts.Contains(host.Trim());

    /// <summary>Reads the installed gateway's configuration, or an empty set when there is none.</summary>
    public static GatewayFacts Read()
    {
        var directory = InstallationReport.Gather().InstallDirectory;
        var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (directory is null)
        {
            return new GatewayFacts(hosts, null);
        }

        foreach (var name in new[] { "appsettings.json", Install.Installer.OverlayFileName })
        {
            ReadHostsInto(Path.Combine(directory, name), hosts);
        }

        return new GatewayFacts(hosts, directory);
    }

    /// <summary>Exposed for tests, which state the configured hosts rather than writing files.</summary>
    internal static GatewayFacts ForHosts(IEnumerable<string> hosts, string? directory = @"C:\Tools\WPShield") =>
        new(new HashSet<string>(hosts, StringComparer.OrdinalIgnoreCase), directory);

    /// <summary>
    /// Pulls <c>Sites[].Hosts[]</c> out of one settings file. Anything unreadable or misshapen
    /// contributes nothing rather than throwing: a configuration this cannot parse must make the
    /// guard refuse, never make the command crash.
    /// </summary>
    private static void ReadHostsInto(string path, HashSet<string> hosts)
    {
        if (!File.Exists(path))
        {
            return;
        }

        try
        {
            using var document = JsonDocument.Parse(
                File.ReadAllText(path),
                new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });

            if (!document.RootElement.TryGetProperty("Sites", out var sites) ||
                sites.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            foreach (var site in sites.EnumerateArray())
            {
                if (site.ValueKind != JsonValueKind.Object ||
                    !site.TryGetProperty("Hosts", out var siteHosts) ||
                    siteHosts.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var host in siteHosts.EnumerateArray())
                {
                    if (host.ValueKind == JsonValueKind.String && host.GetString() is { } value &&
                        !string.IsNullOrWhiteSpace(value))
                    {
                        hosts.Add(value.Trim());
                    }
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
        }
    }
}

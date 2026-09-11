using System.ServiceProcess;
using WPShield.Cli.Sites;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield site</c> — the site table, without hand-authored JSON.
/// </summary>
/// <remarks>
/// <para>
/// This is the verb that was missing. Nine verbs could check a host, install a service, put it in the
/// traffic path, take it out, watch it and report on it — and none of them could tell the gateway
/// which site to protect. The operator had to invent <c>appsettings.Local.json</c> from an example,
/// and a deployment that skipped it produced a gateway resolving nothing and a console with nothing
/// in it.
/// </para>
/// <para>
/// <b>It restarts the service by default.</b> Gateway configuration is not hot-reloaded, so a saved
/// file that nothing has read is a change that did not happen — the exact shape of defect this
/// project keeps finding. Saving and not restarting is available as <c>--no-restart</c>, and says so.
/// </para>
/// </remarks>
internal static class SiteCommand
{
    public const string Help = """
        wpshield site - tell the gateway which sites to protect. No hand-written JSON.

        Usage: wpshield site list
               wpshield site add --id <id> --hosts <a,b> --destination-port <n> [options]
               wpshield site remove --id <id>

          --id <id>                 The site identifier. It is what the log records as SiteId and
                                    what 'watch --host' and 'report --host' filter on, so name it
                                    the way you will look for it - the domain is a good choice.
          --hosts <a,b>             The Host header values this site answers to, comma-separated.
          --destination-port <n>    The PRIVATE loopback port IIS serves this site on - not 80 or
                                    443. WPShield forwards back to 127.0.0.1:<n>.
          --mode <Monitor|Block|Disabled>   Default Monitor: score and record, forward anyway.
          --observe-threshold <n>   Default 30.
          --block-threshold <n>     Default 80.
          --install-path <dir>      Where the gateway is installed. Default: the installed service's
                                    directory.
          --no-restart              Save without restarting the service. The change will NOT be live
                                    until it restarts - configuration is not hot-reloaded.

        It writes appsettings.Local.json, and empties the Sites array in the installed
        appsettings.json. That second part is necessary, not tidy: JSON configuration merges arrays
        element by element, so an overlay declaring one site leaves the shipped .example entries
        live - and the gateway refuses to start on real hostnames mixed with placeholders. Both
        files are backed up as .bak first.

        Exit codes:
          0   done
          1   an argument was wrong, or a file could not be written
        """;

    private static readonly string[] KnownOptions =
    [
        "--id", "--hosts", "--destination-port", "--mode",
        "--observe-threshold", "--block-threshold", "--install-path", "--no-restart"
    ];

    private static readonly string[] Modes = ["Monitor", "Block", "Disabled"];

    /// <summary>Ports that are IIS's public face and must never be a loopback destination.</summary>
    private static readonly int[] PublicPorts = [80, 443];

    public static int Run(CliOptions arguments, TextWriter output, string action)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);

        arguments.RejectUnknown(KnownOptions);

        var configuration = new SiteConfiguration(ResolveInstallDirectory(arguments.Get("--install-path")));

        return action switch
        {
            "list" => List(configuration, output),
            "add" => Add(arguments, configuration, output),
            "remove" => Remove(arguments, configuration, output),
            _ => throw new CliArgumentException(
                $"Unknown 'site' action '{action}'. It is one of: list, add, remove.")
        };
    }

    private static int List(SiteConfiguration configuration, TextWriter output)
    {
        var sites = configuration.Read();

        output.WriteLine();
        if (sites.Count == 0)
        {
            output.WriteLine($"  No sites configured in {configuration.OverlayPath}.");
            output.WriteLine("  Add one with: wpshield site add --id <id> --hosts <host> --destination-port <n>");
            output.WriteLine();
            return 0;
        }

        foreach (var site in sites)
        {
            output.WriteLine($"  {site.Id}");
            output.WriteLine($"    hosts        {string.Join(", ", site.Hosts)}");
            output.WriteLine($"    destination  {site.Destination}");
            output.WriteLine($"    mode         {site.Mode}  (observe {site.ObserveThreshold}, block {site.BlockThreshold})");
            output.WriteLine();
        }

        output.WriteLine($"  {sites.Count} site(s) in {configuration.OverlayPath}.");
        output.WriteLine();
        return 0;
    }

    private static int Add(CliOptions arguments, SiteConfiguration configuration, TextWriter output)
    {
        var entry = Parse(arguments);
        var sites = configuration.Read().ToList();

        var existing = sites.FindIndex(site => string.Equals(site.Id, entry.Id, StringComparison.OrdinalIgnoreCase));
        var replacing = existing >= 0;

        // A host may belong to exactly one site. The gateway fails to start on a host claimed twice,
        // which is a worse place to find out than here.
        foreach (var site in sites.Where((_, index) => index != existing))
        {
            var clash = site.Hosts.FirstOrDefault(host => entry.Hosts.Contains(host, StringComparer.OrdinalIgnoreCase));
            if (clash is not null)
            {
                throw new CliArgumentException(
                    $"Host '{clash}' is already claimed by site '{site.Id}'. A host belongs to exactly one site, " +
                    "and the gateway refuses to start when one is claimed twice. Nothing was changed.");
            }
        }

        if (replacing)
        {
            sites[existing] = entry;
        }
        else
        {
            sites.Add(entry);
        }

        var shippedChanged = configuration.Save(sites);

        output.WriteLine();
        output.WriteLine($"  {(replacing ? "Updated" : "Added")}    {entry.Id}");
        output.WriteLine($"    hosts        {string.Join(", ", entry.Hosts)}");
        output.WriteLine($"    destination  {entry.Destination}");
        output.WriteLine($"    mode         {entry.Mode}");
        output.WriteLine();
        output.WriteLine($"  wrote      {configuration.OverlayPath}");

        if (shippedChanged)
        {
            output.WriteLine($"  emptied    the Sites array in {configuration.ShippedPath}");
            output.WriteLine("             (the shipped .example placeholders would otherwise stay live and the");
            output.WriteLine("              gateway refuses to start on real hosts mixed with placeholders)");
        }

        Restart(arguments, output);
        return 0;
    }

    private static int Remove(CliOptions arguments, SiteConfiguration configuration, TextWriter output)
    {
        var id = arguments.Get("--id");
        if (string.IsNullOrWhiteSpace(id))
        {
            throw new CliArgumentException("--id is required, and names the site to remove.");
        }

        var sites = configuration.Read().ToList();
        var removed = sites.RemoveAll(site => string.Equals(site.Id, id, StringComparison.OrdinalIgnoreCase));

        output.WriteLine();
        if (removed == 0)
        {
            output.WriteLine($"  No site with Id '{id}'. Nothing was changed.");
            output.WriteLine();
            return 0;
        }

        configuration.Save(sites);
        output.WriteLine($"  Removed    {id}");
        output.WriteLine($"  wrote      {configuration.OverlayPath}");

        if (sites.Count == 0)
        {
            output.WriteLine();
            output.WriteLine("  WARNING: no sites remain. The gateway will resolve nothing and answer 421 to");
            output.WriteLine("           every request. Take it out of the traffic path with 'wpshield disable'.");
        }

        Restart(arguments, output);
        return 0;
    }

    private static SiteEntry Parse(CliOptions arguments)
    {
        var id = arguments.Get("--id");
        if (string.IsNullOrWhiteSpace(id))
        {
            throw new CliArgumentException(
                "--id is required. It is what the log records as SiteId and what 'watch --host' filters on.");
        }

        var hosts = arguments.List("--hosts");
        if (hosts.Count == 0)
        {
            throw new CliArgumentException(
                "--hosts is required. It is the Host header value(s) this site answers to, comma-separated.");
        }

        var port = arguments.Integer("--destination-port", 0);
        if (port is <= 0 or > 65535)
        {
            throw new CliArgumentException(
                "--destination-port is required and must be a port number. It is the PRIVATE loopback port IIS " +
                "serves this site on, which WPShield forwards back to.");
        }

        if (PublicPorts.Contains(port))
        {
            throw new CliArgumentException(
                $"--destination-port {port} is IIS's public port. WPShield must forward back to a PRIVATE loopback " +
                "binding, or the gateway would forward to itself through IIS's public face. Give the site a " +
                "127.0.0.1 binding on an unused port and use that.");
        }

        var mode = arguments.Get("--mode", "Monitor");
        var resolved = Modes.FirstOrDefault(candidate => string.Equals(candidate, mode, StringComparison.OrdinalIgnoreCase))
            ?? throw new CliArgumentException($"--mode must be one of: {string.Join(", ", Modes)}. It was '{mode}'.");

        var observe = arguments.Integer("--observe-threshold", 30);
        var block = arguments.Integer("--block-threshold", 80);

        if (observe > block)
        {
            throw new CliArgumentException(
                $"--observe-threshold ({observe}) is above --block-threshold ({block}), so a request would be " +
                "blocked before it was ever observed. Nothing was changed.");
        }

        return new SiteEntry
        {
            Id = id.Trim(),
            Hosts = [.. hosts.Select(host => host.Trim())],
            DestinationPort = port,
            Mode = resolved,
            ObserveThreshold = observe,
            BlockThreshold = block
        };
    }

    /// <summary>
    /// Restarts the gateway unless told not to. Configuration is read once at startup, so a saved
    /// file nothing has re-read is a change that did not happen.
    /// </summary>
    private static void Restart(CliOptions arguments, TextWriter output)
    {
        output.WriteLine();

        if (arguments.Flag("--no-restart"))
        {
            output.WriteLine("  --no-restart: the service was NOT restarted, so this change is not live yet.");
            output.WriteLine($"  Apply it with: sc stop {Install.Installer.ServiceName} && sc start {Install.Installer.ServiceName}");
            output.WriteLine();
            return;
        }

        try
        {
            using var service = new ServiceController(Install.Installer.ServiceName);
            var state = service.Status;

            if (state is ServiceControllerStatus.Stopped)
            {
                output.WriteLine("  The service is stopped, so nothing needed restarting. Start it when ready.");
                output.WriteLine();
                return;
            }

            service.Stop();
            service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
            service.Start();
            service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));

            output.WriteLine("  Restarted the gateway. The new site table is live.");
            output.WriteLine("  Confirm it with: wpshield status");
        }
        catch (InvalidOperationException)
        {
            output.WriteLine("  No installed WPShield service was found, so nothing was restarted.");
            output.WriteLine("  The configuration is saved and will be read the next time the gateway starts.");
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or System.ServiceProcess.TimeoutException)
        {
            output.WriteLine($"  The service could not be restarted: {exception.Message}");
            output.WriteLine($"  The configuration IS saved. Restart it yourself: sc stop {Install.Installer.ServiceName} && sc start {Install.Installer.ServiceName}");
        }

        output.WriteLine();
    }

    private static string ResolveInstallDirectory(string? explicitPath)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            if (!Directory.Exists(explicitPath))
            {
                throw new CliArgumentException($"--install-path '{explicitPath}' does not exist.");
            }

            return explicitPath;
        }

        var directory = InstallationReport.Gather().InstallDirectory;
        if (!string.IsNullOrWhiteSpace(directory) && Directory.Exists(directory))
        {
            return directory;
        }

        throw new CliArgumentException(
            "No installed gateway was found, so there is nowhere to write the site table. Install it first with " +
            "'wpshield install', or pass --install-path <dir> to configure a directory directly.");
    }
}

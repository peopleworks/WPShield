using WPShield.Cli.Enable;
using WPShield.Cli.Preflight;
using WPShield.Cli.Setup;
using WPShield.Cli.Sites;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield setup</c> — the five steps between an unpacked artifact and a first finding.
/// </summary>
/// <remarks>
/// Flags first, and it asks only for what it cannot work out. When the input stream is redirected it
/// never asks: it fails naming the flag, so a script gets an error rather than a hang.
/// </remarks>
internal static class SetupCommand
{
    public const string Help = """
        wpshield setup - take one site from "nothing configured" to "protected and verified",
        stopping at the first thing that needs a person.

        Usage: wpshield setup --site <iis-site-name> [options]

          --site <name>            The IIS site, as IIS names it. Required.
          --id <id>                The gateway's SiteId, which is what 'watch --host' filters on.
                                   Default: the site's first public host header.
          --hosts <a,b>            Host headers to route. Default: every public host header the
                                   IIS site has.
          --destination-port <n>   The private loopback port to forward back to. Default: the
                                   site's existing 127.0.0.1 binding.
          --gateway-port <n>       Default 10000.
          --mode <Monitor|Block>   Default Monitor.
          --dry-run                Print what each step would do. Changes nothing.

        THE FIVE STEPS, in order, and it refuses to skip one:
          1. preflight            is this host able to run WPShield
          2. gateway installed    is the service there and answering
          3. site configuration   does the gateway know this site      (writes it if not)
          4. wp-config.php        has WordPress been told the scheme   (NEVER written for you)
          5. in the traffic path  'enable', verified, reverted if the site stops answering

        It stops at the first blocker, says exactly what to fix, and is safe to run again - every
        step checks before it acts, so a second run continues from where the first stopped.

        Most of the time --site is the only flag you need: the hosts and the destination port are
        read from the IIS site itself.

        Exit codes:
          0   every step passed
          1   an argument was wrong, or a step needs you
        """;

    private static readonly string[] KnownOptions =
    [
        "--site", "--id", "--hosts", "--destination-port", "--gateway-port", "--mode", "--dry-run"
    ];

    public static int Run(CliOptions arguments, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);

        arguments.RejectUnknown(KnownOptions);

        var siteName = arguments.Get("--site") ?? Ask(
            output,
            "--site",
            "Which IIS site? (as IIS names it - 'wpshield preflight' lists them)");

        var options = new SetupOptions
        {
            SiteName = siteName,
            SiteId = arguments.Get("--id"),
            Hosts = arguments.List("--hosts"),
            DestinationPort = arguments.Integer("--destination-port", 0),
            GatewayPort = arguments.Integer("--gateway-port", 10000),
            Mode = arguments.Get("--mode", "Monitor"),
            DryRun = arguments.Flag("--dry-run")
        };

        var host = new HostFacts();
        var iis = IisFacts.Read();

        var installDirectory = ResolveInstallDirectory(InstallationReport.Gather(), options.DryRun);

        return new SetupRunner(
            host,
            iis,
            options,
            new SiteConfiguration(installDirectory),
            site => new PreflightRunner(host, iis, new PreflightOptions
            {
                GatewayPort = options.GatewayPort,
                SiteNames = [site.Name]
            }).Run(),
            InstallationReport.Gather,
            site => RunEnable(site, options, output),
            output).Run();
    }

    /// <summary>
    /// Where the site table lives, or a refusal.
    /// </summary>
    /// <remarks>
    /// <b>A dry run must work before anything is installed.</b> That is the moment an operator most
    /// wants the plan, and refusing to print it until after the install is backwards - the same
    /// principle <see cref="Install.Installer"/> already states for its own preview: requiring more
    /// to read what a tool intends than to let it do it makes the preview harder to reach than the
    /// thing it previews. With nothing installed, a dry run assumes the default path and step 2
    /// reports "not installed" and stops, which is the true and useful answer. Only a real run needs
    /// somewhere to write, and only a real run refuses without it.
    /// </remarks>
    internal static string ResolveInstallDirectory(InstallationReport report, bool dryRun)
    {
        ArgumentNullException.ThrowIfNull(report);

        if (report.InstallDirectory is { } directory)
        {
            return directory;
        }

        return dryRun
            ? Install.Installer.DefaultInstallPath
            : throw new CliArgumentException(
                "No installed gateway was found, so there is nowhere to write a site table. Install it first:" +
                Environment.NewLine +
                "    wpshield install --path <the copied artifact directory> --start" +
                Environment.NewLine +
                "Or run 'wpshield setup --site <name> --dry-run' to see the whole plan first.");
    }

    /// <summary>
    /// Step 5 delegates to the real <see cref="Enabler"/> rather than repeating any of it, so every
    /// refusal that verb owns still fires and the revert-on-failure guarantee is the same one.
    /// </summary>
    private static int RunEnable(IisSite site, SetupOptions options, TextWriter output)
    {
        return new Enabler(
            new IisSiteWriter(),
            new SiteProbe(),
            IisFacts.Read(),
            new HostFacts(),
            GatewayFacts.Read(),
            new EnableOptions
            {
                SiteName = site.Name,
                GatewayPort = options.GatewayPort,
                DestinationPort = options.DestinationPort
            },
            output).Run();
    }

    /// <summary>
    /// Asks for one missing value, or refuses when nothing can answer.
    /// </summary>
    /// <remarks>
    /// The operator's other tools take every value as a flag and fail with a one-line ERROR naming
    /// the missing one. That stays true whenever this is not a person at a prompt - a redirected
    /// input stream means a script, and a script must get the error rather than block forever on a
    /// question nobody will read.
    /// </remarks>
    private static string Ask(TextWriter output, string flag, string question)
    {
        if (Console.IsInputRedirected)
        {
            throw new CliArgumentException($"{flag} is required. {question}");
        }

        output.WriteLine();
        output.WriteLine($"  {question}");
        output.Write("  > ");
        output.Flush();

        var answer = Console.ReadLine()?.Trim();

        return string.IsNullOrWhiteSpace(answer)
            ? throw new CliArgumentException($"{flag} is required and nothing was entered. Nothing was changed.")
            : answer;
    }
}

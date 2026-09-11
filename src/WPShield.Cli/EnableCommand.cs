using WPShield.Cli.Enable;
using WPShield.Cli.Preflight;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield disable</c> — the rollback.
/// </summary>
/// <remarks>
/// Documented and declared before <c>enable</c>, deliberately. An operator looks for this when
/// something is already going wrong, and the thing you reach for under pressure should not be the
/// second half of a file.
/// </remarks>
internal static class DisableCommand
{
    public const string Help = """
        wpshield disable - take WPShield out of the traffic path for one site. THIS IS THE ROLLBACK.

        Usage: wpshield disable --site <name>

          --site <name>  The IIS site. Required, and exactly one.
          --dry-run      Say what would change without changing it.

        It sets enabled="false" on the WPShield rewrite rule rather than deleting it, so the rule's
        position in the order - the thing that is easy to get wrong and silent when you do - is
        preserved, and re-enabling is one command.

        THIS IS THE CONTROL THAT PUTS A SITE BACK. Stopping the WPShield service does NOT bypass
        WPShield: IIS keeps forwarding every request to a loopback port with nothing behind it, and
        the site goes down instead of recovering.

        Exit codes:
          0   disabled, or there was nothing to disable
          1   an argument was wrong, or IIS could not be read
        """;

    private static readonly string[] KnownOptions = ["--site", "--dry-run"];

    public static int Run(CliOptions arguments, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);

        arguments.RejectUnknown(KnownOptions);

        var site = arguments.Get("--site");
        if (string.IsNullOrWhiteSpace(site))
        {
            throw new CliArgumentException("--site is required, and takes exactly one site name.");
        }

        var host = new HostFacts();
        if (!arguments.Flag("--dry-run") && !host.IsElevated)
        {
            throw new CliArgumentException("This must run from an elevated prompt. Nothing was changed.");
        }

        output.WriteLine();

        if (arguments.Flag("--dry-run"))
        {
            output.WriteLine($"  would set enabled=\"false\" on the WPShield rewrite rule of '{site}'");
            output.WriteLine("  --dry-run: nothing was changed.");
            return 0;
        }

        var changed = new IisSiteWriter().SetRuleEnabled(site, enabled: false);

        output.WriteLine(changed
            ? $"  Disabled. '{site}' no longer forwards to WPShield, and the rule kept its position."
            : $"  No WPShield rewrite rule on '{site}'. Nothing to disable.");

        if (changed)
        {
            output.WriteLine($"  Re-enable with: wpshield enable --site \"{site}\"");
        }

        return 0;
    }
}

/// <summary>
/// <c>wpshield enable</c> — put WPShield in the path for one site, and take it back out if the site
/// stops working.
/// </summary>
internal static class EnableCommand
{
    public const string Help = """
        wpshield enable - put WPShield into the traffic path for ONE site, verify the site still
        works, and revert everything if it does not.

        Usage: wpshield enable --site <name> [options]

          --site <name>            The IIS site. Required, and exactly one. There is no --all.
          --gateway-port <n>       The loopback port WPShield listens on. Default 10000.
          --destination-port <n>   The private loopback port to forward back to. Defaults to the
                                   site's existing loopback binding.
          --backup-dir <dir>       Where to put the web.config backup. Default the temp directory.
          --dry-run                Print the exact plan and the rollback. Changes nothing, and does
                                   not require elevation.

        WHAT IT CHANGES, all for the one named site and each individually reversible:
          1. the private loopback binding, if the site has none
          2. HTTP_X_FORWARDED_PROTO added to the allowed server variables
          3. the WPShield rewrite rule, placed FIRST in the list

        WHAT IT REFUSES, and these refusals are the reason it is allowed to exist at all:
          - ARR's preserveHostHeader. Server-wide, no per-site override, and it changes what every
            ARR proxy on this machine sends downstream. Turn it on yourself after reading PRE-017.
          - Writing wp-config.php. That is the site's own source. It reads the file and REFUSES TO
            PROCEED without the scheme translation - which is what makes this verb unable to create
            the redirect loop it exists to prevent.
          - More than one site. The reason these steps were manual is that they need a person
            looking at the site while they happen.
          - Running while nothing answers on the gateway port, which would take the site down
            instantly.
          - Running when the GATEWAY DOES NOT KNOW THIS SITE'S HOST. It answers 421 for a host it
            has no site for, so the site would be down the moment the rule went live. Add the site
            to appsettings.Local.json and restart the service first.

        AFTER APPLYING it requests the site through its public binding. A 5xx, or a redirect chain
        that does not settle, reverts every change before this command returns.

        THE ROLLBACK IS 'wpshield disable --site <name>'. Stopping the service does NOT bypass
        WPShield - it takes the site down.

        Exit codes:
          0   enabled and verified
          1   an argument was wrong, or a refusal fired
          4   applied, the site did not answer, everything was reverted
        """;

    private static readonly string[] KnownOptions =
    [
        "--site", "--gateway-port", "--destination-port", "--backup-dir", "--dry-run"
    ];

    public static int Run(CliOptions arguments, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);

        arguments.RejectUnknown(KnownOptions);

        var site = arguments.Get("--site");
        if (string.IsNullOrWhiteSpace(site))
        {
            throw new CliArgumentException(
                "--site is required, and takes exactly one site name. There is no --all: these changes need a " +
                "person looking at the site while they happen.");
        }

        var options = new EnableOptions
        {
            SiteName = site,
            GatewayPort = arguments.Integer("--gateway-port", 10000),
            DestinationPort = arguments.Integer("--destination-port", 0),
            BackupDirectory = arguments.Get("--backup-dir"),
            DryRun = arguments.Flag("--dry-run")
        };

        output.WriteLine();
        output.WriteLine($"WPShield enable{(options.DryRun ? " - DRY RUN. Nothing will be changed." : string.Empty)}");
        output.WriteLine();

        return new Enabler(
            new IisSiteWriter(),
            new SiteProbe(),
            IisFacts.Read(),
            new HostFacts(),
            GatewayFacts.Read(),
            options,
            output).Run();
    }
}

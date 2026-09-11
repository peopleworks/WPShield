using WPShield.Cli.Preflight;

namespace WPShield.Cli.Enable;

internal sealed record EnableOptions
{
    public required string SiteName { get; init; }
    public int GatewayPort { get; init; } = 10000;
    public int DestinationPort { get; init; }
    public bool DryRun { get; init; }
    public string? BackupDirectory { get; init; }
}

/// <summary>
/// Puts WPShield into the traffic path for <b>one</b> site, and takes it back out the moment the
/// site stops working.
/// </summary>
/// <remarks>
/// <para>
/// This is the verb [ADR 0005] permits, and every refusal in it is part of the permission. It applies
/// only per-site, individually reversible IIS changes; it refuses the server-wide
/// <c>preserveHostHeader</c> outright; and it refuses to run at all until <c>wp-config.php</c> is
/// already translating the header — <b>which is what makes it unable to create the redirect loop it
/// exists to prevent.</b>
/// </para>
/// <para>
/// The rollback is <c>wpshield disable</c>, and it is documented before this is, because an operator
/// looks for it when things are already going wrong.
/// </para>
/// </remarks>
internal sealed class Enabler(
    IIisSiteWriter writer,
    ISiteProbe probe,
    IIisFacts iis,
    IHostFacts host,
    IGatewayFacts gateway,
    EnableOptions options,
    TextWriter output)
{
    private readonly IIisSiteWriter _writer = writer ?? throw new ArgumentNullException(nameof(writer));
    private readonly ISiteProbe _probe = probe ?? throw new ArgumentNullException(nameof(probe));
    private readonly IIisFacts _iis = iis ?? throw new ArgumentNullException(nameof(iis));
    private readonly IHostFacts _host = host ?? throw new ArgumentNullException(nameof(host));
    private readonly IGatewayFacts _gateway = gateway ?? throw new ArgumentNullException(nameof(gateway));
    private readonly EnableOptions _options = options ?? throw new ArgumentNullException(nameof(options));
    private readonly TextWriter _output = output ?? throw new ArgumentNullException(nameof(output));

    public const int ExitEnabled = 0;
    public const int ExitRefused = 1;
    public const int ExitRevertedAfterFailure = 4;

    public int Run()
    {
        var site = Resolve();
        var plan = Plan(site);

        Say($"Site        : {site.Name}");
        Say($"Public host : {plan.PublicHost}");
        Say($"Gateway     : http://127.0.0.1:{_options.GatewayPort}");
        Say($"Destination : http://127.0.0.1:{plan.DestinationPort}");
        Say(string.Empty);

        if (plan.Empty)
        {
            Say("Nothing to do: the binding, the server variable and the rule are all already in place.");
            Say($"If the rule is disabled, re-enable it with: wpshield enable --site \"{site.Name}\"");
            return ExitEnabled;
        }

        Refuse(site, plan);

        if (_options.DryRun)
        {
            Announce(plan);
            Say(string.Empty);
            Say("--dry-run: nothing above was actually done.");
            Say($"The rollback, once this is applied: wpshield disable --site \"{site.Name}\"");
            return ExitEnabled;
        }

        return Apply(site, plan);
    }

    // =============================================================================================
    //  Everything that can refuse, before anything is touched.
    // =============================================================================================

    private IisSite Resolve()
    {
        if (!_iis.Readable)
        {
            throw new CliArgumentException(
                $"IIS could not be read: {_iis.UnreadableReason}. Run elevated. Nothing was changed.");
        }

        // Exactly one site, named. There is no --all, and there will not be: the reason these steps
        // were manual is that they need a person looking at the site while they happen.
        var site = _iis.Sites.FirstOrDefault(candidate =>
            string.Equals(candidate.Name, _options.SiteName, StringComparison.OrdinalIgnoreCase));

        return site ?? throw new CliArgumentException(
            $"No IIS site named '{_options.SiteName}'. Run 'wpshield preflight' to list them. Nothing was changed.");
    }

    private void Refuse(IisSite site, EnablePlan plan)
    {
        if (!_options.DryRun && !_host.IsElevated)
        {
            throw new CliArgumentException("This must run from an elevated prompt. Nothing was changed.");
        }

        // wp-config.php is the customer's application source and this verb does not write it. It
        // reads it, and refuses without it - which enforces the ordering across the boundary and
        // means enabling the rule cannot produce the redirect loop.
        RequireWordPressIsToldTheSchemeChanged(site);

        // The gateway must already know this site's public host. Without it, the gateway resolves no
        // site for the Host header and answers 421 Misdirected Request to every visitor - the site is
        // down the instant the rule goes live. This has to be checked here, from configuration,
        // because there is no way to ask a running gateway the question without first pointing
        // traffic at it, which is the thing being guarded.
        //
        // The probe used to read a 421 as "the site answered", so this failure would have been
        // applied, verified, and reported as success. The probe no longer does; this refuses before
        // anything is written at all, which is the better of the two places to stop it.
        if (!_gateway.Knows(plan.PublicHost))
        {
            var known = _gateway.KnownHosts.Count == 0
                ? "It has no sites configured at all."
                : $"It knows: {string.Join(", ", _gateway.KnownHosts)}.";

            var where = _gateway.ConfigurationDirectory is { } directory
                ? $" Its configuration is in {directory}."
                : " No installed gateway was found on this machine.";

            throw new CliArgumentException(
                $"The gateway does not resolve '{plan.PublicHost}'. {known}{where} Enabling the rule now would " +
                "forward every request for this site to a gateway that answers 421 Misdirected Request, and the " +
                $"site would be down immediately. Add the site to {Install.Installer.OverlayFileName}, restart " +
                "the WPShield service, confirm the resolved site table names this host, and run this again. " +
                "Nothing was changed.");
        }

        // Enabling the rule while nothing answers on the loopback port takes the site down
        // instantly: IIS would forward every request to a closed port.
        if (!_host.ListeningPorts.Contains(_options.GatewayPort))
        {
            throw new CliArgumentException(
                $"Nothing is listening on 127.0.0.1:{_options.GatewayPort}. Enabling the rule now would forward " +
                "every request to a closed port and take the site down immediately. Start the service, confirm it " +
                "answers, and run this again. Nothing was changed.");
        }

        // Server-wide, no per-site override, and it changes what every ARR proxy on this machine
        // sends downstream. This verb reports it and will not touch it.
        if (_iis.ArrPreserveHostHeader is not true)
        {
            throw new CliArgumentException(
                "ARR is not preserving the client Host header, and this verb will not change that: the setting is " +
                "server-wide with no per-site override, and it alters what every ARR proxy on this machine sends " +
                "downstream. WPShield resolves the site from that header and answers 421 without it, so the whole " +
                "site would fail the moment the rule went live. Turn on 'Preserve client Host header' in Server " +
                "Proxy Settings yourself, re-test the applications PRE-017 names, then run this again. Nothing was changed.");
        }

        if (_iis.ArrProxyEnabled is not true)
        {
            throw new CliArgumentException(
                "ARR's server-level proxy is disabled. With it off, the rewrite rule does not proxy - it returns 404 " +
                "for every request, with nothing in the log explaining why. Enable it yourself; it is a server-wide " +
                "setting. Nothing was changed.");
        }

        if (plan.RuleOrderedBefore.Count > 0)
        {
            Say($"note: the rule will be placed ABOVE {string.Join(", ", plan.RuleOrderedBefore)}.");
        }
    }

    private void RequireWordPressIsToldTheSchemeChanged(IisSite site)
    {
        var config = Path.Combine(site.PhysicalPath, "wp-config.php");

        if (!_host.FileExists(config))
        {
            // Not WordPress, so there is nothing to translate. The rule still works; a non-WordPress
            // application either reads the header itself or does not care about the scheme.
            return;
        }

        var text = ReadWpConfig(config);

        if (text.Contains("HTTP_X_FORWARDED_PROTO", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        throw new CliArgumentException(
            $"{config} does not translate X-Forwarded-Proto, and this verb will not write it: that file is the " +
            "site's own source. Without the translation WordPress sees plain HTTP behind an HTTPS site and every " +
            "page redirects to HTTPS forever - ERR_TOO_MANY_REDIRECTS. Add this before " +
            "require_once ABSPATH . 'wp-settings.php'; and run this again:" + Environment.NewLine +
            Environment.NewLine +
            "    if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] )" + Environment.NewLine +
            "         && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https' ) {" + Environment.NewLine +
            "        $_SERVER['HTTPS'] = 'on';" + Environment.NewLine +
            "    }" + Environment.NewLine +
            Environment.NewLine +
            "Nothing was changed.");
    }

    private static string ReadWpConfig(string path)
    {
        try
        {
            return File.ReadAllText(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new CliArgumentException(
                $"{path} could not be read, so this cannot confirm the scheme translation is present: " +
                $"{exception.Message}. Nothing was changed.");
        }
    }

    // =============================================================================================
    //  The plan.
    // =============================================================================================

    private EnablePlan Plan(IisSite site)
    {
        var publicHost = site.Bindings
            .Where(binding => !binding.IsLoopback && !string.IsNullOrWhiteSpace(binding.HostHeader))
            .Select(binding => binding.HostHeader)
            .FirstOrDefault()
            ?? throw new CliArgumentException(
                $"Site '{site.Name}' has no binding with a host header, so there is no name to verify it by after " +
                "the change. Nothing was changed.");

        var loopback = site.Bindings.FirstOrDefault(binding => binding.IsLoopback);
        var destination = _options.DestinationPort > 0 ? _options.DestinationPort : loopback?.Port ?? 0;

        if (destination == 0)
        {
            throw new CliArgumentException(
                $"Site '{site.Name}' has no private loopback binding and none was given. Pass --destination-port " +
                "with the port WPShield should forward back to, and make sure it matches this site's Destination " +
                "in appsettings.Local.json. Nothing was changed.");
        }

        var hasRule = site.RewriteRules.Any(rule =>
            rule.Name.Contains(IisSiteWriter.RuleName, StringComparison.OrdinalIgnoreCase));

        return new EnablePlan
        {
            SiteName = site.Name,
            PublicHost = publicHost,
            DestinationPort = destination,
            NeedsLoopbackBinding = loopback is null,
            NeedsServerVariable = true,
            NeedsRule = !hasRule,
            RuleOrderedBefore = [.. site.RewriteRules.Select(rule => rule.Name)]
        };
    }

    private void Announce(EnablePlan plan)
    {
        if (plan.NeedsLoopbackBinding)
        {
            Say($"would add the private loopback binding 127.0.0.1:{plan.DestinationPort}");
        }

        Say($"would allow the server variable {IisSiteWriter.ServerVariable}");
        Say($"would add the WPShield rewrite rule, FIRST in the list, forwarding to 127.0.0.1:{_options.GatewayPort}");
        Say($"would then request https://{plan.PublicHost}/ and revert everything if it does not answer");
    }

    // =============================================================================================
    //  Apply, verify, and revert if the site stopped working.
    // =============================================================================================

    private int Apply(IisSite site, EnablePlan plan)
    {
        var backup = Path.Combine(
            _options.BackupDirectory ?? Path.GetTempPath(),
            $"web.config.{site.Name}.{DateTimeOffset.UtcNow:yyyyMMddHHmmss}.bak");

        _writer.BackupWebConfig(site.PhysicalPath, backup);
        Say($"web.config backed up to {backup}");

        var applied = new Stack<SiteChange>();

        try
        {
            if (plan.NeedsLoopbackBinding)
            {
                Run(applied, new SiteChange(
                    $"add the private loopback binding 127.0.0.1:{plan.DestinationPort}",
                    () => _writer.AddLoopbackBinding(site.Name, plan.DestinationPort),
                    () => _writer.RemoveLoopbackBinding(site.Name, plan.DestinationPort)));
            }

            // Before the rule, always. A rule that sets a variable which is not on this list returns
            // HTTP 500 for the whole site.
            Run(applied, new SiteChange(
                $"allow the server variable {IisSiteWriter.ServerVariable}",
                () => _writer.AllowServerVariable(site.Name),
                () => _writer.DisallowServerVariable(site.Name)));

            Run(applied, new SiteChange(
                "add the WPShield rewrite rule, first in the list",
                () => _writer.AddRuleFirst(site.Name, _options.GatewayPort),
                () => _writer.RemoveRule(site.Name)));
        }
        catch (Exception exception) when (exception is not CliArgumentException)
        {
            Revert(applied, $"a step failed: {exception.Message}");
            throw new CliArgumentException(
                $"Applying the change failed and everything applied has been reverted: {exception.Message}");
        }

        Say(string.Empty);
        Say($"Verifying https://{plan.PublicHost}/ ...");

        var health = _probe.Check(plan.PublicHost);

        if (health.Healthy)
        {
            Say($"  {health.Detail}");
            Say(string.Empty);
            Say("Enabled. WPShield is now in the path for this site.");
            Say($"The rollback is: wpshield disable --site \"{site.Name}\"");
            Say("Stopping the service does NOT bypass WPShield - it takes the site down, because IIS keeps");
            Say("forwarding to a port with nothing behind it.");
            Say(string.Empty);
            Say("Watch the log in Monitor mode before changing anything to Block. An empty log with real");
            Say("traffic is a finding, not a quiet night.");
            return ExitEnabled;
        }

        Revert(applied, health.Detail);

        Say(string.Empty);
        Say("The site did not answer correctly, so every change above was reverted before this returned.");
        Say($"web.config as it was before: {backup}");
        return ExitRevertedAfterFailure;
    }

    private void Run(Stack<SiteChange> applied, SiteChange change)
    {
        Say(change.Description);
        change.Apply();
        applied.Push(change);
    }

    /// <summary>
    /// Undoes what was applied, newest first, and keeps going when one reversal fails.
    /// </summary>
    /// <remarks>
    /// A reversal that throws must not stop the ones behind it. Leaving a site half-reverted because
    /// the first undo failed is worse than leaving it half-applied, and the operator needs to be told
    /// exactly which one did not come back.
    /// </remarks>
    private void Revert(Stack<SiteChange> applied, string reason)
    {
        Say(string.Empty);
        Say($"REVERTING: {reason}");

        while (applied.Count > 0)
        {
            var change = applied.Pop();
            try
            {
                change.Revert();
                Say($"  reverted: {change.Description}");
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                Say($"  COULD NOT REVERT: {change.Description} - {exception.Message}");
                Say("  Undo this one by hand before anything else.");
            }
        }
    }

    private void Say(string line) => _output.WriteLine(string.IsNullOrEmpty(line) ? string.Empty : $"  {line}");
}

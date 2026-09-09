using System.Text.Json;

namespace WPShield.Cli.Preflight;

/// <summary>
/// The configuration and the IIS changes to make, filled in from what the run found.
/// </summary>
/// <remarks>
/// <para>
/// Printed, never written. An operator's real hostnames and internal ports belong on their server,
/// and a readiness check that quietly created files would be a different and much worse tool.
/// </para>
/// <para>
/// <b>This prints all three IIS changes, and the PowerShell version printed one.</b> It emitted the
/// rewrite rule without the <c>serverVariables</c> block and warned that the alternative was a
/// redirect loop, without naming what prevents it. An operator followed that output exactly and took
/// a live site down with <c>ERR_TOO_MANY_REDIRECTS</c>. Naming the symptom and keeping the cure is
/// the failure this file exists to not repeat.
/// </para>
/// </remarks>
internal static class SuggestedConfiguration
{
    public static void Write(IReadOnlyList<IisSite> sites, PreflightOptions options, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(sites);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(output);

        output.WriteLine();
        output.WriteLine("Suggested appsettings.Local.json, from what was found here.");
        output.WriteLine("Mode is Monitor: WPShield reports and forwards, and refuses nothing, until you change it.");
        output.WriteLine("This file is gitignored and must stay on this server. It is printed, never written.");
        output.WriteLine();
        output.WriteLine(BuildConfiguration(sites, options));

        var anyHttps = sites.SelectMany(site => site.Bindings)
            .Any(binding => binding.Protocol.Equals("https", StringComparison.OrdinalIgnoreCase));

        if (anyHttps)
        {
            WriteHttpsWarning(output);
        }

        WriteIisSteps(sites, options, output, anyHttps);
    }

    internal static string BuildConfiguration(IReadOnlyList<IisSite> sites, PreflightOptions options)
    {
        var configured = new List<object>();
        var port = 0;

        foreach (var site in sites)
        {
            var hosts = site.Bindings
                .Where(binding => !binding.IsLoopback && !string.IsNullOrWhiteSpace(binding.HostHeader))
                .Select(binding => binding.HostHeader)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (hosts.Length == 0)
            {
                continue;
            }

            // Prefer a loopback binding the site already has: on a host that has been set up for
            // this, it is the right answer and the operator does not have to create one. Otherwise
            // fall back to the candidate ports, so the printed file is complete rather than blank.
            var loopback = site.Bindings.FirstOrDefault(binding => binding.IsLoopback);
            var destinationPort = loopback?.Port ?? NextCandidate(options, ref port);

            configured.Add(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["Id"] = Slug(site.Name),
                ["Hosts"] = hosts,
                ["Destination"] = $"http://127.0.0.1:{destinationPort}",
                ["Mode"] = "Monitor",
                ["ObserveThreshold"] = 30,
                ["BlockThreshold"] = 80
            });
        }

        var document = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["Gateway"] = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                // Exact addresses, never a CIDR range: these decide whose forwarding headers become
                // authoritative, and under this traffic path the only trusted peer is a local proxy.
                ["TrustedProxies"] = new[] { "127.0.0.1", "::1" }
            },
            ["Sites"] = configured
        };

        // Serialised rather than assembled from strings. The PowerShell version built this by hand
        // and printed C:\\\\ProgramData\\\\... for a release, because a .NET replacement string does
        // not treat backslash as an escape. A serialiser cannot make that mistake.
        return JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true });
    }

    private static int NextCandidate(PreflightOptions options, ref int index)
    {
        if (options.PrivatePorts.Count == 0)
        {
            return 8081;
        }

        var port = options.PrivatePorts[Math.Min(index, options.PrivatePorts.Count - 1)];
        index++;
        return port;
    }

    private static string Slug(string name)
    {
        var characters = name
            .Select(character => char.IsLetterOrDigit(character) ? char.ToLowerInvariant(character) : '-')
            .ToArray();

        return new string(characters).Trim('-');
    }

    private static void WriteHttpsWarning(TextWriter output)
    {
        output.WriteLine();
        output.WriteLine("At least one site uses HTTPS, so TrustedProxies matters.");
        output.WriteLine("It is set to 127.0.0.1 above because that is the peer address ARR will present. Without it,");
        output.WriteLine("X-Forwarded-Proto is discarded, WordPress sees plain HTTP and starts emitting http:// URLs");
        output.WriteLine("behind an HTTPS site - which is a redirect loop, not a subtle degradation.");
    }

    private static void WriteIisSteps(
        IReadOnlyList<IisSite> sites,
        PreflightOptions options,
        TextWriter output,
        bool anyHttps)
    {
        output.WriteLine();
        output.WriteLine("Then, in IIS, three changes per site - IN THIS ORDER. Doing (b) before (a) returns");
        output.WriteLine("HTTP 500 for the whole site.");
        output.WriteLine();

        output.WriteLine("  (a) Allow the server variable, once per site.");
        output.WriteLine("      IIS Manager -> the site -> URL Rewrite -> View Server Variables -> Add:");
        output.WriteLine("        HTTP_X_FORWARDED_PROTO");
        output.WriteLine("      URL Rewrite refuses to set an HTTP_ variable that is not on this list, and the");
        output.WriteLine("      symptom is a 500 on every request.");
        output.WriteLine();

        output.WriteLine("  (b) The rewrite rule, ordered ABOVE any catch-all the site already has.");
        output.WriteLine("      A WordPress permalink rule is a catch-all: below it, either this rule never runs");
        output.WriteLine("      or it runs against the already-rewritten URL. Both look like a working site.");
        output.WriteLine();
        output.WriteLine("      <rule name=\"WPShield\" patternSyntax=\"ECMAScript\" stopProcessing=\"true\">");
        output.WriteLine("        <match url=\".*\" />");
        output.WriteLine("        <conditions>");
        output.WriteLine("          <add input=\"{HTTP_X_WPSHIELD_REQUEST_ID}\" pattern=\"^$\" />");
        output.WriteLine("        </conditions>");
        output.WriteLine("        <serverVariables>");
        output.WriteLine("          <set name=\"HTTP_X_FORWARDED_PROTO\" value=\"https\" />");
        output.WriteLine("        </serverVariables>");
        output.WriteLine($"        <action type=\"Rewrite\" url=\"http://127.0.0.1:{options.GatewayPort}/{{R:0}}\" />");
        output.WriteLine("      </rule>");
        output.WriteLine();
        output.WriteLine("      The condition is the loop guard. WPShield stamps that header on everything it");
        output.WriteLine("      forwards and strips any inbound copy, so the request coming back does not match");
        output.WriteLine("      the rule and a visitor cannot forge it to skip inspection. Both halves are");
        output.WriteLine("      load-bearing. The value \"https\" is right when the public binding is HTTPS only.");
        output.WriteLine();

        if (anyHttps)
        {
            output.WriteLine("  (c) Let WordPress read it. THIS IS THE ONE THAT GETS SKIPPED.");
            output.WriteLine("      WordPress on IIS reads $_SERVER['HTTPS'], which IIS derives from the REAL");
            output.WriteLine("      connection - plain HTTP on the private binding. Without this, every page");
            output.WriteLine("      redirects to HTTPS forever and the browser reports ERR_TOO_MANY_REDIRECTS.");
            output.WriteLine();
            output.WriteLine("      In wp-config.php, before require_once ABSPATH . 'wp-settings.php';");
            output.WriteLine();
            output.WriteLine("        if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] )");
            output.WriteLine("             && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https' ) {");
            output.WriteLine("            $_SERVER['HTTPS'] = 'on';");
            output.WriteLine("        }");
            output.WriteLine();
        }

        output.WriteLine("  Each site also needs a private loopback binding on its destination port.");
        output.WriteLine();
        output.WriteLine("  KNOW THE ROLLBACK BEFORE YOU ENABLE THE RULE. Once IIS forwards to the gateway,");
        output.WriteLine("  stopping the service does NOT bypass WPShield - it takes the site down, because IIS");
        output.WriteLine("  keeps forwarding to a port with nothing behind it. The control that puts the site");
        output.WriteLine("  back is disabling the rewrite rule.");

        var missingLoopback = sites
            .Where(site => !site.Bindings.Any(binding => binding.IsLoopback))
            .Select(site => site.Name)
            .ToArray();

        if (missingLoopback.Length > 0)
        {
            output.WriteLine();
            output.WriteLine($"  These sites have no loopback binding yet: {string.Join(", ", missingLoopback)}");
        }
    }
}

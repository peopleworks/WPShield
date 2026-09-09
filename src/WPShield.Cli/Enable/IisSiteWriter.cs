using System.Globalization;
using Microsoft.Web.Administration;

namespace WPShield.Cli.Enable;

/// <summary>
/// The only place in WPShield that writes an IIS setting.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every method takes the site name and touches nothing else.</b> That is the structural half of
/// what [ADR 0005] permits: a verb may change IIS only for a single site the operator named on the
/// command line. The old invariant banned IIS writes outright and the script harness enforced it by
/// banning the cmdlets; the equivalent here is that this is the one type that can, every entry point
/// is scoped to one site, and a test asserts that nothing else in the assembly reaches
/// <see cref="ServerManager"/> to write.
/// </para>
/// <para>
/// <b>Nothing server-wide is reachable from here.</b> There is no method that touches
/// <c>system.webServer/proxy</c>, and there will not be: <c>preserveHostHeader</c> has no per-site
/// override and changing it on behalf of an operator who asked about one site is exactly the mistake
/// the invariant exists to prevent.
/// </para>
/// </remarks>
internal sealed class IisSiteWriter : IIisSiteWriter
{
    public const string ServerVariable = "HTTP_X_FORWARDED_PROTO";
    public const string RuleName = "WPShield";

    public void BackupWebConfig(string sitePhysicalPath, string backupPath)
    {
        var source = Path.Combine(sitePhysicalPath, "web.config");
        if (File.Exists(source))
        {
            File.Copy(source, backupPath, overwrite: true);
        }
    }

    public void AddLoopbackBinding(string siteName, int port)
    {
        using var manager = new ServerManager();
        var site = Find(manager, siteName);

        site.Bindings.Add(
            FormattableString.Invariant($"127.0.0.1:{port}:"),
            "http");

        manager.CommitChanges();
    }

    public void RemoveLoopbackBinding(string siteName, int port)
    {
        using var manager = new ServerManager();
        var site = Find(manager, siteName);

        var binding = site.Bindings.FirstOrDefault(candidate =>
            candidate.BindingInformation.StartsWith(
                FormattableString.Invariant($"127.0.0.1:{port}:"), StringComparison.Ordinal));

        if (binding is not null)
        {
            site.Bindings.Remove(binding);
            manager.CommitChanges();
        }
    }

    public void AllowServerVariable(string siteName)
    {
        using var manager = new ServerManager();
        var config = manager.GetWebConfiguration(siteName);
        var collection = config.GetSection("system.webServer/rewrite/allowedServerVariables").GetCollection();

        if (collection.Any(entry => string.Equals(entry["name"] as string, ServerVariable, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        var element = collection.CreateElement("add");
        element["name"] = ServerVariable;
        collection.Add(element);

        manager.CommitChanges();
    }

    public void DisallowServerVariable(string siteName)
    {
        using var manager = new ServerManager();
        var config = manager.GetWebConfiguration(siteName);
        var collection = config.GetSection("system.webServer/rewrite/allowedServerVariables").GetCollection();

        var element = collection.FirstOrDefault(entry =>
            string.Equals(entry["name"] as string, ServerVariable, StringComparison.OrdinalIgnoreCase));

        if (element is not null)
        {
            collection.Remove(element);
            manager.CommitChanges();
        }
    }

    /// <summary>
    /// Adds the rule at position zero.
    /// </summary>
    /// <remarks>
    /// First, not appended. Below a catch-all the rule either never runs or runs against the
    /// already-rewritten URL, and both look like a working site — which is why an operator who
    /// appended it by hand would have no symptom to notice.
    /// </remarks>
    public void AddRuleFirst(string siteName, int gatewayPort)
    {
        using var manager = new ServerManager();
        var config = manager.GetWebConfiguration(siteName);
        var rules = config.GetSection("system.webServer/rewrite/rules").GetCollection();

        var existing = rules.FirstOrDefault(rule =>
            string.Equals(rule["name"] as string, RuleName, StringComparison.OrdinalIgnoreCase));

        if (existing is not null)
        {
            rules.Remove(existing);
        }

        var element = rules.CreateElement("rule");
        element["name"] = RuleName;
        element["patternSyntax"] = "ECMAScript";
        element["stopProcessing"] = true;
        element["enabled"] = true;

        element.GetChildElement("match")["url"] = ".*";

        // The loop guard. WPShield stamps this header on everything it forwards and strips any
        // inbound copy, so the request coming back does not match this rule and a visitor cannot
        // forge it to skip inspection. Both halves are load-bearing.
        var condition = element.GetChildElement("conditions").GetCollection().CreateElement("add");
        condition["input"] = "{HTTP_X_WPSHIELD_REQUEST_ID}";
        condition["pattern"] = "^$";
        element.GetChildElement("conditions").GetCollection().Add(condition);

        var variable = element.GetChildElement("serverVariables").GetCollection().CreateElement("set");
        variable["name"] = ServerVariable;
        variable["value"] = "https";
        element.GetChildElement("serverVariables").GetCollection().Add(variable);

        var action = element.GetChildElement("action");
        action["type"] = "Rewrite";
        action["url"] = FormattableString.Invariant($"http://127.0.0.1:{gatewayPort}/{{R:0}}");

        rules.AddAt(0, element);
        manager.CommitChanges();
    }

    public void RemoveRule(string siteName)
    {
        using var manager = new ServerManager();
        var config = manager.GetWebConfiguration(siteName);
        var rules = config.GetSection("system.webServer/rewrite/rules").GetCollection();

        var element = rules.FirstOrDefault(rule =>
            string.Equals(rule["name"] as string, RuleName, StringComparison.OrdinalIgnoreCase));

        if (element is not null)
        {
            rules.Remove(element);
            manager.CommitChanges();
        }
    }

    /// <summary>
    /// Sets <c>enabled</c> on the rule rather than removing it.
    /// </summary>
    /// <remarks>
    /// Disabling is the rollback, and an operator reaches for it when something is already going
    /// wrong. Keeping the element means re-enabling is one command and the rule's position in the
    /// order — the thing that is easy to get wrong and silent when you do — is preserved.
    /// </remarks>
    public bool SetRuleEnabled(string siteName, bool enabled)
    {
        using var manager = new ServerManager();
        var config = manager.GetWebConfiguration(siteName);
        var rules = config.GetSection("system.webServer/rewrite/rules").GetCollection();

        var element = rules.FirstOrDefault(rule =>
            string.Equals(rule["name"] as string, RuleName, StringComparison.OrdinalIgnoreCase));

        if (element is null)
        {
            return false;
        }

        element["enabled"] = enabled;
        manager.CommitChanges();
        return true;
    }

    private static Site Find(ServerManager manager, string siteName)
    {
        return manager.Sites[siteName]
            ?? throw new CliArgumentException($"No IIS site named '{siteName}'. Run 'wpshield preflight' to list them.");
    }
}

/// <summary>The seam. Everything that writes IIS is behind this, and every method names one site.</summary>
internal interface IIisSiteWriter
{
    void BackupWebConfig(string sitePhysicalPath, string backupPath);
    void AddLoopbackBinding(string siteName, int port);
    void RemoveLoopbackBinding(string siteName, int port);
    void AllowServerVariable(string siteName);
    void DisallowServerVariable(string siteName);
    void AddRuleFirst(string siteName, int gatewayPort);
    void RemoveRule(string siteName);
    bool SetRuleEnabled(string siteName, bool enabled);
}

namespace WPShield.Cli.Audit;

/// <summary>
/// The server posture audit, as a pure function of <see cref="AuditFacts"/>.
/// </summary>
/// <remarks>
/// <para>
/// Each check here is a way a single compromised site becomes a compromised server on a shared IIS
/// host. A web shell runs its commands as a local administrator when its pool does; writes into
/// other sites when their folders are writable by every account; executes there when PHP is mapped
/// for every site; and stays reachable after its own site is stopped when a site answering any host
/// name serves the folder that contains them all. None of those is a WordPress problem, and none of
/// them shows up in a vulnerability scan of the sites themselves.
/// </para>
/// <para>
/// <b>It reads and reports; it never repairs.</b> Every remedy is a change made by hand, one pool or
/// one site at a time, with a person looking at the site while it happens. On a host running other
/// people's applications, a posture tool that "fixed" identities or permissions would take them down.
/// </para>
/// </remarks>
internal sealed class AuditRunner(AuditFacts facts)
{
    /// <summary>How many entries a list prints before it summarises the rest.</summary>
    internal const int ListLimit = 25;

    private readonly AuditFacts _facts = facts ?? throw new ArgumentNullException(nameof(facts));

    public AuditReport Run()
    {
        var report = new AuditReport();

        if (!CheckAccess(report))
        {
            return report;
        }

        CheckAdministratorPools(report);
        CheckSharedIdentities(report);
        CheckServerWidePhp(report);
        CheckWritableFolders(report);
        CheckCatchAllSites(report);

        return report;
    }

    // =============================================================================================
    //  AUDIT-001 - could the audit look at all
    // =============================================================================================

    private bool CheckAccess(AuditReport report)
    {
        if (!_facts.IsElevated)
        {
            report.Complete = false;
            report.Add(new AuditFinding(
                "AUDIT-001", AuditSeverity.Critical, "Not running as administrator",
                "Pool identities, handler mappings and folder permissions are partly or wholly unreadable, so every answer below would come out optimistic - which is the worst direction for an audit.",
                "Run this from an elevated prompt.",
                Data: AuditReport.Fields(("elevated", false))));
        }

        if (!_facts.IisReadable)
        {
            report.Complete = false;
            report.Add(new AuditFinding(
                "AUDIT-001", AuditSeverity.Critical, "The IIS configuration could not be read",
                _facts.IisUnreadableReason ?? "No reason was reported.",
                "Run elevated, and confirm IIS is installed. Nothing in this report says anything about IIS until this passes.",
                Data: AuditReport.Fields(("iisReadable", false))));

            return false;
        }

        if (_facts.IsElevated)
        {
            report.Add(new AuditFinding(
                "AUDIT-001", AuditSeverity.Pass, "Running elevated; IIS is readable",
                $"{_facts.Sites.Count} site(s), {_facts.Pools.Count} application pool(s).",
                Data: AuditReport.Fields(
                    ("elevated", true),
                    ("sites", _facts.Sites.Count),
                    ("pools", _facts.Pools.Count))));
        }

        return true;
    }

    // =============================================================================================
    //  AUDIT-002 - pools that run with administrator rights
    // =============================================================================================

    private void CheckAdministratorPools(AuditReport report)
    {
        var privileged = _facts.Pools
            .Where(pool =>
                IsIdentity(pool, "LocalSystem") ||
                (IsIdentity(pool, "SpecificUser") && pool.RunsAsLocalAdministrator == true))
            .ToArray();

        var unresolved = _facts.Pools
            .Where(pool => IsIdentity(pool, "SpecificUser") && pool.RunsAsLocalAdministrator is null)
            .ToArray();

        if (privileged.Length == 0 && unresolved.Length == 0)
        {
            report.Add(new AuditFinding(
                "AUDIT-002", AuditSeverity.Pass, "No application pool runs with administrator rights",
                Data: AuditReport.Fields(("privilegedPools", 0))));
            return;
        }

        var items = privileged
            .Select(pool => $"{pool.Name}  runs as {Describe(pool)}  serves {SitesOf(pool.Name)}")
            .Concat(unresolved.Select(pool =>
                $"{pool.Name}  runs as {pool.UserName} - could not tell whether that account is an administrator  serves {SitesOf(pool.Name)}"))
            .ToArray();

        report.Add(new AuditFinding(
            "AUDIT-002",
            privileged.Length > 0 ? AuditSeverity.Critical : AuditSeverity.Warn,
            privileged.Length > 0
                ? $"{privileged.Length} application pool(s) run with administrator rights"
                : $"{unresolved.Length} application pool(s) run as an account that could not be resolved",
            "Code that runs in one of these pools - a web shell dropped into any site they serve - runs as an administrator of this server: it can read every other site's secrets, write into every folder, create accounts and install services. A pool that runs as a named account also keeps that account's password in the IIS configuration, where any administrator can read it back in plain text.",
            "Move each pool to ApplicationPoolIdentity, by hand, one pool at a time, and give that identity only what its site needs: read on the site's folder, write only where the application writes. Check the site after each change. Then change the password of every account that was used as a pool identity. For an unresolved account, check by hand whether it is a member of the local Administrators group.",
            items,
            AuditReport.Fields(
                ("privilegedPools", privileged.Select(pool => pool.Name).ToArray()),
                ("unresolvedPools", unresolved.Select(pool => pool.Name).ToArray()))));
    }

    // =============================================================================================
    //  AUDIT-003 - pools that share one built-in identity
    // =============================================================================================

    private void CheckSharedIdentities(AuditReport report)
    {
        var shared = _facts.Pools
            .Where(pool => IsIdentity(pool, "NetworkService") || IsIdentity(pool, "LocalService"))
            .ToArray();

        if (shared.Length == 0)
        {
            report.Add(new AuditFinding(
                "AUDIT-003", AuditSeverity.Pass, "No application pool shares a built-in account",
                Data: AuditReport.Fields(("sharedPools", 0))));
            return;
        }

        report.Add(new AuditFinding(
            "AUDIT-003", AuditSeverity.Warn, $"{shared.Length} application pool(s) share a built-in account",
            "Every pool running as NetworkService, or as LocalService, runs as the same identity, so no folder permission can keep one of those sites out of another's files.",
            "Move each pool to ApplicationPoolIdentity, by hand, one pool at a time, and check the site after each change.",
            [.. shared.Select(pool => $"{pool.Name}  runs as {pool.IdentityType}  serves {SitesOf(pool.Name)}")],
            AuditReport.Fields(("sharedPools", shared.Select(pool => pool.Name).ToArray()))));
    }

    // =============================================================================================
    //  AUDIT-004 - PHP mapped for the whole server
    // =============================================================================================

    private void CheckServerWidePhp(AuditReport report)
    {
        var php = _facts.ServerHandlers.Where(AuditPrimitives.IsPhpHandler).ToArray();

        if (php.Length == 0)
        {
            report.Add(new AuditFinding(
                "AUDIT-004", AuditSeverity.Pass, "PHP is not mapped at the server level",
                Data: AuditReport.Fields(("serverLevelPhp", false))));
            return;
        }

        var running = _facts.Sites.Where(site => site.ExecutesPhp == true).ToArray();
        var withoutWordPress = running.Where(site => !site.LooksLikeWordPress).ToArray();

        // A site whose configuration could not be read may well run PHP. Unknown is listed, never
        // dropped: leaving it out would be the optimistic direction.
        var unknown = _facts.Sites.Where(site => site.ExecutesPhp is null).ToArray();

        var items = php
            .Select(handler => $"handler {handler.Name}  {handler.Path}  -> {handler.ScriptProcessor}")
            .Concat(withoutWordPress.Select(site => $"PHP runs here, and there is no WordPress: {site.Name}  ({site.PhysicalPath})"))
            .Concat(unknown.Select(site => $"could not read this site's configuration, so whether PHP runs here is unknown: {site.Name}  ({site.PhysicalPath})"))
            .ToArray();

        report.Add(new AuditFinding(
            "AUDIT-004",
            withoutWordPress.Length > 0 || unknown.Length > 0 ? AuditSeverity.Warn : AuditSeverity.Info,
            "PHP is mapped for the whole server",
            $"The mapping below is inherited by every site that does not remove it. PHP runs in {running.Length} site(s), {withoutWordPress.Length} of which contain no WordPress, and {unknown.Length} site(s) could not be read. A .php file written into any of those folders executes there.",
            "Map PHP only on the sites that need it: add the handler to each of those sites, check each one, and then remove it from the server level. By hand, one site at a time.",
            items,
            AuditReport.Fields(
                ("serverLevelPhp", true),
                ("sitesRunningPhp", running.Length),
                ("sitesRunningPhpWithoutWordPress", withoutWordPress.Select(site => site.Name).ToArray()),
                ("sitesWithUnreadableConfiguration", unknown.Select(site => site.Name).ToArray()))));
    }

    // =============================================================================================
    //  AUDIT-005 - site folders every account can write into
    // =============================================================================================

    private void CheckWritableFolders(AuditReport report)
    {
        var writable = _facts.Sites
            .Where(site => site.Root.Exists && site.Root.BroadWriters.Count > 0)
            .ToArray();

        var unreadable = _facts.Sites
            .Where(site => site.Root.Exists && site.Root.Problem is not null)
            .ToArray();

        if (writable.Length == 0 && unreadable.Length == 0)
        {
            report.Add(new AuditFinding(
                "AUDIT-005", AuditSeverity.Pass, "No site folder is writable by every account",
                Data: AuditReport.Fields(("writableSiteFolders", 0))));
            return;
        }

        var items = writable
            .Select(site => $"{site.Name}  ({site.PhysicalPath})  writable by {string.Join(", ", site.Root.BroadWriters)}")
            .Concat(unreadable.Select(site => $"{site.Name}  ({site.PhysicalPath})  permissions could not be read: {site.Root.Problem}"))
            .ToArray();

        report.Add(new AuditFinding(
            "AUDIT-005",
            writable.Length > 0 ? AuditSeverity.Critical : AuditSeverity.Warn,
            writable.Length > 0
                ? $"{writable.Length} site folder(s) are writable by every account on this server"
                : $"The permissions on {unreadable.Length} site folder(s) could not be read",
            "Every application pool identity is a member of Users and IIS_IUSRS while it runs. A folder those groups can write into is a folder every other site's code can write into - which is how a shell in one site becomes a shell in another.",
            "Replace the permissions on each site folder, by hand: remove write for Everyone, Users, Authenticated Users and IIS_IUSRS, give the site's own pool identity read, and give it write only on the folders its application writes to. Check the site after each folder.",
            items,
            AuditReport.Fields(
                ("writableSiteFolders", writable.Select(site => site.Name).ToArray()),
                ("unreadableSiteFolders", unreadable.Select(site => site.Name).ToArray()))));
    }

    // =============================================================================================
    //  AUDIT-006 - a site that answers any host name and serves other sites' folders
    // =============================================================================================

    private void CheckCatchAllSites(AuditReport report)
    {
        var found = false;

        foreach (var site in _facts.Sites)
        {
            if (!AnswersAnyHostName(site))
            {
                continue;
            }

            var contained = _facts.Sites
                .Where(other => !ReferenceEquals(other, site) && AuditPrimitives.IsInside(site.PhysicalPath, other.PhysicalPath))
                .ToArray();

            if (contained.Length == 0)
            {
                continue;
            }

            found = true;
            var running = string.Equals(site.State, "Started", StringComparison.OrdinalIgnoreCase);

            report.Add(new AuditFinding(
                $"AUDIT-006.{site.Name}",
                running ? AuditSeverity.Critical : AuditSeverity.Warn,
                $"'{site.Name}' answers any host name, and its folder contains {contained.Length} other site(s)",
                (running
                    ? "Any request to this server's address reaches this site, and every file below its folder is reachable through it - including the folders of the sites listed. Stopping one of those sites does not take its files off the internet while this one runs."
                    : "This site is stopped, so nothing is reachable through it today. The moment it starts, every file below its folder - including the folders of the sites listed - is reachable at this server's address.") +
                $" Its folder is {site.PhysicalPath}.",
                "Give this site a folder of its own that contains no other site, or remove its binding that has no host name. By hand.",
                [.. contained.Select(other => $"{other.Name}  ({other.PhysicalPath})")],
                AuditReport.Fields(
                    ("site", site.Name),
                    ("state", site.State),
                    ("containedSites", contained.Select(other => other.Name).ToArray()))));
        }

        if (!found)
        {
            report.Add(new AuditFinding(
                "AUDIT-006", AuditSeverity.Pass, "No site that answers any host name contains another site's folder"));
        }
    }

    /// <summary>
    /// An HTTP or HTTPS binding with no host name: the site that answers requests addressed to the
    /// server's IP, or to any name that no other binding claims.
    /// </summary>
    private static bool AnswersAnyHostName(AuditSite site) =>
        site.Bindings.Any(binding =>
            (string.Equals(binding.Protocol, "http", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase)) &&
            string.IsNullOrEmpty(binding.HostHeader) &&
            !binding.IsLoopback);

    private static bool IsIdentity(AuditPool pool, string identity) =>
        string.Equals(pool.IdentityType, identity, StringComparison.OrdinalIgnoreCase);

    private static string Describe(AuditPool pool) =>
        IsIdentity(pool, "SpecificUser") ? $"{pool.UserName}, a local administrator" : pool.IdentityType;

    private string SitesOf(string pool)
    {
        var names = _facts.Sites
            .Where(site => string.Equals(site.ApplicationPool, pool, StringComparison.OrdinalIgnoreCase))
            .Select(site => site.Name)
            .ToArray();

        return names.Length switch
        {
            0 => "no site's root application",
            <= 3 => string.Join(", ", names),
            _ => $"{string.Join(", ", names.Take(3))} and {names.Length - 3} more"
        };
    }
}

using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Web.Administration;
using WPShield.Cli.Preflight;

namespace WPShield.Cli.Audit;

/// <summary>
/// Everything the audit reads about this server, as plain data.
/// </summary>
/// <remarks>
/// A snapshot rather than an interface of live queries, so that every check in
/// <see cref="AuditRunner"/> is a pure function of values a test can state. Nothing here writes, and
/// nothing here reads a password: for a pool that runs as a named account the account name is read
/// and the password stored beside it in the IIS configuration is not.
/// </remarks>
internal sealed record AuditFacts(
    bool IsElevated,
    bool IisReadable,
    string? IisUnreadableReason,
    IReadOnlyList<AuditPool> Pools,
    IReadOnlyList<AuditSite> Sites,
    IReadOnlyList<AuditHandler> ServerHandlers);

/// <param name="IdentityType">
/// As IIS names it: <c>ApplicationPoolIdentity</c>, <c>LocalSystem</c>, <c>LocalService</c>,
/// <c>NetworkService</c> or <c>SpecificUser</c>.
/// </param>
/// <param name="UserName">The account, for <c>SpecificUser</c> only.</param>
/// <param name="RunsAsLocalAdministrator">
/// Whether that account is a direct member of the local Administrators group, or
/// <see langword="null"/> when it could not be resolved. Unknown is not "no".
/// </param>
internal sealed record AuditPool(
    string Name,
    string State,
    string IdentityType,
    string? UserName,
    bool? RunsAsLocalAdministrator);

/// <param name="ExecutesPhp">
/// Whether a PHP handler is in the site's effective configuration, or <see langword="null"/> when that
/// could not be read.
/// </param>
internal sealed record AuditSite(
    string Name,
    string State,
    string PhysicalPath,
    string ApplicationPool,
    IReadOnlyList<IisBinding> Bindings,
    bool LooksLikeWordPress,
    bool? ExecutesPhp,
    FolderAccess Root);

/// <param name="BroadWriters">
/// The broad groups - Everyone, Users, Authenticated Users, IIS_IUSRS - that can create or change
/// files in this folder or below it, each as <c>NAME (SID)</c>.
/// </param>
/// <param name="Problem">Why the permissions could not be read, when they could not.</param>
internal sealed record FolderAccess(bool Exists, IReadOnlyList<string> BroadWriters, string? Problem = null);

internal sealed record AuditHandler(string Name, string Path, string ScriptProcessor);

/// <summary>
/// The decisions the audit makes about raw values, kept apart from the reader so a test can reach
/// them without IIS.
/// </summary>
internal static class AuditPrimitives
{
    private const int GenericAll = 0x10000000;
    private const int GenericWrite = 0x40000000;

    /// <summary>
    /// Whether an access mask lets its holder put a file where it was not.
    /// </summary>
    /// <remarks>
    /// Creating files or folders is the harm, so <c>WriteData</c> and <c>AppendData</c> count.
    /// <c>ChangePermissions</c> and <c>TakeOwnership</c> count too, because either lets the holder
    /// grant itself the first two. The generic bits are checked as raw values: they appear in
    /// inherit-only entries and have no name in <see cref="FileSystemRights"/>.
    /// </remarks>
    public static bool GrantsWrite(FileSystemRights rights)
    {
        const int named = (int)(FileSystemRights.WriteData | FileSystemRights.AppendData |
                                FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership);

        return ((int)rights & (named | GenericAll | GenericWrite)) != 0;
    }

    /// <summary>Whether a handler mapping runs PHP.</summary>
    public static bool IsPhpHandler(AuditHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);

        return handler.Path.Contains(".php", StringComparison.OrdinalIgnoreCase) ||
               handler.ScriptProcessor.EndsWith("php-cgi.exe", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Whether <paramref name="child"/> is a folder strictly below <paramref name="parent"/>.
    /// </summary>
    /// <remarks>
    /// Compared with a trailing separator on both sides, so that <c>C:\inetpub\wwwroot2</c> is not
    /// taken to be inside <c>C:\inetpub\wwwroot</c>. Case-insensitive, because NTFS is.
    /// </remarks>
    public static bool IsInside(string parent, string child)
    {
        if (string.IsNullOrWhiteSpace(parent) || string.IsNullOrWhiteSpace(child))
        {
            return false;
        }

        var outer = WithTrailingSeparator(parent);
        var inner = WithTrailingSeparator(child);

        return inner.Length > outer.Length && inner.StartsWith(outer, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The form of a pool's account name that <see cref="NTAccount"/> can resolve. IIS accepts
    /// <c>.\name</c> for a local account; the translation API does not.
    /// </summary>
    public static string NormalizeAccountName(string userName, string machineName)
    {
        ArgumentNullException.ThrowIfNull(userName);

        var trimmed = userName.Trim();
        return trimmed.StartsWith(@".\", StringComparison.Ordinal) ? machineName + trimmed[1..] : trimmed;
    }

    private static string WithTrailingSeparator(string path)
    {
        var full = Path.GetFullPath(path.Trim());
        return full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
    }
}

// =================================================================================================
//  The real reader. Everything below reads.
// =================================================================================================

internal static class AuditFactsReader
{
    public static AuditFacts Read()
    {
        var elevated = ReadElevation();

        try
        {
            using var manager = new ServerManager();

            var administrators = LocalAdministrators.ReadMemberSids();

            return new AuditFacts(
                elevated,
                IisReadable: true,
                IisUnreadableReason: null,
                Pools: [.. manager.ApplicationPools.Select(pool => ReadPool(pool, administrators))],
                Sites: [.. manager.Sites.Select(site => ReadSite(manager, site))],
                ServerHandlers: ReadServerHandlers(manager));
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException or COMException or FileNotFoundException
                or InvalidOperationException or TypeInitializationException or DllNotFoundException)
        {
            return new AuditFacts(elevated, false, exception.Message, [], [], []);
        }
    }

    private static AuditPool ReadPool(ApplicationPool pool, IReadOnlySet<string>? administrators)
    {
        var state = "Unknown";
        try
        {
            state = pool.State.ToString();
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException)
        {
        }

        var model = pool.ProcessModel;
        var identity = model.IdentityType;

        if (identity != ProcessModelIdentityType.SpecificUser)
        {
            return new AuditPool(pool.Name, state, identity.ToString(), null, null);
        }

        // The account name only. The password attribute beside it is never touched.
        var userName = model.UserName;
        bool? administrator = null;

        if (administrators is not null && !string.IsNullOrWhiteSpace(userName))
        {
            var sid = ResolveSid(userName);
            if (sid is not null)
            {
                administrator = administrators.Contains(sid);
            }
        }

        return new AuditPool(pool.Name, state, identity.ToString(), userName, administrator);
    }

    private static string? ResolveSid(string userName)
    {
        try
        {
            var name = AuditPrimitives.NormalizeAccountName(userName, Environment.MachineName);
            return new NTAccount(name).Translate(typeof(SecurityIdentifier)).Value;
        }
        catch (Exception exception) when (exception is IdentityNotMappedException or SystemException)
        {
            return null;
        }
    }

    private static List<AuditHandler> ReadServerHandlers(ServerManager manager)
    {
        try
        {
            var handlers = manager.GetApplicationHostConfiguration()
                .GetSection("system.webServer/handlers")
                .GetCollection();

            return [.. handlers.Select(ReadHandler)];
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException or FileNotFoundException)
        {
            return [];
        }
    }

    private static AuditHandler ReadHandler(ConfigurationElement element)
    {
        return new AuditHandler(
            element["name"] as string ?? string.Empty,
            element["path"] as string ?? string.Empty,
            element["scriptProcessor"] as string ?? string.Empty);
    }

    private static AuditSite ReadSite(ServerManager manager, Site site)
    {
        var physicalPath = string.Empty;
        var applicationPool = string.Empty;
        try
        {
            var root = site.Applications["/"];
            applicationPool = root?.ApplicationPoolName ?? string.Empty;

            var raw = root?.VirtualDirectories["/"]?.PhysicalPath;
            if (!string.IsNullOrWhiteSpace(raw))
            {
                physicalPath = Environment.ExpandEnvironmentVariables(raw);
            }
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException)
        {
        }

        var state = "Unknown";
        try
        {
            state = site.State.ToString();
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException)
        {
            // A site whose application pool is missing throws rather than reporting a state.
        }

        var looksLikeWordPress =
            !string.IsNullOrWhiteSpace(physicalPath) &&
            (File.Exists(Path.Combine(physicalPath, "wp-config.php")) ||
             File.Exists(Path.Combine(physicalPath, "wp-includes", "version.php")));

        return new AuditSite(
            site.Name,
            state,
            physicalPath,
            applicationPool,
            [.. site.Bindings.Select(binding => new IisBinding(binding.Protocol, binding.BindingInformation))],
            looksLikeWordPress,
            ReadExecutesPhp(manager, site.Name),
            DescribeFolder(physicalPath));
    }

    /// <summary>
    /// Whether PHP runs in this site, read from its effective configuration: the server-level mapping
    /// it inherits and whatever its own <c>web.config</c> adds or removes.
    /// </summary>
    private static bool? ReadExecutesPhp(ServerManager manager, string siteName)
    {
        try
        {
            return manager.GetWebConfiguration(siteName)
                .GetSection("system.webServer/handlers")
                .GetCollection()
                .Select(ReadHandler)
                .Any(AuditPrimitives.IsPhpHandler);
        }
        catch (Exception exception) when (
            exception is COMException or InvalidOperationException or FileNotFoundException or UnauthorizedAccessException)
        {
            // A web.config that cannot be parsed. Unknown, which the audit reports as unknown.
            return null;
        }
    }

    /// <summary>
    /// Which broad groups can write into a folder. By SID, never by name.
    /// </summary>
    /// <remarks>
    /// Inherit-only entries are counted: they grant write on everything below the folder, which is
    /// where a dropped file lands. A deny entry for the same group removes it, which is coarse - it
    /// does not compare masks - but errs toward reporting less, never toward inventing a writer.
    /// </remarks>
    private static FolderAccess DescribeFolder(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
        {
            return new FolderAccess(false, []);
        }

        try
        {
            var rules = new DirectoryInfo(path)
                .GetAccessControl()
                .GetAccessRules(true, true, typeof(SecurityIdentifier));

            var writers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var denied = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (FileSystemAccessRule rule in rules)
            {
                var sid = rule.IdentityReference.Value;
                if (!WellKnownSids.BroadGroups.Contains(sid, StringComparer.OrdinalIgnoreCase) ||
                    !AuditPrimitives.GrantsWrite(rule.FileSystemRights))
                {
                    continue;
                }

                (rule.AccessControlType == AccessControlType.Allow ? writers : denied).Add(sid);
            }

            writers.ExceptWith(denied);

            return new FolderAccess(
                true,
                [.. writers.Order(StringComparer.Ordinal).Select(sid => $"{WellKnownSids.Describe(sid)} ({sid})")]);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            return new FolderAccess(true, [], exception.Message);
        }
    }

    private static bool ReadElevation()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}

/// <summary>
/// The direct members of the local Administrators group, as SIDs.
/// </summary>
/// <remarks>
/// <para>
/// The group is found by its well-known SID and then by whatever name this Windows gives it:
/// <c>Administrators</c> is <c>Administradores</c> on a Spanish installation, and asking for the English
/// name there finds nothing. <c>NetLocalGroupGetMembers</c> rather than a directory-services package:
/// one call, no dependency, and it does not fail on a member whose SID no longer resolves.
/// </para>
/// <para>
/// Direct membership only. An account that is an administrator through a nested domain group reads
/// as "not a member" here; the audit's documentation says so.
/// </para>
/// </remarks>
internal static class LocalAdministrators
{
    private const string AdministratorsSid = "S-1-5-32-544";
    private const int MaxPreferredLength = -1;

    public static IReadOnlySet<string>? ReadMemberSids()
    {
        string groupName;
        try
        {
            groupName = new SecurityIdentifier(AdministratorsSid).Translate(typeof(NTAccount)).Value;
        }
        catch (Exception exception) when (exception is IdentityNotMappedException or SystemException)
        {
            return null;
        }

        var separator = groupName.IndexOf('\\', StringComparison.Ordinal);
        if (separator >= 0)
        {
            groupName = groupName[(separator + 1)..];
        }

        var status = NetLocalGroupGetMembers(
            null, groupName, 0, out var buffer, MaxPreferredLength, out var read, out _, IntPtr.Zero);

        if (status != 0)
        {
            return null;
        }

        try
        {
            var members = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var size = Marshal.SizeOf<LocalGroupMembersInfo0>();

            for (var index = 0; index < read; index++)
            {
                var entry = Marshal.PtrToStructure<LocalGroupMembersInfo0>(buffer + (index * size));
                members.Add(new SecurityIdentifier(entry.Sid).Value);
            }

            return members;
        }
        finally
        {
            _ = NetApiBufferFree(buffer);
        }
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int NetLocalGroupGetMembers(
        string? serverName,
        string localGroupName,
        int level,
        out IntPtr buffer,
        int preferredMaximumLength,
        out int entriesRead,
        out int totalEntries,
        IntPtr resumeHandle);

    [DllImport("netapi32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int NetApiBufferFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential)]
    private struct LocalGroupMembersInfo0
    {
        public IntPtr Sid;
    }
}

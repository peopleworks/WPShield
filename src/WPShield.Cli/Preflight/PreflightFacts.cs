using System.Globalization;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Web.Administration;
using Microsoft.Win32;

namespace WPShield.Cli.Preflight;

/// <summary>
/// Everything the preflight reads about the host, behind an interface.
/// </summary>
/// <remarks>
/// <para>
/// <b>This interface is the point of the migration, not a detail of it.</b> The PowerShell preflight
/// could only be exercised by running it on a server that had IIS, ARR, URL Rewrite and the right
/// failure conditions — which meant in practice it was exercised once, on production, and
/// <c>PRE-018</c> shipped unable to match the one rule it existed to find. Behind an interface, every
/// check below is a pure function of facts a test can state.
/// </para>
/// <para>
/// Nothing here writes. The real implementations open the registry read-only, ask the service control
/// manager for a status, read a directory's ACL and read the IIS configuration — and the IIS reader
/// is <see cref="ServerManager"/>, which is the supported managed API rather than a parse of
/// <c>applicationHost.config</c> or a shell-out to <c>appcmd</c>.
/// </para>
/// </remarks>
internal interface IHostFacts
{
    bool IsElevated { get; }
    string OperatingSystem { get; }
    string RuntimeDescription { get; }
    IReadOnlyList<string> AspNetCoreRuntimes { get; }
    bool UrlRewriteInstalled { get; }
    bool ApplicationRequestRoutingInstalled { get; }

    /// <summary>The W3SVC status, or <see langword="null"/> when IIS is not installed at all.</summary>
    string? WebServerServiceState { get; }

    /// <summary>The WPShield service, or <see langword="null"/> when none is registered.</summary>
    InstalledService? WPShieldService { get; }

    IReadOnlyList<int> ListeningPorts { get; }

    /// <summary>Which processes hold a port, best effort. Empty when nothing does or nothing could be read.</summary>
    IReadOnlyList<string> PortOwners(int port);

    DirectoryFacts DescribeDirectory(string path);

    bool FileExists(string path);
    IReadOnlyList<string> ChildDirectories(string path);
}

internal sealed record InstalledService(string State, string? Account, string? ImagePath);

/// <summary>
/// A directory as the preflight cares about it: does it exist, and can an unprivileged account read
/// it. <see cref="BroadAccess"/> holds the identities that make <c>PRE-016</c> a blocker.
/// </summary>
internal sealed record DirectoryFacts(bool Exists, IReadOnlyList<string> BroadAccess, string? Problem = null);

/// <summary>What the preflight reads about IIS.</summary>
internal interface IIisFacts
{
    bool Readable { get; }
    string? UnreadableReason { get; }
    bool? ArrProxyEnabled { get; }
    bool? ArrPreserveHostHeader { get; }
    IReadOnlyList<IisSite> Sites { get; }
}

internal sealed record IisSite(
    string Name,
    string State,
    string PhysicalPath,
    IReadOnlyList<IisBinding> Bindings,
    IReadOnlyList<IisRewriteRule> RewriteRules);

/// <param name="BindingInformation">The raw <c>address:port:hostname</c> triple, as IIS stores it.</param>
internal sealed record IisBinding(string Protocol, string BindingInformation)
{
    public string Address => Parts.Length > 0 ? Parts[0] : string.Empty;

    public int Port =>
        Parts.Length > 1 && int.TryParse(Parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            ? port
            : 0;

    /// <summary>The host header. Joined back with ':' because an IPv6 literal contains them.</summary>
    public string HostHeader => Parts.Length > 2 ? string.Join(':', Parts[2..]) : string.Empty;

    public bool IsLoopback => Address is "127.0.0.1" or "::1";

    private string[] Parts => field ??= BindingInformation.Split(':');
}

internal sealed record IisRewriteRule(
    string Name,
    string MatchUrl,
    string ActionType,
    string ActionUrl,
    bool StopProcessing);

// =================================================================================================
//  The real implementations. Everything below reads.
// =================================================================================================

internal sealed class HostFacts : IHostFacts
{
    private const string ServiceName = "WPShield";

    public bool IsElevated { get; } = ReadElevation();

    public string OperatingSystem { get; } = RuntimeInformation.OSDescription;

    public string RuntimeDescription { get; } = RuntimeInformation.FrameworkDescription;

    public IReadOnlyList<string> AspNetCoreRuntimes { get; } = ReadAspNetCoreRuntimes();

    public bool UrlRewriteInstalled { get; } = File.Exists(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "inetsrv", "rewrite.dll"));

    public bool ApplicationRequestRoutingInstalled { get; } = ReadArrInstalled();

    public string? WebServerServiceState { get; } = ReadServiceState("W3SVC")?.State;

    public InstalledService? WPShieldService { get; } = ReadServiceState(ServiceName);

    public IReadOnlyList<int> ListeningPorts { get; } = ReadListeningPorts();

    public IReadOnlyList<string> PortOwners(int port)
    {
        // Deliberately not implemented by walking every process's connections: that needs elevation
        // beyond what this tool asks for and would make an unelevated run look worse than it is. The
        // PowerShell version reported "System" for an IIS binding, which told an operator nothing
        // they could act on. A port is in use or it is not.
        return [];
    }

    public DirectoryFacts DescribeDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
        {
            return new DirectoryFacts(false, []);
        }

        try
        {
            var rules = new DirectoryInfo(path)
                .GetAccessControl()
                .GetAccessRules(true, true, typeof(SecurityIdentifier));

            var broad = new List<string>();

            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow)
                {
                    continue;
                }

                var sid = rule.IdentityReference.Value;
                if (WellKnownSids.BroadGroups.Contains(sid, StringComparer.OrdinalIgnoreCase))
                {
                    broad.Add($"{WellKnownSids.Describe(sid)} ({sid})");
                }
            }

            return new DirectoryFacts(
                true,
                [.. broad.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal)]);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            return new DirectoryFacts(true, [], exception.Message);
        }
    }

    public bool FileExists(string path) => !string.IsNullOrWhiteSpace(path) && File.Exists(path);

    public IReadOnlyList<string> ChildDirectories(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
        {
            return [];
        }

        try
        {
            return Directory.GetDirectories(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static bool ReadElevation()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static IReadOnlyList<string> ReadAspNetCoreRuntimes()
    {
        var shared = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "dotnet", "shared", "Microsoft.AspNetCore.App");

        if (!Directory.Exists(shared))
        {
            return [];
        }

        try
        {
            return [.. Directory.GetDirectories(shared)
                .Select(Path.GetFileName)
                .Where(name => !string.IsNullOrEmpty(name))
                .Select(name => name!)
                .Order(StringComparer.Ordinal)];
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static bool ReadArrInstalled()
    {
        foreach (var folder in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
        {
            var root = Environment.GetFolderPath(folder);
            if (string.IsNullOrWhiteSpace(root))
            {
                continue;
            }

            if (Directory.Exists(Path.Combine(root, "IIS", "Application Request Routing")))
            {
                return true;
            }
        }

        return false;
    }

    private static InstalledService? ReadServiceState(string name)
    {
        string state;
        try
        {
            using var controller = new ServiceController(name);
            state = controller.Status.ToString();
        }
        catch (InvalidOperationException)
        {
            return null;
        }

        // The account lives in the registry; ServiceController does not expose it, and the account is
        // the field that mattered - an install that threw partway left the gateway on LocalSystem.
        string? account = null;
        string? imagePath = null;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{name}", writable: false);

            account = key?.GetValue("ObjectName") as string;
            imagePath = key?.GetValue("ImagePath") as string;
        }
        catch (Exception exception) when (
            exception is System.Security.SecurityException or UnauthorizedAccessException)
        {
        }

        return new InstalledService(state, account, imagePath);
    }

    private static IReadOnlyList<int> ReadListeningPorts()
    {
        try
        {
            return [.. IPGlobalProperties.GetIPGlobalProperties()
                .GetActiveTcpListeners()
                .Select(endpoint => endpoint.Port)
                .Distinct()
                .Order()];
        }
        catch (NetworkInformationException)
        {
            return [];
        }
    }
}

internal static class WellKnownSids
{
    /// <summary>
    /// Granted by SID rather than matched by name. <c>BUILTIN\Administrators</c> is
    /// <c>BUILTIN\Administradores</c> on a Spanish Windows, and a check that compares names silently
    /// finds nothing there.
    /// </summary>
    public static readonly string[] BroadGroups =
    [
        "S-1-5-32-545", // BUILTIN\Users
        "S-1-1-0",      // Everyone
        "S-1-5-11",     // NT AUTHORITY\Authenticated Users
        "S-1-5-32-568"  // BUILTIN\IIS_IUSRS
    ];

    public static string Describe(string sid)
    {
        try
        {
            return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;
        }
        catch (Exception exception) when (exception is IdentityNotMappedException or SystemException)
        {
            return "unresolved";
        }
    }
}

internal sealed class IisFacts : IIisFacts
{
    private IisFacts()
    {
    }

    public bool Readable { get; private init; }
    public string? UnreadableReason { get; private init; }
    public bool? ArrProxyEnabled { get; private init; }
    public bool? ArrPreserveHostHeader { get; private init; }
    public IReadOnlyList<IisSite> Sites { get; private init; } = [];

    public static IisFacts Read()
    {
        try
        {
            using var manager = new ServerManager();

            bool? proxyEnabled = null;
            bool? preserveHost = null;

            try
            {
                var proxy = manager.GetApplicationHostConfiguration().GetSection("system.webServer/proxy");
                proxyEnabled = proxy["enabled"] as bool?;
                preserveHost = proxy["preserveHostHeader"] as bool?;
            }
            catch (Exception exception) when (exception is COMException or FileNotFoundException or InvalidOperationException)
            {
                // ARR not installed, so the section does not exist. PRE-006 reports that; leaving
                // these null is what lets PRE-007 and PRE-008 say "could not be read" rather than
                // inventing a false.
            }

            return new IisFacts
            {
                Readable = true,
                ArrProxyEnabled = proxyEnabled,
                ArrPreserveHostHeader = preserveHost,
                Sites = [.. manager.Sites.Select(ReadSite)]
            };
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException or COMException or FileNotFoundException
                or InvalidOperationException or TypeInitializationException or DllNotFoundException)
        {
            return new IisFacts { Readable = false, UnreadableReason = exception.Message };
        }
    }

    private static IisSite ReadSite(Site site)
    {
        var physicalPath = string.Empty;
        try
        {
            var raw = site.Applications["/"]?.VirtualDirectories["/"]?.PhysicalPath;
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

        return new IisSite(
            site.Name,
            state,
            physicalPath,
            [.. site.Bindings.Select(binding => new IisBinding(binding.Protocol, binding.BindingInformation))],
            ReadRules(site));
    }

    private static IReadOnlyList<IisRewriteRule> ReadRules(Site site)
    {
        try
        {
            var config = site.GetWebConfiguration();
            var rules = config.GetSection("system.webServer/rewrite/rules").GetCollection();

            return
            [
                .. rules.Select(rule => new IisRewriteRule(
                    rule["name"] as string ?? string.Empty,
                    rule.GetChildElement("match")["url"] as string ?? string.Empty,
                    rule.GetChildElement("action")["type"]?.ToString() ?? string.Empty,
                    rule.GetChildElement("action")["url"] as string ?? string.Empty,
                    rule["stopProcessing"] as bool? ?? false))
            ];
        }
        catch (Exception exception) when (
            exception is COMException or InvalidOperationException or UnauthorizedAccessException
                or FileNotFoundException)
        {
            // A site whose web.config cannot be read reports no rules rather than failing the run.
            // PRE-013 says how many it found, so zero here reads as "none visible".
            return [];
        }
    }
}

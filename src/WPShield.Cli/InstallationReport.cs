using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.Json;
using Microsoft.Win32;

namespace WPShield.Cli;

/// <summary>
/// What is installed on this machine, gathered by reading and nothing else.
/// </summary>
/// <remarks>
/// <para>
/// Every question here was asked by hand, one command at a time, during the first real deployment:
/// which account is the service running under, did the directories actually get locked down, where
/// does the configuration say the log goes, and is anything in it. Assembling that from four
/// separate commands is how a half-finished install went unnoticed for a day.
/// </para>
/// <para>
/// <b>Reads only.</b> No service is started or stopped, no file is written, no ACL is changed. The
/// verb that reports the state of an installation must never be the verb that alters it.
/// </para>
/// </remarks>
internal sealed class InstallationReport
{
    /// <summary>
    /// The one place the service name is written. Every lookup below names this rather than a
    /// literal, for the same reason the installer does: a tool that can be pointed at an arbitrary
    /// service on a host running sixty-six applications is a different and much worse tool.
    /// </summary>
    public const string ServiceName = "WPShield";

    /// <summary>The virtual account an installation is supposed to end up running as.</summary>
    public const string ExpectedAccount = @"NT SERVICE\WPShield";

    /// <summary>Groups whose read access to an evidence log is the condition PRE-016 refuses.</summary>
    private static readonly string[] BroadGroupSids =
    [
        "S-1-5-32-545", // BUILTIN\Users
        "S-1-1-0",      // Everyone
        "S-1-5-11",     // NT AUTHORITY\Authenticated Users
        "S-1-5-32-568"  // BUILTIN\IIS_IUSRS
    ];

    public bool ServiceInstalled { get; init; }
    public string? ServiceState { get; init; }
    public string? ServiceAccount { get; init; }
    public string? InstallDirectory { get; init; }
    public string? ConfiguredLogDirectory { get; init; }
    public string? ConfiguredUrls { get; init; }
    public bool OperatorConfigurationPresent { get; init; }
    public string? NewestLogFile { get; init; }
    public DateTimeOffset? NewestLogWritten { get; init; }
    public IReadOnlyList<string> LogDirectoryBroadAccess { get; init; } = [];
    public IReadOnlyList<string> Problems { get; init; } = [];

    public static InstallationReport Gather()
    {
        var problems = new List<string>();

        var (installed, state) = ReadServiceState();
        var (imagePath, account) = ReadServiceRegistration();
        var installDirectory = imagePath is null ? null : SafeDirectoryName(imagePath);

        string? logDirectory = null;
        string? urls = null;
        var operatorConfiguration = false;

        if (installDirectory is not null)
        {
            var settings = Path.Combine(installDirectory, "appsettings.json");
            var overlay = Path.Combine(installDirectory, "appsettings.Local.json");
            operatorConfiguration = File.Exists(overlay);

            // The overlay wins at runtime, so it wins here. Reading only the shipped file would
            // report a directory the gateway does not use, which is the exact class of mistake this
            // verb exists to catch.
            foreach (var file in new[] { settings, overlay })
            {
                var read = ReadGatewaySettings(file, problems);
                logDirectory = read.LogDirectory ?? logDirectory;
                urls = read.Urls ?? urls;
            }
        }

        string? newestLog = null;
        DateTimeOffset? newestWritten = null;
        IReadOnlyList<string> broadAccess = [];

        if (logDirectory is not null && Directory.Exists(logDirectory))
        {
            try
            {
                var newest = new DirectoryInfo(logDirectory)
                    .GetFiles("*.jsonl")
                    .OrderByDescending(file => file.LastWriteTimeUtc)
                    .FirstOrDefault();

                if (newest is not null)
                {
                    newestLog = newest.Name;
                    newestWritten = new DateTimeOffset(newest.LastWriteTimeUtc, TimeSpan.Zero);
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                problems.Add($"The log directory could not be listed: {exception.Message}");
            }

            broadAccess = ReadBroadAccess(logDirectory, problems);
        }

        return new InstallationReport
        {
            ServiceInstalled = installed,
            ServiceState = state,
            ServiceAccount = account,
            InstallDirectory = installDirectory,
            ConfiguredLogDirectory = logDirectory,
            ConfiguredUrls = urls,
            OperatorConfigurationPresent = operatorConfiguration,
            NewestLogFile = newestLog,
            NewestLogWritten = newestWritten,
            LogDirectoryBroadAccess = broadAccess,
            Problems = problems
        };
    }

    private static (bool Installed, string? State) ReadServiceState()
    {
        try
        {
            using var controller = new ServiceController(ServiceName);
            return (true, controller.Status.ToString());
        }
        catch (InvalidOperationException)
        {
            // The only way ServiceController reports "no such service".
            return (false, null);
        }
    }

    /// <summary>
    /// Reads the registration from the registry rather than through a management query.
    /// </summary>
    /// <remarks>
    /// <c>ServiceController</c> exposes the status and not the account, and the account is the field
    /// that mattered: an install that threw partway left the gateway running as <c>LocalSystem</c>
    /// while every summary it had printed said otherwise.
    /// </remarks>
    private static (string? ImagePath, string? Account) ReadServiceRegistration()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{ServiceName}", writable: false);

            if (key is null)
            {
                return (null, null);
            }

            var imagePath = key.GetValue("ImagePath") as string;
            var account = key.GetValue("ObjectName") as string;
            return (Unquote(imagePath), account);
        }
        catch (Exception exception) when (exception is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return (null, null);
        }
    }

    private static (string? LogDirectory, string? Urls) ReadGatewaySettings(string file, List<string> problems)
    {
        if (!File.Exists(file))
        {
            return (null, null);
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllBytes(file));
            var root = document.RootElement;

            string? logDirectory = null;
            if (root.TryGetProperty("Logging", out var logging) &&
                logging.TryGetProperty("File", out var fileSection) &&
                fileSection.TryGetProperty("Directory", out var directory) &&
                directory.ValueKind == JsonValueKind.String)
            {
                logDirectory = directory.GetString();
            }

            string? urls = null;
            if (root.TryGetProperty("Gateway", out var gateway) &&
                gateway.TryGetProperty("Urls", out var urlArray) &&
                urlArray.ValueKind == JsonValueKind.Array)
            {
                var values = urlArray.EnumerateArray()
                    .Where(element => element.ValueKind == JsonValueKind.String)
                    .Select(element => element.GetString()!)
                    .ToArray();

                if (values.Length > 0)
                {
                    urls = string.Join(", ", values);
                }
            }

            return (logDirectory, urls);
        }
        catch (JsonException exception)
        {
            problems.Add($"{Path.GetFileName(file)} is not valid JSON: {exception.Message}");
            return (null, null);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            problems.Add($"{Path.GetFileName(file)} could not be read: {exception.Message}");
            return (null, null);
        }
    }

    private static IReadOnlyList<string> ReadBroadAccess(string directory, List<string> problems)
    {
        try
        {
            var rules = new DirectoryInfo(directory)
                .GetAccessControl()
                .GetAccessRules(true, true, typeof(SecurityIdentifier));

            var found = new List<string>();

            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow)
                {
                    continue;
                }

                var sid = rule.IdentityReference.Value;
                if (!BroadGroupSids.Contains(sid, StringComparer.OrdinalIgnoreCase))
                {
                    continue;
                }

                // Reported by SID and by name. The SID is what the comparison used, and the name is
                // what an operator recognises - and on a Spanish Windows the two do not look alike.
                found.Add($"{DescribeSid(sid)} ({sid})");
            }

            return found.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal).ToArray();
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            problems.Add($"The log directory permissions could not be read: {exception.Message}");
            return [];
        }
    }

    private static string DescribeSid(string sid)
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

    private static string? Unquote(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        if (trimmed.StartsWith('"'))
        {
            var end = trimmed.IndexOf('"', 1);
            if (end > 1)
            {
                return trimmed[1..end];
            }
        }

        // An unquoted ImagePath ends at the first space, which is also how the service control
        // manager reads it.
        var space = trimmed.IndexOf(' ');
        return space > 0 ? trimmed[..space] : trimmed;
    }

    private static string? SafeDirectoryName(string path)
    {
        try
        {
            return Path.GetDirectoryName(path);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    public static string FormatTimestamp(DateTimeOffset value)
    {
        return value.ToString("u", CultureInfo.InvariantCulture);
    }
}

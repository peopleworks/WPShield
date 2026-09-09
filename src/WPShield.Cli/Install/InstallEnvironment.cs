using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using WPShield.Cli.Preflight;

namespace WPShield.Cli.Install;

/// <summary>
/// Every side effect the installer has, behind an interface.
/// </summary>
/// <remarks>
/// <para>
/// <b>The order of these calls is the thing that broke.</b> An install threw between registering the
/// service and restricting the directories, and what was left was the gateway running as
/// <c>LocalSystem</c> with an evidence log readable by every account on a sixty-six-site server —
/// while every summary it had printed said otherwise. Behind an interface, a test can assert the
/// order, assert that a dry run performs none of it, and assert that the web-root refusal happens
/// before the first mutation.
/// </para>
/// <para>
/// The PowerShell installer could be checked for those properties only by reading it.
/// </para>
/// </remarks>
internal interface IInstallEnvironment
{
    bool IsElevated { get; }

    bool DirectoryExists(string path);
    bool FileExists(string path);
    IReadOnlyList<string> ChildDirectories(string path);

    void CreateDirectory(string path);
    void CopyTree(string source, string destination);
    void CopyFile(string source, string destination);
    int CountFiles(string path);
    void DeleteDirectory(string path);

    /// <summary>Writes <c>Logging:File:Directory</c> into the installed configuration.</summary>
    void SetLogDirectory(string settingsFile, string logDirectory);

    void HardenDirectory(string path, FileSystemRights serviceRights, SecurityIdentifier serviceSid);
    IReadOnlyList<string> BroadAccess(string path);

    InstalledService? QueryService(string name);
    void StopService(string name);
    void CreateService(string name, string binaryPath, string displayName, string description);
    void DeleteService(string name);
    void SetServiceBinaryPath(string name, string binaryPath);
    void EnableServiceSid(string name);
    void SetServiceIdentity(string name, string account);
    void ConfigureServiceRecovery(string name);
    void StartService(string name);
    SecurityIdentifier ResolveServiceSid(string name);

    /// <summary>Every directory IIS serves from, for the web-root refusal.</summary>
    IReadOnlyList<string> ServedDirectories();

    /// <summary>
    /// Whether IIS could be read at all, and every WPShield rewrite rule found.
    /// </summary>
    /// <remarks>
    /// Two answers rather than one, because the uninstall guard treats them differently and must:
    /// an empty list from a readable IIS means nothing forwards to the gateway, and an empty list
    /// from an unreadable one means nobody could look. Collapsing them would turn "could not check"
    /// into "checked and fine", which is the shape of the mistake that takes a site down.
    /// </remarks>
    (bool Readable, IReadOnlyList<string> Rules) WPShieldRewriteRules();

    void Report(string line);
}

/// <summary>The real one. Everything here changes the machine.</summary>
internal sealed class InstallEnvironment(TextWriter output) : IInstallEnvironment
{
    private readonly TextWriter _output = output ?? throw new ArgumentNullException(nameof(output));

    public bool IsElevated
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    public bool DirectoryExists(string path) => Directory.Exists(path);

    public bool FileExists(string path) => File.Exists(path);

    public IReadOnlyList<string> ChildDirectories(string path)
    {
        try
        {
            return Directory.Exists(path) ? Directory.GetDirectories(path) : [];
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    public void CreateDirectory(string path) => Directory.CreateDirectory(path);

    public void CopyTree(string source, string destination)
    {
        foreach (var directory in Directory.GetDirectories(source, "*", SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(directory.Replace(source, destination, StringComparison.OrdinalIgnoreCase));
        }

        foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
        {
            File.Copy(file, file.Replace(source, destination, StringComparison.OrdinalIgnoreCase), overwrite: true);
        }
    }

    public void CopyFile(string source, string destination) => File.Copy(source, destination, overwrite: true);

    public int CountFiles(string path) =>
        Directory.Exists(path) ? Directory.GetFiles(path, "*", SearchOption.AllDirectories).Length : 0;

    public void DeleteDirectory(string path) => Directory.Delete(path, recursive: true);

    /// <summary>
    /// Writes the log directory into the configuration the gateway reads.
    /// </summary>
    /// <remarks>
    /// Until this existed the installer created the log directory, removed inheritance, granted the
    /// service account Modify and printed the path — and told the gateway none of it. The gateway
    /// resolved a relative default against its own installation directory, which this same installer
    /// deliberately leaves read-and-execute, so every write failed silently. An installer that hardens
    /// a directory nothing writes to has not hardened anything; it has only said it did.
    /// </remarks>
    public void SetLogDirectory(string settingsFile, string logDirectory)
    {
        if (!File.Exists(settingsFile))
        {
            throw new CliArgumentException(
                $"The installed build has no appsettings.json at {settingsFile}, so the log directory cannot be written into it.");
        }

        JsonNode? root;
        try
        {
            root = JsonNode.Parse(File.ReadAllText(settingsFile));
        }
        catch (JsonException exception)
        {
            throw new CliArgumentException($"The installed appsettings.json is not valid JSON: {exception.Message}");
        }

        // Checked rather than created. A build whose configuration has lost this section is not a
        // build to install quietly, and adding the section here would hide that it went missing.
        if (root?["Logging"]?["File"] is not JsonObject fileSection)
        {
            throw new CliArgumentException(
                "The installed appsettings.json has no Logging:File section. This is not a WPShield build this installer understands.");
        }

        fileSection["Directory"] = logDirectory;

        // UTF-8 with no byte order mark. A BOM is invisible in a diff and some readers choke on it.
        File.WriteAllText(
            settingsFile,
            root!.ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    /// <summary>
    /// Replaces a directory's permissions with an explicit, inheritance-free set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Principals by well-known SID, never by name: <c>BUILTIN\Administrators</c> is
    /// <c>BUILTIN\Administradores</c> on a Spanish Windows, and granting by name silently grants
    /// nothing there.
    /// </para>
    /// <para>
    /// <b>The owner is read back and modified, never freshly constructed.</b> A new
    /// <see cref="DirectorySecurity"/> carries an empty, unprotected DACL, and writing one over the
    /// descriptor silently undoes the permissions applied moments earlier — which is what the first
    /// version of this did, putting the log directory back to inheriting <c>C:\ProgramData</c> and
    /// its read-for-<c>BUILTIN\Users</c>. It could not fail on an unelevated machine, because setting
    /// the owner threw first; it only ever went wrong where it mattered.
    /// </para>
    /// </remarks>
    public void HardenDirectory(string path, FileSystemRights serviceRights, SecurityIdentifier serviceSid)
    {
        ArgumentNullException.ThrowIfNull(serviceSid);

        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

        var security = new DirectorySecurity();

        // true disables inheritance; false DISCARDS the inherited entries rather than copying them.
        // Copying them would keep exactly the broad access this removes.
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        const InheritanceFlags Inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

        security.AddAccessRule(new FileSystemAccessRule(
            administrators, FileSystemRights.FullControl, Inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            localSystem, FileSystemRights.FullControl, Inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            serviceSid, serviceRights, Inherit, PropagationFlags.None, AccessControlType.Allow));

        var info = new DirectoryInfo(path);
        info.SetAccessControl(security);

        // Ownership is defence in depth and is applied separately, because it can fail on its own:
        // it needs a privilege the DACL write does not. Failing here would abort after the files are
        // copied and the service is registered, which is the worst place to stop.
        try
        {
            var descriptor = info.GetAccessControl();
            descriptor.SetOwner(administrators);
            info.SetAccessControl(descriptor);
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException or InvalidOperationException or PrivilegeNotHeldException)
        {
            Report($"note: could not set the owner of {path} to Administrators. The permissions above were applied. {exception.Message}");
        }
    }

    public IReadOnlyList<string> BroadAccess(string path)
    {
        try
        {
            var rules = new DirectoryInfo(path)
                .GetAccessControl()
                .GetAccessRules(true, true, typeof(SecurityIdentifier));

            var found = new List<string>();

            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType == AccessControlType.Allow &&
                    WellKnownSids.BroadGroups.Contains(rule.IdentityReference.Value, StringComparer.OrdinalIgnoreCase))
                {
                    found.Add(rule.IdentityReference.Value);
                }
            }

            return [.. found.Distinct(StringComparer.OrdinalIgnoreCase)];
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    public InstalledService? QueryService(string name)
    {
        try
        {
            using var controller = new ServiceController(name);
            var state = controller.Status.ToString();

            string? account = null;
            string? imagePath = null;

            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{name}", writable: false);

            account = key?.GetValue("ObjectName") as string;
            imagePath = key?.GetValue("ImagePath") as string;

            return new InstalledService(state, account, imagePath);
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    public void StopService(string name)
    {
        using var controller = new ServiceController(name);
        if (controller.Status == ServiceControllerStatus.Stopped)
        {
            return;
        }

        controller.Stop();
        controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
    }

    public void StartService(string name)
    {
        using var controller = new ServiceController(name);
        controller.Start();
        controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
    }

    public void CreateService(string name, string binaryPath, string displayName, string description)
    {
        // binPath= carries the '=' and the value is a separate argument. ArgumentList passes each
        // element as its own argument, which is exactly what Windows PowerShell 5.1 failed to do:
        // it DROPS an empty element, so 'password=' followed by '' arrived at sc.exe with no value
        // and the whole command line was rejected with 1639 - leaving the service on LocalSystem.
        Sc("Creating the service", "create", name, "binPath=", Quote(binaryPath),
            "start=", "auto", "DisplayName=", displayName);

        Sc("Setting the description", "description", name, description);
    }

    public void DeleteService(string name) => Sc("Deleting the service", "delete", name);

    public void SetServiceBinaryPath(string name, string binaryPath) =>
        Sc("Updating the binary path", "config", name, "binPath=", Quote(binaryPath));

    public void EnableServiceSid(string name) => Sc("Enabling the per-service SID", "sidtype", name, "unrestricted");

    /// <summary>
    /// A virtual service account: Windows manages it, it has no password, and it cannot log on.
    /// </summary>
    /// <remarks>
    /// No <c>password=</c> token at all. Passing one with an empty value is what Windows PowerShell
    /// 5.1 silently dropped, and a virtual account has no password to give it.
    /// </remarks>
    public void SetServiceIdentity(string name, string account) =>
        Sc("Setting the service identity", "config", name, "obj=", account);

    public void ConfigureServiceRecovery(string name) =>
        Sc("Configuring recovery actions", "failure", name, "reset=", "86400",
            "actions=", "restart/5000/restart/15000/restart/60000");

    public SecurityIdentifier ResolveServiceSid(string name) =>
        (SecurityIdentifier)new NTAccount($@"NT SERVICE\{name}").Translate(typeof(SecurityIdentifier));

    public (bool Readable, IReadOnlyList<string> Rules) WPShieldRewriteRules()
    {
        var iis = IisFacts.Read();

        if (!iis.Readable)
        {
            return (false, []);
        }

        return (true,
        [
            .. iis.Sites
                .SelectMany(site => site.RewriteRules.Select(rule => (Site: site.Name, rule.Name)))
                .Where(entry => entry.Name.Contains("WPShield", StringComparison.OrdinalIgnoreCase))
                .Select(entry => $"{entry.Site}/{entry.Name}")
        ]);
    }

    public IReadOnlyList<string> ServedDirectories()
    {
        var roots = new List<string>();

        var systemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        if (!string.IsNullOrWhiteSpace(systemDrive))
        {
            roots.Add(Path.Combine(systemDrive, "inetpub"));
        }

        var iis = IisFacts.Read();
        roots.AddRange(iis.Sites.Select(site => site.PhysicalPath).Where(path => !string.IsNullOrWhiteSpace(path)));

        return [.. roots.Distinct(StringComparer.OrdinalIgnoreCase)];
    }

    public void Report(string line) => _output.WriteLine($"  {line}");

    private static string Quote(string value) => $"\"{value}\"";

    private void Sc(string what, params string[] arguments)
    {
        var info = new ProcessStartInfo("sc.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        foreach (var argument in arguments)
        {
            if (string.IsNullOrEmpty(argument))
            {
                // Refused rather than passed. A key with no value is how sc.exe gets a command line
                // it rejects with 1639, and it is the shape that left a gateway on LocalSystem.
                throw new CliArgumentException(
                    $"{what} was built with an empty sc.exe argument. Omit the key instead of passing an empty value for it.");
            }

            info.ArgumentList.Add(argument);
        }

        using var process = Process.Start(info)
            ?? throw new CliArgumentException($"{what} failed: sc.exe could not be started.");

        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            var detail = string.Join(" ", $"{stdout} {stderr}".Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
            throw new CliArgumentException($"{what} failed. sc.exe exited with {process.ExitCode}: {detail}");
        }
    }
}

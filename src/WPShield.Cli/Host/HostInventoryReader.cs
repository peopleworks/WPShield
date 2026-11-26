using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;
using WPShield.Cli.Audit;
using WPShield.Evidence;
using WPShield.SecurityMonitor;

namespace WPShield.Cli.Host;

/// <summary>
/// The host inventory of ADR 0013, section 1.3: local accounts, non-Microsoft services and non-Microsoft
/// scheduled tasks. Read-only. Arguments are reduced to flags and dropped; full names are held in memory for
/// the full-name indicator only; passwords and descriptions are never read.
/// </summary>
internal sealed class HostInventoryReader(Authenticode signatures)
{
    private const string AdministratorsSid = "S-1-5-32-544";
    private const string RemoteDesktopUsersSid = "S-1-5-32-555";
    private const int MaxTaskFolders = 500;

    /// <summary>
    /// Microsoft binaries attackers run their payloads through (<see cref="WPShield.Evidence.ScriptHosts"/>). A service
    /// or task that runs one of these is listed even though its binary is Microsoft's.
    /// </summary>
    internal static IReadOnlySet<string> ScriptHosts => WPShield.Evidence.ScriptHosts.Names;

    public HostInventoryReading Read(string kind, CancellationToken cancellationToken) => kind switch
    {
        HostFacts.Accounts => ReadAccounts(cancellationToken),
        HostFacts.Services => new(ReadServices(cancellationToken)),
        HostFacts.Tasks => new(ReadTasks(cancellationToken)),
        _ => throw new ArgumentException("An inventory kind is accounts, services or tasks.", nameof(kind))
    };

    /// <summary>Listed when not Microsoft's, or when Microsoft's but running something that hides a payload.</summary>
    internal static bool IsQuietMicrosoft(SignatureResult signature, string? executable, IReadOnlyList<string> flags) =>
        signature.Microsoft && signature.Status == HostSignature.Signed &&
        !flags.Contains(CommandFlags.EncodedCommand) && !flags.Contains(CommandFlags.ContainsUrl) &&
        !flags.Contains(CommandFlags.UserWritablePath) &&
        !(executable is not null && ScriptHosts.Contains(SafeFileName(executable)));

    // ---------------------------------------------------------------------------------------------
    //  Accounts
    // ---------------------------------------------------------------------------------------------

    private static HostInventoryReading ReadAccounts(CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var administrators = LocalAdministrators.ReadMemberSids(AdministratorsSid);
        var remoteDesktop = LocalAdministrators.ReadMemberSids(RemoteDesktopUsersSid);
        var accounts = new List<HostAccount>();
        var fullNames = new List<string>();
        var resume = 0;
        int status;
        do
        {
            cancellationToken.ThrowIfCancellationRequested();
            status = NetUserEnum(null, 2, 2 /* FILTER_NORMAL_ACCOUNT */, out var buffer, -1, out var read, out _, ref resume);
            if (status is not (0 or 234 /* ERROR_MORE_DATA */))
            {
                return new(HostFactReading.Failed(HostFacts.Inventory, HostFacts.Accounts, now,
                    status == 5 ? HostFactStatus.NeedsElevation : HostFactStatus.Unreadable, $"netuserenum: {status}",
                    "Run the collector elevated; local accounts are read with NetUserEnum."));
            }
            try
            {
                var size = Marshal.SizeOf<UserInfo2>();
                for (var i = 0; i < read && accounts.Count < HostFacts.MaxInventoryItems; i++)
                {
                    var info = Marshal.PtrToStructure<UserInfo2>(buffer + i * size);
                    var name = Marshal.PtrToStringUni(info.Name) ?? "";
                    if (name.Length == 0) continue;
                    // The full name is read for the indicator and kept in memory only. The password field is never touched.
                    var full = Marshal.PtrToStringUni(info.FullName);
                    if (!string.IsNullOrWhiteSpace(full)) fullNames.Add(full);
                    var sid = Sid(name);
                    accounts.Add(new HostAccount(
                        HostFacts.Clean(name),
                        (info.Flags & 0x2) == 0,
                        sid is null || administrators is null ? null : administrators.Contains(sid),
                        sid is null || remoteDesktop is null ? null : remoteDesktop.Contains(sid),
                        info.LastLogon == 0 ? null : DateTimeOffset.FromUnixTimeSeconds(info.LastLogon),
                        (int)(info.PasswordAge / 86_400),
                        (info.Flags & 0x10000) != 0));
                }
            }
            finally
            {
                NetApiBufferFree(buffer);
            }
        }
        while (status == 234 && accounts.Count < HostFacts.MaxInventoryItems);

        var partial = administrators is null || remoteDesktop is null;
        var value = new HostAccounts(accounts, null, null);
        var reading = partial
            ? HostFactReading.Of(HostFacts.Inventory, HostFacts.Accounts, now, value, HostFactStatus.Partial, "group-membership-unreadable",
                "Administrators and Remote Desktop Users could not be read; membership is shown as unknown. Run the collector elevated.")
            : HostFactReading.Of(HostFacts.Inventory, HostFacts.Accounts, now, value);
        return new(reading, fullNames);
    }

    private static string? Sid(string name)
    {
        try
        {
            return new NTAccount(Environment.MachineName, name).Translate(typeof(SecurityIdentifier)).Value;
        }
        catch (Exception exception) when (exception is IdentityNotMappedException or SystemException)
        {
            return null;
        }
    }

    // ---------------------------------------------------------------------------------------------
    //  Services
    // ---------------------------------------------------------------------------------------------

    private HostFactReading ReadServices(CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var budget = new Authenticode.Budget(HostFacts.MaxSignatureChecks);
        var states = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var controller in ServiceController.GetServices())
            {
                using (controller)
                {
                    try { states[controller.ServiceName] = controller.Status.ToString().ToLowerInvariant(); }
                    catch (InvalidOperationException) { }
                }
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return HostFactReading.Failed(HostFacts.Inventory, HostFacts.Services, now, HostFactStatus.Unreadable, "service-control-manager",
                "The service control manager could not be queried. Run the collector elevated.");
        }

        // State changes and failures from the System log, for the start-loop flags. Unreadable leaves the counts
        // unknown, which adds no flag rather than a guess.
        var serviceEvents = WindowsHostReaders.ReadServiceControlEvents(now, cancellationToken);
        var (changes, failures) = serviceEvents is null
            ? ((IReadOnlyDictionary<string, int>?)null, (IReadOnlyDictionary<string, int>?)null)
            : ServiceStates.Count(serviceEvents, now);

        var services = new List<HostService>();
        using var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (root is null)
            return HostFactReading.Failed(HostFacts.Inventory, HostFacts.Services, now, HostFactStatus.Unreadable, "registry",
                "The services registry key could not be read. Run the collector elevated.");
        var partial = false;
        foreach (var name in root.GetSubKeyNames().Take(4000))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (services.Count >= HostFacts.MaxInventoryItems)
            {
                partial = true;
                break;
            }
            try
            {
                using var key = root.OpenSubKey(name);
                // Win32 services only (own or shared process); drivers are another inventory.
                if (key?.GetValue("Type") is not int type || (type & 0x30) == 0) continue;
                var imagePath = key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                var (executable, flags) = CommandFlags.Inspect(imagePath, null, IsUserWritable);
                // A service hosted in svchost.exe is its ServiceDll; svchost itself says nothing.
                if (executable is not null && SafeFileName(executable).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
                {
                    using var parameters = key.OpenSubKey("Parameters");
                    if ((parameters?.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames)
                            ?? key.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames)) is string dll)
                        executable = HostFacts.Clean(dll);
                }
                var signature = signatures.Check(executable, budget);
                if (IsQuietMicrosoft(signature, executable, flags)) continue;
                var displayName = HostFacts.Clean(key.GetValue("DisplayName") as string ?? name);
                var state = states.GetValueOrDefault(name, "unknown");
                var startMode = StartMode(key.GetValue("Start") as int?);
                var stateFlags = ServiceStates.Flags(state, startMode,
                    changes is null ? null : changes.GetValueOrDefault(displayName),
                    failures is null ? null : failures.GetValueOrDefault(displayName));
                services.Add(new HostService(
                    HostFacts.Clean(name),
                    displayName,
                    state,
                    startMode,
                    HostFacts.Clean(key.GetValue("ObjectName") as string ?? "LocalSystem"),
                    executable,
                    signature.Status,
                    signature.Signer,
                    stateFlags.Count == 0 ? flags : [.. flags, .. stateFlags]));
            }
            catch (Exception exception) when (exception is UnauthorizedAccessException or System.Security.SecurityException or IOException)
            {
                partial = true;
            }
        }
        var value = new HostServices(services, budget.NotChecked);
        return partial || budget.NotChecked > 0
            ? HostFactReading.Of(HostFacts.Inventory, HostFacts.Services, now, value, HostFactStatus.Partial,
                budget.NotChecked > 0 ? "signature-budget" : "some-services-unreadable",
                "Signatures not checked this time are checked on the next snapshot; unreadable services need an elevated collector.")
            : HostFactReading.Of(HostFacts.Inventory, HostFacts.Services, now, value);
    }

    private static string StartMode(int? start) => start switch
    {
        0 => "boot",
        1 => "system",
        2 => "automatic",
        3 => "manual",
        4 => "disabled",
        _ => "unknown"
    };

    // ---------------------------------------------------------------------------------------------
    //  Scheduled tasks
    // ---------------------------------------------------------------------------------------------

    private HostFactReading ReadTasks(CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var budget = new Authenticode.Budget(HostFacts.MaxSignatureChecks);
        var tasks = new List<HostTask>();
        var partial = false;
        try
        {
            var scheduler = ComLateBound.Create("Schedule.Service");
            if (scheduler is null)
                return HostFactReading.Failed(HostFacts.Inventory, HostFacts.Tasks, now, HostFactStatus.Unreadable, "task-scheduler-missing",
                    "The Task Scheduler service could not be reached. Check that it is running.");
            ComLateBound.Invoke(scheduler, "Connect");
            var folders = new Queue<object>();
            folders.Enqueue(ComLateBound.Invoke(scheduler, "GetFolder", "\\")
                ?? throw new InvalidCastException("The Task Scheduler returned no root folder."));
            var visited = 0;
            while (folders.Count > 0 && visited < MaxTaskFolders)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var folder = folders.Dequeue();
                visited++;
                try
                {
                    foreach (var sub in ComLateBound.Items(ComLateBound.Invoke(folder, "GetFolders", 0))) folders.Enqueue(sub);
                    foreach (var task in ComLateBound.Items(ComLateBound.Invoke(folder, "GetTasks", 1 /* include hidden */)))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        if (tasks.Count >= HostFacts.MaxInventoryItems)
                        {
                            partial = true;
                            break;
                        }
                        if (ReadTask(task, budget) is HostTask item) tasks.Add(item);
                    }
                }
                catch (COMException)
                {
                    // A folder this account may not read: the snapshot says so.
                    partial = true;
                }
            }
            if (folders.Count > 0) partial = true;
        }
        catch (COMException exception)
        {
            return HostFactReading.Failed(HostFacts.Inventory, HostFacts.Tasks, now,
                exception.HResult == unchecked((int)0x80070005) ? HostFactStatus.NeedsElevation : HostFactStatus.Unreadable,
                $"task-scheduler: 0x{exception.HResult:X8}", "Run the collector elevated; tasks are read through the Task Scheduler.");
        }
        catch (UnauthorizedAccessException)
        {
            return HostFactReading.Failed(HostFacts.Inventory, HostFacts.Tasks, now, HostFactStatus.NeedsElevation, "access-denied",
                "Run the collector elevated; tasks are read through the Task Scheduler.");
        }
        catch (Exception exception) when (exception is InvalidCastException or MissingMethodException or MissingMemberException)
        {
            return HostFactReading.Failed(HostFacts.Inventory, HostFacts.Tasks, now, HostFactStatus.Unreadable,
                "task-scheduler: " + exception.GetType().Name, "The Task Scheduler answered in an unexpected shape; run 'wpshield host inventory tasks --live' elevated.");
        }

        var value = new HostTasks(tasks, budget.NotChecked);
        return partial || budget.NotChecked > 0
            ? HostFactReading.Of(HostFacts.Inventory, HostFacts.Tasks, now, value, HostFactStatus.Partial,
                budget.NotChecked > 0 ? "signature-budget" : "some-tasks-unreadable",
                "Signatures not checked this time are checked on the next snapshot; folders this account cannot read need an elevated collector.")
            : HostFactReading.Of(HostFacts.Inventory, HostFacts.Tasks, now, value);
    }

    private HostTask? ReadTask(object task, Authenticode.Budget budget)
    {
        var path = ComLateBound.GetString(task, "Path") ?? "";
        var definition = ComLateBound.GetObject(task, "Definition");
        string? executable = null;
        IReadOnlyList<string> flags = [];
        foreach (var action in ComLateBound.Items(ComLateBound.Get(definition, "Actions")))
        {
            // The first program action decides; a task's other actions are rare and counted in its flags.
            if (ComLateBound.GetInt(action, "Type") != 0) continue;
            (executable, flags) = CommandFlags.Inspect(QuoteIfNeeded(ComLateBound.GetString(action, "Path")),
                ComLateBound.GetString(action, "Arguments"), IsUserWritable);
            break;
        }
        var signature = executable is null ? SignatureResult.NotChecked : signatures.Check(executable, budget);
        var underMicrosoft = path.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);
        if (underMicrosoft && (executable is null || IsQuietMicrosoft(signature, executable, flags))) return null;
        var principal = ComLateBound.GetObject(definition, "Principal");
        var runsAs = ComLateBound.GetString(principal, "UserId") ?? ComLateBound.GetString(principal, "GroupId") ?? "";
        return new HostTask(
            HostFacts.Clean(path),
            TaskState(ComLateBound.GetInt(task, "State")),
            HostFacts.Clean(runsAs),
            Time(ComLateBound.GetDate(task, "LastRunTime")),
            Time(ComLateBound.GetDate(task, "NextRunTime")),
            executable,
            signature.Status,
            signature.Signer,
            flags);
    }

    private static string? QuoteIfNeeded(string? path) =>
        path is null ? null : path.Contains(' ', StringComparison.Ordinal) && !path.StartsWith('"') ? $"\"{path}\"" : path;

    private static string TaskState(int state) => state switch
    {
        1 => "disabled",
        2 => "queued",
        3 => "ready",
        4 => "running",
        _ => "unknown"
    };

    private static DateTimeOffset? Time(DateTime? value) =>
        value is { } time && time.Year > 1900 ? new DateTimeOffset(time.ToUniversalTime(), TimeSpan.Zero) : null;

    // ---------------------------------------------------------------------------------------------
    //  Shared
    // ---------------------------------------------------------------------------------------------

    /// <summary>Whether Everyone, Users, Authenticated Users or IIS_IUSRS can write the file or its folder.</summary>
    /// <remarks>
    /// A bare program name (<c>xcopy</c>, <c>sc.exe</c>) is found the way Windows finds it - the system folder, then
    /// the folders of <c>PATH</c> - never in the reader's current folder, which would judge every bare name by the
    /// folder WPShield happened to be started from. A name found nowhere is not judged.
    /// </remarks>
    internal static bool IsUserWritable(string path)
    {
        var expanded = Environment.ExpandEnvironmentVariables(path.Trim('"'));
        if (!Path.IsPathFullyQualified(expanded))
        {
            if (Resolve(expanded) is not { } resolved) return false;
            expanded = resolved;
        }
        var file = new FileInfo(expanded);
        if (file.Exists && Writable(file.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)))) return true;
        var directory = file.Directory;
        return directory is { Exists: true } &&
               Writable(directory.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)));
    }

    /// <summary>The most <c>PATH</c> folders searched for a bare program name.</summary>
    private const int MaxPathFolders = 64;

    /// <summary>
    /// Where Windows would find a bare program name: the system folder, then each folder of <c>PATH</c>, trying the
    /// name as given and with <c>.exe</c>. A relative path with a folder in it is not resolved: there is no folder it
    /// is relative to that the program's caller is known to use.
    /// </summary>
    internal static string? Resolve(string name, string? systemFolder = null, string? pathVariable = null)
    {
        if (string.IsNullOrWhiteSpace(name) || name.IndexOfAny(['\\', '/', ':']) >= 0) return null;
        var candidates = Path.HasExtension(name) ? new[] { name } : [name + ".exe", name];
        var folders = new List<string>();
        var system = systemFolder ?? Environment.GetFolderPath(Environment.SpecialFolder.System);
        if (!string.IsNullOrWhiteSpace(system)) folders.Add(system);
        foreach (var folder in (pathVariable ?? Environment.GetEnvironmentVariable("PATH") ?? "")
                     .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Take(MaxPathFolders))
        {
            var expanded = Environment.ExpandEnvironmentVariables(folder.Trim('"'));
            if (Path.IsPathFullyQualified(expanded)) folders.Add(expanded);
        }
        foreach (var folder in folders)
            foreach (var candidate in candidates)
            {
                var full = Path.Join(folder, candidate);
                if (File.Exists(full)) return full;
            }
        return null;
    }

    private static bool Writable(AuthorizationRuleCollection rules)
    {
        var allowed = false;
        foreach (FileSystemAccessRule rule in rules)
        {
            if (!Preflight.WellKnownSids.BroadGroups.Contains(rule.IdentityReference.Value, StringComparer.OrdinalIgnoreCase)) continue;
            if (!AuditPrimitives.GrantsWrite(rule.FileSystemRights)) continue;
            if (rule.AccessControlType == AccessControlType.Deny) return false;
            allowed = true;
        }
        return allowed;
    }

    private static string SafeFileName(string path)
    {
        try { return Path.GetFileName(path.Trim('"')); }
        catch (ArgumentException) { return path; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UserInfo2
    {
        public IntPtr Name;
        public IntPtr Password; // never read
        public uint PasswordAge;
        public uint Privilege;
        public IntPtr HomeDirectory;
        public IntPtr Comment;
        public uint Flags;
        public IntPtr ScriptPath;
        public uint AuthFlags;
        public IntPtr FullName;
        public IntPtr UserComment;
        public IntPtr Parameters;
        public IntPtr Workstations;
        public uint LastLogon;
        public uint LastLogoff;
        public uint AccountExpires;
        public uint MaxStorage;
        public uint UnitsPerWeek;
        public IntPtr LogonHours;
        public uint BadPasswordCount;
        public uint NumberOfLogons;
        public IntPtr LogonServer;
        public uint CountryCode;
        public uint CodePage;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int NetUserEnum(string? server, int level, int filter, out IntPtr buffer, int preferredMaximumLength,
        out int entriesRead, out int totalEntries, ref int resumeHandle);

    [DllImport("netapi32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int NetApiBufferFree(IntPtr buffer);
}

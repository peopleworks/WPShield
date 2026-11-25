using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security;
using WPShield.Evidence;

namespace WPShield.SecurityMonitor;

/// <summary>
/// The host facts this library can read on its own (ADR 0013): health, unexpected restarts and RDP sessions.
/// Everything here reads; nothing writes, and nothing needs more than the System and LocalSessionManager logs,
/// which are readable without elevation.
/// </summary>
public static class WindowsHostReaders
{
    internal const string SystemLog = "System";
    internal const string SessionLog = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
    private const string KernelPower = "Microsoft-Windows-Kernel-Power";
    private const string EventLogProvider = "EventLog";
    private const string WerSystem = "Microsoft-Windows-WER-SystemErrorReporting";
    private const string LegacyBugCheck = "BugCheck";

    // ---------------------------------------------------------------------------------------------
    //  host_health
    // ---------------------------------------------------------------------------------------------

    /// <param name="iisLogDirectory">The IIS log folder, to mark the volume that holds it; may be <see langword="null"/>.</param>
    public static HostFactReading ReadHealth(string? storePath, string? iisLogDirectory, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var problems = new List<string>();
        var uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);

        var cpu = ReadCpu(cancellationToken, problems);
        long? total = null, available = null;
        var memory = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
        if (GlobalMemoryStatusEx(ref memory))
        {
            total = (long)memory.TotalPhysical;
            available = (long)memory.AvailablePhysical;
        }
        else problems.Add("memory");

        var volumes = new List<HostVolume>();
        string? logRoot = null;
        try { logRoot = iisLogDirectory is null ? null : Path.GetPathRoot(Environment.ExpandEnvironmentVariables(iisLogDirectory)); }
        catch (ArgumentException) { }
        try
        {
            foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed).Take(HostFacts.MaxVolumes))
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    if (!drive.IsReady) continue;
                    volumes.Add(new HostVolume(HostFacts.Clean(drive.Name), drive.TotalSize, drive.AvailableFreeSpace,
                        logRoot is null ? null : string.Equals(drive.RootDirectory.FullName, logRoot, StringComparison.OrdinalIgnoreCase)));
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    problems.Add("volume");
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            problems.Add("volumes");
        }

        long? storeBytes = null;
        if (storePath is not null)
        {
            try
            {
                storeBytes = new[] { storePath, storePath + "-wal", storePath + "-shm" }
                    .Select(p => new FileInfo(p)).Where(f => f.Exists).Sum(f => f.Length);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
            {
                problems.Add("store-size");
            }
        }

        var patch = ReadPatchLevel(now, cancellationToken, problems);
        var health = new HostHealth(now - uptime, (long)uptime.TotalSeconds, cpu, total, available, volumes, storeBytes, patch);
        return problems.Count == 0
            ? HostFactReading.Of(HostFacts.Health, null, now, health)
            : HostFactReading.Of(HostFacts.Health, null, now, health, HostFactStatus.Partial, "not-read: " + string.Join(", ", problems.Distinct()),
                "The values that could not be read are left empty; they are read again in five minutes.");
    }

    internal const string UpdateLog = "Microsoft-Windows-WindowsUpdateClient/Operational";

    /// <summary>
    /// The patch level as Windows reports it: the registry's build, the kernel file's version and the Windows Update
    /// log. Read-only and bounded. Facts, never a verdict: there is no offline source of the latest build.
    /// </summary>
    internal static HostPatchLevel ReadPatchLevel(DateTimeOffset now, CancellationToken cancellationToken, List<string> problems)
    {
        string? build = null, display = null, kernel = null;
        int? ubr = null;
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            build = Bounded(key?.GetValue("CurrentBuild") as string, 16);
            ubr = key?.GetValue("UBR") as int?;
            display = Bounded(key?.GetValue("DisplayVersion") as string, 16);
            if (key is null) problems.Add("os-version");
        }
        catch (Exception exception) when (exception is SecurityException or UnauthorizedAccessException or IOException)
        {
            problems.Add("os-version");
        }
        try
        {
            var path = Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.System), "ntoskrnl.exe");
            kernel = File.Exists(path) ? Bounded(System.Diagnostics.FileVersionInfo.GetVersionInfo(path).ProductVersion, 32) : null;
            if (kernel is null) problems.Add("kernel-version");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            problems.Add("kernel-version");
        }

        var events = new List<UpdateEvent>();
        var readable = true;
        var foundCumulative = false;
        try
        {
            const string filter = "*[System[(EventID=19 or EventID=20)]]";
            using var reader = new EventLogReader(new EventLogQuery(UpdateLog, PathType.LogName, filter) { ReverseDirection = true }) { BatchSize = 64 };
            for (var i = 0; i < PatchLevels.MaxEvents; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var record = reader.ReadEvent();
                if (record is null || record.TimeCreated is not DateTime created) break;
                var at = new DateTimeOffset(created.ToUniversalTime(), TimeSpan.Zero);
                var title = record.Properties.Count > 0 ? record.Properties[0].Value as string : null;
                events.Add(new UpdateEvent(at, record.Id, title is null ? null : EvidenceText.Clean(title, HostPatchLevel.MaxTitleLength)));
                foundCumulative |= record.Id == PatchLevels.InstallSucceeded && PatchLevels.IsCumulative(title);
                // Newest first: once a cumulative update is found and the failure window is behind, nothing older matters.
                if (foundCumulative && at < now - HostPatchLevel.FailureWindow) break;
            }
        }
        catch (OperationCanceledException)
        {
            readable = false;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or SecurityException or EventLogException)
        {
            readable = false;
        }
        if (!readable)
        {
            problems.Add("update-log");
            return new HostPatchLevel(build, ubr, display, kernel, false, null, null, null);
        }
        var (lastTitle, lastAt, failed) = PatchLevels.FromUpdateEvents(events, now);
        return new HostPatchLevel(build, ubr, display, kernel, true, lastTitle, lastAt, failed, OldestRecord(UpdateLog));
    }

    /// <summary>The time of the oldest record a log still holds, so "not found" can say "since when".</summary>
    private static DateTimeOffset? OldestRecord(string log)
    {
        try
        {
            using var reader = new EventLogReader(new EventLogQuery(log, PathType.LogName, "*")) { BatchSize = 1 };
            using var record = reader.ReadEvent();
            return record?.TimeCreated is DateTime created ? new DateTimeOffset(created.ToUniversalTime(), TimeSpan.Zero) : null;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or SecurityException or EventLogException)
        {
            return null;
        }
    }

    private static string? Bounded(string? text, int max) => string.IsNullOrWhiteSpace(text) ? null : EvidenceText.Clean(text.Trim(), max);

    private static double? ReadCpu(CancellationToken cancellationToken, List<string> problems)
    {
        if (!GetSystemTimes(out var idle1, out var kernel1, out var user1))
        {
            problems.Add("cpu");
            return null;
        }
        // Two samples half a second apart: a usage figure, not a since-boot average.
        if (cancellationToken.WaitHandle.WaitOne(500))
        {
            problems.Add("cpu");
            return null;
        }
        if (!GetSystemTimes(out var idle2, out var kernel2, out var user2))
        {
            problems.Add("cpu");
            return null;
        }
        var idle = idle2 - idle1;
        var busy = kernel2 - kernel1 + (user2 - user1); // kernel time includes idle time
        if (busy <= 0) return null;
        return Math.Round(Math.Clamp(100.0 * (busy - idle) / busy, 0, 100), 1);
    }

    // ---------------------------------------------------------------------------------------------
    //  Unexpected restarts
    // ---------------------------------------------------------------------------------------------

    public static HostRestartReading ReadRestarts(DateTimeOffset since, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var start = since.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
        var filter = $"*[System[(EventID=41 or EventID=6008 or EventID=1001) and TimeCreated[@SystemTime >= '{start}']]]";
        var records = new List<HostRestartRecord>();
        try
        {
            using var reader = new EventLogReader(new EventLogQuery(SystemLog, PathType.LogName, filter)) { BatchSize = 64 };
            for (var i = 0; i < HostFacts.MaxRestartEvents; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var record = reader.ReadEvent();
                if (record is null) return new(now, HostFactStatus.Ok, null, null, records);
                if (Restart(record) is { } restart) records.Add(restart);
            }
            return new(now, HostFactStatus.Partial, "record-bound", "Only the first records were read; the rest are read on the next pass.", records);
        }
        catch (OperationCanceledException)
        {
            return new(now, HostFactStatus.Partial, "time-budget", "The System log is read again on its cadence.", records);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or SecurityException)
        {
            return new(now, HostFactStatus.Unreadable, "access-denied",
                "The System log could not be read. Run the collector elevated, or check the System log's permissions.", []);
        }
        catch (EventLogException exception)
        {
            return new(now, HostFactStatus.Unreadable, "query-failed: " + exception.GetType().Name,
                "The System log could not be queried. Check that the Windows Event Log service is running.", []);
        }
    }

    internal static HostRestartRecord? Restart(EventRecord record)
    {
        if (record.TimeCreated is not DateTime created || record.RecordId is not long id) return null;
        var at = new DateTimeOffset(created.ToUniversalTime(), TimeSpan.Zero);
        var provider = record.ProviderName ?? "";
        var properties = record.Properties;
        switch (record.Id)
        {
            case 41 when string.Equals(provider, KernelPower, StringComparison.OrdinalIgnoreCase):
                var code = properties.Count > 0 ? BugChecks.Parse(Convert.ToString(properties[0].Value, CultureInfo.InvariantCulture)) : null;
                return new(at, id, 41, code);
            case 6008 when string.Equals(provider, EventLogProvider, StringComparison.OrdinalIgnoreCase):
                return new(at, id, 6008, null);
            case 1001 when string.Equals(provider, WerSystem, StringComparison.OrdinalIgnoreCase) ||
                           string.Equals(provider, LegacyBugCheck, StringComparison.OrdinalIgnoreCase):
                return new(at, id, 1001, properties.Count > 0 ? BugChecks.Parse(properties[0].Value as string) : null);
            default:
                return null;
        }
    }

    // ---------------------------------------------------------------------------------------------
    //  rdp_sessions
    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// Current sessions from the session API, and RDP logons and reconnections from LocalSessionManager 21 and 25 -
    /// the evidence-grade source of a session's address. The client-reported address is never read.
    /// </summary>
    public static HostFactReading ReadSessions(DateTimeOffset since, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var problems = new List<string>();
        var current = ReadCurrentSessions(problems);
        var recent = new List<HostRdpLogon>();
        var start = since.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
        var filter = $"*[System[(EventID=21 or EventID=25) and TimeCreated[@SystemTime >= '{start}']]]";
        try
        {
            using var reader = new EventLogReader(new EventLogQuery(SessionLog, PathType.LogName, filter) { ReverseDirection = true }) { BatchSize = 64 };
            for (var i = 0; i < HostFacts.MaxRecentLogons; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var record = reader.ReadEvent();
                if (record is null) break;
                if (Logon(record) is { } logon) recent.Add(logon);
            }
        }
        catch (OperationCanceledException)
        {
            problems.Add("time-budget");
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or SecurityException or EventLogException)
        {
            problems.Add(exception is EventLogException ? "logon-log-query-failed" : "logon-log-access-denied");
        }

        var sessions = new HostSessions(current, recent);
        return problems.Count == 0
            ? HostFactReading.Of(HostFacts.Sessions, null, now, sessions)
            : HostFactReading.Of(HostFacts.Sessions, null, now, sessions, HostFactStatus.Partial, string.Join(", ", problems),
                "What could not be read is left out, not shown as empty. Run the collector elevated; it reads again in 15 minutes.");
    }

    internal static HostRdpLogon? Logon(EventRecord record)
    {
        if (record.Id is not (21 or 25) || record.TimeCreated is not DateTime created) return null;
        var properties = record.Properties;
        if (properties.Count < 3) return null;
        var user = HostFacts.Clean(properties[0].Value as string);
        var address = properties[2].Value as string;
        // The console logs "LOCAL" instead of an address.
        address = string.IsNullOrWhiteSpace(address) || address.Equals("LOCAL", StringComparison.OrdinalIgnoreCase)
            ? null
            : System.Net.IPAddress.TryParse(address.Trim(), out var ip) ? ip.ToString() : null;
        return new(new DateTimeOffset(created.ToUniversalTime(), TimeSpan.Zero), user, address, record.Id == 21 ? "logon" : "reconnect");
    }

    private static IReadOnlyList<HostSession> ReadCurrentSessions(List<string> problems)
    {
        var result = new List<HostSession>();
        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var buffer, out var count))
        {
            problems.Add("sessions");
            return result;
        }
        try
        {
            var size = Marshal.SizeOf<SessionInfo>();
            for (var i = 0; i < Math.Min(count, HostFacts.MaxSessions); i++)
            {
                var info = Marshal.PtrToStructure<SessionInfo>(buffer + i * size);
                if (info.State is 6 /* listen */ or 9 /* init */ || info.SessionId == 0) continue;
                var user = Query(info.SessionId, 5 /* WTSUserName */);
                var domain = Query(info.SessionId, 7 /* WTSDomainName */);
                var name = string.IsNullOrEmpty(user) ? "" : string.IsNullOrEmpty(domain) ? user : $"{domain}\\{user}";
                result.Add(new HostSession(info.SessionId, StateName(info.State), HostFacts.Clean(name), LogonTime(info.SessionId)));
            }
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
        return result;
    }

    private static string StateName(int state) => state switch
    {
        0 => "active",
        1 => "connected",
        2 => "connect-query",
        3 => "shadow",
        4 => "disconnected",
        5 => "idle",
        7 => "reset",
        8 => "down",
        _ => "unknown"
    };

    private static string? Query(int session, int infoClass)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, session, infoClass, out var buffer, out _)) return null;
        try { return Marshal.PtrToStringUni(buffer); }
        finally { WTSFreeMemory(buffer); }
    }

    private static DateTimeOffset? LogonTime(int session)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, session, 24 /* WTSSessionInfo */, out var buffer, out var bytes)) return null;
        try
        {
            if (bytes < Marshal.SizeOf<WtsInfo>()) return null;
            var info = Marshal.PtrToStructure<WtsInfo>(buffer);
            return info.LogonTime > 0 ? DateTimeOffset.FromFileTime(info.LogonTime).ToUniversalTime() : null;
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
        finally { WTSFreeMemory(buffer); }
    }

    // ---------------------------------------------------------------------------------------------
    //  Interop
    // ---------------------------------------------------------------------------------------------

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatus
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhysical;
        public ulong AvailablePhysical;
        public ulong TotalPageFile;
        public ulong AvailablePageFile;
        public ulong TotalVirtual;
        public ulong AvailableVirtual;
        public ulong AvailableExtendedVirtual;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SessionInfo
    {
        public int SessionId;
        public IntPtr WinStationName;
        public int State;
    }

    /// <summary>WTSINFOW: only the fields up to the logon time are read.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WtsInfo
    {
        public int State;
        public int SessionId;
        public int IncomingBytes;
        public int OutgoingBytes;
        public int IncomingFrames;
        public int OutgoingFrames;
        public int IncomingCompressedBytes;
        public int OutgoingCompressedBytes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string WinStationName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)] public string Domain;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string UserName;
        public long ConnectTime;
        public long DisconnectTime;
        public long LastInputTime;
        public long LogonTime;
        public long CurrentTime;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemTimes(out long idle, out long kernel, out long user);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatus buffer);

    [DllImport("wtsapi32.dll", EntryPoint = "WTSEnumerateSessionsW", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);

    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformation(IntPtr server, int session, int infoClass, out IntPtr buffer, out int bytes);

    [DllImport("wtsapi32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void WTSFreeMemory(IntPtr memory);
}

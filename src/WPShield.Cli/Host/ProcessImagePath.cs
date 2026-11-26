using System.Runtime.InteropServices;
using System.Text;

namespace WPShield.Cli.Host;

/// <summary>
/// The executable behind a listener's PID, in the drive-letter form a firewall rule's program is written in.
/// </summary>
/// <remarks>
/// <para>
/// Opening the process for <c>PROCESS_QUERY_LIMITED_INFORMATION</c> is the first way. It is not always enough: a process
/// whose security descriptor grants an administrator nothing refuses even that, even to an elevated collector. Its
/// listeners then read "unknown", and the verdict - rightly, in the open direction - kept every program and app-container
/// rule, burying the port rules an operator restricts under rules for programs that do not own the port.
/// </para>
/// <para>
/// The second way is the kernel's own image name (<c>SystemProcessIdInformation</c>), which needs no handle and so no
/// access to the process. It is a device path (<c>\Device\HarddiskVolume3\...</c>) and is used only when its device
/// maps to a drive letter on a separator boundary. Anything else is unknown, never a guess: the firewall compares
/// programs by exact path, so a wrong path drops every program rule - the closed direction.
/// </para>
/// </remarks>
internal static class ProcessImagePath
{
    /// <summary>A drive (<c>C:</c>) and the device it names (<c>\Device\HarddiskVolume3</c>).</summary>
    internal readonly record struct DosDevice(string Drive, string Device);

    private const uint SystemProcess = 4;
    private const int SystemProcessIdInformation = 88;
    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
    private const int FirstImageBytes = 1024;
    private const int MaxDeviceChars = 1024;

    /// <summary>The executable for <paramref name="processId"/>, or <see langword="null"/> when it cannot be named.</summary>
    /// <param name="devices">The drive map, asked for only when the kernel's name is needed.</param>
    internal static string? Read(uint processId, Func<IReadOnlyList<DosDevice>> devices) =>
        Read(processId, Open, KernelImageName, devices);

    internal static string? Read(uint processId, Func<uint, string?> open, Func<uint, string?> kernel,
        Func<IReadOnlyList<DosDevice>> devices)
    {
        if (processId == SystemProcess) return "System";
        if (processId == 0) return null;
        return open(processId) ?? ToDosPath(kernel(processId), devices());
    }

    /// <summary>
    /// The drive-letter form of a kernel device path, or <see langword="null"/> when no drive maps its device. The
    /// device must end at a separator: <c>\Device\HarddiskVolume1</c> is not a prefix of <c>\Device\HarddiskVolume10\x</c>.
    /// </summary>
    internal static string? ToDosPath(string? devicePath, IReadOnlyList<DosDevice> devices)
    {
        if (string.IsNullOrEmpty(devicePath)) return null;
        foreach (var (drive, device) in devices)
        {
            if (device.Length == 0 || devicePath.Length <= device.Length + 1 || devicePath[device.Length] != '\\') continue;
            if (devicePath.StartsWith(device, StringComparison.OrdinalIgnoreCase)) return drive + devicePath[device.Length..];
        }
        return null;
    }

    /// <summary>Every local drive letter and the device it names now. Empty when the drives cannot be listed.</summary>
    internal static IReadOnlyList<DosDevice> DosDevices()
    {
        string[] roots;
        try
        {
            roots = Environment.GetLogicalDrives();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }
        var devices = new List<DosDevice>();
        var target = new char[MaxDeviceChars];
        foreach (var root in roots.Take(26))
        {
            if (root.Length < 2 || root[1] != ':') continue;
            var drive = root[..2];
            if (QueryDosDevice(drive, target, MaxDeviceChars) == 0) continue;
            // The answer is a list of strings; the first is the mapping in force.
            var length = Array.IndexOf(target, '\0');
            if (length > 0) devices.Add(new DosDevice(drive, new string(target, 0, length)));
        }
        return devices;
    }

    /// <summary>The path from the process itself, or <see langword="null"/> when it refuses to be opened.</summary>
    internal static string? Open(uint processId)
    {
        var handle = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, processId);
        if (handle == IntPtr.Zero) return null;
        try
        {
            var buffer = new StringBuilder(1024);
            var size = buffer.Capacity;
            return QueryFullProcessImageName(handle, 0, buffer, ref size) ? buffer.ToString(0, size) : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    /// <summary>
    /// The kernel's image name for <paramref name="processId"/>, a device path, without opening the process. Bounded:
    /// one retry at the size the kernel asks for, which a <c>UNICODE_STRING</c> caps at 64 KiB.
    /// </summary>
    internal static string? KernelImageName(uint processId)
    {
        var bytes = FirstImageBytes;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(bytes);
            try
            {
                var information = new ProcessIdInformation
                {
                    ProcessId = (nint)processId,
                    ImageName = new UnicodeString { Length = 0, MaximumLength = (ushort)bytes, Buffer = buffer }
                };
                var status = NtQuerySystemInformation(SystemProcessIdInformation, ref information,
                    Marshal.SizeOf<ProcessIdInformation>(), out _);
                if (status == StatusInfoLengthMismatch && information.ImageName.MaximumLength > bytes)
                {
                    bytes = information.ImageName.MaximumLength;
                    continue;
                }
                if (status != 0 || information.ImageName.Buffer == IntPtr.Zero || information.ImageName.Length == 0) return null;
                return Marshal.PtrToStringUni(information.ImageName.Buffer, information.ImageName.Length / sizeof(char));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        return null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessIdInformation
    {
        public IntPtr ProcessId;
        public UnicodeString ImageName;
    }

    [DllImport("ntdll.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int NtQuerySystemInformation(int informationClass, ref ProcessIdInformation information, int length,
        out int returnLength);

    [DllImport("kernel32.dll", EntryPoint = "QueryDosDeviceW", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint QueryDosDevice(string deviceName, [Out] char[] targetPath, uint max);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}

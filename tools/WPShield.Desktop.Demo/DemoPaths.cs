using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using WPShield.Evidence;

namespace WPShield.Desktop.Demo;

internal static class DemoPaths
{
    internal static string NewStorePath(string path, string? protectedDirectory = null)
    {
        var full = Path.GetFullPath(path);
        var name = Path.GetFileName(full);
        if (name.Length == 0 || name.Contains(':') || name.EndsWith(' ') || name.EndsWith('.'))
            throw new ArgumentException("Choose a new, ordinary database filename.", nameof(path));
        RequireSafeDirectory(Path.GetDirectoryName(full)!, protectedDirectory);
        if (File.Exists(full) || Directory.Exists(full))
            throw new IOException("The demo store destination already exists.");
        return full;
    }

    internal static void RequireSafeDirectory(string path, string? protectedDirectory = null, bool mayBeMissing = false)
    {
        var directory = Path.GetFullPath(path);
        var protectedPath = Path.GetFullPath(protectedDirectory ?? Path.GetDirectoryName(EvidenceStore.DefaultPath)!);
        if (IsAtOrBelow(directory, protectedPath) ||
            IsAtOrBelow(ResolveDirectory(directory, mayBeMissing), ResolveDirectory(protectedPath, mayBeMissing: true)))
            throw new IOException("The demo tool refuses to write inside WPShield's default evidence directory.");
    }

    private static bool IsAtOrBelow(string path, string parent)
    {
        var root = Path.TrimEndingDirectorySeparator(parent) + Path.DirectorySeparatorChar;
        return path.Equals(parent, StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }

    // Resolve directory handles to their NT paths. Comparing textual FullPath values alone
    // would accept another spelling of the live directory through a junction or a drive alias.
    private static string ResolveDirectory(string path, bool mayBeMissing)
    {
        path = Path.TrimEndingDirectorySeparator(path);
        using var handle = OpenDirectory(path, 0, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero, FileMode.Open, 0x02000000, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            if (mayBeMissing && error is 2 or 3 && Path.GetDirectoryName(path) is { } parent)
                return Path.Combine(ResolveDirectory(parent, mayBeMissing: true), Path.GetFileName(path));
            throw new IOException("Could not verify the demo output directory.", new Win32Exception(error));
        }

        const int volumeNameNt = 2;
        var buffer = new StringBuilder(32768);
        var length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, volumeNameNt);
        if (length == 0 || length >= buffer.Capacity)
            throw new IOException("Could not resolve the demo output directory.", new Win32Exception(Marshal.GetLastWin32Error()));
        return Path.TrimEndingDirectorySeparator(buffer.ToString());
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle OpenDirectory(string path, uint access, FileShare share, IntPtr security,
        FileMode mode, uint flags, IntPtr template);

    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
}

internal sealed class DemoWorkspace : IDisposable
{
    private readonly DirectoryInfo directory;

    internal DemoWorkspace()
    {
        DemoPaths.RequireSafeDirectory(Path.GetTempPath());
        directory = Directory.CreateTempSubdirectory("wpshield-demo-");
    }

    internal string FilePath(string name) => Path.Combine(directory.FullName, name);

    public void Dispose()
    {
        foreach (var file in directory.EnumerateFiles()) file.Delete();
        directory.Delete();
    }
}

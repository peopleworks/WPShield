using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace WPShield.Cli.Preflight;

/// <summary>
/// Whether an account is a member of a local group, or that nobody could look.
/// </summary>
/// <param name="IsMember">
/// <see langword="null"/> when membership could not be read. "Could not read it" and "not a member"
/// are different findings and must never render alike.
/// </param>
internal sealed record GroupMembership(bool? IsMember, string? Problem = null);

/// <summary>
/// Reads a local group's members by SID. Reads only: nothing here adds or removes a member.
/// </summary>
/// <remarks>
/// <para>
/// <b>By SID on both sides.</b> The group is named by its well-known SID and its name is looked up
/// only to call the API, because <c>Event Log Readers</c> is <c>Lectores del registro de eventos</c>
/// on a Spanish Windows. Members come back as SIDs and are compared as SIDs.
/// </para>
/// <para>
/// <c>NetLocalGroupGetMembers</c> at level 0 rather than <c>System.DirectoryServices</c> or
/// <c>Get-LocalGroupMember</c>: it needs no package, and it returns every member as a SID - including
/// a virtual service account and an orphaned SID, which the higher-level readers are known to choke
/// on and report as an error about the whole group.
/// </para>
/// </remarks>
internal static class LocalGroupMembership
{
    private const int Success = 0;
    private const int MoreData = 234;
    private const int MaxPreferredLength = -1;

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int NetLocalGroupGetMembers(string? serverName, string localGroupName, int level,
        out IntPtr buffer, int preferredMaximumLength, out int entriesRead, out int totalEntries, ref IntPtr resumeHandle);

    [DllImport("netapi32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int NetApiBufferFree(IntPtr buffer);

    public static GroupMembership Read(string groupSid, string account)
    {
        SecurityIdentifier member;
        string groupName;
        try
        {
            member = (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier));
            var qualified = new SecurityIdentifier(groupSid).Translate(typeof(NTAccount)).Value;
            groupName = qualified[(qualified.IndexOf('\\', StringComparison.Ordinal) + 1)..];
        }
        catch (Exception exception) when (exception is IdentityNotMappedException or SystemException)
        {
            return new GroupMembership(null, $"{account} or {groupSid} could not be resolved: {exception.Message}");
        }

        var members = new List<SecurityIdentifier>();
        var resume = IntPtr.Zero;
        int status;
        do
        {
            status = NetLocalGroupGetMembers(null, groupName, 0, out var buffer, MaxPreferredLength, out var read, out _, ref resume);
            try
            {
                if (status is not (Success or MoreData))
                {
                    return new GroupMembership(null, $"the members of {groupSid} could not be listed: {new Win32Exception(status).Message}");
                }

                // LOCALGROUP_MEMBERS_INFO_0 is a single PSID.
                for (var index = 0; index < read; index++)
                {
                    members.Add(new SecurityIdentifier(Marshal.ReadIntPtr(buffer, index * IntPtr.Size)));
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
            }
        }
        while (status == MoreData);

        return new GroupMembership(members.Contains(member));
    }
}

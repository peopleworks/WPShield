using System.Security.AccessControl;
using System.Text.RegularExpressions;
using WPShield.Cli.Audit;

namespace WPShield.Cli.Tests.Audit;

/// <summary>
/// The decisions the audit makes about raw values: access masks, folder containment, account names.
/// </summary>
public sealed partial class AuditPrimitivesTests
{
    // =============================================================================================
    //  Write access
    // =============================================================================================

    [Theory]
    [InlineData(FileSystemRights.WriteData)]
    [InlineData(FileSystemRights.AppendData)]
    [InlineData(FileSystemRights.Modify)]
    [InlineData(FileSystemRights.FullControl)]
    [InlineData(FileSystemRights.Write)]
    // Either of these lets the holder grant itself write, so either counts as write.
    [InlineData(FileSystemRights.ChangePermissions)]
    [InlineData(FileSystemRights.TakeOwnership)]
    // GENERIC_WRITE and GENERIC_ALL, which appear in inherit-only entries and have no enum name.
    [InlineData((FileSystemRights)0x40000000)]
    [InlineData((FileSystemRights)0x10000000)]
    public void MasksThatCanPutAFileInPlace_GrantWrite(FileSystemRights rights)
    {
        Assert.True(AuditPrimitives.GrantsWrite(rights));
    }

    [Theory]
    [InlineData(FileSystemRights.ReadAndExecute)]
    [InlineData(FileSystemRights.Read)]
    [InlineData(FileSystemRights.ListDirectory)]
    [InlineData(FileSystemRights.Synchronize)]
    // GENERIC_READ.
    [InlineData(unchecked((FileSystemRights)(int)0x80000000))]
    public void ReadOnlyMasks_DoNotGrantWrite(FileSystemRights rights)
    {
        Assert.False(AuditPrimitives.GrantsWrite(rights));
    }

    // =============================================================================================
    //  Folder containment
    // =============================================================================================

    [Theory]
    [InlineData(@"C:\inetpub\wwwroot", @"C:\inetpub\wwwroot\blog", true)]
    [InlineData(@"C:\inetpub\wwwroot\", @"C:\inetpub\wwwroot\blog\", true)]
    [InlineData(@"C:\INETPUB\WWWROOT", @"c:\inetpub\wwwroot\Blog", true)]
    [InlineData(@"C:\inetpub\wwwroot", @"C:\inetpub\wwwroot\a\b\c", true)]
    // A shared prefix is not containment.
    [InlineData(@"C:\inetpub\wwwroot", @"C:\inetpub\wwwroot2", false)]
    [InlineData(@"C:\inetpub\wwwroot", @"C:\inetpub\wwwroot-old\blog", false)]
    // The same folder is not inside itself, and a parent is not inside its child.
    [InlineData(@"C:\inetpub\wwwroot", @"C:\inetpub\wwwroot", false)]
    [InlineData(@"C:\inetpub\wwwroot\blog", @"C:\inetpub\wwwroot", false)]
    [InlineData("", @"C:\inetpub\wwwroot", false)]
    [InlineData(@"C:\inetpub\wwwroot", "", false)]
    public void IsInside_ComparesWholeFolderNames(string parent, string child, bool expected)
    {
        Assert.Equal(expected, AuditPrimitives.IsInside(parent, child));
    }

    // =============================================================================================
    //  Account names and handlers
    // =============================================================================================

    [Theory]
    [InlineData(@".\svc-app", @"HOST\svc-app")]
    [InlineData("Administrator", "Administrator")]
    [InlineData(@"DOMAIN\user", @"DOMAIN\user")]
    [InlineData("  Administrator  ", "Administrator")]
    public void NormalizeAccountName_MakesTheLocalFormResolvable(string input, string expected)
    {
        Assert.Equal(expected, AuditPrimitives.NormalizeAccountName(input, "HOST"));
    }

    [Theory]
    [InlineData("*.php", "", true)]
    [InlineData("*.PHP", "", true)]
    [InlineData("*", @"C:\Program Files\PHP\v7.4\php-cgi.exe", true)]
    [InlineData("*.aspx", "", false)]
    [InlineData("*", "", false)]
    public void IsPhpHandler_RecognisesThePathOrTheProcessor(string path, string processor, bool expected)
    {
        Assert.Equal(expected, AuditPrimitives.IsPhpHandler(new AuditHandler("handler", path, processor)));
    }

    // =============================================================================================
    //  The audit never reads a password
    // =============================================================================================

    /// <summary>
    /// A pool that runs as a named account keeps that account's password in the IIS configuration,
    /// and an administrator can read it back. The audit reads the account and must never read the
    /// password - not to print it, not to hold it. Asserted on the data it carries and on its source.
    /// </summary>
    [Fact]
    public void TheAuditCarriesNoPassword()
    {
        var properties = typeof(AuditPool).GetProperties()
            .Concat(typeof(AuditFacts).GetProperties())
            .Concat(typeof(AuditSite).GetProperties())
            .Select(property => property.Name);

        Assert.DoesNotContain(properties, name => name.Contains("Password", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void TheAuditSourceNeverReadsAPasswordAttribute()
    {
        foreach (var file in AuditSourceFiles())
        {
            var code = CommentLines().Replace(File.ReadAllText(file), string.Empty);

            Assert.DoesNotContain(".Password", code, StringComparison.Ordinal);
            Assert.DoesNotContain("\"password\"", code, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static IReadOnlyList<string> AuditSourceFiles()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !Directory.Exists(Path.Combine(directory.FullName, "src", "WPShield.Cli")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);

        var cli = Path.Combine(directory.FullName, "src", "WPShield.Cli");
        var files = Directory.GetFiles(Path.Combine(cli, "Audit"), "*.cs")
            .Append(Path.Combine(cli, "AuditCommand.cs"))
            .ToArray();

        Assert.NotEmpty(files);
        return files;
    }

    [GeneratedRegex(@"^\s*//.*$", RegexOptions.Multiline)]
    private static partial Regex CommentLines();
}

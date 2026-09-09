using System.Text.RegularExpressions;

namespace WPShield.Cli.Tests;

/// <summary>
/// The structural guard ADR 0005 says must move rather than disappear.
/// </summary>
/// <remarks>
/// <para>
/// The PowerShell harness banned every IIS-writing cmdlet in every script, and the scripts are gone.
/// The equivalent here is narrower and stronger: <b>exactly one type may commit a change to IIS</b>,
/// every entry point on it names one site, and nothing else in the assembly can reach the write path
/// at all.
/// </para>
/// <para>
/// A source scan rather than a reflection scan, because what matters is that a future edit cannot add
/// a second writer without a reviewer seeing this test fail — and the name of the file it appears in
/// is the review.
/// </para>
/// </remarks>
public sealed class IisWriteBoundaryTests
{
    /// <summary>The single seam. Everything that writes IIS lives here and nowhere else.</summary>
    private const string TheOnlyWriter = "IisSiteWriter.cs";

    [Fact]
    public void OnlyOneFileCommitsAChangeToIis()
    {
        var offenders = SourceFiles()
            .Where(file => File.ReadAllText(file).Contains("CommitChanges()", StringComparison.Ordinal))
            .Select(Path.GetFileName)
            .Where(name => !string.Equals(name, TheOnlyWriter, StringComparison.Ordinal))
            .ToArray();

        Assert.True(
            offenders.Length == 0,
            $"Only {TheOnlyWriter} may commit a change to IIS. These also do: {string.Join(", ", offenders)}. " +
            "ADR 0005 permits an IIS write only for a single site named on the command line, only when it is " +
            "individually reversible, and only when the result is verified and reverted on failure. A second " +
            "writer is a second place those guarantees have to be re-argued.");
    }

    /// <summary>
    /// Nothing may reach the server-wide proxy section. <c>preserveHostHeader</c> has no per-site
    /// override, and changing it for an operator who asked about one site is exactly what the
    /// invariant exists to prevent — on the host this was written for, it would alter what sixty-five
    /// unrelated applications send downstream.
    /// </summary>
    [Fact]
    public void NothingWritesTheServerWideProxySection()
    {
        var offenders = SourceFiles()
            .Where(file =>
            {
                // Comments stripped first. The file that documents why it never touches this section
                // is the file that names it, and a scan that could not tell the two apart failed on
                // the guard's own explanation the first time it ran.
                var text = WithoutComments(File.ReadAllText(file));
                return text.Contains("system.webServer/proxy", StringComparison.Ordinal) &&
                       text.Contains("CommitChanges()", StringComparison.Ordinal);
            })
            .Select(Path.GetFileName)
            .ToArray();

        Assert.True(
            offenders.Length == 0,
            $"These reach the server-wide proxy section and commit: {string.Join(", ", offenders)}. " +
            "It is server-wide with no per-site override. WPShield reports it and never sets it.");
    }

    /// <summary>
    /// Every write names a site. The equivalent of the old rule that a service-mutating call had to
    /// bind its name to a variable rather than a literal, so it could never be pointed at one of the
    /// sixty-five other applications on a shared host.
    /// </summary>
    [Fact]
    public void EveryWriteEntryPointTakesASiteName()
    {
        var writer = SourceFiles().Single(file =>
            string.Equals(Path.GetFileName(file), TheOnlyWriter, StringComparison.Ordinal));

        var methods = Regex.Matches(
            File.ReadAllText(writer),
            @"public\s+(?:void|bool)\s+(\w+)\s*\(([^)]*)\)");

        Assert.NotEmpty(methods);

        foreach (Match method in methods)
        {
            var name = method.Groups[1].Value;
            var parameters = method.Groups[2].Value;

            // BackupWebConfig takes the site's physical path, which is just as specific.
            var scoped = parameters.Contains("siteName", StringComparison.Ordinal) ||
                         parameters.Contains("sitePhysicalPath", StringComparison.Ordinal);

            Assert.True(
                scoped,
                $"{name} does not take a site. Every IIS write must be scoped to one site the operator named, " +
                "so no call can reach an application nobody asked about.");
        }
    }

    /// <summary>
    /// Drops line comments and XML documentation, so a rule cannot be tripped by the sentence that
    /// explains it.
    /// </summary>
    private static string WithoutComments(string source)
    {
        var kept = source
            .ReplaceLineEndings(" | ")
            .Split(" | ", StringSplitOptions.RemoveEmptyEntries)
            .Where(line => !line.TrimStart().StartsWith("//", StringComparison.Ordinal));

        return string.Join(" ", kept);
    }

    private static IReadOnlyList<string> SourceFiles()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null && !Directory.Exists(Path.Combine(directory.FullName, "src", "WPShield.Cli")))
        {
            directory = directory.Parent;
        }

        Assert.True(directory is not null, "The repository could not be located from the test output directory.");

        var source = Path.Combine(directory!.FullName, "src", "WPShield.Cli");
        var files = Directory.GetFiles(source, "*.cs", SearchOption.AllDirectories)
            .Where(file => !file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(file => !file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .ToArray();

        Assert.NotEmpty(files);
        return files;
    }
}

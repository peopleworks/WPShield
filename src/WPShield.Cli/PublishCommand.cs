using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield publish</c> — builds a self-contained <c>win-x64</c> deployment, with a checksum.
/// </summary>
/// <remarks>
/// <para>
/// Runs on a build machine, not on a server. It needs the .NET SDK; a web server does not have one
/// and should not get one.
/// </para>
/// <para>
/// <b>Self-contained, deliberately.</b> A framework-dependent build is smaller and works wherever the
/// matching runtime is installed. This publishes self-contained anyway, because the host WPShield is
/// written for is a shared one: a server running dozens of unrelated applications, where somebody
/// else's patch to the shared runtime should not be able to stop the security gateway.
/// </para>
/// <para>
/// <b>Not trimmed.</b> Trimming would cut the size substantially and would also silently remove types
/// that configuration binding and dependency injection resolve by reflection. A gateway that fails to
/// start on a server at three in the morning because a trimmer removed a binder is a worse outcome
/// than a large directory.
/// </para>
/// <para>
/// <b>The artifact name says what this is.</b> WPShield is a research preview and is not approved for
/// production traffic, and an archive gets renamed, forwarded and unpacked months later by someone
/// who never saw the page that said so. The file name is the last place that warning survives.
/// </para>
/// </remarks>
internal static partial class PublishCommand
{
    public const string Help = """
        wpshield publish - build a self-contained win-x64 deployment of the gateway and this tool,
        with a checksum. Runs on a BUILD MACHINE, not on a server.

        Usage: wpshield publish [options]

          --repository <dir>  The repository root. Defaults to walking up from the current
                              directory until Directory.Build.props is found.
          --output <dir>      Where to place the publish directory and the archive.
                              Default <repository>\artifacts.
          --skip-archive      Produce the directory only, without the archive and its checksum.

        Both WPShield.Gateway.exe and wpshield.exe are published into one directory. Their runtime
        files are identical, so the directory holds one copy of each and the archive does not
        double - which this asserts rather than assumes.

        It refuses to produce an artifact containing appsettings.Local.json, and deletes the output
        if it finds one. That file carries real hostnames and topology and must never enter a
        deployment package.

        Exit codes:
          0   published
          1   an argument was wrong, a build failed, or a check refused
        """;

    private static readonly string[] KnownOptions = ["--repository", "--output", "--skip-archive"];

    private const string GatewayExecutable = "WPShield.Gateway.exe";
    private const string CliExecutable = "wpshield.exe";
    private const string OverlayFileName = "appsettings.Local.json";

    public static int Run(CliOptions arguments, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);

        arguments.RejectUnknown(KnownOptions);

        var repository = ResolveRepository(arguments.Get("--repository"));
        var version = ReadVersion(Path.Combine(repository, "Directory.Build.props"));
        var artifacts = arguments.Get("--output", Path.Combine(repository, "artifacts"));

        var name = $"wpshield-{version}-win-x64-RESEARCH-PREVIEW-NOT-FOR-PRODUCTION";
        var publishDirectory = Path.Combine(artifacts, name);

        output.WriteLine();
        output.WriteLine($"WPShield {version} - self-contained win-x64 publish");
        output.WriteLine($"Output: {publishDirectory}");
        output.WriteLine();

        if (Directory.Exists(publishDirectory))
        {
            output.WriteLine("Removing the previous publish directory.");
            Directory.Delete(publishDirectory, recursive: true);
        }

        // Both applications into one directory. The CLI is what installs the gateway, so shipping it
        // beside the gateway is what lets an operator run the install from the artifact itself.
        Build(Path.Combine(repository, "src", "WPShield.Gateway", "WPShield.Gateway.csproj"), publishDirectory, output);
        Build(Path.Combine(repository, "src", "WPShield.Cli", "WPShield.Cli.csproj"), publishDirectory, output);

        Verify(publishDirectory, version, output);

        if (!arguments.Flag("--skip-archive"))
        {
            Archive(artifacts, name, publishDirectory, output);
        }

        WriteNextSteps(output);
        return 0;
    }

    private static void Build(string project, string destination, TextWriter output)
    {
        if (!File.Exists(project))
        {
            throw new CliArgumentException($"Project not found at {project}. Is --repository correct?");
        }

        output.WriteLine($"Publishing {Path.GetFileNameWithoutExtension(project)}");

        var info = new ProcessStartInfo("dotnet") { UseShellExecute = false };
        foreach (var argument in new[]
        {
            "publish", project,
            "--configuration", "Release",
            "--runtime", "win-x64",
            "--self-contained", "true",
            "--output", destination
        })
        {
            info.ArgumentList.Add(argument);
        }

        using var process = Process.Start(info)
            ?? throw new CliArgumentException("dotnet could not be started. Is the SDK installed?");

        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            throw new CliArgumentException($"dotnet publish failed with exit code {process.ExitCode}.");
        }
    }

    /// <summary>
    /// Checks on what came out. Each of these has a way of being wrong quietly.
    /// </summary>
    private static void Verify(string publishDirectory, string version, TextWriter output)
    {
        output.WriteLine();
        output.WriteLine("Verifying the artifact");

        foreach (var executable in new[] { GatewayExecutable, CliExecutable })
        {
            if (!File.Exists(Path.Combine(publishDirectory, executable)))
            {
                throw new CliArgumentException($"The publish output has no {executable}.");
            }

            output.WriteLine($"  ok    {executable} is present");
        }

        // The operator overlay carries real hostnames, destinations and topology. The csproj marks it
        // CopyToPublishDirectory=Never, but that is one attribute away from not being true, and the
        // consequence - a deployment package that leaks a customer's topology - is not one to leave
        // to a setting nobody re-reads.
        var overlay = Path.Combine(publishDirectory, OverlayFileName);
        if (File.Exists(overlay))
        {
            Directory.Delete(publishDirectory, recursive: true);
            throw new CliArgumentException(
                $"{OverlayFileName} was copied into the publish output. That file carries real hostnames and " +
                "topology and must never enter a deployment package. The publish directory has been deleted. " +
                "Check CopyToPublishDirectory in WPShield.Gateway.csproj.");
        }

        output.WriteLine("  ok    no operator configuration was packaged");

        // The assembly version and the archive name both come from Directory.Build.props, so a
        // mismatch means the build did not read what this read.
        var reported = FileVersionInfo.GetVersionInfo(Path.Combine(publishDirectory, GatewayExecutable)).ProductVersion;
        if (reported is null || !reported.StartsWith(version, StringComparison.Ordinal))
        {
            throw new CliArgumentException(
                $"The published binary reports version \"{reported}\", which does not match the \"{version}\" in Directory.Build.props.");
        }

        output.WriteLine($"  ok    the binary reports {reported}");

        var files = Directory.GetFiles(publishDirectory, "*", SearchOption.AllDirectories);
        var bytes = files.Sum(file => new FileInfo(file).Length);
        output.WriteLine($"  ok    {files.Length} files, {Megabytes(bytes)} MB");

        AssertTheRuntimeIsNotDuplicated(publishDirectory, files, output);
    }

    /// <summary>
    /// Two self-contained applications share one runtime, and this proves it rather than assuming it.
    /// </summary>
    /// <remarks>
    /// ADR 0003 says the artifact carries both executables and that the archive does not double
    /// because their runtime files are identical. If a future change made them differ - a different
    /// target framework, a different RID - the directory would quietly grow by a hundred megabytes and
    /// nobody would notice until an operator waited twice as long for a copy over RDP.
    /// </remarks>
    private static void AssertTheRuntimeIsNotDuplicated(string publishDirectory, string[] files, TextWriter output)
    {
        var runtime = Path.Combine(publishDirectory, "System.Private.CoreLib.dll");
        if (!File.Exists(runtime))
        {
            throw new CliArgumentException(
                "The publish output has no System.Private.CoreLib.dll, so it is not self-contained. " +
                "A framework-dependent artifact depends on a shared runtime somebody else can patch.");
        }

        var duplicates = files
            .Select(Path.GetFileName)
            .GroupBy(file => file, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .ToArray();

        if (duplicates.Length > 0)
        {
            throw new CliArgumentException(
                $"The publish output holds more than one copy of: {string.Join(", ", duplicates)}. Both applications " +
                "publish into one directory and are expected to share every runtime file; two copies means they no " +
                "longer agree on a framework or a runtime identifier.");
        }

        output.WriteLine("  ok    one runtime, shared by both executables");
    }

    private static void Archive(string artifacts, string name, string publishDirectory, TextWriter output)
    {
        output.WriteLine();
        output.WriteLine("Archiving");

        var archivePath = Path.Combine(artifacts, $"{name}.zip");
        if (File.Exists(archivePath))
        {
            File.Delete(archivePath);
        }

        ZipFile.CreateFromDirectory(publishDirectory, archivePath, CompressionLevel.Optimal, includeBaseDirectory: false);

        using var stream = File.OpenRead(archivePath);
        var hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();

        // The format `sha256sum -c` understands, so the operator can verify with whatever they have.
        var checksumPath = $"{archivePath}.sha256";
        File.WriteAllText(checksumPath, $"{hash} *{Path.GetFileName(archivePath)}\n", new UTF8Encoding(false));

        output.WriteLine($"  archive : {archivePath}");
        output.WriteLine($"  size    : {Megabytes(new FileInfo(archivePath).Length)} MB");
        output.WriteLine($"  sha256  : {hash}");
        output.WriteLine($"  checksum: {checksumPath}");
    }

    private static void WriteNextSteps(TextWriter output)
    {
        output.WriteLine();
        output.WriteLine("Done.");
        output.WriteLine();
        output.WriteLine("Next, on the server:");
        output.WriteLine("  1. Copy the directory or the archive across, and verify the SHA-256.");
        output.WriteLine("  2. Run 'wpshield preflight' from the copied directory and clear every blocker.");
        output.WriteLine("  3. Run 'wpshield install --path <the copied directory> --dry-run' first, then without it.");
        output.WriteLine();
        output.WriteLine("Copy Invoke-WPShieldTriage.ps1 across too. It is not in this artifact: it is a");
        output.WriteLine("standalone script for hosts that have no WPShield installed yet. See ADR 0003.");
        output.WriteLine();
        output.WriteLine("This is a research preview. It is not approved for production traffic.");
    }

    /// <summary>
    /// Walks up for <c>Directory.Build.props</c>, so the verb works from anywhere in the tree.
    /// </summary>
    internal static string ResolveRepository(string? given)
    {
        if (!string.IsNullOrWhiteSpace(given))
        {
            if (!File.Exists(Path.Combine(given, "Directory.Build.props")))
            {
                throw new CliArgumentException($"{given} has no Directory.Build.props, so it is not the repository root.");
            }

            return Path.GetFullPath(given);
        }

        var directory = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Directory.Build.props")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new CliArgumentException(
            "No Directory.Build.props was found in this directory or any above it. Run this from the repository, or pass --repository.");
    }

    internal static string ReadVersion(string propsFile)
    {
        if (!File.Exists(propsFile))
        {
            throw new CliArgumentException($"Directory.Build.props was not found at {propsFile}.");
        }

        var match = VersionPattern().Match(File.ReadAllText(propsFile));
        if (!match.Success)
        {
            throw new CliArgumentException($"Could not read <Version> from {propsFile}.");
        }

        return match.Groups[1].Value;
    }

    private static string Megabytes(long bytes) =>
        Math.Round(bytes / 1024d / 1024d, 1).ToString(CultureInfo.InvariantCulture);

    [GeneratedRegex(@"<Version>([^<]+)</Version>")]
    private static partial Regex VersionPattern();
}

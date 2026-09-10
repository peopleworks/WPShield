namespace WPShield.Cli.Watch;

/// <summary>
/// Where the gateway's evidence lives, resolved the same way for every verb that reads it.
/// </summary>
/// <remarks>
/// <c>watch</c> and <c>report</c> must never disagree about which directory is the log, so the
/// resolution and the file-name pattern live here once. An explicit path wins; otherwise the
/// installed service's configured directory is used, and failing that the installer's default.
/// </remarks>
internal static class EvidenceLog
{
    /// <summary>The glob every writer and reader in this project agrees the log files match.</summary>
    public const string SearchPattern = "wpshield-*.jsonl";

    /// <summary>Where <c>install</c> puts the log and hardens it, and the last-resort default here.</summary>
    public const string DefaultDirectory = @"C:\ProgramData\WPShield\logs";

    /// <summary>
    /// Resolves the directory to read: the caller's explicit choice, else the installed service's
    /// configured directory, else the installer default. It must exist — a typo that silently read an
    /// empty default would look exactly like a quiet night.
    /// </summary>
    /// <exception cref="CliArgumentException">
    /// An explicit directory does not exist, or nothing was installed and the default is absent.
    /// </exception>
    public static string ResolveDirectory(string? explicitDirectory)
    {
        if (!string.IsNullOrWhiteSpace(explicitDirectory))
        {
            if (!Directory.Exists(explicitDirectory))
            {
                throw new CliArgumentException(
                    $"--log-dir '{explicitDirectory}' does not exist. Point it at the gateway's log directory.");
            }

            return explicitDirectory;
        }

        var configured = InstallationReport.Gather().ConfiguredLogDirectory;
        if (!string.IsNullOrWhiteSpace(configured) && Directory.Exists(configured))
        {
            return configured;
        }

        if (Directory.Exists(DefaultDirectory))
        {
            return DefaultDirectory;
        }

        throw new CliArgumentException(
            "No log directory found. WPShield does not appear to be installed here, and " +
            $"'{DefaultDirectory}' does not exist. Pass --log-dir <dir> to point at a specific log " +
            "folder, for example a copy pulled from a server.");
    }
}

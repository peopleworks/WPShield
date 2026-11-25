using System.Text.RegularExpressions;

namespace WPShield.Evidence;

/// <summary>
/// What a service's or a task's command line says about itself, without keeping the command line
/// (ADR 0013, section 1.3).
/// </summary>
/// <remarks>
/// <b>Arguments are never stored or shown.</b> They can carry a password or a token, and an encoded command
/// is the attacker's payload. The executable path is kept; the rest is reduced to flags here and discarded.
/// Nothing this class returns contains a character of the arguments.
/// </remarks>
public static partial class CommandFlags
{
    public const string HasArguments = "has-arguments";
    public const string EncodedCommand = "encoded-command";
    public const string ContainsUrl = "contains-url";
    public const string UserWritablePath = "user-writable-path";

    /// <summary>The longest command line inspected; the rest is not read.</summary>
    public const int MaxCommandLine = 32 * 1024;

    /// <summary>How many paths of one command line are checked for being user-writable.</summary>
    public const int MaxPathChecks = 4;

    /// <summary>
    /// Splits a command line into its executable and flags. <paramref name="arguments"/> is for sources that
    /// keep them apart (a task's action); a service's <c>ImagePath</c> carries both in <paramref name="commandLine"/>.
    /// </summary>
    /// <param name="isUserWritable">
    /// Whether users or Everyone can write a path - a Windows check, supplied by the reader. <see langword="null"/>
    /// leaves the flag out rather than guessing.
    /// </param>
    public static (string? Executable, IReadOnlyList<string> Flags) Inspect(string? commandLine, string? arguments = null,
        Func<string, bool>? isUserWritable = null)
    {
        var line = Bound(commandLine);
        var (executable, rest) = Split(line);
        var args = string.Join(' ', new[] { rest, Bound(arguments) }.Where(s => !string.IsNullOrWhiteSpace(s))).Trim();

        var flags = new List<string>(4);
        if (args.Length > 0) flags.Add(HasArguments);
        if (Encoded().IsMatch(args)) flags.Add(EncodedCommand);
        if (Url().IsMatch(line) || Url().IsMatch(args)) flags.Add(ContainsUrl);
        if (isUserWritable is not null && Paths(executable, args).Take(MaxPathChecks).Any(Safe(isUserWritable))) flags.Add(UserWritablePath);
        return (executable is null ? null : HostFacts.Clean(executable), flags);
    }

    /// <summary>
    /// The executable of a command line: inside quotes when quoted; otherwise up to the first <c>.exe</c> that
    /// ends a word, and failing that the first space, which is how the service control manager reads it.
    /// </summary>
    internal static (string? Executable, string Arguments) Split(string line)
    {
        var trimmed = line.Trim();
        if (trimmed.Length == 0) return (null, "");
        if (trimmed[0] == '"')
        {
            var end = trimmed.IndexOf('"', 1);
            return end > 1 ? (trimmed[1..end], trimmed[(end + 1)..].Trim()) : (trimmed.Trim('"'), "");
        }
        var exe = ExeEnd().Match(trimmed);
        if (exe.Success) return (trimmed[..exe.Length], trimmed[exe.Length..].Trim());
        var space = trimmed.IndexOf(' ');
        return space > 0 ? (trimmed[..space], trimmed[(space + 1)..].Trim()) : (trimmed, "");
    }

    private static string Bound(string? text) => text is null ? "" : text.Length > MaxCommandLine ? text[..MaxCommandLine] : text;

    private static IEnumerable<string> Paths(string? executable, string args)
    {
        if (!string.IsNullOrWhiteSpace(executable)) yield return executable;
        foreach (Match match in PathToken().Matches(args))
            yield return match.Value.Trim('"');
    }

    private static Func<string, bool> Safe(Func<string, bool> check) => path =>
    {
        try { return check(path); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    };

    /// <summary>PowerShell accepts any unambiguous prefix of <c>-EncodedCommand</c>, and <c>-ec</c>.</summary>
    [GeneratedRegex(@"(?:^|\s)[-/](?:ec|e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?)(?=\s|$|:)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Encoded();

    [GeneratedRegex(@"\b(?:https?|ftp)://", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Url();

    [GeneratedRegex(@"^.+?\.exe(?=\s|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ExeEnd();

    [GeneratedRegex(@"""[A-Za-z]:\\[^""]+""|[A-Za-z]:\\[^\s""]+", RegexOptions.CultureInvariant)]
    private static partial Regex PathToken();
}

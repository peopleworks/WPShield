using System.Globalization;

namespace WPShield.Cli;

/// <summary>
/// The arguments after the verb, parsed the way every other tool in this operator's toolbox parses
/// them.
/// </summary>
/// <remarks>
/// <para>
/// <b>Hand-written rather than <c>System.CommandLine</c>, and that is a deliberate reversal.</b> The
/// first draft of this CLI used the package. It is a good package, it validates types and it
/// generates help — and it does not answer <c>/?</c>, which is the form a Windows operator reaches
/// for first and the one that prompted this migration in the first place.
/// </para>
/// <para>
/// The stronger reason is consistency. SQLDiff, DBFSync and SyncJob already parse arguments exactly
/// like this, print help exactly like this and return exit codes exactly like this. A fourth tool
/// run by the same person at eleven at night should not have its own dialect, and the parsing this
/// needs is fifty lines. A dependency that buys fifty lines and costs a house style is a bad trade.
/// </para>
/// <para>
/// Grammar: <c>--name value</c> or <c>--name=value</c>, and a bare <c>--name</c> is a flag. Lists are
/// comma-separated, following <c>sqldiff --include</c>.
/// </para>
/// </remarks>
internal sealed class CliOptions
{
    private readonly Dictionary<string, string?> _values;

    private CliOptions(Dictionary<string, string?> values)
    {
        _values = values;
    }

    public static CliOptions Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        for (var index = 0; index < args.Count; index++)
        {
            var token = args[index];
            if (!token.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            var separator = token.IndexOf('=', StringComparison.Ordinal);
            if (separator > 2)
            {
                values[token[..separator]] = token[(separator + 1)..];
                continue;
            }

            if (index + 1 < args.Count && !args[index + 1].StartsWith("--", StringComparison.Ordinal))
            {
                values[token] = args[index + 1];
                index++;
                continue;
            }

            // A bare --name is a flag. Stored as null rather than absent, so Has and Get can tell
            // "given with no value" apart from "not given".
            values[token] = null;
        }

        return new CliOptions(values);
    }

    public bool Has(string name) => _values.ContainsKey(name);

    public string? Get(string name) => _values.TryGetValue(name, out var value) ? value : null;

    public string Get(string name, string fallback)
    {
        var value = Get(name);
        return string.IsNullOrWhiteSpace(value) ? fallback : value;
    }

    /// <summary>A flag is true when it is present at all, or present as <c>--name true</c>.</summary>
    public bool Flag(string name)
    {
        if (!_values.TryGetValue(name, out var value))
        {
            return false;
        }

        return value is null || !bool.TryParse(value, out var parsed) || parsed;
    }

    /// <summary>
    /// An integer option, or the fallback. A value that is present and not a number is an error
    /// rather than a silent fallback: an operator who typed <c>--gateway-port 1000O</c> has not
    /// asked for 10000.
    /// </summary>
    public int Integer(string name, int fallback)
    {
        var value = Get(name);
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            throw new CliArgumentException($"{name} must be a number. It was '{value}'.");
        }

        return parsed;
    }

    /// <summary>Comma-separated, following <c>sqldiff --include</c>.</summary>
    public IReadOnlyList<string> List(string name)
    {
        var value = Get(name);
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        return
        [
            .. value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        ];
    }

    public IReadOnlyList<int> IntegerList(string name, IReadOnlyList<int> fallback)
    {
        ArgumentNullException.ThrowIfNull(fallback);

        var values = List(name);
        if (values.Count == 0)
        {
            return fallback;
        }

        var parsed = new List<int>(values.Count);
        foreach (var value in values)
        {
            if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number))
            {
                throw new CliArgumentException($"{name} must be a comma-separated list of numbers. '{value}' is not one.");
            }

            parsed.Add(number);
        }

        return parsed;
    }

    /// <summary>
    /// Refuses an option this verb does not have.
    /// </summary>
    /// <remarks>
    /// A misspelled option that is silently ignored is worse here than an error, because the verbs
    /// this CLI is growing into change a machine: <c>--dry-runn</c> accepted and dropped would run
    /// the real thing while the operator believed they were previewing it.
    /// </remarks>
    public void RejectUnknown(params string[] known)
    {
        ArgumentNullException.ThrowIfNull(known);

        var unknown = _values.Keys
            .Where(key => !known.Contains(key, StringComparer.OrdinalIgnoreCase))
            .Order(StringComparer.Ordinal)
            .ToArray();

        if (unknown.Length > 0)
        {
            throw new CliArgumentException(
                $"Unknown option(s): {string.Join(", ", unknown)}. Known: {string.Join(", ", known.Order(StringComparer.Ordinal))}.");
        }
    }
}

/// <summary>An argument the operator got wrong. Reported as one line, not a stack trace.</summary>
internal sealed class CliArgumentException(string message) : Exception(message);

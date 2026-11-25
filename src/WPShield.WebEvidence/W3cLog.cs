using System.Buffers.Text;
using System.Net;
using System.Text;

namespace WPShield.WebEvidence;

/// <summary>
/// Where each field this sensor reads sits in a W3C log line, taken from the file's own <c>#Fields:</c>
/// directive and never assumed (ADR 0011, section 1).
/// </summary>
/// <remarks>
/// <para>
/// <b>Only the fields read are mapped.</b> The URI query, the referer and the user name have no member
/// here: their columns are skipped by position while a line is split, so no string ever exists for them.
/// The query carries tokens and password-reset links, the referer is a full URL, and the user name names
/// a person; not reading them is the only version that cannot leak them (ADR 0011, "Alternatives").
/// </para>
/// <para>
/// IIS writes a new directive after every restart of a site's logging, and may change the field set
/// when the operator does, so the map is replaced whenever a directive appears.
/// </para>
/// </remarks>
public sealed class W3cFieldMap
{
    /// <summary>The fields without which a line cannot be judged. A directive lacking one leaves the site uncovered.</summary>
    public static readonly IReadOnlyList<string> Required = ["date", "time", "c-ip", "cs-method", "cs-uri-stem", "sc-status"];

    private W3cFieldMap()
    {
    }

    public int Columns { get; private init; }
    internal int Date { get; private init; } = -1;
    internal int Time { get; private init; } = -1;
    internal int ClientIp { get; private init; } = -1;
    internal int ServerPort { get; private init; } = -1;
    internal int Method { get; private init; } = -1;
    internal int UriStem { get; private init; } = -1;
    internal int Status { get; private init; } = -1;
    internal int SubStatus { get; private init; } = -1;
    internal int Win32Status { get; private init; } = -1;
    internal int BytesReceived { get; private init; } = -1;
    internal int TimeTaken { get; private init; } = -1;
    internal int UserAgent { get; private init; } = -1;

    /// <summary>Whether a line is a <c>#Fields:</c> directive.</summary>
    public static bool IsFieldsDirective(ReadOnlySpan<byte> line) => line.StartsWith("#Fields:"u8);

    /// <summary>
    /// Reads a <c>#Fields:</c> directive. Returns the map, or <see langword="null"/> and the first required
    /// field it lacks, written as <c>missing-field: name</c>.
    /// </summary>
    public static W3cFieldMap? Parse(ReadOnlySpan<byte> directive, out string? problem)
    {
        problem = null;
        if (!IsFieldsDirective(directive))
        {
            problem = "not-a-fields-directive";
            return null;
        }

        var rest = directive["#Fields:"u8.Length..];
        int date = -1, time = -1, ip = -1, port = -1, method = -1, stem = -1, status = -1, sub = -1, win32 = -1, bytes = -1, taken = -1, agent = -1;
        var column = 0;
        foreach (var range in rest.Split((byte)' '))
        {
            var name = rest[range].Trim((byte)'\r');
            if (name.IsEmpty) continue;
            if (Is(name, "date"u8)) date = column;
            else if (Is(name, "time"u8)) time = column;
            else if (Is(name, "c-ip"u8)) ip = column;
            else if (Is(name, "s-port"u8)) port = column;
            else if (Is(name, "cs-method"u8)) method = column;
            else if (Is(name, "cs-uri-stem"u8)) stem = column;
            else if (Is(name, "sc-status"u8)) status = column;
            else if (Is(name, "sc-substatus"u8)) sub = column;
            else if (Is(name, "sc-win32-status"u8)) win32 = column;
            else if (Is(name, "cs-bytes"u8)) bytes = column;
            else if (Is(name, "time-taken"u8)) taken = column;
            else if (Is(name, "cs(User-Agent)"u8)) agent = column;
            column++;
        }

        string? missing = date < 0 ? "date" : time < 0 ? "time" : ip < 0 ? "c-ip" : method < 0 ? "cs-method"
            : stem < 0 ? "cs-uri-stem" : status < 0 ? "sc-status" : null;
        if (missing is not null)
        {
            problem = "missing-field: " + missing;
            return null;
        }

        return new W3cFieldMap
        {
            Columns = column,
            Date = date,
            Time = time,
            ClientIp = ip,
            ServerPort = port,
            Method = method,
            UriStem = stem,
            Status = status,
            SubStatus = sub,
            Win32Status = win32,
            BytesReceived = bytes,
            TimeTaken = taken,
            UserAgent = agent
        };
    }

    private static bool Is(ReadOnlySpan<byte> name, ReadOnlySpan<byte> field) => Ascii.EqualsIgnoreCase(name, field);
}

/// <summary>One logged request, reduced to the fields this sensor reads. Nothing else of the line survives.</summary>
/// <param name="Timestamp">W3C writes the date and time in UTC.</param>
/// <param name="Stem">
/// The URI stem as IIS logged it, with the W3C <c>+</c> turned back into a space. Transient: it is
/// normalized before anything is stored, and never stored itself.
/// </param>
public sealed record W3cRequest(DateTimeOffset Timestamp, IPAddress Address, int? ServerPort, string Method, string Stem, int Status,
    int? SubStatus, long? Win32Status, long? BytesReceived, long? TimeTaken, string UserAgent);

/// <summary>Why a line could not be read. Counted, never logged with its content.</summary>
public enum W3cLineProblem
{
    None,

    /// <summary>A comment or directive line other than <c>#Fields:</c>.</summary>
    Comment,

    /// <summary>More or fewer columns than the directive names, or a field that does not parse.</summary>
    Malformed
}

/// <summary>
/// Splits a W3C log line by position. Every column the map does not name is skipped without being
/// decoded, so the query, the referer and the user name never become strings.
/// </summary>
/// <remarks>
/// <para>
/// <b>What the stem is.</b> HTTP.sys hands IIS a URL it has percent-decoded once, and IIS logs that
/// decoded path in <c>cs-uri-stem</c>, UTF-8 encoded when the site logs in UTF-8 (the <c>u_ex</c> files,
/// the default). The HTTP Server API replaces a character that would break the line format with a plus
/// sign (Microsoft, "W3C Logging", HTTP Server API documentation), and fields are separated by spaces,
/// so a space in a path is logged as <c>+</c>. The stem is therefore the same once-decoded path the
/// gateway sees as <c>Request.Path</c>, except that <c>+</c> is ambiguous between a space and a literal
/// plus. It is read back as a space: that is the form under which Windows strips a trailing one at open
/// time, which <see cref="Abstractions.NormalizedRequestPath"/> models, and a literal plus means nothing
/// to any path rule.
/// </para>
/// <para>
/// <b>The second-decode view still applies.</b> A double-encoded <c>%252e</c> reaches the log as
/// <c>%2e</c>, exactly as it reaches the gateway, so building the normalized path from the stem gives the
/// rules the same two views the gateway gives them (AGENTS.md, "Evaluate the second path view").
/// </para>
/// </remarks>
public static class W3cLineParser
{
    /// <summary>The longest stem decoded. Normalization bounds the segments further.</summary>
    public const int MaxStemBytes = 4096;

    /// <summary>The longest user agent decoded; it is cleaned and bounded again before it is stored.</summary>
    public const int MaxUserAgentBytes = 1024;

    private static readonly Encoding Utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false);

    public static W3cLineProblem TryParse(ReadOnlySpan<byte> line, W3cFieldMap map, out W3cRequest? request)
    {
        ArgumentNullException.ThrowIfNull(map);
        request = null;
        if (!line.IsEmpty && line[^1] == (byte)'\r') line = line[..^1];
        if (line.IsEmpty || line[0] == (byte)'#') return W3cLineProblem.Comment;

        ReadOnlySpan<byte> date = default, time = default, ip = default, port = default, method = default, stem = default,
            status = default, sub = default, win32 = default, bytes = default, taken = default, agent = default;
        var column = 0;
        foreach (var range in line.Split((byte)' '))
        {
            // Only the mapped columns are looked at. The rest - the query, the referer, the user name,
            // the server address - are passed over by position and never decoded.
            var value = line[range];
            if (column == map.Date) date = value;
            else if (column == map.Time) time = value;
            else if (column == map.ClientIp) ip = value;
            else if (column == map.ServerPort) port = value;
            else if (column == map.Method) method = value;
            else if (column == map.UriStem) stem = value;
            else if (column == map.Status) status = value;
            else if (column == map.SubStatus) sub = value;
            else if (column == map.Win32Status) win32 = value;
            else if (column == map.BytesReceived) bytes = value;
            else if (column == map.TimeTaken) taken = value;
            else if (column == map.UserAgent) agent = value;
            column++;
        }

        if (column != map.Columns) return W3cLineProblem.Malformed;
        if (!TryTimestamp(date, time, out var timestamp)) return W3cLineProblem.Malformed;
        if (!TryAddress(ip, out var address)) return W3cLineProblem.Malformed;
        if (!IsToken(method)) return W3cLineProblem.Malformed;
        if (!Utf8Parser.TryParse(status, out int code, out var used) || used != status.Length || code is < 100 or > 999)
            return W3cLineProblem.Malformed;
        if (stem.IsEmpty || stem.Length > MaxStemBytes || stem[0] != (byte)'/') return W3cLineProblem.Malformed;

        request = new W3cRequest(timestamp, address, Int(port), Encoding.ASCII.GetString(method).ToUpperInvariant(), Text(stem),
            code, Int(sub), Long(win32), Long(bytes), Long(taken), agent.Length is 0 or > MaxUserAgentBytes || agent.SequenceEqual("-"u8) ? "" : Text(agent));
        return W3cLineProblem.None;
    }

    /// <summary>UTF-8 decoded, invalid bytes replaced, and the W3C <c>+</c> read back as a space.</summary>
    private static string Text(ReadOnlySpan<byte> value) => Utf8.GetString(value).Replace('+', ' ');

    private static bool TryTimestamp(ReadOnlySpan<byte> date, ReadOnlySpan<byte> time, out DateTimeOffset timestamp)
    {
        timestamp = default;
        // yyyy-MM-dd and HH:mm:ss, both UTC in a W3C log.
        if (date.Length != 10 || time.Length != 8 || date[4] != '-' || date[7] != '-' || time[2] != ':' || time[5] != ':') return false;
        if (!Digits(date[..4], out var year) || !Digits(date[5..7], out var month) || !Digits(date[8..], out var day)
            || !Digits(time[..2], out var hour) || !Digits(time[3..5], out var minute) || !Digits(time[6..], out var second))
            return false;
        if (month is < 1 or > 12 || day < 1 || year < 2000 || day > DateTime.DaysInMonth(year, month) || hour > 23 || minute > 59 || second > 59)
            return false;
        timestamp = new DateTimeOffset(year, month, day, hour, minute, second, TimeSpan.Zero);
        return true;
    }

    private static bool Digits(ReadOnlySpan<byte> text, out int value)
    {
        value = 0;
        foreach (var b in text)
        {
            if (b is < (byte)'0' or > (byte)'9') return false;
            value = value * 10 + (b - '0');
        }
        return true;
    }

    private static bool TryAddress(ReadOnlySpan<byte> text, out IPAddress address)
    {
        address = IPAddress.None;
        if (text.IsEmpty || text.Length > 64) return false;
        Span<char> chars = stackalloc char[64];
        for (var i = 0; i < text.Length; i++)
        {
            var b = text[i];
            if (b > 0x7F) return false;
            chars[i] = (char)b;
        }
        if (!IPAddress.TryParse(chars[..text.Length], out var parsed)) return false;
        address = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed;
        return true;
    }

    private static bool IsToken(ReadOnlySpan<byte> method)
    {
        if (method.IsEmpty || method.Length > 16) return false;
        foreach (var b in method)
            if (!(b is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z' or >= (byte)'0' and <= (byte)'9' or (byte)'-' or (byte)'_'))
                return false;
        return true;
    }

    private static int? Int(ReadOnlySpan<byte> text) =>
        Utf8Parser.TryParse(text, out int value, out var used) && used == text.Length && value >= 0 ? value : null;

    private static long? Long(ReadOnlySpan<byte> text) =>
        Utf8Parser.TryParse(text, out long value, out var used) && used == text.Length && value >= 0 ? value : null;
}

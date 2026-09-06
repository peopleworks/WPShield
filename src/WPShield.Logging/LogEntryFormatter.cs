using System.Buffers;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace WPShield.Logging;

/// <summary>
/// Renders one log entry to a single line of UTF-8 JSON.
/// </summary>
/// <remarks>
/// <para>
/// One entry, one line, no indentation, no trailing newline - the writer adds that. JSON Lines is
/// chosen over a human-formatted log because the intended readers are a person tailing the file
/// during a Monitor rollout and, later, whatever aggregates it; a format that is only pleasant for
/// the first of those has to be reparsed by everything else.
/// </para>
/// <para>
/// <b>What this does not do is redact.</b> The chokepoint for that is the call site, which
/// <c>AGENTS.md</c> already binds: no credentials, cookies, authorization headers, nonces, tokens,
/// full query strings or request bodies are passed to a logger in the first place. A formatter that
/// tried to recognise a secret in an arbitrary string would produce false confidence rather than
/// safety, and would silently stop working the first time a value arrived in a shape it did not
/// expect. The automated redaction tests M4 calls for belong against the call sites for the same
/// reason.
/// </para>
/// <para>
/// The one thing this does refuse is <c>{OriginalFormat}</c>. It is the message template rather than
/// data, the rendered message is already present, and emitting both doubles the size of every line
/// for no reader's benefit.
/// </para>
/// </remarks>
public static class LogEntryFormatter
{
    private const string OriginalFormatKey = "{OriginalFormat}";

    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Indented = false,
        // Skipping validation is safe because the shape below is written by this method alone, and
        // it costs a check per token on a path that runs for every log line.
        SkipValidation = true
    };

    public static byte[] Format(
        DateTimeOffset timestamp,
        LogLevel level,
        string category,
        EventId eventId,
        string message,
        IReadOnlyList<KeyValuePair<string, object?>>? state,
        Exception? exception)
    {
        var buffer = new ArrayBufferWriter<byte>(initialCapacity: 512);
        using var writer = new Utf8JsonWriter(buffer, WriterOptions);

        writer.WriteStartObject();
        writer.WriteString("timestamp", timestamp.ToUniversalTime());
        writer.WriteString("level", level.ToString());
        writer.WriteString("category", category);

        if (eventId.Id != 0 || !string.IsNullOrEmpty(eventId.Name))
        {
            writer.WriteNumber("eventId", eventId.Id);
        }

        writer.WriteString("message", message);

        WriteState(writer, state);
        WriteException(writer, exception);

        writer.WriteEndObject();
        writer.Flush();

        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// The line that admits to a gap. It is written by the writer itself rather than through the
    /// logging pipeline, because the pipeline is exactly what was full.
    /// </summary>
    public static byte[] FormatDroppedNotice(DateTimeOffset timestamp, int droppedEntries)
    {
        return Format(
            timestamp,
            LogLevel.Warning,
            "WPShield.Gateway.Logging",
            default,
            "Log entries were dropped because the write queue was full. The gap is in this file, not in what the gateway did.",
            [new KeyValuePair<string, object?>("DroppedEntries", droppedEntries)],
            exception: null);
    }

    private static void WriteState(Utf8JsonWriter writer, IReadOnlyList<KeyValuePair<string, object?>>? state)
    {
        if (state is null || state.Count == 0)
        {
            return;
        }

        var started = false;
        for (var index = 0; index < state.Count; index++)
        {
            var pair = state[index];
            if (string.Equals(pair.Key, OriginalFormatKey, StringComparison.Ordinal))
            {
                continue;
            }

            if (!started)
            {
                writer.WriteStartObject("state");
                started = true;
            }

            WriteValue(writer, pair.Key, pair.Value);
        }

        if (started)
        {
            writer.WriteEndObject();
        }
    }

    /// <summary>
    /// Writes a state value with its own JSON type where the type is unambiguous, and as a string
    /// otherwise.
    /// </summary>
    /// <remarks>
    /// Numbers and booleans are written natively so that a consumer can filter on them without
    /// parsing every value back out of a string. Everything else - including every type this method
    /// has never seen - becomes a string through <see cref="object.ToString"/>, which is the only
    /// conversion that is guaranteed to terminate and to produce something a reader can act on.
    /// </remarks>
    private static void WriteValue(Utf8JsonWriter writer, string name, object? value)
    {
        switch (value)
        {
            case null:
                writer.WriteNull(name);
                break;
            case string text:
                writer.WriteString(name, text);
                break;
            case bool flag:
                writer.WriteBoolean(name, flag);
                break;
            case int number:
                writer.WriteNumber(name, number);
                break;
            case long number:
                writer.WriteNumber(name, number);
                break;
            case double number:
                writer.WriteNumber(name, number);
                break;
            case decimal number:
                writer.WriteNumber(name, number);
                break;
            default:
                writer.WriteString(name, value.ToString());
                break;
        }
    }

    /// <summary>
    /// Writes the exception as type, message and stack trace.
    /// </summary>
    /// <remarks>
    /// The stack trace is included because an Error line from this gateway is meant to mean "WPShield
    /// is broken", and a report of that with no stack is a report nobody can act on. Inner exceptions
    /// arrive inside <see cref="Exception.ToString"/> on the <c>stackTrace</c> field rather than as a
    /// nested structure, which keeps the shape of every line the same.
    /// </remarks>
    private static void WriteException(Utf8JsonWriter writer, Exception? exception)
    {
        if (exception is null)
        {
            return;
        }

        writer.WriteStartObject("exception");
        writer.WriteString("type", exception.GetType().FullName);
        writer.WriteString("message", exception.Message);
        writer.WriteString("stackTrace", exception.ToString());
        writer.WriteEndObject();
    }
}

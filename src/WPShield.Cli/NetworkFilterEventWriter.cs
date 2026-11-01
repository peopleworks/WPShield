using System.Globalization;
using System.Text;
using System.Text.Json;
using WPShield.NetworkFilter;

namespace WPShield.Cli;

/// <summary>
/// Prints network filter events to the console and, optionally, appends them to a JSON Lines file in
/// the gateway's envelope - <c>timestamp, level, category, message, state</c> - so <c>watch</c>,
/// <c>report</c> and an incident timeline read them with the parser they already have.
/// </summary>
/// <remarks>
/// Called from the observer thread and the maintenance timer at once, so every write is serialized.
/// The file is the only thing the network filter writes to disk.
/// </remarks>
internal sealed class NetworkFilterEventWriter : INetworkFilterEventSink, IDisposable
{
    private readonly TextWriter _console;
    private readonly StreamWriter? _file;
    private readonly object _gate = new();

    public NetworkFilterEventWriter(TextWriter console, string? jsonLinesPath)
    {
        ArgumentNullException.ThrowIfNull(console);
        _console = console;
        if (!string.IsNullOrWhiteSpace(jsonLinesPath))
        {
            _file = new StreamWriter(jsonLinesPath, append: true, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
            {
                AutoFlush = true,
            };
        }
    }

    public void Write(NetworkFilterEvent networkFilterEvent)
    {
        ArgumentNullException.ThrowIfNull(networkFilterEvent);

        var line = new StringBuilder()
            .Append(networkFilterEvent.Timestamp.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture))
            .Append(' ')
            .Append(networkFilterEvent.Level.ToString().ToUpperInvariant())
            .Append(' ')
            .Append(networkFilterEvent.Message);
        foreach (var (key, value) in networkFilterEvent.State.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            line.Append(' ').Append(key).Append('=').Append(Format(value));
        }

        lock (_gate)
        {
            _console.WriteLine(line.ToString());
            _file?.WriteLine(ToJson(networkFilterEvent));
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _file?.Dispose();
        }
    }

    internal static string ToJson(NetworkFilterEvent networkFilterEvent)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("timestamp", networkFilterEvent.Timestamp.ToUniversalTime());
            writer.WriteString("level", networkFilterEvent.Level.ToString());
            writer.WriteString("category", NetworkFilterEvent.Category);
            writer.WriteString("message", networkFilterEvent.Message);
            writer.WriteStartObject("state");
            foreach (var (key, value) in networkFilterEvent.State.OrderBy(pair => pair.Key, StringComparer.Ordinal))
            {
                switch (value)
                {
                    case int number:
                        writer.WriteNumber(key, number);
                        break;
                    case bool flag:
                        writer.WriteBoolean(key, flag);
                        break;
                    default:
                        writer.WriteString(key, Format(value));
                        break;
                }
            }

            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static string Format(object value) =>
        Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty;
}

using System.Globalization;
using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;
using WPShield.Evidence;
using WPShield.WebEvidence;

namespace WPShield.WebEvidence.Tests;

/// <summary>
/// Synthetic W3C logs, written the way IIS writes them: the 17 fields the incident host logs, a space
/// between fields, a plus sign for a space inside one. Hosts are <c>.example</c>, addresses RFC 5737.
/// </summary>
internal static class W3c
{
    public const string Fields =
        "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) " +
        "sc-status sc-substatus sc-win32-status sc-bytes cs-bytes time-taken";

    public static string Header(DateTimeOffset at, string fields = Fields) =>
        "#Software: Microsoft Internet Information Services 10.0\r\n#Version: 1.0\r\n" +
        $"#Date: {at.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)}\r\n{fields}\r\n";

    public static string Line(DateTimeOffset at, string method, string stem, string ip, int status, string query = "-",
        string user = "-", string agent = "Mozilla/5.0+(synthetic)", string referer = "-", long received = 400) =>
        $"{at.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)} 192.0.2.10 {method} {stem} {query} 443 {user} {ip} {agent} " +
        $"{referer} {status} 0 0 1234 {received.ToString(CultureInfo.InvariantCulture)} 15\r\n";

    public static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);
}

/// <summary>A temporary store, a fake IIS configuration and log folders, for one test.</summary>
internal sealed class SensorHarness : IDisposable
{
    public static readonly DateTimeOffset Now = new(2026, 11, 25, 12, 0, 0, TimeSpan.Zero);

    public SensorHarness()
    {
        Directory.CreateDirectory(LogRoot);
        Store = EvidenceStore.OpenForWriting(StorePath);
        Sensor = new WebLogSensor(() => Configuration, () => [IPAddress.Parse("192.0.2.10")], Logger);
    }

    public string Root { get; } = Path.Combine(Path.GetTempPath(), "wpshield-web-tests", Guid.NewGuid().ToString("N"));
    public string LogRoot => Path.Combine(Root, "LogFiles");
    public string StorePath => Path.Combine(Root, EvidenceStore.FileName);
    public EvidenceStore Store { get; }
    public RecordingLogger Logger { get; } = new();
    public WebLogSensor Sensor { get; }
    public IisLogConfiguration Configuration { get; set; } = new([], null, null);

    public IisLogSite Site(long id, string name = "shop.example")
    {
        var site = new IisLogSite(id, name, LogRoot, LoggingEnabled: true, "W3C", ServesHttp: true);
        Configuration = Configuration with { Sites = [.. Configuration.Sites.Where(s => s.Id != id), site] };
        Directory.CreateDirectory(site.Folder!);
        return site;
    }

    public string File(long id, string name = "u_ex261125.log") => Path.Combine(LogRoot, "W3SVC" + id.ToString(CultureInfo.InvariantCulture), name);

    public void Append(long id, string text, string name = "u_ex261125.log")
    {
        using var stream = new FileStream(File(id, name), FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        stream.Write(W3c.Bytes(text));
    }

    public WebEvidenceQueries Queries => new(Store);

    public IReadOnlyList<WebFindingRecord> Findings() => Queries.Findings(Now.AddDays(-2), Now.AddDays(2), limit: 500);

    public void Dispose()
    {
        Store.Dispose();
        try { Directory.Delete(Root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}

internal sealed class RecordingLogger : ILogger
{
    private readonly List<string> lines = [];

    public IReadOnlyList<string> Lines
    {
        get { lock (lines) return [.. lines]; }
    }

    public string Text => string.Join('\n', Lines);

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        lock (lines) lines.Add($"{logLevel}: {formatter(state, exception)}");
    }
}

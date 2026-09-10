using System.Text;
using Spectre.Console;
using WPShield.Cli;
using WPShield.Cli.Watch;

namespace WPShield.Cli.Tests.Watch;

/// <summary>
/// Renders one frame of the live layout to a recording console. This is the closest a headless test
/// gets to the operator's screen: it proves the table and footer compose without throwing, that a
/// value carrying markup characters is escaped rather than interpreted, and that the honest counters
/// are what the footer shows.
/// </summary>
public sealed class WatchViewTests : IDisposable
{
    private readonly string _dir;

    public WatchViewTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "wpshield-view-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private static string Line(string message, string state) =>
        $$"""{"timestamp":"2026-09-09T14:30:00.0000000+00:00","level":"Warning","category":"c","message":"{{message}}","state":{{state}}}""";

    [Fact]
    public void A_frame_renders_the_findings_the_actions_and_the_honest_counters()
    {
        var log = Path.Combine(_dir, "wpshield-20260909.jsonl");
        File.WriteAllLines(log,
        [
            Line("Request path finding. x",
                """{"SiteId":"peopleworks.example","RuleId":"WP-PATH-002","Score":100}"""),
            Line("Request path inspected. x",
                """{"SiteId":"peopleworks.example","Method":"GET","Score":100,"Action":"Observe","Mode":"Monitor"}"""),
            Line("Upload inspection complete. x",
                """{"SiteId":"shop.example","Method":"POST","Path":"/wp-admin/async-upload.php","Score":80,"Action":"Block","RuleIds":"WP-UPLOAD-001,WP-UPLOAD-002"}"""),
        ]);

        var session = new WatchSession(new WatchSettings { LogDirectory = _dir, FromStart = true });
        session.PumpOnce();

        var recorder = RecordingConsole();
        session.RenderOnce(recorder);

        var text = recorder.ExportText();

        Assert.Contains("WPShield watch", text);
        Assert.Contains("WP-PATH-002", text);
        Assert.Contains("WP-UPLOAD-001,WP-UPLOAD-002", text);
        Assert.Contains("Block", text);
        Assert.Contains("Observe", text);
        Assert.Contains("findings", text);
        Assert.Contains("blocked", text);

        // If a path is set, drop the rendered frame there so it can be looked at as HTML. Off by
        // default, so the suite writes nothing outside its temp directory.
        var snapshot = Environment.GetEnvironmentVariable("WPSHIELD_WATCH_SNAPSHOT");
        if (!string.IsNullOrWhiteSpace(snapshot))
        {
            File.WriteAllText(snapshot, recorder.ExportHtml(), new UTF8Encoding(false));
        }
    }

    [Fact]
    public void A_site_name_carrying_markup_characters_is_escaped_not_interpreted()
    {
        var log = Path.Combine(_dir, "wpshield-20260909.jsonl");
        File.WriteAllLines(log,
        [
            Line("Request path inspected. x",
                """{"SiteId":"a[red]b.example","Method":"GET","Score":10,"Action":"Observe"}"""),
        ]);

        var session = new WatchSession(new WatchSettings { LogDirectory = _dir, FromStart = true });
        session.PumpOnce();

        var recorder = RecordingConsole();

        // The bug this guards against is a value with a '[' being read as a Spectre markup tag, which
        // throws on an unknown style or silently eats text. Rendering must simply succeed and the
        // literal must survive.
        session.RenderOnce(recorder);

        Assert.Contains("a[red]b.example", recorder.ExportText());
    }

    private static Recorder RecordingConsole()
    {
        var inner = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.Yes,
            ColorSystem = ColorSystemSupport.Standard,
            Out = new AnsiConsoleOutput(new StringWriter())
        });

        inner.Profile.Width = 120;
        inner.Profile.Height = 30;
        return new Recorder(inner);
    }
}

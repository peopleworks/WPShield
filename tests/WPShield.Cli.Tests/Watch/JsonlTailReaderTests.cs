using System.Text;
using WPShield.Cli.Watch;

namespace WPShield.Cli.Tests.Watch;

public sealed class JsonlTailReaderTests : IDisposable
{
    private readonly string _dir;

    public JsonlTailReaderTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "wpshield-tail-" + Guid.NewGuid().ToString("N"));
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

    private string PathTo(string name) => System.IO.Path.Combine(_dir, name);

    private void Append(string name, string text) =>
        File.AppendAllText(PathTo(name), text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

    [Fact]
    public void From_end_ignores_what_was_already_there_then_follows()
    {
        Append("wpshield-20260909.jsonl", "old-line\n");
        var reader = new JsonlTailReader(_dir, fromStart: false);

        Assert.Empty(reader.ReadNewLines());

        Append("wpshield-20260909.jsonl", "new-line\n");
        Assert.Equal(["new-line"], reader.ReadNewLines());
    }

    [Fact]
    public void From_start_returns_the_existing_content_first()
    {
        Append("wpshield-20260909.jsonl", "line-1\nline-2\n");
        var reader = new JsonlTailReader(_dir, fromStart: true);

        Assert.Equal(["line-1", "line-2"], reader.ReadNewLines());
    }

    [Fact]
    public void A_half_written_line_is_held_until_it_is_complete()
    {
        Append("wpshield-20260909.jsonl", "seed\n");
        var reader = new JsonlTailReader(_dir, fromStart: false);
        reader.ReadNewLines();

        // The gateway is mid-write: bytes with no terminating newline yet.
        Append("wpshield-20260909.jsonl", "half-a-");
        Assert.Empty(reader.ReadNewLines());

        Append("wpshield-20260909.jsonl", "line\n");
        Assert.Equal(["half-a-line"], reader.ReadNewLines());
    }

    [Fact]
    public void Rotation_drains_the_old_file_then_reads_the_new_one()
    {
        Append("wpshield-20260909.jsonl", "line-1\n");
        var reader = new JsonlTailReader(_dir, fromStart: false);
        reader.ReadNewLines(); // start at the end of the first file

        // A line lands in the old file, then the gateway rotates and writes to a newer name.
        Append("wpshield-20260909.jsonl", "line-2\n");
        Append("wpshield-20260909_0001.jsonl", "line-3\n");

        Assert.Equal(["line-2", "line-3"], reader.ReadNewLines());
        Assert.Equal("wpshield-20260909_0001.jsonl", reader.CurrentFile);
    }

    [Fact]
    public void Carriage_returns_are_trimmed()
    {
        var reader = new JsonlTailReader(_dir, fromStart: true);
        Append("wpshield-20260909.jsonl", "with-crlf\r\n");

        Assert.Equal(["with-crlf"], reader.ReadNewLines());
    }

    [Fact]
    public void An_empty_directory_returns_nothing_and_no_current_file()
    {
        var reader = new JsonlTailReader(_dir, fromStart: false);

        Assert.Empty(reader.ReadNewLines());
        Assert.Null(reader.CurrentFile);
    }

    [Fact]
    public void Blank_lines_between_records_are_dropped()
    {
        var reader = new JsonlTailReader(_dir, fromStart: true);
        Append("wpshield-20260909.jsonl", "a\n\nb\n");

        Assert.Equal(["a", "b"], reader.ReadNewLines());
    }
}

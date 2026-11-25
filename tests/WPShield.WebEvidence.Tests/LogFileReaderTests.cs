using System.Text;
using WPShield.WebEvidence;
using Xunit;

namespace WPShield.WebEvidence.Tests;

/// <summary>Whole lines only, bounded, from a file another process is still writing.</summary>
public sealed class LogFileReaderTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "wpshield-logreader-tests", Guid.NewGuid().ToString("N"));

    public LogFileReaderTests() => Directory.CreateDirectory(directory);

    public void Dispose()
    {
        try { Directory.Delete(directory, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string Write(string text)
    {
        var path = Path.Combine(directory, "u_ex261125.log");
        File.WriteAllText(path, text, new UTF8Encoding(false));
        return path;
    }

    private static (LogReadResult Result, List<string> Lines) Read(string path, long offset = 0, int max = 1000, bool resync = false)
    {
        var lines = new List<string>();
        var result = LogFileReader.Read(path, offset, max, line => lines.Add(Encoding.UTF8.GetString(line).TrimEnd('\r')), resync);
        return (result, lines);
    }

    [Fact]
    public void ALineIisIsStillWritingIsLeftForTheNextRead()
    {
        var path = Write("one\r\ntwo\r\nthr");

        var (first, lines) = Read(path);

        Assert.Equal(["one", "two"], lines);
        Assert.Equal(10, first.Offset);
        Assert.True(first.AtEnd);

        File.AppendAllText(path, "ee\r\n");
        var (_, rest) = Read(path, first.Offset);
        Assert.Equal(["three"], rest);
    }

    [Fact]
    public void ALineLongerThanTheBoundIsSkippedWholeAndCountedOnce()
    {
        var path = Write("short\n" + new string('x', LogFileReader.MaxLineBytes + 100) + "\nafter\n");

        var (result, lines) = Read(path);

        Assert.Equal(["short", "after"], lines);
        Assert.Equal(1, result.LongLinesSkipped);
        Assert.False(result.InsideDiscardedLine);
    }

    [Fact]
    public void ALongLineStillBeingWrittenIsNotCountedTwice()
    {
        var path = Write("short\n" + new string('x', LogFileReader.MaxLineBytes + 100));

        var (first, _) = Read(path);
        Assert.Equal(1, first.LongLinesSkipped);
        Assert.True(first.InsideDiscardedLine);

        File.AppendAllText(path, "yyyy\nnext\n");
        var (second, lines) = Read(path, first.Offset, resync: first.InsideDiscardedLine);

        Assert.Equal(0, second.LongLinesSkipped);
        Assert.Equal(["next"], lines);
    }

    [Fact]
    public void AtMostTheGivenNumberOfLinesIsRead()
    {
        var path = Write(string.Concat(Enumerable.Range(0, 100).Select(i => $"line{i}\n")));

        var (result, lines) = Read(path, max: 10);

        Assert.Equal(10, lines.Count);
        Assert.False(result.AtEnd);
        var (_, rest) = Read(path, result.Offset);
        Assert.Equal(90, rest.Count);
        Assert.Equal("line10", rest[0]);
    }

    [Fact]
    public void AReadThatStartsInsideALineDropsItsRest()
    {
        var path = Write("first line\nsecond\n");

        var (_, lines) = Read(path, offset: 3, resync: true);

        Assert.Equal(["second"], lines);
    }

    [Fact]
    public void AFileIisHoldsOpenForWritingCanBeRead()
    {
        var path = Path.Combine(directory, "u_ex261126.log");
        using var iis = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
        iis.Write("held\n"u8);
        iis.Flush();

        var (_, lines) = Read(path);

        Assert.Equal(["held"], lines);
    }
}

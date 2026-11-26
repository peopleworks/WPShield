using System.Text;
using Xunit;

namespace WPShield.Desktop.Tests;

/// <summary>The CSV writer behind "Export CSV…": UTF-8 with BOM, RFC 4180 quoting, CRLF, and no formula injection.</summary>
public sealed class CsvExportTests
{
    private static (byte[] Bytes, string Text) Write(IReadOnlyList<string> headers, params IReadOnlyList<object?>[] rows)
    {
        using var stream = new MemoryStream();
        CsvExport.Write(stream, headers, rows);
        var bytes = stream.ToArray();
        return (bytes, Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3));
    }

    [Fact]
    public void TheFileStartsWithAByteOrderMarkAndEndsEveryLineWithCrLf()
    {
        var (bytes, text) = Write(["Dirección", "Peticiones"], ["203.0.113.7", 12L], ["198.51.100.9", 3L]);

        Assert.Equal(new byte[] { 0xEF, 0xBB, 0xBF }, bytes[..3]);
        Assert.Equal("\"Dirección\",\"Peticiones\"\r\n\"203.0.113.7\",12\r\n\"198.51.100.9\",3\r\n", text);
        Assert.DoesNotContain("\n\"", text.Replace("\r\n", "", StringComparison.Ordinal), StringComparison.Ordinal);
    }

    [Fact]
    public void QuotesInsideTextAreDoubledAndCommasStayInsideTheField()
    {
        Assert.Equal("\"say \"\"hi\"\", then go\"", CsvExport.Cell("say \"hi\", then go"));
    }

    [Theory]
    [InlineData("=HYPERLINK(\"http://198.51.100.1/x\",\"ok\")")]
    [InlineData("+cmd|' /C calc'!A0")]
    [InlineData("@SUM(1)")]
    [InlineData("-2+3")]
    [InlineData("  =1+1")]
    [InlineData("＝1+1")]
    public void TextThatASpreadsheetWouldRunIsPrefixedWithAQuote(string hostile)
    {
        var cell = CsvExport.Cell(hostile);

        Assert.StartsWith("\"'", cell, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("\t=1+1")]
    [InlineData("\r=1+1")]
    public void ATabOrCarriageReturnAtTheStartIsCleanedAndNeverLeads(string hostile)
    {
        var cell = CsvExport.Cell(hostile);

        Assert.DoesNotContain('\t', cell);
        Assert.DoesNotContain('\r', cell);
        Assert.StartsWith("\"", cell, StringComparison.Ordinal);
        Assert.False(cell.Length > 1 && cell[1] is '=' or '+' or '-' or '@', cell);
    }

    [Fact]
    public void TheDecisionFollowsTheColumnsTypeNotTheValue()
    {
        // A number WPShield counted is written as a number, even when negative.
        Assert.Equal("-5", CsvExport.Cell(-5));
        Assert.Equal("12", CsvExport.Cell(12L));
        Assert.Equal("0.25", CsvExport.Cell(0.25));
        // The same characters in a text column are text, and neutralised.
        Assert.Equal("\"'-5\"", CsvExport.Cell("-5"));
        Assert.Equal("\"42\"", CsvExport.Cell("42"));
    }

    [Fact]
    public void TimesAreUtcAndKeepMillisecondsOnlyWhenTheyHaveThem()
    {
        Assert.Equal("2026-11-25 23:19:00", CsvExport.Cell(new DateTimeOffset(2026, 11, 25, 18, 19, 0, TimeSpan.FromHours(-5))));
        Assert.Equal("2026-11-25 23:19:00.123", CsvExport.Cell(new DateTimeOffset(2026, 11, 25, 23, 19, 0, 123, TimeSpan.Zero)));
        Assert.Equal("", CsvExport.Cell(null));
        Assert.Equal("true", CsvExport.Cell(true));
    }

    [Fact]
    public void ControlCharactersNeverSplitARowAndLongTextIsBounded()
    {
        var (_, text) = Write(["Path"], ["/a\r\nb‮.php"], [new string('x', 10_000)]);

        var lines = text.Split("\r\n");
        Assert.Equal(4, lines.Length); // header, two rows, and the empty piece after the last CRLF
        Assert.DoesNotContain('‮', text);
        Assert.True(lines[2].Length <= CsvExport.MaxCell + 3, lines[2].Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Assert.EndsWith("…\"", lines[2], StringComparison.Ordinal);
    }
}

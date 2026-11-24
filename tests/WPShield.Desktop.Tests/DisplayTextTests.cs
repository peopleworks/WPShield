using Xunit;

namespace WPShield.Desktop.Tests;

public sealed class DisplayTextTests
{
    [Fact]
    public void KeepsAccentedLetters() =>
        Assert.Equal("Conexión de área local", DisplayText.Clean("Conexión de área local"));

    [Theory]
    [InlineData("eth\u001b[31m0", "eth�[31m0")]
    [InlineData("line\nbreak", "line�break")]
    [InlineData("abc‮gpj.exe", "abc�gpj.exe")]
    [InlineData("zero​width", "zero�width")]
    public void ReplacesControlAndFormatCharacters(string raw, string expected) =>
        Assert.Equal(expected, DisplayText.Clean(raw));

    [Fact]
    public void BoundsTheLength()
    {
        var cleaned = DisplayText.Clean(new string('a', 500), 10);
        Assert.Equal(new string('a', 10) + "…", cleaned);
    }

    [Fact]
    public void EmptyAndNullBecomeEmpty()
    {
        Assert.Equal("", DisplayText.Clean(null));
        Assert.Equal("", DisplayText.Clean(""));
    }
}

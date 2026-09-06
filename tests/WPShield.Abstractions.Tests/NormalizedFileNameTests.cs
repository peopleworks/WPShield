using WPShield.Abstractions;

namespace WPShield.Abstractions.Tests;

public sealed class NormalizedFileNameTests
{
    /// <summary>
    /// Every form here defeats <c>Path.GetExtension</c>, which is what the rule used before this
    /// change. Windows normalizes each of them to <c>shell.php</c> on write, so inspection has to see
    /// the same name the file system will.
    /// </summary>
    [Theory]
    [InlineData("shell.php")]
    [InlineData("shell.php.")]
    [InlineData("shell.php...")]
    [InlineData("shell.php ")]
    [InlineData("shell.php   ")]
    [InlineData("shell.php . . ")]
    [InlineData("shell.php::$DATA")]
    [InlineData("shell.php:extra:$DATA")]
    [InlineData("../shell.php")]
    [InlineData("../../etc/shell.php")]
    [InlineData(@"..\..\shell.php")]
    [InlineData(@"C:\inetpub\wwwroot\shell.php")]
    [InlineData("shell.php\u0000")]
    [InlineData("shell.p\u0000hp")]
    [InlineData("shell\t.php")]
    public void Create_CollapsesWindowsEvasionFormsToTheRealName(string rawFileName)
    {
        var normalized = NormalizedFileName.Create(rawFileName);

        Assert.Equal("shell.php", normalized.BaseName);
        Assert.Equal(".php", normalized.Extension);
        Assert.Equal(["php"], normalized.ExtensionSegments);
    }

    [Theory]
    [InlineData("shell.php.", true, false, false, false)]
    [InlineData("shell.php ", true, false, false, false)]
    [InlineData("shell.php::$DATA", false, true, false, false)]
    [InlineData(@"..\..\shell.php", false, false, true, false)]
    [InlineData("shell.p\u0000hp", false, false, false, true)]
    public void Create_ReportsWhichAnomalyItRemoved(
        string rawFileName,
        bool trailingDotsOrSpaces,
        bool alternateDataStream,
        bool pathSeparator,
        bool controlCharacter)
    {
        var normalized = NormalizedFileName.Create(rawFileName);

        Assert.Equal(trailingDotsOrSpaces, normalized.HadTrailingDotsOrSpaces);
        Assert.Equal(alternateDataStream, normalized.HadAlternateDataStream);
        Assert.Equal(pathSeparator, normalized.HadPathSeparator);
        Assert.Equal(controlCharacter, normalized.HadControlCharacter);
        Assert.True(normalized.HasUnsafeForm);
    }

    [Theory]
    [InlineData("photo.jpg", "jpg")]
    [InlineData("document.pdf", "pdf")]
    [InlineData("Photo.JPG", "jpg")]
    [InlineData("archive.tar.gz", "tar", "gz")]
    [InlineData("style.min.css", "min", "css")]
    [InlineData("report.2024.xlsx", "2024", "xlsx")]
    [InlineData("photo.php.jpg", "php", "jpg")]
    [InlineData("file..php", "php")]
    [InlineData(".htaccess", "htaccess")]
    public void Create_ExposesEveryExtensionSegmentInOrder(string rawFileName, params string[] expected)
    {
        var normalized = NormalizedFileName.Create(rawFileName);

        Assert.Equal(expected, normalized.ExtensionSegments);
    }

    [Theory]
    [InlineData("photo.jpg")]
    [InlineData("My Vacation Photo.jpeg")]
    [InlineData("archive.tar.gz")]
    [InlineData("informe-anual.pdf")]
    [InlineData("presentación-española.pptx")]
    [InlineData("日本語のファイル.png")]
    [InlineData("emoji-🎉-name.gif")]
    [InlineData("no-extension")]
    public void Create_LeavesOrdinaryNamesUnflagged(string rawFileName)
    {
        var normalized = NormalizedFileName.Create(rawFileName);

        Assert.False(normalized.HasUnsafeForm);
        Assert.False(normalized.IsEmpty);
        Assert.Equal(rawFileName, normalized.BaseName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("...")]
    [InlineData("::$DATA")]
    [InlineData("../")]
    public void Create_TreatsNamesThatVanishAsEmpty(string? rawFileName)
    {
        var normalized = NormalizedFileName.Create(rawFileName);

        Assert.True(normalized.IsEmpty);
        Assert.Null(normalized.Extension);
        Assert.Empty(normalized.ExtensionSegments);
    }

    [Theory]
    [InlineData("CON")]
    [InlineData("con.txt")]
    [InlineData("NUL.jpg")]
    [InlineData("LPT1.png")]
    [InlineData("aux.php")]
    public void Create_FlagsReservedWindowsDeviceNames(string rawFileName)
    {
        var normalized = NormalizedFileName.Create(rawFileName);

        Assert.True(normalized.IsReservedDeviceName);
        Assert.True(normalized.HasUnsafeForm);
    }

    [Theory]
    [InlineData("console.txt")]
    [InlineData("nullable.md")]
    [InlineData("auxiliary.png")]
    [InlineData("comment.php")]
    public void Create_DoesNotConfuseOrdinaryNamesWithDeviceNames(string rawFileName)
    {
        Assert.False(NormalizedFileName.Create(rawFileName).IsReservedDeviceName);
    }

    [Fact]
    public void Create_FlagsExcessiveLength()
    {
        var longName = new string('a', NormalizedFileName.MaximumSafeLength) + ".jpg";

        var normalized = NormalizedFileName.Create(longName);

        Assert.True(normalized.ExceedsSafeLength);
        Assert.True(normalized.HasUnsafeForm);
    }

    [Fact]
    public void Create_AcceptsNameAtExactlyTheLengthLimit()
    {
        var boundaryName = new string('a', NormalizedFileName.MaximumSafeLength - 4) + ".jpg";

        var normalized = NormalizedFileName.Create(boundaryName);

        Assert.Equal(NormalizedFileName.MaximumSafeLength, normalized.BaseName.Length);
        Assert.False(normalized.ExceedsSafeLength);
        Assert.False(normalized.HasUnsafeForm);
    }

    [Fact]
    public void Create_PreservesTheRawNameForDiagnostics()
    {
        const string raw = "../../shell.php.";

        var normalized = NormalizedFileName.Create(raw);

        Assert.Equal(raw, normalized.Raw);
        Assert.Equal("shell.php", normalized.BaseName);
    }

    [Theory]
    [InlineData("photo.php.jpg", "php", false)]
    [InlineData("photo.php.jpg", "jpg", true)]
    [InlineData("shell.php", "php", true)]
    public void IsFinalExtension_DistinguishesPositionWithinTheName(
        string rawFileName,
        string extension,
        bool expected)
    {
        Assert.Equal(expected, NormalizedFileName.Create(rawFileName).IsFinalExtension(extension));
    }

    [Fact]
    public void ContextNormalization_IsNotCachedAcrossWithExpressions()
    {
        var context = new InspectionContext("site", "example.test", "POST", "/upload", "photo.jpg");
        _ = context.NormalizedFile;

        var replaced = context with { FileName = "shell.php." };

        Assert.Equal("shell.php", replaced.NormalizedFile.BaseName);
        Assert.Equal("photo.jpg", context.NormalizedFile.BaseName);
    }
}

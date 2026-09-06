namespace WPShield.Abstractions.Tests;

/// <summary>
/// Covers the path normalization the request-path rules match against.
/// </summary>
/// <remarks>
/// The question every case here answers is the same one the file-name normalization answers: <i>which
/// file does a Windows web server actually open for this request?</i> A rule that compares against
/// anything else is comparing against a path that will not be the one served.
/// </remarks>
public sealed class NormalizedRequestPathTests
{
    [Theory]
    [InlineData("/wp-content/uploads/shell.php", "/wp-content/uploads/shell.php")]
    [InlineData("/WP-Content/Uploads/Shell.PHP", "/wp-content/uploads/shell.php")]
    [InlineData("/wp-content//uploads//shell.php", "/wp-content/uploads/shell.php")]
    [InlineData("/wp-content/./uploads/shell.php", "/wp-content/uploads/shell.php")]
    [InlineData("/wp-content/uploads/nested/../shell.php", "/wp-content/uploads/shell.php")]
    [InlineData("/wp-content\\uploads\\shell.php", "/wp-content/uploads/shell.php")]
    [InlineData("/wp-content/uploads/shell.php.", "/wp-content/uploads/shell.php")]
    [InlineData("/wp-content/uploads/shell.php   ", "/wp-content/uploads/shell.php")]
    [InlineData("/wp-content/uploads/shell.php::$DATA", "/wp-content/uploads/shell.php")]
    public void EquivalentForms_NormalizeToTheSamePath(string raw, string expected)
    {
        Assert.Equal(expected, NormalizedRequestPath.Create(raw).Literal.Value);
    }

    [Theory]
    [InlineData("", "/")]
    [InlineData("/", "/")]
    [InlineData(null, "/")]
    public void EmptyAndRootPaths_AreHandled(string? raw, string expected)
    {
        Assert.Equal(expected, NormalizedRequestPath.Create(raw).Literal.Value);
    }

    [Fact]
    public void Traversal_CannotClimbAboveTheRoot()
    {
        var path = NormalizedRequestPath.Create("/../../../../windows/win.ini");

        Assert.Equal("/windows/win.ini", path.Literal.Value);
        Assert.True(path.HadTraversal);
    }

    // ---------------------------------------------------------------------------------------------
    // Anomalies
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/a/../b", nameof(NormalizedRequestPath.HadTraversal))]
    [InlineData("/a\\b", nameof(NormalizedRequestPath.HadBackslash))]
    [InlineData("/a/b.php::$DATA", nameof(NormalizedRequestPath.HadAlternateDataStream))]
    [InlineData("/a/b.php.", nameof(NormalizedRequestPath.HadTrailingDotsOrSpaces))]
    [InlineData("/a//b", nameof(NormalizedRequestPath.HadEmptySegment))]
    public void EachAnomaly_IsRecordedSeparately(string raw, string flag)
    {
        var path = NormalizedRequestPath.Create(raw);

        var value = flag switch
        {
            nameof(NormalizedRequestPath.HadTraversal) => path.HadTraversal,
            nameof(NormalizedRequestPath.HadBackslash) => path.HadBackslash,
            nameof(NormalizedRequestPath.HadAlternateDataStream) => path.HadAlternateDataStream,
            nameof(NormalizedRequestPath.HadTrailingDotsOrSpaces) => path.HadTrailingDotsOrSpaces,
            nameof(NormalizedRequestPath.HadEmptySegment) => path.HadEmptySegment,
            _ => throw new ArgumentOutOfRangeException(nameof(flag), flag, null)
        };

        Assert.True(value, $"{flag} was not recorded for '{raw}'.");
    }

    /// <summary>
    /// A doubled slash is produced constantly by careless URL concatenation, so it is recorded but
    /// must not make a path unsafe on its own.
    /// </summary>
    [Fact]
    public void DoubledSlash_IsRecordedWithoutMakingThePathUnsafe()
    {
        var path = NormalizedRequestPath.Create("/wp-content//themes//example//style.css");

        Assert.True(path.HadEmptySegment);
        Assert.False(path.HasUnsafeForm);
    }

    [Fact]
    public void ControlCharacters_AreStrippedAndRecorded()
    {
        var path = NormalizedRequestPath.Create("/wp-content/uploads/sh\u0000ell.php");

        Assert.True(path.HadControlCharacter);
        Assert.Equal("/wp-content/uploads/shell.php", path.Literal.Value);
    }

    [Fact]
    public void OrdinaryPaths_CarryNoAnomalies()
    {
        var path = NormalizedRequestPath.Create("/wp-content/uploads/2026/09/photo-1024x768.webp");

        Assert.False(path.HasUnsafeForm);
        Assert.Empty(path.Anomalies);
    }

    // ---------------------------------------------------------------------------------------------
    // The second decode
    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// A request written as <c>%252e%252e%252f</c> arrives here decoded once, looking inert, and
    /// becomes traversal one decode later — at a point where nothing is inspecting.
    /// </summary>
    [Fact]
    public void ASecondDecode_ProducesASecondViewWhenItChangesThePath()
    {
        var path = NormalizedRequestPath.Create("/wp-content/%2e%2e%2fwp-config.php");

        Assert.True(path.DivergesWhenDecodedAgain);
        Assert.Equal(2, path.Views.Count);
        Assert.Equal("/wp-config.php", path.Decoded.Value);
        Assert.Contains("doubleEncoded", path.Anomalies);
    }

    [Fact]
    public void APathWithoutPercentSigns_HasOneView()
    {
        var path = NormalizedRequestPath.Create("/wp-content/uploads/photo.jpg");

        Assert.False(path.DivergesWhenDecodedAgain);
        Assert.Single(path.Views);
        Assert.Same(path.Literal, path.Decoded);
    }

    /// <summary>
    /// A malformed escape stays literal. A decoder that repaired or rejected it would answer a
    /// different question than "what would a second naive decode produce".
    /// </summary>
    [Theory]
    [InlineData("/a/b%")]
    [InlineData("/a/b%zz")]
    [InlineData("/a/b%2")]
    public void MalformedEscapes_AreLeftAlone(string raw)
    {
        var path = NormalizedRequestPath.Create(raw);

        Assert.False(path.DivergesWhenDecodedAgain);
    }

    // ---------------------------------------------------------------------------------------------
    // Executable segment search
    // ---------------------------------------------------------------------------------------------

    private static readonly HashSet<string> Php = new(["php"], StringComparer.Ordinal);

    [Fact]
    public void ExecutableSegment_IsFoundInTheFinalSegment()
    {
        var match = NormalizedRequestPath.Create("/a/b/shell.php").Literal.FindExecutableSegment(Php);

        Assert.NotNull(match);
        Assert.Equal(2, match.SegmentIndex);
        Assert.Equal("php", match.Extension);
        Assert.True(match.IsFinalSegment);
        Assert.True(match.IsFinalExtension);
    }

    /// <summary>
    /// PHP path-info execution. The last segment is an image; the executed file is earlier.
    /// </summary>
    [Fact]
    public void ExecutableSegment_IsFoundBeforeAPathInfoSuffix()
    {
        var match = NormalizedRequestPath.Create("/a/shell.php/logo.jpg").Literal.FindExecutableSegment(Php);

        Assert.NotNull(match);
        Assert.Equal(1, match.SegmentIndex);
        Assert.False(match.IsFinalSegment);
    }

    [Fact]
    public void ExecutableSegment_IsFoundInANonFinalExtensionPosition()
    {
        var match = NormalizedRequestPath.Create("/a/shell.php.jpg").Literal.FindExecutableSegment(Php);

        Assert.NotNull(match);
        Assert.Equal("php", match.Extension);
        Assert.False(match.IsFinalExtension);
    }

    [Theory]
    [InlineData("/a/b/photo.jpg")]
    [InlineData("/a/b/php")]
    [InlineData("/a/b/phpinfo")]
    [InlineData("/a/b/notphp.txt")]
    [InlineData("/a/b/.1788607765")]
    public void NonExecutableSegments_AreNotMatched(string raw)
    {
        Assert.Null(NormalizedRequestPath.Create(raw).Literal.FindExecutableSegment(Php));
    }

    // ---------------------------------------------------------------------------------------------
    // Directory queries
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/wp-content/uploads/shell.php", 2)]
    [InlineData("/blog/wp-content/uploads/shell.php", 3)]
    [InlineData("/wp-content/plugins/x/shell.php", -1)]
    [InlineData("/uploads/wp-content/shell.php", -1)]
    public void IndexAfterSequence_MatchesAConsecutiveRunOnly(string raw, int expected)
    {
        var view = NormalizedRequestPath.Create(raw).Literal;

        Assert.Equal(expected, view.IndexAfterSequence(["wp-content", "uploads"]));
    }

    [Fact]
    public void IndexOfSegment_FindsTheFirstNamedDirectory()
    {
        var view = NormalizedRequestPath.Create("/wp-content/plugins/x/static/y/shell.php").Literal;

        Assert.Equal(3, view.IndexOfSegment(new HashSet<string>(["static"], StringComparer.Ordinal)));
    }

    // ---------------------------------------------------------------------------------------------
    // Bounds
    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// A deep path is truncated and flagged rather than walked, so a request cannot make
    /// normalization expensive by being long.
    /// </summary>
    [Fact]
    public void ADeepPath_IsBoundedAndRecorded()
    {
        var raw = "/" + string.Join('/', Enumerable.Range(0, NormalizedRequestPath.MaximumSegments + 20)
            .Select(index => $"s{index}"));

        var path = NormalizedRequestPath.Create(raw);

        Assert.True(path.ExceedsBounds);
        Assert.Equal(NormalizedRequestPath.MaximumSegments, path.Literal.Segments.Count);
        Assert.True(path.HasUnsafeForm);
    }

    [Fact]
    public void ALongSegment_IsTruncatedAndRecorded()
    {
        var raw = "/" + new string('a', NormalizedRequestPath.MaximumSegmentLength + 50);

        var path = NormalizedRequestPath.Create(raw);

        Assert.True(path.ExceedsBounds);
        Assert.Equal(NormalizedRequestPath.MaximumSegmentLength, path.Literal.Segments[0].Length);
    }

    // ---------------------------------------------------------------------------------------------
    // Contract
    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// The context recomputes the normalization on each access, so a <c>with</c> expression cannot
    /// hand a rule a normalization of a path that was replaced.
    /// </summary>
    [Fact]
    public void InspectionContext_RecomputesTheNormalizedPath()
    {
        var context = new InspectionContext("site", "example.test", "GET", "/wp-content/uploads/a.php");
        var replaced = context with { Path = "/wp-content/uploads/b.php" };

        Assert.Equal("/wp-content/uploads/a.php", context.NormalizedPath.Literal.Value);
        Assert.Equal("/wp-content/uploads/b.php", replaced.NormalizedPath.Literal.Value);
    }

    [Fact]
    public void Raw_IsPreservedButNeverUsedForComparison()
    {
        const string raw = "/wp-content/UPLOADS/shell.php.";

        var path = NormalizedRequestPath.Create(raw);

        Assert.Equal(raw, path.Raw);
        Assert.NotEqual(raw, path.Literal.Value);
    }
}

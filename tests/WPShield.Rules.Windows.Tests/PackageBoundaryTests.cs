namespace WPShield.Rules.Windows.Tests;

/// <summary>
/// The layering the split rests on, asserted rather than documented.
/// </summary>
/// <remarks>
/// <para>
/// <c>WPShield.Rules.WordPress</c> references this package and never the reverse: WordPress on Windows
/// is the specialisation. The first rule that reaches back "for one constant" makes the two packages a
/// single package again under two names, and nothing in a build would say so until the reference
/// became a cycle. So it is checked here, against the compiled assembly.
/// </para>
/// <para>
/// The second assertion is the portability claim the Linux CI leg makes, stated where a reader of this
/// package will find it: "Windows" names the attack surface these rules understand, not a platform they
/// depend on. A package that can be built on Linux can still reference a Windows-only assembly that
/// happens to compile there, and this catches that case too.
/// </para>
/// </remarks>
public sealed class PackageBoundaryTests
{
    private static IReadOnlyList<string> ReferencedAssemblies() =>
        [.. typeof(DangerousUploadExtensions).Assembly.GetReferencedAssemblies().Select(name => name.Name ?? string.Empty)];

    /// <summary>
    /// The positive control. Every assertion below is a "does not contain", and those pass just as well
    /// against an empty list; this proves the list is the real one.
    /// </summary>
    [Fact]
    public void TheReferenceListIsReal_AndIncludesTheContracts()
    {
        Assert.Contains("WPShield.Abstractions", ReferencedAssemblies());
    }

    [Fact]
    public void TheWindowsRules_NeverReferenceTheWordPressRules()
    {
        Assert.DoesNotContain("WPShield.Rules.WordPress", ReferencedAssemblies());
    }

    [Theory]
    [InlineData("Microsoft.AspNetCore")]
    [InlineData("Yarp")]
    [InlineData("Microsoft.Web.Administration")]
    [InlineData("System.ServiceProcess")]
    [InlineData("Microsoft.Win32.Registry")]
    [InlineData("WPShield.Gateway")]
    [InlineData("WPShield.Core")]
    public void TheWindowsRules_ReferenceNothingThatTiesThemToAHostOrAPlatform(string forbiddenPrefix)
    {
        Assert.DoesNotContain(
            ReferencedAssemblies(),
            name => name.StartsWith(forbiddenPrefix, StringComparison.Ordinal));
    }
}

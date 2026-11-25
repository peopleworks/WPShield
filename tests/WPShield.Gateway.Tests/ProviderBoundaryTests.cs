using System.Xml.Linq;

namespace WPShield.Gateway.Tests;

/// <summary>
/// The gateway never reaches a model provider (ADR 0010, section 5): it references neither the analyst
/// nor a provider SDK, directly or through any project it builds on. Asserted three ways, because each
/// alone has a blind spot - a compiled reference list misses a reference nothing uses yet, an output
/// directory misses a reference that is not copied, and the project files miss a hand-placed binary.
/// </summary>
public sealed class ProviderBoundaryTests
{
    private static readonly string[] Forbidden = ["WPShield.Analyst", "Anthropic"];

    [Fact]
    public void TheGatewayAssemblyReferencesNoAnalystAndNoProviderSdk()
    {
        var referenced = typeof(GatewayConfigurationValidator).Assembly.GetReferencedAssemblies().Select(a => a.Name ?? "").ToArray();

        // Positive control: the list is the real one.
        Assert.Contains("WPShield.Core", referenced);
        foreach (var name in Forbidden)
            Assert.DoesNotContain(referenced, r => r.Equals(name, StringComparison.Ordinal) || r.StartsWith(name + ".", StringComparison.Ordinal));
    }

    [Fact]
    public void NoAnalystOrProviderAssemblyIsCopiedBesideTheGateway()
    {
        var output = AppContext.BaseDirectory;

        Assert.True(File.Exists(Path.Combine(output, "WPShield.Gateway.dll")));
        Assert.False(File.Exists(Path.Combine(output, "WPShield.Analyst.dll")));
        Assert.False(File.Exists(Path.Combine(output, "Anthropic.dll")));
    }

    [Fact]
    public void NoProjectTheGatewayBuildsOnReferencesTheAnalystOrAProviderSdk()
    {
        var gateway = Path.Combine(RepositoryRoot(), "src", "WPShield.Gateway", "WPShield.Gateway.csproj");
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pending = new Stack<string>([Path.GetFullPath(gateway)]);
        while (pending.Count > 0)
        {
            var project = pending.Pop();
            if (!seen.Add(project)) continue;
            var document = XDocument.Load(project);
            foreach (var package in document.Descendants("PackageReference"))
                Assert.DoesNotContain("Anthropic", (string?)package.Attribute("Include") ?? "", StringComparison.OrdinalIgnoreCase);
            foreach (var reference in document.Descendants("ProjectReference"))
            {
                var path = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(project)!, ((string)reference.Attribute("Include")!).Replace('\\', '/')));
                Assert.DoesNotContain("WPShield.Analyst", Path.GetFileName(path), StringComparison.OrdinalIgnoreCase);
                pending.Push(path);
            }
        }
        // Positive control: the walk reached the gateway's own references.
        Assert.Contains(seen, p => p.EndsWith("WPShield.Core.csproj", StringComparison.OrdinalIgnoreCase));
    }

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "WPShield.slnx"))) return directory.FullName;
        throw new InvalidOperationException("The repository root (WPShield.slnx) was not found above the test output.");
    }
}

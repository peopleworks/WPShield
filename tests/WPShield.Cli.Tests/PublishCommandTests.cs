namespace WPShield.Cli.Tests;

/// <summary>
/// The parts of <c>wpshield publish</c> that can be decided without running a build. The build,
/// the archive and the shared-runtime assertion are exercised by running the verb.
/// </summary>
public sealed class PublishCommandTests : IDisposable
{
    private readonly string _root = Path.Combine(
        AppContext.BaseDirectory, "publish-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public void TheVersionIsReadFromDirectoryBuildProps()
    {
        var props = Write("Directory.Build.props", "<Project><PropertyGroup><Version>1.4.2</Version></PropertyGroup></Project>");

        Assert.Equal("1.4.2", PublishCommand.ReadVersion(props));
    }

    /// <summary>
    /// The archive name and the assembly version both come from this file, so a version that cannot
    /// be read is an error rather than a default. An artifact named for the wrong version is one
    /// somebody installs believing it is something else.
    /// </summary>
    [Fact]
    public void APropsFileWithNoVersion_IsAnError()
    {
        var props = Write("Directory.Build.props", "<Project><PropertyGroup></PropertyGroup></Project>");

        var exception = Assert.Throws<CliArgumentException>(() => PublishCommand.ReadVersion(props));
        Assert.Contains("Could not read <Version>", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AMissingPropsFile_IsAnError()
    {
        Assert.Throws<CliArgumentException>(
            () => PublishCommand.ReadVersion(Path.Combine(_root, "nowhere", "Directory.Build.props")));
    }

    [Fact]
    public void AnExplicitRepositoryWithoutThePropsFile_IsRefused()
    {
        Directory.CreateDirectory(_root);

        var exception = Assert.Throws<CliArgumentException>(() => PublishCommand.ResolveRepository(_root));
        Assert.Contains("not the repository root", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnExplicitRepositoryWithThePropsFile_IsAccepted()
    {
        Write("Directory.Build.props", "<Project><PropertyGroup><Version>0.1.0</Version></PropertyGroup></Project>");

        Assert.Equal(Path.GetFullPath(_root), PublishCommand.ResolveRepository(_root));
    }

    /// <summary>
    /// The repository is found by walking up, so the verb works from anywhere in the tree rather
    /// than only from the root.
    /// </summary>
    [Fact]
    public void TheRepositoryIsFoundByWalkingUpFromTheCurrentDirectory()
    {
        Write("Directory.Build.props", "<Project><PropertyGroup><Version>0.1.0</Version></PropertyGroup></Project>");
        var deep = Path.Combine(_root, "src", "WPShield.Cli");
        Directory.CreateDirectory(deep);

        var previous = Directory.GetCurrentDirectory();
        try
        {
            Directory.SetCurrentDirectory(deep);
            Assert.Equal(Path.GetFullPath(_root), PublishCommand.ResolveRepository(null));
        }
        finally
        {
            Directory.SetCurrentDirectory(previous);
        }
    }

    private string Write(string name, string content)
    {
        Directory.CreateDirectory(_root);
        var path = Path.Combine(_root, name);
        File.WriteAllText(path, content);
        return path;
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}

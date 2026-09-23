using WPShield.Abstractions;

namespace WPShield.Rules.Windows.Tests;

/// <summary>
/// <c>EXPOSE-PATH-001</c> to <c>005</c> - the files a web root gives away when a project folder is
/// copied up whole.
/// </summary>
/// <remarks>
/// The firing cases are shapes taken from a week of real IIS logs, reduced to paths: no host, no
/// client address. The silent cases are the reason each rule is a shape and not a prefix - the
/// neighbours that look alike and have a legitimate caller.
/// </remarks>
public sealed class ExposurePathRuleTests
{
    private static InspectionContext Request(string path) => new("site", "example.test", "GET", path);

    // ---------------------------------------------------------------------------------------------
    // EXPOSE-PATH-001 - dotenv
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/.env")]
    [InlineData("/.ENV")]
    [InlineData("/.env.production")]
    [InlineData("/.env.local")]
    [InlineData("/.env.backup")]
    [InlineData("/.env-example")]
    [InlineData("/.env_copy")]
    [InlineData("/.env2")]
    // Any folder. A list of paths from a scanner catalogue missed most of these.
    [InlineData("/backend/.env")]
    [InlineData("/app/config/.env")]
    [InlineData("/laravel/.env.production")]
    // A .env folder - a Python virtual environment is often named that.
    [InlineData("/.env/lib/site.py")]
    // What normalization undoes before the rule looks.
    [InlineData("/.env.")]
    [InlineData("/.env::$DATA")]
    [InlineData("\\app\\.env")]
    public async Task ADotenvSegment_IsBlockedWherever_ItSits(string path)
    {
        var finding = await new DotEnvRequestRule().EvaluateAsync(Request(path));

        Assert.NotNull(finding);
        Assert.Equal("EXPOSE-PATH-001", finding.RuleId);
        Assert.Equal(100, finding.Score);
    }

    [Theory]
    // A different file that starts with the same letters.
    [InlineData("/.envrc")]
    [InlineData("/.environment")]
    // Words, not files.
    [InlineData("/env")]
    [InlineData("/environment/settings")]
    [InlineData("/blog/how-to-use-.env-files")]
    [InlineData("/docs/dotenv.html")]
    public async Task NamesThatOnlyLookLikeDotenv_StaySilent(string path)
    {
        Assert.Null(await new DotEnvRequestRule().EvaluateAsync(Request(path)));
    }

    /// <summary>
    /// The second decode. <c>%65</c> is <c>e</c>: a request the host decoded once to <c>/.%65nv</c>
    /// becomes <c>/.env</c> on a rewrite chain that decodes again, and the rule sees that view too.
    /// </summary>
    [Fact]
    public async Task ADotenvHiddenBehindASecondEncoding_IsFoundInTheDecodedView()
    {
        var finding = await new DotEnvRequestRule().EvaluateAsync(Request("/.%65nv"));

        Assert.NotNull(finding);
        Assert.NotNull(finding.Evidence);
        Assert.Equal(RequestPathView.DecodedToken, finding.Evidence["view"]);
        Assert.Equal("/.env", finding.Evidence["normalizedPath"]);
    }

    // ---------------------------------------------------------------------------------------------
    // EXPOSE-PATH-002 - version control
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/.git/config")]
    [InlineData("/.git/HEAD")]
    [InlineData("/.git")]
    [InlineData("/.svn/wc.db")]
    [InlineData("/.hg/store/data")]
    [InlineData("/.bzr/branch/branch.conf")]
    [InlineData("/server/.git/config")]
    // Trailing dots are stripped the way Windows strips them, so this reaches /events/.git/config.
    [InlineData("/events../.git/config")]
    public async Task AVersionControlFolder_IsBlocked(string path)
    {
        var finding = await new VersionControlRequestRule().EvaluateAsync(Request(path));

        Assert.NotNull(finding);
        Assert.Equal("EXPOSE-PATH-002", finding.RuleId);
        Assert.Equal(100, finding.Score);
    }

    [Theory]
    [InlineData("/.gitignore")]
    [InlineData("/.gitattributes")]
    [InlineData("/.github/workflows/build.yml")]
    [InlineData("/.gitlab-ci.yml")]
    // Certificate renewal. A rule shaped as "any dot-folder" would break this on every site.
    [InlineData("/.well-known/acme-challenge/token-value")]
    [InlineData("/.well-known/security.txt")]
    [InlineData("/git/")]
    public async Task NeighboursOfVersionControl_StaySilent(string path)
    {
        Assert.Null(await new VersionControlRequestRule().EvaluateAsync(Request(path)));
    }

    // ---------------------------------------------------------------------------------------------
    // EXPOSE-PATH-003 - credential stores and tool state
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/.aws/credentials", "folder")]
    [InlineData("/.config/gcloud/application_default_credentials.json", "folder")]
    [InlineData("/.docker/config.json", "folder")]
    [InlineData("/.kube/config", "folder")]
    [InlineData("/.ssh/authorized_keys", "folder")]
    [InlineData("/.vscode/sftp.json", "folder")]
    [InlineData("/.terraform/terraform.tfstate", "folder")]
    [InlineData("/.claude/settings.json", "folder")]
    [InlineData("/.codex/auth.json", "folder")]
    [InlineData("/.git-credentials", "file")]
    [InlineData("/.npmrc", "file")]
    [InlineData("/.netrc", "file")]
    [InlineData("/.htpasswd", "file")]
    [InlineData("/id_rsa", "privateKey")]
    [InlineData("/id_ed25519.pub", "privateKey")]
    [InlineData("/backup/id_rsa.bak", "privateKey")]
    public async Task ACredentialStore_IsBlockedAndSaysWhatKindItIs(string path, string kind)
    {
        var finding = await new CredentialStoreRequestRule().EvaluateAsync(Request(path));

        Assert.NotNull(finding);
        Assert.Equal("EXPOSE-PATH-003", finding.RuleId);
        Assert.Equal(100, finding.Score);
        Assert.NotNull(finding.Evidence);
        Assert.Equal(kind, finding.Evidence["kind"]);
    }

    [Theory]
    [InlineData("/.github/dependabot.yml")]
    [InlineData("/.gitlab-ci.yml")]
    [InlineData("/config/app.json")]
    [InlineData("/aws/")]
    [InlineData("/docs/id_rsa_setup_guide")]
    [InlineData("/.well-known/openid-configuration")]
    public async Task NamesNextToCredentialStores_StaySilent(string path)
    {
        Assert.Null(await new CredentialStoreRequestRule().EvaluateAsync(Request(path)));
    }

    // ---------------------------------------------------------------------------------------------
    // EXPOSE-PATH-004 - backup copies
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/wp-config.php.bak", "bak")]
    [InlineData("/web.config.old", "old")]
    [InlineData("/.env.save", "save")]
    [InlineData("/.env.backup", "backup")]
    [InlineData("/index.php~", "~")]
    [InlineData("/.wp-config.php.swp", "swp")]
    [InlineData("/config.orig", "orig")]
    [InlineData("/credentials.old", "old")]
    public async Task ABackupCopyOfANamedFile_IsBlocked(string path, string form)
    {
        var finding = await new BackupCopyRequestRule().EvaluateAsync(Request(path));

        Assert.NotNull(finding);
        Assert.Equal("EXPOSE-PATH-004", finding.RuleId);
        Assert.Equal(100, finding.Score);
        Assert.NotNull(finding.Evidence);
        Assert.Equal(form, finding.Evidence["form"]);
    }

    [Theory]
    // A backup suffix inside a name is not a backup.
    [InlineData("/uploads/photo.bak.jpg")]
    [InlineData("/files/report.old.pdf")]
    // A native database backup is EXPOSE-PATH-005's, which observes: a site may publish one.
    [InlineData("/downloads/sample-database.bak")]
    [InlineData("/downloads/export.backup")]
    // Folders named like suffixes.
    [InlineData("/old/index.html")]
    [InlineData("/backup/")]
    [InlineData("/~")]
    public async Task ThingsThatAreNotABackupCopy_StaySilent(string path)
    {
        Assert.Null(await new BackupCopyRequestRule().EvaluateAsync(Request(path)));
    }

    // ---------------------------------------------------------------------------------------------
    // EXPOSE-PATH-005 - database files and dumps
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/database.sql", "sql")]
    [InlineData("/backup/db.sql", "sql")]
    [InlineData("/dump.sql.gz", "sql")]
    [InlineData("/data/db.sqlite", "sqlite")]
    [InlineData("/db.sqlite3", "sqlite3")]
    [InlineData("/App_Data/site.mdb", "mdb")]
    [InlineData("/mysql.dump", "dump")]
    [InlineData("/downloads/sample-database.bak", "bak")]
    public async Task ADatabaseFile_IsObservedButNeverBlockedAlone(string path, string extension)
    {
        var finding = await new DatabaseDumpRequestRule().EvaluateAsync(Request(path));

        Assert.NotNull(finding);
        Assert.Equal("EXPOSE-PATH-005", finding.RuleId);
        Assert.Equal(30, finding.Score);
        Assert.NotNull(finding.Evidence);
        Assert.Equal(extension, finding.Evidence["extension"]);
    }

    [Theory]
    // Archives are ordinary downloads, and a compressed sitemap is a sitemap.
    [InlineData("/sitemap.xml.gz")]
    [InlineData("/downloads/brochure.zip")]
    [InlineData("/release.tar.gz")]
    [InlineData("/setup.7z")]
    [InlineData("/sql/")]
    [InlineData("/docs/sql-tutorial.html")]
    public async Task ArchivesAndPagesAboutSql_StaySilent(string path)
    {
        Assert.Null(await new DatabaseDumpRequestRule().EvaluateAsync(Request(path)));
    }

    // ---------------------------------------------------------------------------------------------
    // Contracts shared by the family
    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// Evidence carries the normalized path and never the raw target. An escape sequence in the raw
    /// path would otherwise reach a terminal or a log viewer intact.
    /// </summary>
    [Fact]
    public async Task Evidence_IsTheNormalizedPathNeverTheRawTarget()
    {
        const string escape = "\u001b";
        var finding = await new DotEnvRequestRule().EvaluateAsync(Request($"/ap{escape}[31mp/.env"));

        Assert.NotNull(finding);
        Assert.NotNull(finding.Evidence);
        Assert.All(finding.Evidence.Values, value => Assert.DoesNotContain(escape, value, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Rules_HonourCancellation()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await new VersionControlRequestRule().EvaluateAsync(Request("/.git/config"), cancelled.Token));
    }

    /// <summary>
    /// The scores, pinned. A blocking score here is a claim that the shape has no legitimate caller,
    /// and the observing ones are observing on purpose. Changing either is a decision, so it has to
    /// fail a test first.
    /// </summary>
    [Fact]
    public void Scores_AreThePublishedCalibration()
    {
        Assert.Equal(100, DotEnvRequestRule.Score);
        Assert.Equal(100, VersionControlRequestRule.Score);
        Assert.Equal(100, CredentialStoreRequestRule.Score);
        Assert.Equal(100, BackupCopyRequestRule.Score);
        Assert.Equal(30, DatabaseDumpRequestRule.Score);
    }
}

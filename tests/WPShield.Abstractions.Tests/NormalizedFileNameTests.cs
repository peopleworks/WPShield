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

    // ---------------------------------------------------------------------------------------------
    // The WordPress view — F4
    //
    // Everything above this line is the NTFS view, and none of it was meant to change. What follows
    // covers the second view: the name WordPress's sanitize_file_name() would write. The two views
    // exist because two different components decide the final name and they disagree, and an
    // attacker only needs one of the two answers to be dangerous.
    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// The deletion set. <c>sanitize_file_name()</c> does not replace these characters, it
    /// <b>removes</b> them and lets the neighbours close up, which is the whole of the attack: one
    /// brace inside an extension token is invisible to a check that reads the name as sent, and gone
    /// by the time the file is on disk.
    /// </summary>
    /// <remarks>
    /// The seven rows the adversarial review measured come first, then one row for every remaining
    /// character in WordPress's default set that can sit inside an extension. <c>/</c> and <c>\</c>
    /// are deliberately absent: PHP's <c>_php_rfc1867_basename()</c> runs first, so a separator never
    /// reaches <c>sanitize_file_name()</c> — that case is
    /// <see cref="Create_DerivesTheWordPressViewFromTheFinalPathSegment"/>.
    /// </remarks>
    [Theory]
    [InlineData("shell.p{h}p", "shell.php")]
    [InlineData("shell.php-", "shell.php")]
    [InlineData("shell.p%hp", "shell.php")]
    [InlineData("web.con{f}ig", "web.config")]
    [InlineData("web.config-", "web.config")]
    [InlineData("shell.as{p}x", "shell.aspx")]
    [InlineData("shell.p(h)p", "shell.php")]
    [InlineData("shell.p!hp", "shell.php")]
    [InlineData("shell.p+hp", "shell.php")]
    [InlineData("shell.p#hp", "shell.php")]
    [InlineData("shell.p~hp", "shell.php")]
    [InlineData("shell.php_", "shell.php")]
    [InlineData("shell.p\u0060hp", "shell.php")]
    [InlineData("shell.p?hp", "shell.php")]
    [InlineData("shell.p[h]p", "shell.php")]
    [InlineData("shell.p=hp", "shell.php")]
    [InlineData("shell.p<hp", "shell.php")]
    [InlineData("shell.p>hp", "shell.php")]
    [InlineData("shell.p;hp", "shell.php")]
    [InlineData("shell.p,hp", "shell.php")]
    [InlineData("shell.p'hp", "shell.php")]
    [InlineData("shell.p\"hp", "shell.php")]
    [InlineData("shell.p&hp", "shell.php")]
    [InlineData("shell.p$hp", "shell.php")]
    [InlineData("shell.p*hp", "shell.php")]
    [InlineData("shell.p|hp", "shell.php")]
    [InlineData("shell.p\u2019hp", "shell.php")]
    [InlineData("shell.p\u00abhp", "shell.php")]
    [InlineData("shell.p\u201chp", "shell.php")]
    public void WordPressView_DeletesTheCharactersSanitizeFileNameDeletes(string rawFileName, string expected)
    {
        var normalized = NormalizedFileName.Create(rawFileName);

        Assert.Equal(expected, normalized.WordPress.BaseName);
        Assert.True(normalized.DivergesUnderWordPress);
    }

    /// <summary>
    /// The NTFS view must not move when the WordPress view does. These are the same payloads as
    /// above: Windows writes them verbatim, which is exactly why the name as sent looks inert.
    /// </summary>
    [Theory]
    [InlineData("shell.p{h}p")]
    [InlineData("shell.php-")]
    [InlineData("shell.p%hp")]
    [InlineData("web.con{f}ig")]
    [InlineData("web.config-")]
    [InlineData("shell.as{p}x")]
    [InlineData("shell.php_")]
    public void WordPressView_DoesNotDisturbTheNtfsView(string rawFileName)
    {
        var normalized = NormalizedFileName.Create(rawFileName);

        Assert.Equal(rawFileName, normalized.Windows.BaseName);
        Assert.Equal(rawFileName, normalized.BaseName);
        Assert.Equal(FileNameView.NtfsToken, normalized.Windows.Token);
        Assert.Equal(FileNameView.WordPressToken, normalized.WordPress.Token);
    }

    /// <summary>
    /// <c>trim($filename, '.-_')</c>, the last line of <c>sanitize_file_name()</c>. NTFS strips a
    /// trailing dot and nothing else, so a trailing hyphen or underscore is a character Windows keeps
    /// and WordPress throws away — a divergence in the opposite direction from the deletion set.
    /// </summary>
    [Theory]
    [InlineData("shell.php-", "shell.php")]
    [InlineData("shell.php_", "shell.php")]
    [InlineData("shell.php~", "shell.php")]
    [InlineData("web.config-", "web.config")]
    [InlineData("functions.php-", "functions.php")]
    [InlineData("-photo.jpg", "photo.jpg")]
    [InlineData("_draft.pdf", "draft.pdf")]
    [InlineData(".htaccess", "htaccess")]
    public void WordPressView_TrimsDotsHyphensAndUnderscoresFromBothEnds(string rawFileName, string expected)
    {
        Assert.Equal(expected, NormalizedFileName.Create(rawFileName).WordPress.BaseName);
    }

    /// <summary>
    /// <c>preg_replace('/[\r\n\t -]+/', '-')</c>. Whitespace is <b>replaced</b>, not deleted, and the
    /// distinction decides whether a name is dangerous: <c>shell.p{h}p</c> becomes an executable
    /// script, <c>shell.ph p</c> becomes the inert <c>shell.ph-p</c>. A view that deleted whitespace
    /// too would report every file name with a space in it.
    /// </summary>
    [Theory]
    [InlineData("shell.ph p", "shell.ph-p")]
    [InlineData("shell.p\u00a0hp", "shell.p-hp")]
    [InlineData("web.co nfig", "web.co-nfig")]
    [InlineData("my file - copy.docx", "my-file-copy.docx")]
    [InlineData("Captura de pantalla (3).png", "Captura-de-pantalla-3.png")]
    [InlineData("50% off banner.png", "50-off-banner.png")]
    [InlineData("sh ell.php", "sh-ell.php")]
    public void WordPressView_CollapsesWhitespaceAndHyphenRunsIntoOneHyphen(string rawFileName, string expected)
    {
        Assert.Equal(expected, NormalizedFileName.Create(rawFileName).WordPress.BaseName);
    }

    /// <summary>
    /// PHP runs <c>_php_rfc1867_basename()</c> before <c>$_FILES</c> exists, so
    /// <c>sanitize_file_name()</c> never sees a directory component. Deriving the view from the whole
    /// submitted value would model nothing real, and it would put the client's local path into a log
    /// line — the one thing this type exists to prevent.
    /// </summary>
    [Theory]
    [InlineData(@"C:\Users\author\Pictures\shell.p{h}p")]
    [InlineData("../../wp-content/uploads/shell.p{h}p")]
    [InlineData(@"..\..\shell.p{h}p")]
    public void Create_DerivesTheWordPressViewFromTheFinalPathSegment(string rawFileName)
    {
        var normalized = NormalizedFileName.Create(rawFileName);

        Assert.Equal("shell.php", normalized.WordPress.BaseName);
        Assert.Equal("shell.p{h}p", normalized.Windows.BaseName);
        Assert.DoesNotContain("author", normalized.WordPress.BaseName, StringComparison.Ordinal);
        Assert.DoesNotContain("uploads", normalized.WordPress.BaseName, StringComparison.Ordinal);
    }

    /// <summary>
    /// When the two components would write the same name there is nothing to disagree about, and the
    /// views are one object. Every benign upload without punctuation lands here, so the sharing keeps
    /// a second extension split off the hot path.
    /// </summary>
    [Theory]
    [InlineData("photo.jpg")]
    [InlineData("shell.php")]
    [InlineData("web.config")]
    [InlineData("archive.tar.gz")]
    [InlineData("informe-anual-2024.pdf")]
    [InlineData("a\u00f1o-nuevo.jpg")]
    [InlineData("presentaci\u00f3n-espa\u00f1ola.pptx")]
    public void Views_CollapseToOneWhenTheComponentsAgree(string rawFileName)
    {
        var normalized = NormalizedFileName.Create(rawFileName);

        Assert.False(normalized.DivergesUnderWordPress);
        Assert.Same(normalized.Windows, normalized.WordPress);
        Assert.Equal([normalized.Windows], normalized.Views);
    }

    [Theory]
    [InlineData("shell.p{h}p")]
    [InlineData("web.con{f}ig")]
    [InlineData("Captura de pantalla (3).png")]
    public void Views_CarryBothAnswersWhenTheComponentsDisagree(string rawFileName)
    {
        var normalized = NormalizedFileName.Create(rawFileName);

        Assert.True(normalized.DivergesUnderWordPress);
        Assert.Equal(2, normalized.Views.Count);
        Assert.Same(normalized.Windows, normalized.Views[0]);
        Assert.Same(normalized.WordPress, normalized.Views[1]);
    }

    /// <summary>
    /// The search the extension rules delegate to. Without it every one of these names carries an
    /// extension segment no handler mapping has ever heard of — <c>p{h}p</c>, <c>as{p}x</c> — and the
    /// rules stay silent while WordPress writes the executable form.
    /// </summary>
    [Theory]
    [InlineData("shell.p{h}p", "php", true, FileNameView.WordPressToken)]
    [InlineData("shell.php-", "php", true, FileNameView.WordPressToken)]
    [InlineData("shell.p%hp", "php", true, FileNameView.WordPressToken)]
    [InlineData("shell.as{p}x", "aspx", true, FileNameView.WordPressToken)]
    [InlineData("shell.php", "php", true, FileNameView.NtfsToken)]
    [InlineData("photo.p{h}p.jpg", "php", false, FileNameView.WordPressToken)]
    public void FindMostSevereExtension_SearchesBothViewsAndNamesTheOneThatMatched(
        string rawFileName,
        string expectedExtension,
        bool expectedFinalPosition,
        string expectedViewToken)
    {
        var dangerous = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "php", "aspx" };

        var match = NormalizedFileName.Create(rawFileName).FindMostSevereExtension(dangerous);

        Assert.NotNull(match);
        Assert.Equal(expectedExtension, match.Extension);
        Assert.Equal(expectedFinalPosition, match.IsFinalPosition);
        Assert.Equal(expectedViewToken, match.View.Token);
    }

    /// <summary>
    /// A final-position segment outranks an embedded one whichever view produced it, because final
    /// position is what a handler mapping executes.
    /// </summary>
    [Fact]
    public void FindMostSevereExtension_PrefersAFinalPositionMatchFromEitherView()
    {
        var dangerous = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "php" };

        // NTFS sees photo.php.p(h)p — php embedded behind a segment nothing executes. WordPress
        // deletes the parentheses and writes photo.php.php, where php is also the final segment.
        var match = NormalizedFileName.Create("photo.php.p(h)p").FindMostSevereExtension(dangerous);

        Assert.NotNull(match);
        Assert.True(match.IsFinalPosition);
        Assert.Equal(FileNameView.WordPressToken, match.View.Token);
    }

    [Theory]
    [InlineData("web.con{f}ig", FileNameView.WordPressToken)]
    [InlineData("web.config-", FileNameView.WordPressToken)]
    [InlineData("web.config~", FileNameView.WordPressToken)]
    [InlineData("web.con(f)ig", FileNameView.WordPressToken)]
    [InlineData("web.config", FileNameView.NtfsToken)]
    [InlineData("WEB.CONFIG", FileNameView.NtfsToken)]
    public void FindViewNamed_FindsAReservedNameInEitherView(string rawFileName, string expectedViewToken)
    {
        var view = NormalizedFileName.Create(rawFileName).FindViewNamed("web.config");

        Assert.NotNull(view);
        Assert.Equal(expectedViewToken, view.Token);
    }

    [Theory]
    [InlineData("app.config")]
    [InlineData("webbing.config")]
    [InlineData("web.configuration")]
    [InlineData("my-web.config-notes.txt")]
    public void FindViewNamed_DoesNotStretchToNamesThatMerelyResembleTheReservedOne(string rawFileName)
    {
        Assert.Null(NormalizedFileName.Create(rawFileName).FindViewNamed("web.config"));
    }

    // ---------------------------------------------------------------------------------------------
    // The false-positive half of F4 — this is what decides whether the second view is shippable
    //
    // sanitize_file_name() rewrites a large fraction of real WordPress uploads. If divergence alone
    // counted as an anomaly, a media library would stop accepting screenshots, and the operator's
    // fastest remedy would be to switch WPShield off. Every name below diverges; not one of them may
    // acquire a dangerous form, and not one may set HasUnsafeForm.
    // ---------------------------------------------------------------------------------------------

    public static TheoryData<string> BenignNamesThatWordPressRewrites =>
    [
        "Captura de pantalla (3).png",
        "Q&A final.pdf",
        "report [final].xlsx",
        "price=list.csv",
        "photo (1).jpeg",
        "50% off banner.png",
        "my file - copy.docx",
        "R\u00e9sum\u00e9, 2026.pdf",
        "Elementor Kit #3 (backup).zip",
        "Google Site Kit \u2014 settings.json",
        "invoice #42 [paid].pdf",
        "100% cotton.png",
        "don't panic.gif",
        "a&b~c.png",
        "budget (2026) v2.xlsx",
        "C++ notes.txt",
        "menu ~ dinner.pdf",
        "test!.png",
        "1+1=2.png",
        "Pantallazo (copia 2).png",
        "Screenshot 2026-08-24 at 12.00.00.png",
        "factura n.\u00ba 42.pdf",
        "style.css~",
        "notes.txt-"
    ];

    [Theory]
    [MemberData(nameof(BenignNamesThatWordPressRewrites))]
    public void BenignRewrites_NeverProduceADangerousForm(string rawFileName)
    {
        var dangerous = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "php", "phtml", "phar", "aspx", "asp", "ashx", "cshtml", "asax"
        };

        var normalized = NormalizedFileName.Create(rawFileName);

        Assert.False(
            normalized.HasUnsafeForm,
            $"'{rawFileName}' acquired a structural anomaly, which is a false positive.");
        Assert.Null(normalized.FindMostSevereExtension(dangerous));
        Assert.Null(normalized.FindViewNamed("web.config"));
        Assert.False(normalized.WordPress.IsReservedDeviceName);
        Assert.False(normalized.WordPress.IsEmpty);
    }

    /// <summary>
    /// Divergence is evidence, never a score. Every one of these names diverges and none of them is
    /// suspicious, which is why <see cref="NormalizedFileName.HasUnsafeForm"/> deliberately leaves it
    /// out — but an operator still has to be able to see that the name in their media library will
    /// not be the name on the log line.
    /// </summary>
    [Theory]
    [MemberData(nameof(BenignNamesThatWordPressRewrites))]
    public void BenignRewrites_AreStillVisibleAsDivergence(string rawFileName)
    {
        var normalized = NormalizedFileName.Create(rawFileName);

        Assert.True(normalized.DivergesUnderWordPress);
        Assert.NotEqual(normalized.Windows.BaseName, normalized.WordPress.BaseName);
        Assert.False(normalized.HasUnsafeForm);
    }

    // ---------------------------------------------------------------------------------------------
    // F6 — invisible formatting characters must not reach a log
    //
    // The attack is on the reader rather than on the file system: a right-to-left override makes a
    // name render in a terminal or a dashboard as though it ended in .jpg while the bytes say .php,
    // so an operator reviewing Monitor output approves an upload they never saw. The characters are
    // written as escapes throughout and never pasted as themselves — a source file is read by people
    // too, and a bidi override sitting inside a security test is the trick the test exists to report.
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("shell\u200b.php")]           // ZERO WIDTH SPACE
    [InlineData("shell\u200e.php")]           // LEFT-TO-RIGHT MARK
    [InlineData("shell\u200f.php")]           // RIGHT-TO-LEFT MARK
    [InlineData("shell\u202a.php")]           // LEFT-TO-RIGHT EMBEDDING
    [InlineData("shell\u202d.php")]           // LEFT-TO-RIGHT OVERRIDE
    [InlineData("shell\u202e.php")]           // RIGHT-TO-LEFT OVERRIDE
    [InlineData("shell\u2066.php")]           // LEFT-TO-RIGHT ISOLATE
    [InlineData("shell\u2069.php")]           // POP DIRECTIONAL ISOLATE
    public void Create_StripsInvisibleFormattingAndReportsIt(string rawFileName)
    {
        var normalized = NormalizedFileName.Create(rawFileName);

        Assert.True(normalized.HadInvisibleFormatting);
        Assert.True(normalized.HasUnsafeForm);
        Assert.Equal("shell.php", normalized.BaseName);
        Assert.Equal("shell.php", normalized.WordPress.BaseName);
    }

    /// <summary>
    /// The property F6 is really about. Whatever a view carries into evidence has to render as what
    /// it is, so no character of it may be one that reorders or hides the characters around it.
    /// </summary>
    [Theory]
    [InlineData("shell\u202egpj.php")]
    [InlineData("photo\u2066.jpg")]
    [InlineData("invoice\u202b\u200b.pdf")]
    [InlineData("sh\u200bell.p{h}p")]
    [InlineData("\u202eshell.php\u2069")]
    public void Create_NeverLetsAnInvisibleCharacterReachAView(string rawFileName)
    {
        var normalized = NormalizedFileName.Create(rawFileName);

        foreach (var view in normalized.Views)
        {
            Assert.DoesNotContain(view.BaseName, IsInvisible);
        }

        Assert.True(normalized.HadInvisibleFormatting);

        static bool IsInvisible(char character) =>
            char.IsControl(character) ||
            character is (>= '\u200b' and <= '\u200f')
                or (>= '\u202a' and <= '\u202e')
                or (>= '\u2066' and <= '\u2069');
    }

    /// <summary>
    /// A right-to-left override cannot survive to make a <c>.php</c> upload read as a <c>.jpg</c>
    /// one. The rendered form of the raw name is the attack; the view is what a log line gets.
    /// </summary>
    [Fact]
    public void Create_DefeatsTheRightToLeftOverrideExtensionSpoof()
    {
        // Rendered right-to-left this reads as though it ended in .jpg. The bytes say .php.
        var normalized = NormalizedFileName.Create("invoice\u202egpj.php");

        Assert.Equal("invoicegpj.php", normalized.BaseName);
        Assert.Equal(".php", normalized.Extension);
        Assert.True(normalized.HadInvisibleFormatting);
    }

    /// <summary>
    /// The one deliberate exclusion. U+200C and U+200D cannot reorder anything and are ordinary
    /// content in Persian, Arabic and Indic names and in every multi-person emoji sequence, so
    /// flagging them would put a 60-point <c>FILE-NAME-001</c> on legitimate uploads. They are still
    /// removed, so a name that uses one to split an extension token is matched on the joined form.
    /// </summary>
    [Theory]
    [InlineData("photo\u200c.jpg", "photo.jpg")]
    [InlineData("photo\u200d.jpg", "photo.jpg")]
    [InlineData("\u0645\u200c\u0644\u0641.png", "\u0645\u0644\u0641.png")]
    public void Create_RemovesJoinersWithoutCallingThemAnAnomaly(string rawFileName, string expected)
    {
        var normalized = NormalizedFileName.Create(rawFileName);

        Assert.Equal(expected, normalized.BaseName);
        Assert.False(normalized.HadInvisibleFormatting);
        Assert.False(normalized.HasUnsafeForm);
    }

    /// <summary>
    /// A zero-width space inside an extension token must not hide it from the extension rules. The
    /// joined form is what both views carry.
    /// </summary>
    [Theory]
    [InlineData("shell.p\u200bhp")]
    [InlineData("shell.p\u200fhp")]
    [InlineData("shell.ph\u202ep")]
    public void Create_JoinsAnExtensionTokenSplitByAnInvisibleCharacter(string rawFileName)
    {
        var normalized = NormalizedFileName.Create(rawFileName);

        Assert.Equal("shell.php", normalized.BaseName);
        Assert.Equal(["php"], normalized.ExtensionSegments);
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

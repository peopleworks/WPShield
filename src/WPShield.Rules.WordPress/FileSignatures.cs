using System.Buffers.Binary;
using System.Collections.Frozen;

namespace WPShield.Rules.WordPress;

/// <summary>
/// The format family an upload claims through its final extension, or that its leading bytes
/// actually carry.
/// </summary>
/// <remarks>
/// Identification is deliberately by <i>family</i> rather than by exact format. <c>.jpg</c> and
/// <c>.jpeg</c> make the same claim, and <c>.docx</c>, <c>.xlsx</c>, <c>.pptx</c> and <c>.odt</c>
/// are all ZIP containers underneath, so a rule that compared exact formats would report an Office
/// document as disagreeing with itself on every upload.
/// </remarks>
internal enum FileFormatFamily
{
    /// <summary>No signature in the table matched, or the extension is not one we know.</summary>
    Unknown = 0,

    Jpeg,
    Png,
    Gif,
    Riff,
    Bmp,
    Tiff,
    Ico,
    Pdf,
    Zip,
    IsoBaseMedia,
    Matroska,
    Ogg,
    Flac,
    MpegAudio,
    Woff,
    Woff2,
    Sfnt,
    Photoshop,
    Gzip,
    Bzip2,
    Xz,
    SevenZip,
    Rar,
    Rtf,
    CompoundFile,

    /// <summary>
    /// <c>MZ</c> or ELF. Never claimed by an extension: this family exists only to name a program
    /// that arrived under the name of a document.
    /// </summary>
    NativeExecutable
}

/// <summary>
/// Whether a bounded sample reads as text, reads as binary, or is too short to say.
/// </summary>
/// <remarks>
/// The third state is not pedantry. A sample of <c>&lt;?php echo 'x';</c> is twenty-odd bytes, far
/// below the window a printable-ratio test needs to mean anything, and a two-state answer would
/// have to call it <see cref="Binary"/> and stay silent on the shortest webshell there is. Keeping
/// <see cref="Undetermined"/> separate lets the script tier fire on a marker it can see, while the
/// weaker text tier, which has nothing but the ratio to go on, correctly declines to answer.
/// </remarks>
internal enum ContentClassification
{
    Undetermined = 0,
    Text = 1,
    Binary = 2
}

/// <summary>
/// The magic-byte table and the byte-level searches shared by <see cref="FileTypeMismatchRule"/>
/// and <see cref="PhpPolyglotUploadRule"/>.
/// </summary>
/// <remarks>
/// <para>
/// Built in the style of <see cref="DangerousUploadExtensions"/>: frozen collections created once,
/// matched by span, no allocation on the evaluation path.
/// </para>
/// <para>
/// Everything here searches <b>raw bytes</b>. Nothing decodes the sample to a string.
/// <c>Encoding.UTF8.GetString</c> substitutes <c>U+FFFD</c> for every invalid sequence in binary
/// input, which shifts the index of everything after it; <see cref="PhpPolyglotUploadRule"/>
/// reports offsets and reasons about positions, so a decoded search would report offsets that do
/// not exist in the file. It also avoids one string allocation per file per rule.
/// </para>
/// </remarks>
internal static class FileSignatures
{
    /// <summary>
    /// Fewest bytes <see cref="FileTypeMismatchRule"/> will decide anything from. Every signature in
    /// the table fits in twelve bytes; sixteen leaves a margin and makes a truncated part silent
    /// rather than a finding. The absence of evidence is not evidence.
    /// </summary>
    internal const int MinimumBytesToDecide = 16;

    /// <summary>Bytes examined by <see cref="Classify"/> before it stops counting.</summary>
    internal const int ClassificationWindowBytes = 512;

    /// <summary>
    /// Below this, <see cref="Classify"/> returns <see cref="ContentClassification.Undetermined"/>.
    /// A ratio over a handful of bytes is noise, not a classification.
    /// </summary>
    internal const int MinimumBytesToClassify = 64;

    /// <summary>
    /// How far into the sample a <c>%PDF-</c> header is still accepted. Real PDFs in the wild carry
    /// leading junk that readers tolerate, and so must we, or every such file becomes a mismatch.
    /// </summary>
    internal const int PdfHeaderToleranceBytes = 1024;

    /// <summary>Textual share, in parts per thousand, at which a sample is called text.</summary>
    /// <remarks>
    /// Uniformly distributed binary scores about 870 under this classification, and JPEG entropy
    /// data scores lower still because <c>FF 00</c> byte stuffing sprays NULs through the stream.
    /// The margin between 870 and 970 is real rather than nominal.
    /// </remarks>
    internal const int TextualPermille = 970;

    /// <summary>Bytes inspected after a short marker before the hit is believed.</summary>
    internal const int ShortMarkerGuardBytes = 16;

    /// <summary>Fewest bytes after a short marker that make the guard meaningful.</summary>
    internal const int MinimumShortMarkerGuardBytes = 8;

    /// <summary>Printable share, in parts per thousand, a short marker's tail must reach.</summary>
    internal const int ShortMarkerPrintablePermille = 900;

    /// <summary>
    /// Markers at least this long are believed on sight; shorter ones must pass the printable guard.
    /// </summary>
    /// <remarks>
    /// <c>&lt;?=</c> is three bytes and appears in 4096 bytes of uniform binary with probability
    /// around one in four thousand; <c>&lt;%</c> is two bytes and appears in roughly six per cent of
    /// such files. <c>PHP-CONTENT-001</c> carries that weakness harmlessly at 75, which is an
    /// Observe. A rule that blocks cannot. <c>&lt;?php</c> is five bytes, about four in a billion,
    /// and needs no guard.
    /// </remarks>
    internal const int UnguardedMarkerLength = 5;

    /// <summary>
    /// Upper bound on iterations of any structural walk. The walks parse fully attacker-controlled
    /// bytes, so every one of them is bounded twice over: by the sample length, and by this counter.
    /// </summary>
    private const int MaximumStructuralSteps = 4096;

    /// <summary>Smallest legal <c>BITMAPFILEHEADER</c>, used to reject an absurd declared length.</summary>
    private const int MinimumBmpHeaderBytes = 14;

    /// <summary>Size of the MS-DOS header, whose last field is <c>e_lfanew</c>.</summary>
    private const int DosHeaderBytes = 0x40;

    /// <summary>Offset of <c>e_lfanew</c>, the pointer to the real executable header.</summary>
    private const int DosNewHeaderOffset = 0x3C;

    /// <summary>
    /// Largest <c>e_lfanew</c> WPShield believes. Real DOS stubs are a couple of hundred bytes; four
    /// kibibytes is generous and still narrow enough to make the field corroborating evidence.
    /// </summary>
    private const int MaximumDosStubBytes = 0x1000;

    /// <summary>Longest declared media type WPShield will look at before calling it opaque.</summary>
    private const int MaximumDeclaredTypeLength = 100;

    // Marker tokens. Evidence may only ever carry a member of this closed set, never bytes taken
    // from the sample, which become attacker-controlled output the moment they reach a log.

    internal const string PhpOpenTagToken = "<?php";
    internal const string PhpShortEchoToken = "<?=";
    internal const string AspOpenTagToken = "<%";
    internal const string ScriptElementToken = "<script";
    internal const string ShebangToken = "#!/";
    internal const string DosExecutableToken = "MZ";
    internal const string ElfExecutableToken = "ELF";

    // Declared-Content-Type tokens. The header value itself is never emitted.

    internal const string DeclaredTypeAgrees = "agrees";
    internal const string DeclaredTypeDisagrees = "disagrees";
    internal const string DeclaredTypeOpaque = "opaque";
    internal const string DeclaredTypeAbsent = "absent";

    // Region tokens for PHP-CONTENT-002.

    internal const string RegionAfterTrailer = "afterTrailer";
    internal const string RegionAfterIend = "afterIend";
    internal const string RegionAfterEoi = "afterEoi";
    internal const string RegionBeyondDeclaredLength = "beyondDeclaredLength";

    // Container tokens for PHP-CONTENT-002.

    internal const string ContainerGif = "gif";
    internal const string ContainerPng = "png";
    internal const string ContainerJpeg = "jpeg";
    internal const string ContainerBmp = "bmp";
    internal const string ContainerWebp = "webp";

    private const string OctetStream = "application/octet-stream";

    private static ReadOnlySpan<byte> JpegMagic => [0xFF, 0xD8, 0xFF];
    private static ReadOnlySpan<byte> PngMagic => [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    private static ReadOnlySpan<byte> Gif87Magic => "GIF87a"u8;
    private static ReadOnlySpan<byte> Gif89Magic => "GIF89a"u8;
    private static ReadOnlySpan<byte> RiffMagic => "RIFF"u8;
    private static ReadOnlySpan<byte> WebPForm => "WEBP"u8;
    private static ReadOnlySpan<byte> BmpMagic => "BM"u8;
    private static ReadOnlySpan<byte> TiffLittleMagic => [0x49, 0x49, 0x2A, 0x00];
    private static ReadOnlySpan<byte> TiffBigMagic => [0x4D, 0x4D, 0x00, 0x2A];
    private static ReadOnlySpan<byte> IcoMagic => [0x00, 0x00, 0x01, 0x00];
    private static ReadOnlySpan<byte> CursorMagic => [0x00, 0x00, 0x02, 0x00];
    private static ReadOnlySpan<byte> PdfMagic => "%PDF-"u8;
    private static ReadOnlySpan<byte> ZipLocalMagic => [0x50, 0x4B, 0x03, 0x04];
    private static ReadOnlySpan<byte> ZipEmptyMagic => [0x50, 0x4B, 0x05, 0x06];
    private static ReadOnlySpan<byte> ZipSpannedMagic => [0x50, 0x4B, 0x07, 0x08];
    private static ReadOnlySpan<byte> IsoBaseMediaMagic => "ftyp"u8;
    private static ReadOnlySpan<byte> MatroskaMagic => [0x1A, 0x45, 0xDF, 0xA3];
    private static ReadOnlySpan<byte> OggMagic => "OggS"u8;
    private static ReadOnlySpan<byte> FlacMagic => "fLaC"u8;
    private static ReadOnlySpan<byte> Id3Magic => "ID3"u8;
    private static ReadOnlySpan<byte> WoffMagic => "wOFF"u8;
    private static ReadOnlySpan<byte> Woff2Magic => "wOF2"u8;
    private static ReadOnlySpan<byte> SfntTrueTypeMagic => [0x00, 0x01, 0x00, 0x00];
    private static ReadOnlySpan<byte> SfntOpenTypeMagic => "OTTO"u8;
    private static ReadOnlySpan<byte> SfntTrueMagic => "true"u8;
    private static ReadOnlySpan<byte> SfntCollectionMagic => "ttcf"u8;
    private static ReadOnlySpan<byte> PhotoshopMagic => "8BPS"u8;
    private static ReadOnlySpan<byte> GzipMagic => [0x1F, 0x8B];
    private static ReadOnlySpan<byte> Bzip2Magic => "BZh"u8;
    private static ReadOnlySpan<byte> XzMagic => [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
    private static ReadOnlySpan<byte> SevenZipMagic => [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    private static ReadOnlySpan<byte> RarMagic => [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07];
    private static ReadOnlySpan<byte> RtfMagic => "{\\rtf"u8;
    private static ReadOnlySpan<byte> CompoundFileMagic => [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    private static ReadOnlySpan<byte> DosExecutableMagic => "MZ"u8;
    private static ReadOnlySpan<byte> ElfMagic => [0x7F, 0x45, 0x4C, 0x46];

    private static ReadOnlySpan<byte> PhpOpenTagBytes => "<?php"u8;
    private static ReadOnlySpan<byte> PhpShortEchoBytes => "<?="u8;
    private static ReadOnlySpan<byte> AspOpenTagBytes => "<%"u8;
    private static ReadOnlySpan<byte> ScriptElementBytes => "<script"u8;
    private static ReadOnlySpan<byte> ShebangBytes => "#!/"u8;

    private static ReadOnlySpan<byte> PngEndChunk => "IEND"u8;

    private static ReadOnlySpan<byte> PortableExecutableSignature => "PE"u8;
    private static ReadOnlySpan<byte> NewExecutableSignature => "NE"u8;
    private static ReadOnlySpan<byte> LinearExecutableSignature => "LE"u8;
    private static ReadOnlySpan<byte> LinearExecutableExtendedSignature => "LX"u8;

    /// <summary>
    /// Final extension to the family it claims. An extension absent both from this map and from
    /// <see cref="SignatureLessExtensions"/> is unknown to WPShield, and an unknown extension makes
    /// no claim that can be violated.
    /// </summary>
    private static readonly FrozenDictionary<string, FileFormatFamily> ExpectedFamilies =
        new Dictionary<string, FileFormatFamily>(StringComparer.OrdinalIgnoreCase)
        {
            ["jpg"] = FileFormatFamily.Jpeg,
            ["jpeg"] = FileFormatFamily.Jpeg,
            ["jpe"] = FileFormatFamily.Jpeg,
            ["jfif"] = FileFormatFamily.Jpeg,
            ["jfi"] = FileFormatFamily.Jpeg,
            ["png"] = FileFormatFamily.Png,
            ["apng"] = FileFormatFamily.Png,
            ["gif"] = FileFormatFamily.Gif,
            ["webp"] = FileFormatFamily.Riff,
            ["wav"] = FileFormatFamily.Riff,
            ["avi"] = FileFormatFamily.Riff,
            ["bmp"] = FileFormatFamily.Bmp,
            ["dib"] = FileFormatFamily.Bmp,
            ["tif"] = FileFormatFamily.Tiff,
            ["tiff"] = FileFormatFamily.Tiff,
            ["ico"] = FileFormatFamily.Ico,
            ["cur"] = FileFormatFamily.Ico,
            ["pdf"] = FileFormatFamily.Pdf,
            ["zip"] = FileFormatFamily.Zip,
            ["docx"] = FileFormatFamily.Zip,
            ["xlsx"] = FileFormatFamily.Zip,
            ["pptx"] = FileFormatFamily.Zip,
            ["odt"] = FileFormatFamily.Zip,
            ["ods"] = FileFormatFamily.Zip,
            ["odp"] = FileFormatFamily.Zip,
            ["epub"] = FileFormatFamily.Zip,
            ["kmz"] = FileFormatFamily.Zip,
            ["mp4"] = FileFormatFamily.IsoBaseMedia,
            ["m4v"] = FileFormatFamily.IsoBaseMedia,
            ["m4a"] = FileFormatFamily.IsoBaseMedia,
            ["mov"] = FileFormatFamily.IsoBaseMedia,
            ["3gp"] = FileFormatFamily.IsoBaseMedia,
            ["avif"] = FileFormatFamily.IsoBaseMedia,
            ["heic"] = FileFormatFamily.IsoBaseMedia,
            ["heif"] = FileFormatFamily.IsoBaseMedia,
            ["webm"] = FileFormatFamily.Matroska,
            ["mkv"] = FileFormatFamily.Matroska,
            ["ogg"] = FileFormatFamily.Ogg,
            ["ogv"] = FileFormatFamily.Ogg,
            ["oga"] = FileFormatFamily.Ogg,
            ["opus"] = FileFormatFamily.Ogg,
            ["flac"] = FileFormatFamily.Flac,
            ["mp3"] = FileFormatFamily.MpegAudio,
            ["woff"] = FileFormatFamily.Woff,
            ["woff2"] = FileFormatFamily.Woff2,
            ["ttf"] = FileFormatFamily.Sfnt,
            ["otf"] = FileFormatFamily.Sfnt,
            ["ttc"] = FileFormatFamily.Sfnt,
            ["psd"] = FileFormatFamily.Photoshop,
            ["gz"] = FileFormatFamily.Gzip,
            ["tgz"] = FileFormatFamily.Gzip,
            ["svgz"] = FileFormatFamily.Gzip,
            ["bz2"] = FileFormatFamily.Bzip2,
            ["xz"] = FileFormatFamily.Xz,
            ["7z"] = FileFormatFamily.SevenZip,
            ["rar"] = FileFormatFamily.Rar,
            ["rtf"] = FileFormatFamily.Rtf,
            ["xls"] = FileFormatFamily.CompoundFile,
            ["doc"] = FileFormatFamily.CompoundFile,
            ["ppt"] = FileFormatFamily.CompoundFile
        }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Extensions that name a known format which simply has no magic number.
    /// </summary>
    /// <remarks>
    /// Recorded separately from "unknown extension" even though both outcomes are silence, because
    /// the two are different statements and the tests assert them separately. <c>.tar</c> belongs
    /// here rather than in the signature table: the <c>ustar</c> marker sits at offset 257, past the
    /// twelve bytes the table budgets, and the pre-POSIX v7 layout has no marker at all.
    /// </remarks>
    private static readonly FrozenSet<string> SignatureLessExtensions = new[]
    {
        "svg", "txt", "csv", "tsv", "json", "xml", "html", "htm",
        "md", "log", "ini", "vtt", "srt", "ics", "tar", "po", "pot"
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>Family to the token evidence may carry.</summary>
    private static readonly FrozenDictionary<FileFormatFamily, string> FamilyTokens =
        new Dictionary<FileFormatFamily, string>
        {
            [FileFormatFamily.Unknown] = "unknown",
            [FileFormatFamily.Jpeg] = "jpeg",
            [FileFormatFamily.Png] = "png",
            [FileFormatFamily.Gif] = "gif",
            [FileFormatFamily.Riff] = "riff",
            [FileFormatFamily.Bmp] = "bmp",
            [FileFormatFamily.Tiff] = "tiff",
            [FileFormatFamily.Ico] = "ico",
            [FileFormatFamily.Pdf] = "pdf",
            [FileFormatFamily.Zip] = "zip",
            [FileFormatFamily.IsoBaseMedia] = "isoBaseMedia",
            [FileFormatFamily.Matroska] = "matroska",
            [FileFormatFamily.Ogg] = "ogg",
            [FileFormatFamily.Flac] = "flac",
            [FileFormatFamily.MpegAudio] = "mpegAudio",
            [FileFormatFamily.Woff] = "woff",
            [FileFormatFamily.Woff2] = "woff2",
            [FileFormatFamily.Sfnt] = "sfnt",
            [FileFormatFamily.Photoshop] = "photoshop",
            [FileFormatFamily.Gzip] = "gzip",
            [FileFormatFamily.Bzip2] = "bzip2",
            [FileFormatFamily.Xz] = "xz",
            [FileFormatFamily.SevenZip] = "sevenZip",
            [FileFormatFamily.Rar] = "rar",
            [FileFormatFamily.Rtf] = "rtf",
            [FileFormatFamily.CompoundFile] = "compoundFile",
            [FileFormatFamily.NativeExecutable] = "nativeExecutable"
        }.ToFrozenDictionary();

    /// <summary>
    /// Media types WPShield can place in a family, used only to reduce the declared
    /// <c>Content-Type</c> to a four-state token. Nothing in this map can produce a finding.
    /// </summary>
    private static readonly FrozenDictionary<string, FileFormatFamily> DeclaredTypeFamilies =
        new Dictionary<string, FileFormatFamily>(StringComparer.OrdinalIgnoreCase)
        {
            ["image/jpeg"] = FileFormatFamily.Jpeg,
            ["image/pjpeg"] = FileFormatFamily.Jpeg,
            ["image/png"] = FileFormatFamily.Png,
            ["image/apng"] = FileFormatFamily.Png,
            ["image/gif"] = FileFormatFamily.Gif,
            ["image/webp"] = FileFormatFamily.Riff,
            ["audio/wav"] = FileFormatFamily.Riff,
            ["audio/x-wav"] = FileFormatFamily.Riff,
            ["video/x-msvideo"] = FileFormatFamily.Riff,
            ["image/bmp"] = FileFormatFamily.Bmp,
            ["image/x-ms-bmp"] = FileFormatFamily.Bmp,
            ["image/tiff"] = FileFormatFamily.Tiff,
            ["image/x-icon"] = FileFormatFamily.Ico,
            ["image/vnd.microsoft.icon"] = FileFormatFamily.Ico,
            ["application/pdf"] = FileFormatFamily.Pdf,
            ["application/zip"] = FileFormatFamily.Zip,
            ["application/x-zip-compressed"] = FileFormatFamily.Zip,
            ["application/epub+zip"] = FileFormatFamily.Zip,
            ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = FileFormatFamily.Zip,
            ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = FileFormatFamily.Zip,
            ["application/vnd.openxmlformats-officedocument.presentationml.presentation"] = FileFormatFamily.Zip,
            ["application/vnd.oasis.opendocument.text"] = FileFormatFamily.Zip,
            ["application/vnd.oasis.opendocument.spreadsheet"] = FileFormatFamily.Zip,
            ["application/vnd.oasis.opendocument.presentation"] = FileFormatFamily.Zip,
            ["video/mp4"] = FileFormatFamily.IsoBaseMedia,
            ["audio/mp4"] = FileFormatFamily.IsoBaseMedia,
            ["video/quicktime"] = FileFormatFamily.IsoBaseMedia,
            ["image/heic"] = FileFormatFamily.IsoBaseMedia,
            ["image/heif"] = FileFormatFamily.IsoBaseMedia,
            ["image/avif"] = FileFormatFamily.IsoBaseMedia,
            ["video/webm"] = FileFormatFamily.Matroska,
            ["audio/webm"] = FileFormatFamily.Matroska,
            ["video/x-matroska"] = FileFormatFamily.Matroska,
            ["audio/ogg"] = FileFormatFamily.Ogg,
            ["video/ogg"] = FileFormatFamily.Ogg,
            ["application/ogg"] = FileFormatFamily.Ogg,
            ["audio/flac"] = FileFormatFamily.Flac,
            ["audio/x-flac"] = FileFormatFamily.Flac,
            ["audio/mpeg"] = FileFormatFamily.MpegAudio,
            ["audio/mp3"] = FileFormatFamily.MpegAudio,
            ["font/woff"] = FileFormatFamily.Woff,
            ["application/font-woff"] = FileFormatFamily.Woff,
            ["font/woff2"] = FileFormatFamily.Woff2,
            ["font/ttf"] = FileFormatFamily.Sfnt,
            ["font/otf"] = FileFormatFamily.Sfnt,
            ["font/collection"] = FileFormatFamily.Sfnt,
            ["application/font-sfnt"] = FileFormatFamily.Sfnt,
            ["image/vnd.adobe.photoshop"] = FileFormatFamily.Photoshop,
            ["application/gzip"] = FileFormatFamily.Gzip,
            ["application/x-gzip"] = FileFormatFamily.Gzip,
            ["application/x-bzip2"] = FileFormatFamily.Bzip2,
            ["application/x-xz"] = FileFormatFamily.Xz,
            ["application/x-7z-compressed"] = FileFormatFamily.SevenZip,
            ["application/vnd.rar"] = FileFormatFamily.Rar,
            ["application/x-rar-compressed"] = FileFormatFamily.Rar,
            ["application/rtf"] = FileFormatFamily.Rtf,
            ["text/rtf"] = FileFormatFamily.Rtf,
            ["application/vnd.ms-excel"] = FileFormatFamily.CompoundFile,
            ["application/msword"] = FileFormatFamily.CompoundFile,
            ["application/vnd.ms-powerpoint"] = FileFormatFamily.CompoundFile
        }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Span lookup over <see cref="DeclaredTypeFamilies"/>, so reducing a header value to a token
    /// costs no string allocation. Declared after the dictionary because static field initializers
    /// run in declaration order.
    /// </summary>
    private static readonly FrozenDictionary<string, FileFormatFamily>.AlternateLookup<ReadOnlySpan<char>>
        DeclaredTypeLookup = DeclaredTypeFamilies.GetAlternateLookup<ReadOnlySpan<char>>();

    /// <summary>The token evidence may carry for <paramref name="family"/>.</summary>
    internal static string FamilyToken(FileFormatFamily family) =>
        FamilyTokens.TryGetValue(family, out var token) ? token : "unknown";

    /// <summary>The family <paramref name="extension"/> claims, lowercased and without its dot.</summary>
    internal static bool TryGetExpectedFamily(string? extension, out FileFormatFamily family)
    {
        if (string.IsNullOrEmpty(extension))
        {
            family = FileFormatFamily.Unknown;
            return false;
        }

        return ExpectedFamilies.TryGetValue(extension, out family);
    }

    /// <summary>Whether <paramref name="extension"/> names a known format that has no magic number.</summary>
    internal static bool IsSignatureLess(string? extension) =>
        !string.IsNullOrEmpty(extension) && SignatureLessExtensions.Contains(extension);

    /// <summary>
    /// Whether the nativeExecutable tier applies to an extension claiming <paramref name="family"/>.
    /// </summary>
    /// <remarks>
    /// A whitelist rather than a blacklist, and deliberately narrow. Self-extracting archives are an
    /// ordinary thing that legitimately begins with <c>MZ</c>, so <c>.zip</c>, <c>.7z</c>,
    /// <c>.rar</c> and the other container families are excluded. So are the legacy Office families,
    /// and that is a real gap stated plainly: an executable renamed <c>invoice.doc</c> is a live
    /// phishing technique and this rule stays silent on it. Closing it needs a compound-file-aware
    /// check rather than a signature comparison, because <c>.doc</c> is also the extension people
    /// mail each other by the million.
    /// </remarks>
    internal static bool AllowsNativeExecutableTier(FileFormatFamily family) => family switch
    {
        FileFormatFamily.Jpeg or FileFormatFamily.Png or FileFormatFamily.Gif or
        FileFormatFamily.Riff or FileFormatFamily.Bmp or FileFormatFamily.Tiff or
        FileFormatFamily.Ico or FileFormatFamily.Photoshop or FileFormatFamily.Pdf or
        FileFormatFamily.IsoBaseMedia or FileFormatFamily.Matroska or FileFormatFamily.Ogg or
        FileFormatFamily.Flac or FileFormatFamily.MpegAudio or FileFormatFamily.Woff or
        FileFormatFamily.Woff2 or FileFormatFamily.Sfnt => true,
        _ => false
    };

    /// <summary>
    /// The family the leading bytes carry, or <see langword="false"/> when nothing in the table
    /// matches.
    /// </summary>
    /// <remarks>
    /// Order is chosen so that a longer signature is tested before any shorter one whose prefix it
    /// shares. The MPEG frame sync is last because it is the weakest entry in the table — eleven set
    /// bits and nothing else — and would otherwise shadow stronger matches beginning <c>FF</c>.
    /// </remarks>
    internal static bool TryIdentify(ReadOnlySpan<byte> sample, out FileFormatFamily family)
    {
        family = FileFormatFamily.Unknown;

        if (sample.Length < 2)
        {
            return false;
        }

        if (sample.StartsWith(JpegMagic)) { family = FileFormatFamily.Jpeg; return true; }
        if (sample.StartsWith(PngMagic)) { family = FileFormatFamily.Png; return true; }
        if (sample.StartsWith(Gif87Magic) || sample.StartsWith(Gif89Magic)) { family = FileFormatFamily.Gif; return true; }
        if (sample.StartsWith(RiffMagic) && sample.Length >= 12) { family = FileFormatFamily.Riff; return true; }
        if (sample.StartsWith(TiffLittleMagic) || sample.StartsWith(TiffBigMagic)) { family = FileFormatFamily.Tiff; return true; }
        if (sample.StartsWith(IcoMagic) || sample.StartsWith(CursorMagic)) { family = FileFormatFamily.Ico; return true; }
        if (sample.StartsWith(PdfMagic)) { family = FileFormatFamily.Pdf; return true; }
        if (sample.StartsWith(ZipLocalMagic) || sample.StartsWith(ZipEmptyMagic) || sample.StartsWith(ZipSpannedMagic)) { family = FileFormatFamily.Zip; return true; }
        if (sample.Length >= 12 && sample.Slice(4, 4).SequenceEqual(IsoBaseMediaMagic)) { family = FileFormatFamily.IsoBaseMedia; return true; }
        if (sample.StartsWith(MatroskaMagic)) { family = FileFormatFamily.Matroska; return true; }
        if (sample.StartsWith(OggMagic)) { family = FileFormatFamily.Ogg; return true; }
        if (sample.StartsWith(FlacMagic)) { family = FileFormatFamily.Flac; return true; }
        if (sample.StartsWith(Woff2Magic)) { family = FileFormatFamily.Woff2; return true; }
        if (sample.StartsWith(WoffMagic)) { family = FileFormatFamily.Woff; return true; }
        if (sample.StartsWith(SfntTrueTypeMagic) || sample.StartsWith(SfntOpenTypeMagic) ||
            sample.StartsWith(SfntTrueMagic) || sample.StartsWith(SfntCollectionMagic)) { family = FileFormatFamily.Sfnt; return true; }
        if (sample.StartsWith(PhotoshopMagic)) { family = FileFormatFamily.Photoshop; return true; }
        if (sample.StartsWith(XzMagic)) { family = FileFormatFamily.Xz; return true; }
        if (sample.StartsWith(SevenZipMagic)) { family = FileFormatFamily.SevenZip; return true; }
        if (sample.StartsWith(RarMagic)) { family = FileFormatFamily.Rar; return true; }
        if (sample.StartsWith(RtfMagic)) { family = FileFormatFamily.Rtf; return true; }
        if (sample.StartsWith(CompoundFileMagic)) { family = FileFormatFamily.CompoundFile; return true; }
        if (IsElfExecutable(sample) || IsDosExecutable(sample)) { family = FileFormatFamily.NativeExecutable; return true; }
        if (sample.StartsWith(Bzip2Magic)) { family = FileFormatFamily.Bzip2; return true; }
        if (sample.StartsWith(BmpMagic)) { family = FileFormatFamily.Bmp; return true; }
        if (sample.StartsWith(GzipMagic)) { family = FileFormatFamily.Gzip; return true; }
        if (sample.StartsWith(Id3Magic) || IsMpegFrameSync(sample)) { family = FileFormatFamily.MpegAudio; return true; }

        return false;
    }

    /// <summary>
    /// Whether the sample is an MS-DOS executable header with a real executable behind it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>MZ</c> alone is two bytes, so one uniformly random file in 65,536 opens with it. That is
    /// not an abstract concern: WPShield caps a request at 6 MiB, so every large media upload arrives
    /// as plupload chunks, and chunk 2..N is a file part named <c>photo.jpg</c> whose first bytes are
    /// arbitrary mid-file data. At a one-in-65,536 rate a busy media library would eventually score
    /// 70 on a perfectly ordinary video chunk — and 70 plus <c>FILE-NAME-001</c>'s 60 blocks.
    /// </para>
    /// <para>
    /// So the header must corroborate itself. <c>e_lfanew</c> at offset <c>0x3C</c> has to point
    /// somewhere plausible, and when the sample reaches that far, the bytes there have to be a real
    /// executable signature. That takes the random-file rate to roughly one in 10^11 while accepting
    /// every PE, NE, LE and LX binary an attacker would actually upload. What it loses is a museum
    /// piece: a pure DOS-era <c>MZ</c> binary with no secondary header is no longer recognized, and
    /// that is the right thing to lose.
    /// </para>
    /// </remarks>
    private static bool IsDosExecutable(ReadOnlySpan<byte> sample)
    {
        if (!sample.StartsWith(DosExecutableMagic) || sample.Length < DosHeaderBytes)
        {
            return false;
        }

        long headerOffset = BinaryPrimitives.ReadUInt32LittleEndian(sample.Slice(DosNewHeaderOffset, 4));
        if (headerOffset < DosHeaderBytes || headerOffset > MaximumDosStubBytes)
        {
            return false;
        }

        if (headerOffset + 2 > sample.Length)
        {
            // The sample stops before the secondary header. A plausible e_lfanew is corroboration
            // enough on its own: it is a 32-bit field constrained to a 4 KiB window.
            return true;
        }

        var signature = sample.Slice((int)headerOffset, 2);
        return signature.SequenceEqual(PortableExecutableSignature) ||
               signature.SequenceEqual(NewExecutableSignature) ||
               signature.SequenceEqual(LinearExecutableSignature) ||
               signature.SequenceEqual(LinearExecutableExtendedSignature);
    }

    /// <summary>
    /// Whether the sample is an ELF header. The three identification bytes after the magic number —
    /// class, data encoding and version — cost nothing to check and take the random-file rate from
    /// one in four billion to something no site will ever see.
    /// </summary>
    private static bool IsElfExecutable(ReadOnlySpan<byte> sample) =>
        sample.StartsWith(ElfMagic) &&
        sample.Length >= 7 &&
        sample[4] is 1 or 2 &&
        sample[5] is 1 or 2 &&
        sample[6] == 1;

    /// <summary>
    /// Whether the leading bytes satisfy the claim <paramref name="expected"/> makes.
    /// </summary>
    /// <remarks>
    /// Not simply <see cref="TryIdentify"/> equality, because PDF is the one format whose header is
    /// tolerated away from offset 0. That asymmetry is deliberate: a real PDF carrying leading junk
    /// must still be accepted as a PDF, while <c>%PDF-</c> appearing nine hundred bytes into a
    /// script must not make that script look like a document.
    /// </remarks>
    internal static bool MatchesExpectedFamily(ReadOnlySpan<byte> sample, FileFormatFamily expected)
    {
        if (expected == FileFormatFamily.Pdf)
        {
            var window = sample.Length > PdfHeaderToleranceBytes ? sample[..PdfHeaderToleranceBytes] : sample;
            if (window.IndexOf(PdfMagic) >= 0)
            {
                return true;
            }
        }

        return TryIdentify(sample, out var observed) && observed == expected;
    }

    /// <summary>
    /// Whether the sample reads as text, as binary, or is too short to say.
    /// </summary>
    /// <remarks>
    /// <c>09 0A 0D</c>, <c>20</c>–<c>7E</c> and <c>80</c>–<c>FF</c> count as textual; <c>00</c>–
    /// <c>08</c>, <c>0B</c>, <c>0C</c>, <c>0E</c>–<c>1F</c> and <c>7F</c> count as binary. The high
    /// half counts as textual so that UTF-8 prose in any language is not mistaken for binary — a
    /// classifier that flagged Spanish or Japanese text would be a defect, not a conservative
    /// default.
    /// </remarks>
    internal static ContentClassification Classify(ReadOnlySpan<byte> sample)
    {
        if (sample.Length < MinimumBytesToClassify)
        {
            return ContentClassification.Undetermined;
        }

        var window = sample.Length > ClassificationWindowBytes ? sample[..ClassificationWindowBytes] : sample;
        var textual = 0;
        foreach (var value in window)
        {
            if (IsTextualByte(value))
            {
                textual++;
            }
        }

        return textual * 1000 >= window.Length * TextualPermille
            ? ContentClassification.Text
            : ContentClassification.Binary;
    }

    /// <summary>
    /// The offset of the first validated PHP marker at or after <paramref name="startAt"/>.
    /// </summary>
    /// <remarks>
    /// The marker set is exactly the one <c>PHP-CONTENT-001</c> uses — <c>&lt;?php</c> and
    /// <c>&lt;?=</c> — so the two rules cannot disagree about what PHP is. <c>&lt;?xml</c> and
    /// <c>&lt;?xpacket</c> are excluded by construction: an XML declaration is not PHP, and matching
    /// it would flag every photograph carrying an XMP packet and every SVG ever uploaded.
    /// </remarks>
    internal static bool TryFindPhpMarker(ReadOnlySpan<byte> sample, int startAt, out string token, out int offset) =>
        TryFindFirstMarker(sample, startAt, phpOnly: true, out token, out offset);

    /// <summary>
    /// The offset of the first validated script marker anywhere in the sample.
    /// </summary>
    /// <remarks>
    /// The PHP set widened with <c>&lt;%</c> (which subsumes <c>&lt;%@</c>), <c>&lt;script</c> and
    /// <c>#!/</c>, so that ASP, ASP.NET and shebang forms are recognized as source text too. WPShield
    /// protects Windows hosting, where an <c>.aspx</c> handler is at least as dangerous as PHP.
    /// </remarks>
    internal static bool TryFindScriptMarker(ReadOnlySpan<byte> sample, out string token, out int offset) =>
        TryFindFirstMarker(sample, 0, phpOnly: false, out token, out offset);

    /// <summary>
    /// The offset of the first validated script marker when the sample opens with a UTF-16 byte
    /// order mark.
    /// </summary>
    /// <remarks>
    /// Searches the UTF-16 encoding of each marker directly rather than decoding the sample, so the
    /// no-string-allocation rule holds here too. This closes part of the UTF-16 evasion
    /// <c>PHP-CONTENT-001</c> is documented as missing: a BOM-prefixed UTF-16 PHP file named
    /// <c>photo.jpg</c> is recognized here even though a UTF-8 decode of it contains no marker at
    /// all. UTF-16 without a byte order mark remains a gap, and detecting it by alternating NULs is
    /// guesswork on binary media that would cost more in false positives than it buys.
    /// </remarks>
    internal static bool TryFindWideScriptMarker(ReadOnlySpan<byte> sample, out string token, out int offset)
    {
        token = string.Empty;
        offset = -1;

        if (sample.Length < 4)
        {
            return false;
        }

        bool littleEndian;
        if (sample[0] == 0xFF && sample[1] == 0xFE)
        {
            littleEndian = true;
        }
        else if (sample[0] == 0xFE && sample[1] == 0xFF)
        {
            littleEndian = false;
        }
        else
        {
            return false;
        }

        ConsiderWide(sample, littleEndian, PhpOpenTagBytes, PhpOpenTagToken, ref token, ref offset);
        ConsiderWide(sample, littleEndian, PhpShortEchoBytes, PhpShortEchoToken, ref token, ref offset);
        ConsiderWide(sample, littleEndian, ScriptElementBytes, ScriptElementToken, ref token, ref offset);
        ConsiderWide(sample, littleEndian, AspOpenTagBytes, AspOpenTagToken, ref token, ref offset);
        ConsiderWide(sample, littleEndian, ShebangBytes, ShebangToken, ref token, ref offset);

        return offset >= 0;
    }

    /// <summary>
    /// The offset of <paramref name="marker"/> at or after <paramref name="startAt"/>, matched
    /// case-insensitively over raw bytes, with the printable-run guard applied to short markers.
    /// </summary>
    internal static int IndexOfMarker(ReadOnlySpan<byte> sample, ReadOnlySpan<byte> marker, int startAt)
    {
        if (marker.IsEmpty || startAt < 0 || startAt > sample.Length - marker.Length)
        {
            return -1;
        }

        var guarded = marker.Length < UnguardedMarkerLength;
        var position = startAt;

        while (position <= sample.Length - marker.Length)
        {
            var relative = IndexOfAsciiCaseInsensitive(sample[position..], marker);
            if (relative < 0)
            {
                return -1;
            }

            var absolute = position + relative;
            if (!guarded || IsFollowedByPrintableRun(sample, absolute + marker.Length))
            {
                return absolute;
            }

            position = absolute + 1;
        }

        return -1;
    }

    /// <summary>
    /// The <c>getimagesize()</c>-set container the sample opens with, if any.
    /// </summary>
    /// <remarks>
    /// GIF, PNG, JPEG, BMP and RIFF carrying the <c>WEBP</c> form. These are exactly the formats
    /// WordPress's own image validation accepts, which is exactly what the polyglot bypass targets.
    /// </remarks>
    internal static bool TryGetImageContainer(
        ReadOnlySpan<byte> sample,
        out FileFormatFamily family,
        out string container)
    {
        family = FileFormatFamily.Unknown;
        container = string.Empty;

        if (!TryIdentify(sample, out var observed))
        {
            return false;
        }

        switch (observed)
        {
            case FileFormatFamily.Gif:
                container = ContainerGif;
                break;
            case FileFormatFamily.Png:
                container = ContainerPng;
                break;
            case FileFormatFamily.Jpeg:
                container = ContainerJpeg;
                break;
            case FileFormatFamily.Bmp:
                container = ContainerBmp;
                break;
            case FileFormatFamily.Riff when sample.Length >= 12 && sample.Slice(8, 4).SequenceEqual(WebPForm):
                container = ContainerWebp;
                break;
            default:
                return false;
        }

        family = observed;
        return true;
    }

    /// <summary>
    /// Where the container's own structure says its data ends, when a bounded walk can establish
    /// that from the sample alone.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the primitive <c>PHP-CONTENT-002</c> is built on. The design note names it
    /// <c>TryProveOutsideDeclaredData(sample, family, offset, out region)</c> — an offset in, a
    /// verdict out. Returning the boundary instead is a deliberate change, and it is not cosmetic:
    /// with an offset going in, the caller has to pick a marker first, and the natural choice is the
    /// first one — which is exactly the marker an attacker would place inside an EXIF comment to
    /// make the walk fail while a second marker sits after the trailer. Handing the boundary back
    /// lets the caller search only the region it has already established, so no arrangement of decoy
    /// markers changes the answer.
    /// </para>
    /// <para>
    /// Every walk here parses fully attacker-controlled bytes. Each is bounded by the sample length
    /// and by <see cref="MaximumStructuralSteps"/>, each advances by a strictly positive step or
    /// aborts, and each treats any inconsistency as "not established" rather than as an error.
    /// Failing a walk yields silence, never a finding.
    /// </para>
    /// </remarks>
    internal static bool TryGetDeclaredDataEnd(
        ReadOnlySpan<byte> sample,
        FileFormatFamily family,
        out int declaredEnd,
        out string region)
    {
        switch (family)
        {
            case FileFormatFamily.Gif when TryWalkGif(sample, out declaredEnd):
                region = RegionAfterTrailer;
                return true;
            case FileFormatFamily.Png when TryWalkPng(sample, out declaredEnd):
                region = RegionAfterIend;
                return true;
            case FileFormatFamily.Jpeg when TryWalkJpeg(sample, out declaredEnd):
                region = RegionAfterEoi;
                return true;
            case FileFormatFamily.Bmp when TryReadBmpDeclaredLength(sample, out declaredEnd):
                region = RegionBeyondDeclaredLength;
                return true;
            case FileFormatFamily.Riff when TryReadRiffDeclaredLength(sample, out declaredEnd):
                region = RegionBeyondDeclaredLength;
                return true;
            default:
                declaredEnd = 0;
                region = string.Empty;
                return false;
        }
    }

    /// <summary>
    /// Reduces the part's declared <c>Content-Type</c> to one of four tokens.
    /// </summary>
    /// <remarks>
    /// The header value itself never leaves this method. A <c>Content-Type</c> is as
    /// attacker-controlled as a file name and can carry control characters into a log consumer just
    /// as easily, so anything malformed, control-bearing or longer than a hundred characters is
    /// reported as <c>opaque</c> rather than quoted. A media type WPShield does not know is
    /// <c>opaque</c> too: not knowing what something is, is not the same as knowing it disagrees.
    /// </remarks>
    internal static string DescribeDeclaredType(string? declaredContentType, FileFormatFamily expected)
    {
        if (string.IsNullOrWhiteSpace(declaredContentType))
        {
            return DeclaredTypeAbsent;
        }

        if (declaredContentType.Length > MaximumDeclaredTypeLength)
        {
            return DeclaredTypeOpaque;
        }

        var value = declaredContentType.AsSpan();
        var semicolon = value.IndexOf(';');
        if (semicolon >= 0)
        {
            value = value[..semicolon];
        }

        value = value.Trim();

        if (!IsWellFormedMediaType(value) || value.Equals(OctetStream, StringComparison.OrdinalIgnoreCase))
        {
            return DeclaredTypeOpaque;
        }

        if (!DeclaredTypeLookup.TryGetValue(value, out var declaredFamily))
        {
            return DeclaredTypeOpaque;
        }

        return declaredFamily == expected ? DeclaredTypeAgrees : DeclaredTypeDisagrees;
    }

    private static bool IsWellFormedMediaType(ReadOnlySpan<char> value)
    {
        if (value.Length < 3 || value.Length > MaximumDeclaredTypeLength)
        {
            return false;
        }

        var slashes = 0;
        foreach (var character in value)
        {
            if (character == '/')
            {
                slashes++;
                continue;
            }

            if (!IsMediaTypeTokenCharacter(character))
            {
                return false;
            }
        }

        return slashes == 1 && value[0] != '/' && value[^1] != '/';
    }

    private static bool IsMediaTypeTokenCharacter(char character) =>
        char.IsAsciiLetterOrDigit(character) ||
        character is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or
                     '^' or '_' or '`' or '|' or '~';

    private static bool TryFindFirstMarker(
        ReadOnlySpan<byte> sample,
        int startAt,
        bool phpOnly,
        out string token,
        out int offset)
    {
        token = string.Empty;
        offset = -1;

        Consider(sample, startAt, PhpOpenTagBytes, PhpOpenTagToken, ref token, ref offset);
        Consider(sample, startAt, PhpShortEchoBytes, PhpShortEchoToken, ref token, ref offset);

        if (!phpOnly)
        {
            Consider(sample, startAt, ScriptElementBytes, ScriptElementToken, ref token, ref offset);
            Consider(sample, startAt, AspOpenTagBytes, AspOpenTagToken, ref token, ref offset);
            Consider(sample, startAt, ShebangBytes, ShebangToken, ref token, ref offset);
        }

        return offset >= 0;
    }

    private static void Consider(
        ReadOnlySpan<byte> sample,
        int startAt,
        ReadOnlySpan<byte> marker,
        string markerToken,
        ref string token,
        ref int offset)
    {
        var hit = IndexOfMarker(sample, marker, startAt);
        if (hit < 0 || (offset >= 0 && hit >= offset))
        {
            return;
        }

        offset = hit;
        token = markerToken;
    }

    private static void ConsiderWide(
        ReadOnlySpan<byte> sample,
        bool littleEndian,
        ReadOnlySpan<byte> marker,
        string markerToken,
        ref string token,
        ref int offset)
    {
        var hit = IndexOfWideMarker(sample, marker, littleEndian);
        if (hit < 0 || (offset >= 0 && hit >= offset))
        {
            return;
        }

        offset = hit;
        token = markerToken;
    }

    private static int IndexOfWideMarker(ReadOnlySpan<byte> sample, ReadOnlySpan<byte> marker, bool littleEndian)
    {
        var guarded = marker.Length < UnguardedMarkerLength;
        var needed = marker.Length * 2;
        var lowOffset = littleEndian ? 0 : 1;
        var highOffset = littleEndian ? 1 : 0;

        // The byte order mark guarantees even alignment, so stepping two bytes at a time cannot
        // straddle a code unit and cannot match a marker that is not really there.
        for (var position = 2; position + needed <= sample.Length; position += 2)
        {
            var matched = true;
            for (var index = 0; index < marker.Length; index++)
            {
                var unit = position + (index * 2);
                if (sample[unit + highOffset] != 0 ||
                    ToLowerAscii(sample[unit + lowOffset]) != ToLowerAscii(marker[index]))
                {
                    matched = false;
                    break;
                }
            }

            if (matched && (!guarded || IsFollowedByWidePrintableRun(sample, position + needed, littleEndian)))
            {
                return position;
            }
        }

        return -1;
    }

    private static int IndexOfAsciiCaseInsensitive(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        var lower = ToLowerAscii(needle[0]);
        var upper = ToUpperAscii(needle[0]);
        var searched = 0;

        while (searched <= haystack.Length - needle.Length)
        {
            var window = haystack[searched..];
            var relative = lower == upper ? window.IndexOf(lower) : window.IndexOfAny(lower, upper);
            if (relative < 0)
            {
                return -1;
            }

            var candidate = searched + relative;
            if (candidate > haystack.Length - needle.Length)
            {
                return -1;
            }

            if (EqualsAsciiCaseInsensitive(haystack.Slice(candidate, needle.Length), needle))
            {
                return candidate;
            }

            searched = candidate + 1;
        }

        return -1;
    }

    private static bool EqualsAsciiCaseInsensitive(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        for (var index = 0; index < right.Length; index++)
        {
            if (ToLowerAscii(left[index]) != ToLowerAscii(right[index]))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsFollowedByPrintableRun(ReadOnlySpan<byte> sample, int from)
    {
        if (from >= sample.Length)
        {
            return false;
        }

        var available = Math.Min(ShortMarkerGuardBytes, sample.Length - from);
        if (available < MinimumShortMarkerGuardBytes)
        {
            // Too few bytes left to validate. Declining is the conservative direction: a short marker
            // at the very tail of a sample is exactly the case we cannot tell apart from coincidence.
            return false;
        }

        var printable = 0;
        for (var index = 0; index < available; index++)
        {
            if (IsPrintableAscii(sample[from + index]))
            {
                printable++;
            }
        }

        return printable * 1000 >= available * ShortMarkerPrintablePermille;
    }

    private static bool IsFollowedByWidePrintableRun(ReadOnlySpan<byte> sample, int from, bool littleEndian)
    {
        var lowOffset = littleEndian ? 0 : 1;
        var highOffset = littleEndian ? 1 : 0;
        var available = Math.Min(ShortMarkerGuardBytes, (sample.Length - from) / 2);
        if (available < MinimumShortMarkerGuardBytes)
        {
            return false;
        }

        var printable = 0;
        for (var index = 0; index < available; index++)
        {
            var unit = from + (index * 2);
            if (sample[unit + highOffset] == 0 && IsPrintableAscii(sample[unit + lowOffset]))
            {
                printable++;
            }
        }

        return printable * 1000 >= available * ShortMarkerPrintablePermille;
    }

    private static bool IsPrintableAscii(byte value) =>
        value is (>= 0x20 and <= 0x7E) or 0x09 or 0x0A or 0x0D;

    private static bool IsTextualByte(byte value) =>
        value is 0x09 or 0x0A or 0x0D || value is >= 0x20 and <= 0x7E || value >= 0x80;

    private static bool IsMpegFrameSync(ReadOnlySpan<byte> sample) =>
        sample.Length >= 2 && sample[0] == 0xFF && (sample[1] & 0xE0) == 0xE0;

    private static byte ToLowerAscii(byte value) =>
        value is >= (byte)'A' and <= (byte)'Z' ? (byte)(value + 32) : value;

    private static byte ToUpperAscii(byte value) =>
        value is >= (byte)'a' and <= (byte)'z' ? (byte)(value - 32) : value;

    /// <summary>Walks GIF blocks to the <c>3B</c> trailer.</summary>
    private static bool TryWalkGif(ReadOnlySpan<byte> sample, out int declaredEnd)
    {
        const byte Trailer = 0x3B;
        const byte ExtensionIntroducer = 0x21;
        const byte ImageSeparator = 0x2C;

        declaredEnd = 0;
        var position = 6;

        // `GIF89a;` — six header bytes and a trailer, with no logical screen descriptor at all — is
        // the stub the published WordPress bypass actually uses, precisely because an attacker wants
        // the smallest carrier that survives validation. It is not a legal GIF, so the ordinary walk
        // below would reject it; recognizing it explicitly is the difference between catching the
        // real bypass and catching only the textbook one.
        if (position < sample.Length && sample[position] == Trailer)
        {
            declaredEnd = position + 1;
            return true;
        }

        if (sample.Length < position + 7)
        {
            return false;
        }

        var screenPacked = sample[position + 4];
        position += 7;
        if ((screenPacked & 0x80) != 0)
        {
            position += (1 << ((screenPacked & 0x07) + 1)) * 3;
        }

        var steps = 0;
        while (position >= 0 && position < sample.Length && steps++ < MaximumStructuralSteps)
        {
            var block = sample[position];

            if (block == Trailer)
            {
                declaredEnd = position + 1;
                return true;
            }

            if (block == ExtensionIntroducer)
            {
                // Introducer plus label, then data sub-blocks. Comment, graphic control, plain text
                // and application extensions all share this shape, which is why a marker hidden in a
                // GIF comment is walked over rather than reported.
                if (position + 2 > sample.Length)
                {
                    return false;
                }

                position += 2;
                if (!TrySkipGifSubBlocks(sample, ref position))
                {
                    return false;
                }

                continue;
            }

            if (block == ImageSeparator)
            {
                if (position + 10 > sample.Length)
                {
                    return false;
                }

                var imagePacked = sample[position + 9];
                position += 10;
                if ((imagePacked & 0x80) != 0)
                {
                    position += (1 << ((imagePacked & 0x07) + 1)) * 3;
                }

                if (position < 0 || position >= sample.Length)
                {
                    return false;
                }

                position += 1;
                if (!TrySkipGifSubBlocks(sample, ref position))
                {
                    return false;
                }

                continue;
            }

            return false;
        }

        return false;
    }

    private static bool TrySkipGifSubBlocks(ReadOnlySpan<byte> sample, ref int position)
    {
        var steps = 0;
        while (position >= 0 && position < sample.Length && steps++ < MaximumStructuralSteps)
        {
            var length = sample[position];
            if (length == 0)
            {
                position += 1;
                return true;
            }

            position += 1 + length;
            if (position > sample.Length)
            {
                return false;
            }
        }

        return false;
    }

    /// <summary>
    /// Walks PNG chunks — four-byte length, four-byte type, data, four-byte CRC — to the end of
    /// <c>IEND</c>.
    /// </summary>
    private static bool TryWalkPng(ReadOnlySpan<byte> sample, out int declaredEnd)
    {
        declaredEnd = 0;
        var position = 8;
        var steps = 0;

        while (steps++ < MaximumStructuralSteps)
        {
            if (position < 0 || position + 8 > sample.Length)
            {
                return false;
            }

            long length = BinaryPrimitives.ReadUInt32BigEndian(sample.Slice(position, 4));
            var isEnd = sample.Slice(position + 4, 4).SequenceEqual(PngEndChunk);
            var next = position + 12L + length;

            if (isEnd)
            {
                // A tEXt, iTXt or zTXt chunk carrying a PHP marker was walked over on the way here,
                // so it lies below this boundary and the caller never sees it. A metadata field is
                // allowed to contain arbitrary text; PHP-CONTENT-001 records that case at 75, which
                // is an Observe, and that is the right treatment for it.
                declaredEnd = next > int.MaxValue ? int.MaxValue : (int)next;
                return true;
            }

            if (next > sample.Length)
            {
                // A real PNG's IDAT runs far past a 4 KiB sample, so this is the ordinary outcome for
                // a genuine photograph and the reason PHP-CONTENT-002 catches minimal carriers only.
                return false;
            }

            position = (int)next;
        }

        return false;
    }

    /// <summary>Walks JPEG segments to <c>FF D9</c>.</summary>
    /// <remarks>
    /// Goes inconclusive at <c>SOS</c>: entropy-coded scan data carries no length, so from there the
    /// walk would have to hunt for a marker inside data that can legally contain anything. Failing
    /// closed there is also what keeps a marker inside an APP1 EXIF or XMP segment from ever being
    /// read as proof.
    /// </remarks>
    private static bool TryWalkJpeg(ReadOnlySpan<byte> sample, out int declaredEnd)
    {
        declaredEnd = 0;
        var position = 2;
        var steps = 0;

        while (steps++ < MaximumStructuralSteps)
        {
            if (position < 0 || position + 2 > sample.Length || sample[position] != 0xFF)
            {
                return false;
            }

            var marker = sample[position + 1];
            while (marker == 0xFF)
            {
                // Fill bytes are legal padding before a marker.
                position++;
                if (position + 2 > sample.Length)
                {
                    return false;
                }

                marker = sample[position + 1];
            }

            if (marker == 0xD9)
            {
                declaredEnd = position + 2;
                return true;
            }

            if (marker == 0xDA)
            {
                return false;
            }

            if (marker == 0x01 || marker is >= 0xD0 and <= 0xD8)
            {
                position += 2;
                continue;
            }

            if (position + 4 > sample.Length)
            {
                return false;
            }

            var length = BinaryPrimitives.ReadUInt16BigEndian(sample.Slice(position + 2, 2));
            if (length < 2)
            {
                return false;
            }

            var next = position + 2L + length;
            if (next > sample.Length)
            {
                return false;
            }

            position = (int)next;
        }

        return false;
    }

    /// <summary>Reads the total file size a BMP declares in bytes 2–5.</summary>
    /// <remarks>
    /// Two consistency checks keep a malformed header from establishing anything: the declared size
    /// must cover at least a <c>BITMAPFILEHEADER</c>, and it must exceed the pixel-data offset the
    /// same header declares. Some writers emit a wrong <c>bfSize</c>; requiring it to be larger than
    /// <c>bfOffBits</c> catches the common form of that bug, in which a header size is written where
    /// the file size belongs.
    /// </remarks>
    private static bool TryReadBmpDeclaredLength(ReadOnlySpan<byte> sample, out int declaredEnd)
    {
        declaredEnd = 0;
        if (sample.Length < 14)
        {
            return false;
        }

        long declared = BinaryPrimitives.ReadUInt32LittleEndian(sample.Slice(2, 4));
        long pixelOffset = BinaryPrimitives.ReadUInt32LittleEndian(sample.Slice(10, 4));

        if (declared < MinimumBmpHeaderBytes || pixelOffset < MinimumBmpHeaderBytes || declared <= pixelOffset)
        {
            return false;
        }

        declaredEnd = declared > int.MaxValue ? int.MaxValue : (int)declared;
        return true;
    }

    /// <summary>
    /// Reads the RIFF payload size from bytes 4–7. The declared file length is that plus the eight
    /// header bytes the size field does not count.
    /// </summary>
    private static bool TryReadRiffDeclaredLength(ReadOnlySpan<byte> sample, out int declaredEnd)
    {
        declaredEnd = 0;
        if (sample.Length < 12)
        {
            return false;
        }

        long size = BinaryPrimitives.ReadUInt32LittleEndian(sample.Slice(4, 4));
        if (size < 4)
        {
            return false;
        }

        var end = 8L + size;
        declaredEnd = end > int.MaxValue ? int.MaxValue : (int)end;
        return true;
    }
}

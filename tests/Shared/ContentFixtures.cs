using System.Text;
using WPShield.Abstractions;
using WPShield.Rules.Windows;

namespace WPShield.Rules.Tests.Shared;

/// <summary>
/// The synthetic byte fixtures and upload contexts the content-rule tests of BOTH rule packages use.
/// </summary>
/// <remarks>
/// <para>
/// One source file, compiled into both test projects through a link, rather than a copy in each.
/// These fixtures encode decisions - which JPEG, which XMP packet, which Elementor export counts as
/// ordinary traffic - and two copies of a decision drift apart the first time one of them is
/// corrected. The split of the rules into <c>WPShield.Rules.Windows</c> and
/// <c>WPShield.Rules.WordPress</c> (ADR 0004, exit condition 1) moved the tests that use them into
/// two projects; it must not have moved the fixtures into two files.
/// </para>
/// <para>
/// Every fixture is a synthetic byte array built here. Nothing reads a real media file, nothing writes
/// to disk, and the only script marker used anywhere is <c>&lt;?php echo 'synthetic marker';</c>. No
/// fixture constructs a working webshell.
/// </para>
/// </remarks>
internal static class ContentFixtures
{
    /// <summary>The only marker any fixture in this file carries. Inert: it echoes a string.</summary>
    internal const string SyntheticMarker = "<?php echo 'synthetic marker';";

    /// <summary><c>SiteOptions.ObserveThreshold</c>'s default, restated because Core is not referenced.</summary>
    internal const int ObserveThreshold = 30;

    /// <summary><c>SiteOptions.BlockThreshold</c>'s default, restated because Core is not referenced.</summary>
    internal const int BlockThreshold = 80;

    internal static InspectionContext Upload(string? fileName, byte[]? sample = null, string? contentType = null) =>
        new(
            "site",
            "wordpress-one.example",
            "POST",
            "/wp-admin/async-upload.php",
            fileName,
            contentType,
            sample ?? []);

    internal static ValueTask<RuleFinding?> TypeAsync(InspectionContext context) =>
        new FileTypeMismatchRule().EvaluateAsync(context);

    internal static ValueTask<RuleFinding?> PolyglotAsync(InspectionContext context) =>
        new PhpPolyglotUploadRule().EvaluateAsync(context);

    // =============================================================================================
    // Synthetic fixtures. No file is read, no file is written, and nothing here is a working payload.
    // =============================================================================================

    /// <summary>
    /// An ordinary XMP packet, which genuinely opens <c>&lt;?xpacket</c>. Trimmed but structurally
    /// faithful: the processing instruction, the <c>x:xmpmeta</c> wrapper and the closing instruction
    /// are what a camera or an image editor actually writes.
    /// </summary>
    internal const string XmpPacket =
        "<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>" +
        "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"XMP Core 6.0.0\">" +
        "<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">" +
        "<rdf:Description rdf:about=\"\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" " +
        "photoshop:Credit=\"studio\" photoshop:DateCreated=\"2026-08-24\"/>" +
        "</rdf:RDF></x:xmpmeta><?xpacket end=\"w\"?>";

    /// <summary>An exporter's HTML table: printable, well over the classification window's floor.</summary>
    internal const string HtmlExport =
        "<html><head><title>Sales</title></head><body><table>" +
        "<tr><th>Quarter</th><th>Revenue</th></tr>" +
        "<tr><td>Q1</td><td>1200</td></tr><tr><td>Q2</td><td>1450</td></tr>" +
        "</table></body></html>\n";

    internal const string SvgDocument =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\" width=\"24\" height=\"24\">" +
        "<path d=\"M4 4h16v16H4z\" fill=\"none\" stroke=\"currentColor\"/></svg>\n";

    internal static byte[] Ascii(string value) => Encoding.ASCII.GetBytes(value);

    /// <summary>
    /// Guards a silence assertion against going vacuous. A fixture that quietly stopped containing
    /// the bytes it is named for would satisfy every "produces no finding" assertion in this file for
    /// entirely the wrong reason, and nothing else here would notice.
    /// </summary>
    internal static void AssertSampleContains(InspectionContext context, string expected) =>
        Assert.True(
            context.Sample.Span.IndexOf(Ascii(expected)) >= 0,
            $"The fixture no longer carries the bytes this test exists to prove are harmless: '{expected}'.");

    internal static byte[] Concat(params byte[][] parts)
    {
        var buffer = new byte[parts.Sum(part => part.Length)];
        var offset = 0;
        foreach (var part in parts)
        {
            part.CopyTo(buffer, offset);
            offset += part.Length;
        }

        return buffer;
    }

    internal static byte[] BigEndian16(int value) => [(byte)(value >> 8), (byte)value];

    internal static byte[] LittleEndian16(int value) => [(byte)value, (byte)(value >> 8)];

    internal static byte[] BigEndian32(int value) =>
        [(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value];

    internal static byte[] LittleEndian32(int value) =>
        [(byte)value, (byte)(value >> 8), (byte)(value >> 16), (byte)(value >> 24)];

    /// <summary>
    /// Deterministic pseudo-entropy standing in for compressed image or video data. Uniform over all
    /// 256 values, so it classifies as binary the way real entropy-coded data does, with the
    /// <c>FF 00</c> byte stuffing a JPEG encoder emits sprayed through it.
    /// </summary>
    internal static byte[] EntropyBytes(int count)
    {
        var buffer = new byte[count];
        for (var index = 0; index < count; index++)
        {
            buffer[index] = (byte)((index * 37) + 11);
        }

        for (var index = 8; index + 1 < count; index += 16)
        {
            buffer[index] = 0xFF;
            buffer[index + 1] = 0x00;
        }

        return buffer;
    }

    internal static byte[] JpegSegment(byte marker, byte[] payload) =>
        Concat([0xFF, marker], BigEndian16(payload.Length + 2), payload);

    /// <summary>
    /// A JPEG in the shape a camera writes it: <c>SOI</c>, the given metadata segments, then
    /// <c>SOS</c> and scan data. The scan is what makes the structural walk go inconclusive, which is
    /// the ordinary outcome for a genuine photograph.
    /// </summary>
    internal static byte[] Jpeg(params byte[][] segments) => Concat(
        [0xFF, 0xD8],
        Concat(segments),
        JpegSegment(0xDA, [0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]),
        EntropyBytes(96));

    internal static byte[] JpegPhotograph() => Jpeg(JfifSegment());

    internal static byte[] JfifSegment() =>
        JpegSegment(0xE0, Concat(Ascii("JFIF"), [0x00, 0x01, 0x02, 0x01], [0x00, 0x48, 0x00, 0x48], [0x00, 0x00]));

    internal static byte[] JpegWithXmp(string packet) => Jpeg(
        JfifSegment(),
        JpegSegment(0xE1, Concat(Ascii("Exif\0\0"), Ascii("II*\0"), [0x08, 0x00, 0x00, 0x00], [0x00, 0x00])),
        JpegSegment(0xE1, Concat(Ascii("http://ns.adobe.com/xap/1.0/\0"), Ascii(packet))));

    internal static byte[] JpegWithComment(string comment) =>
        Jpeg(JfifSegment(), JpegSegment(0xFE, Ascii(comment)));

    /// <summary>
    /// The seven-byte carrier the published WordPress bypass actually uses: a GIF header and a
    /// trailer, with no logical screen descriptor at all. <c>getimagesize()</c> accepts it.
    /// </summary>
    internal static byte[] GifStub() => Concat(Ascii("GIF89a"), [0x3B]);

    /// <summary>A one-by-one GIF: header, logical screen descriptor, the given blocks, trailer.</summary>
    internal static byte[] Gif(params byte[][] blocks) => Concat(
        Ascii("GIF89a"),
        [0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        Concat(blocks),
        [0x3B]);

    /// <summary>Image descriptor, LZW minimum code size, one data sub-block and its terminator.</summary>
    internal static byte[] GifImageBlock() =>
        [0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x4C, 0x01, 0x00];

    internal static byte[] GifCommentBlock(byte[] text) =>
        Concat([0x21, 0xFE, (byte)text.Length], text, [0x00]);

    /// <summary>
    /// A PNG chunk: length, type, data, CRC. The CRC is zero because nothing in WPShield validates it
    /// — the structural walk follows declared lengths, which is the property the rule depends on and
    /// also the property an attacker controls.
    /// </summary>
    internal static byte[] PngChunk(string type, byte[] data) =>
        Concat(BigEndian32(data.Length), Ascii(type), data, [0x00, 0x00, 0x00, 0x00]);

    internal static byte[] Png(params byte[][] chunks) => Concat(
        [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        Concat(chunks));

    internal static byte[] PngIhdr() =>
        PngChunk("IHDR", Concat(BigEndian32(1), BigEndian32(1), [0x08, 0x06, 0x00, 0x00, 0x00]));

    internal static byte[] PngIdat() =>
        PngChunk("IDAT", [0x78, 0x9C, 0x62, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01]);

    internal static byte[] PngIend() => PngChunk("IEND", []);

    internal static byte[] PngImage() => Png(PngIhdr(), PngIdat(), PngIend());

    internal static byte[] Riff(string form, byte[] payload) =>
        Concat(Ascii("RIFF"), LittleEndian32(4 + payload.Length), Ascii(form), payload);

    internal static byte[] WebPImage() =>
        Riff("WEBP", Concat(Ascii("VP8L"), LittleEndian32(8), [0x2F, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88, 0x08]));

    /// <summary>
    /// A 24-bit bitmap: a 14-byte file header declaring the total size and the pixel offset, a 40-byte
    /// information header, and eight bytes of pixel data. The declared size is what the polyglot walk
    /// reads, so it is set honestly here and any appended bytes fall beyond it.
    /// </summary>
    internal static byte[] BitmapImage()
    {
        var pixels = new byte[] { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00 };
        var infoHeader = Concat(
            LittleEndian32(40),
            LittleEndian32(1),
            LittleEndian32(1),
            [0x01, 0x00],
            [0x18, 0x00],
            LittleEndian32(0),
            LittleEndian32(pixels.Length),
            LittleEndian32(2835),
            LittleEndian32(2835),
            LittleEndian32(0),
            LittleEndian32(0));
        var declaredSize = 14 + infoHeader.Length + pixels.Length;
        var fileHeader = Concat(
            Ascii("BM"),
            LittleEndian32(declaredSize),
            [0x00, 0x00, 0x00, 0x00],
            LittleEndian32(14 + infoHeader.Length));

        return Concat(fileHeader, infoHeader, pixels);
    }

    internal static byte[] ZipArchive(string entryName) => Concat(
        [0x50, 0x4B, 0x03, 0x04],
        [0x14, 0x00],
        [0x00, 0x00],
        [0x08, 0x00],
        [0x00, 0x00, 0x00, 0x00],
        LittleEndian32(0),
        LittleEndian32(32),
        LittleEndian32(64),
        LittleEndian16(entryName.Length),
        [0x00, 0x00],
        Ascii(entryName),
        EntropyBytes(32));

    internal static byte[] Mp4Video() => Concat(
        BigEndian32(0x20),
        Ascii("ftyp"),
        Ascii("isom"),
        BigEndian32(0x200),
        Ascii("isomiso2avc1mp41"),
        EntropyBytes(64));

    internal static byte[] HeicImage() => Concat(
        BigEndian32(0x18),
        Ascii("ftyp"),
        Ascii("heic"),
        BigEndian32(0),
        Ascii("mif1heic"),
        EntropyBytes(64));

    internal static byte[] WebmVideo() => Concat(
        [0x1A, 0x45, 0xDF, 0xA3],
        [0x9F, 0x42, 0x86, 0x81, 0x01, 0x42, 0xF7, 0x81, 0x01],
        EntropyBytes(64));

    internal static byte[] Mp3WithId3() => Concat(
        Ascii("ID3"),
        [0x04, 0x00, 0x00],
        [0x00, 0x00, 0x02, 0x01],
        EntropyBytes(96));

    internal static byte[] Mp3RawFrame() => Concat([0xFF, 0xFB, 0x90, 0x44], EntropyBytes(96));

    internal static byte[] TrueTypeFont() => Concat(
        [0x00, 0x01, 0x00, 0x00],
        BigEndian16(9),
        BigEndian16(128),
        BigEndian16(3),
        BigEndian16(64),
        EntropyBytes(64));

    internal static byte[] WoffFont() => Concat(
        Ascii("wOFF"),
        Ascii("OTTO"),
        BigEndian32(1024),
        BigEndian16(9),
        BigEndian16(0),
        EntropyBytes(64));

    internal static byte[] Woff2Font() => Concat(
        Ascii("wOF2"),
        Ascii("OTTO"),
        BigEndian32(1024),
        BigEndian16(9),
        BigEndian16(0),
        EntropyBytes(64));

    internal static byte[] PdfDocument() => Concat(
        Ascii("%PDF-1.7\n"),
        [0x25, 0xE2, 0xE3, 0xCF, 0xD3, 0x0A],
        Ascii("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"));

    /// <summary>
    /// An MS-DOS header with a plausible <c>e_lfanew</c> and a real <c>PE</c> signature behind it.
    /// Corroboration matters: <c>MZ</c> alone is two bytes and would otherwise match one uniformly
    /// random chunk in 65,536.
    /// </summary>
    internal static byte[] PortableExecutable()
    {
        var image = new byte[0x88];
        image[0] = (byte)'M';
        image[1] = (byte)'Z';
        LittleEndian32(0x80).CopyTo(image, 0x3C);
        image[0x80] = (byte)'P';
        image[0x81] = (byte)'E';
        return image;
    }

    internal static byte[] ElfExecutable() =>
        Concat([0x7F], Ascii("ELF"), [0x02, 0x01, 0x01, 0x00], new byte[56]);

    /// <summary>
    /// The ordinary-traffic corpus. Keyed by name so the theory data stays serializable and each case
    /// shows up in the runner under the name of the upload it stands for.
    /// </summary>
    internal static InspectionContext TrafficFixture(string fixtureName) => fixtureName switch
    {
        "photo.jpg" => Upload("photo.jpg", JpegPhotograph(), "image/jpeg"),
        "photo.jpeg" => Upload("photo.jpeg", JpegWithXmp(XmpPacket), "image/jpeg"),
        "banner.png" => Upload("banner.png", PngImage(), "image/png"),
        "animation.gif" => Upload("animation.gif", Gif(GifImageBlock()), "image/gif"),
        "logo.webp" => Upload("logo.webp", WebPImage(), "image/webp"),
        "diagram.bmp" => Upload("diagram.bmp", BitmapImage(), "image/bmp"),
        "icon.svg" => Upload("icon.svg", Ascii(SvgDocument), "image/svg+xml"),
        "analytics-report.pdf" => Upload("analytics-report.pdf", PdfDocument(), "application/pdf"),
        "document.docx" => Upload(
            "document.docx",
            ZipArchive("word/document.xml"),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        "spreadsheet.xlsx" => Upload(
            "spreadsheet.xlsx",
            ZipArchive("xl/workbook.xml"),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        "presentation.pptx" => Upload(
            "presentation.pptx",
            ZipArchive("ppt/presentation.xml"),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
        "report.odt" => Upload("report.odt", ZipArchive("content.xml"), "application/vnd.oasis.opendocument.text"),
        "video.mp4" => Upload("video.mp4", Mp4Video(), "video/mp4"),
        "video.webm" => Upload("video.webm", WebmVideo(), "video/webm"),
        "audio.mp3" => Upload("audio.mp3", Mp3WithId3(), "audio/mpeg"),
        "podcast-raw.mp3" => Upload("podcast-raw.mp3", Mp3RawFrame(), "audio/mpeg"),
        "font.ttf" => Upload("font.ttf", TrueTypeFont(), "font/ttf"),
        "elementor-icons.woff" => Upload("elementor-icons.woff", WoffFont(), "font/woff"),
        "elementor-icons.woff2" => Upload("elementor-icons.woff2", Woff2Font(), "font/woff2"),
        "elementor-kit-export.zip" => Upload("elementor-kit-export.zip", ZipArchive("manifest.json"), "application/zip"),
        "elementor-template.json" => Upload(
            "elementor-template.json",
            Ascii("{\"version\":\"0.4\",\"title\":\"Hero\",\"type\":\"section\",\"content\":[]}"),
            "application/json"),
        // The plupload fallback and every non-browser client send octet-stream, so the declared type
        // disagreeing with the extension must never be a finding on its own.
        "elementor-background.jpg" => Upload("elementor-background.jpg", JpegPhotograph(), "application/octet-stream"),
        "site-kit-export.csv" => Upload(
            "site-kit-export.csv",
            Ascii("Date,Sessions,Users\n2026-08-01,1240,980\n2026-08-02,1310,1024\n"),
            "text/csv"),
        "googlesitekit-report.pdf" => Upload("googlesitekit-report.pdf", PdfDocument(), "application/pdf"),
        "photo-heic-rename.jpg" => Upload("photo-heic-rename.jpg", HeicImage(), "image/jpeg"),
        "screenshot-webp-rename.png" => Upload("screenshot-webp-rename.png", WebPImage(), "image/png"),
        "chunked-upload-part-2.jpg" => Upload("chunked-upload-part-2.jpg", EntropyBytes(2048), "application/octet-stream"),
        "presentación-española.pptx" => Upload(
            "presentación-española.pptx",
            ZipArchive("ppt/presentation.xml"),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
        "日本語のファイル.png" => Upload("日本語のファイル.png", PngImage(), "image/png"),
        "My Vacation Photo.jpeg" => Upload("My Vacation Photo.jpeg", JpegPhotograph(), "image/jpeg"),
        // A part cut short by a chunk boundary, and an unselected file input the browser still sends.
        "truncated-part.jpg" => Upload("truncated-part.jpg", [0xFF, 0xD8, 0xFF], "image/jpeg"),
        "empty-file-input.jpg" => Upload("empty-file-input.jpg", [], "image/jpeg"),
        "sales-report.xls" => Upload("sales-report.xls", Ascii(HtmlExport), "application/vnd.ms-excel"),
        "installer.zip" => Upload("installer.zip", PortableExecutable(), "application/zip"),
        _ => throw new ArgumentOutOfRangeException(nameof(fixtureName), fixtureName, "Unknown fixture.")
    };
}

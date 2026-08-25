# Content inspection rules: `FILE-TYPE-001` and `PHP-CONTENT-002`

Design for the two M2 content rules. Every rule WPShield ships so far reasons about the *name* of an
upload. These two reason about its *bytes*, which is the only way to catch the payload that arrives
with a name WordPress happily accepts.

Both rules live in `src/WPShield.Rules.WordPress/`, implement `IInspectionRule`, and share a single
`internal static FileSignatures` table. Neither touches ASP.NET Core, YARP, IIS or any Windows API,
so both build and test on the Linux CI leg.

## What the rules can see

The engine hands a rule an `InspectionContext`. For a content rule the useful members are:

| Member | Provenance | Trust |
| --- | --- | --- |
| `NormalizedFile` | `FileName` after Windows-aware normalization | derived from attacker input, safe to log |
| `DeclaredContentType` | the part's `Content-Type` header | attacker-controlled, **never logged verbatim** |
| `Sample` | a bounded *leading* slice of the part body | attacker-controlled bytes, never logged |

`Sample` is produced by `MultipartInspectionReader` from `MultipartInspectionOptions.SampleBytes`
(default 4096, ceiling 64 KiB). Two properties matter to this design and must not change:

1. The sample always starts at **offset 0 of the part body**. Every signature check depends on this.
2. The sample may be shorter than `SampleBytes` — a small file, a truncated body, or a client
   disconnect. A rule must decide nothing from a sample too short to decide from.

`InspectionContext` carries no byte count, so a rule cannot know whether the sample is the whole file
or only its first page. Neither rule below needs to know.

### Byte budget

| Need | Bytes from offset 0 |
| --- | --- |
| Identify every signature in the table | 12 |
| Minimum before `FILE-TYPE-001` decides anything | 16 |
| Printable-ratio classification window | 512 |
| `%PDF-` tolerance window | 1024 |
| `PHP-CONTENT-002` structural walk | whatever the sample reaches |

The 4096-byte default is comfortable. Below 512 the text classification degrades and the `%PDF-`
tolerance disappears, so `GatewayConfigurationValidator` should reject a `SampleBytes` value under 512
rather than let a configuration silently disable content inspection. That floor is the Gateway
agent's to add; it is a validator rule, not a change to the fixed `MultipartInspectionOptions` shape.

---

## `FileSignatures` — the shared table

`internal static class FileSignatures`, in the style of `DangerousUploadExtensions`: frozen
collections, built once, matched by span.

### Format families

Identification is by **family**, never by exact format. `.jpg` and `.jpeg` are the same claim;
`.docx`, `.xlsx`, `.pptx` and `.odt` are all ZIP containers and must never be reported as disagreeing
with each other.

| Family | Signature | Offset | Bytes needed | Extensions claiming it |
| --- | --- | --- | --- | --- |
| `Jpeg` | `FF D8 FF` | 0 | 3 | `jpg` `jpeg` `jpe` `jfif` `jfi` |
| `Png` | `89 50 4E 47 0D 0A 1A 0A` | 0 | 8 | `png` `apng` |
| `Gif` | `47 49 46 38 37 61` or `47 49 46 38 39 61` | 0 | 6 | `gif` |
| `Riff` | `52 49 46 46`, plus the form at offset 8: `WEBP`, `WAVE` or `AVI ` | 0 and 8 | 12 | `webp` `wav` `avi` |
| `Bmp` | `42 4D` | 0 | 2 | `bmp` `dib` |
| `Tiff` | `49 49 2A 00` or `4D 4D 00 2A` | 0 | 4 | `tif` `tiff` |
| `Ico` | `00 00 01 00` or `00 00 02 00` | 0 | 4 | `ico` `cur` |
| `Pdf` | `25 50 44 46 2D` — `%PDF-` | 0, tolerated up to 1024 | 5 | `pdf` |
| `Zip` | `50 4B 03 04`, `50 4B 05 06` or `50 4B 07 08` | 0 | 4 | `zip` `docx` `xlsx` `pptx` `odt` `ods` `odp` `epub` `kmz` |
| `IsoBaseMedia` | `66 74 79 70` — `ftyp` | 4 | 12 | `mp4` `m4v` `m4a` `mov` `3gp` `avif` `heic` `heif` |
| `Matroska` | `1A 45 DF A3` | 0 | 4 | `webm` `mkv` |
| `Ogg` | `4F 67 67 53` — `OggS` | 0 | 4 | `ogg` `ogv` `oga` `opus` |
| `Flac` | `66 4C 61 43` — `fLaC` | 0 | 4 | `flac` |
| `MpegAudio` | `49 44 33` — `ID3` — or `FF` followed by a byte whose top three bits are set | 0 | 3 | `mp3` |
| `Woff` | `77 4F 46 46` — `wOFF` | 0 | 4 | `woff` |
| `Woff2` | `77 4F 32 46` — `wOF2` | 0 | 4 | `woff2` |
| `Sfnt` | `00 01 00 00`, `4F 54 54 4F`, `74 72 75 65` or `74 74 63 66` | 0 | 4 | `ttf` `otf` `ttc` |
| `Photoshop` | `38 42 50 53` — `8BPS` | 0 | 4 | `psd` |
| `Gzip` | `1F 8B` | 0 | 2 | `gz` `tgz` `svgz` |
| `Bzip2` | `42 5A 68` | 0 | 3 | `bz2` |
| `Xz` | `FD 37 7A 58 5A 00` | 0 | 6 | `xz` |
| `SevenZip` | `37 7A BC AF 27 1C` | 0 | 6 | `7z` |
| `Rar` | `52 61 72 21 1A 07` | 0 | 6 | `rar` |
| `Rtf` | `7B 5C 72 74 66` — an opening brace, a backslash, then `rtf` | 0 | 5 | `rtf` |
| `CompoundFile` | `D0 CF 11 E0 A1 B1 1A E1` | 0 | 8 | `xls` `doc` `ppt` |

Two families exist only to name hostile content and are never claimed by an extension:

| Family | Signature | Meaning |
| --- | --- | --- |
| `NativeExecutable` | `4D 5A` — `MZ` — or `7F 45 4C 46` — ELF | a program, not a document |
| `Script` | see the marker set below | source text, not a document |

### Signature-less extensions

These are recorded explicitly as *having no signature*, so the rule can distinguish "this format has
no magic number" from "this extension is unknown to us". Both outcomes are silent; recording them
separately keeps the table honest and gives the tests something to assert.

`svg` `txt` `csv` `tsv` `json` `xml` `html` `htm` `md` `log` `ini` `vtt` `srt` `ics` `tar` `po` `pot`

`.tar` belongs here rather than in the signature table, because the `ustar` marker sits at offset 257
and the pre-POSIX v7 layout has no marker at all.

### Marker sets

| Set | Members | Notes |
| --- | --- | --- |
| PHP | `<?php` (case-insensitive), `<?=` | identical to `PHP-CONTENT-001`, so the two rules agree about what PHP is |
| Script (superset) | the PHP set, plus `<%`, `<%@`, `<script` and `#!/` | ASP, ASP.NET and shebang forms, matched case-insensitively |
| Deliberately excluded | `<?xml`, `<?xpacket`, and `<?` alone | XML declarations and XMP packets are not PHP; matching them would flag every photograph and every SVG |

Markers are searched **over the raw bytes**, never over a decoded string.
`Encoding.UTF8.GetString` substitutes `U+FFFD` for every invalid sequence in binary input, which
shifts the index of everything after it. `PHP-CONTENT-002` reports offsets and reasons about
positions, so a decoded-string search would report offsets that do not exist in the file.

### The three-byte marker problem

`<?=` is three bytes. In 4096 bytes of uniformly distributed binary it appears with probability of
roughly 4096 / 2^24, about one file in four thousand. A site that accepts ten thousand images will
hit it. `PHP-CONTENT-001` already carries this weakness at score 75, which is an `Observe`, so it
costs a log line. A rule that blocks cannot afford it.

`FileSignatures` therefore exposes a *validated* marker search: a `<?=` hit counts only when the next
16 bytes are at least 90 % printable ASCII. Random binary clears that bar with probability around
5 x 10^-8. `<?php` is five bytes, about 4 x 10^-9 per file, and needs no guard.

### Members

| Member | Purpose |
| --- | --- |
| `TryIdentify(sample, out family)` | the first matching signature, or `false` when nothing matches |
| `TryGetExpectedFamily(extension, out family)` | extension to claimed family; `false` for an unknown extension |
| `IsSignatureLess(extension)` | the extension names a known format that has no magic number |
| `IsTextLike(sample)` | the printable-ratio classification described below |
| `IndexOfMarker(sample, marker)` | byte-level, case-insensitive, with the `<?=` guard applied |
| `TryProveOutsideDeclaredData(sample, family, offset, out region)` | the `PHP-CONTENT-002` structural walk |

`IsTextLike` classifies each of the first 512 bytes, or the whole sample when it is shorter, and
refuses to answer at all below 64 bytes. `09 0A 0D`, `20`–`7E` and `80`–`FF` count as textual;
`00`–`08`, `0B`, `0C`, `0E`–`1F` and `7F` count as binary. The threshold is **97 % textual**.
Uniformly distributed binary scores about 87 % under this classification, and JPEG entropy data
scores lower still, because `FF 00` byte stuffing sprays NULs through the stream. The margin is real
rather than nominal.

---

## `FILE-TYPE-001` — declared type versus actual content

**Class:** `FileTypeMismatchRule`. **MessageKey:** `Findings.UploadContentSignatureMismatch`.

### The failure it addresses

WordPress decides what an upload is from its extension, and `wp_check_filetype_and_ext()` consults
the real bytes for only a handful of types. A plugin endpoint that writes the file itself consults
nothing. So a file named `photo.jpg` whose body is a PHP script lands in `wp-content/uploads` as an
ordinary-looking image and stays there until an LFI, a second bug, or a handler misconfiguration
reaches it. The name rules cannot see this, because `photo.jpg` is a perfect name.

### The one direction that fires

The trigger is always **final extension versus leading bytes**. The final segment is the claim the
file makes about itself: it is what the IIS static handler maps to a MIME type and what WordPress
stores in the attachment record. An executable segment in a *non-final* position is a different
question, already answered by `WP-UPLOAD-001` and `WP-UPLOAD-002`.

`DeclaredContentType` never triggers a finding. Two reasons:

- Browsers derive the part's `Content-Type` from the same extension by way of the operating system
  registry, so on legitimate traffic it carries no information the extension did not already carry.
- Every non-browser client is entitled to send `application/octet-stream`, and many do: `curl`,
  `wp-cli`, mobile applications, and the plupload fallback path. Triggering on a disagreement between
  the declared type and the bytes turns each of those into a finding, which is the fastest way to
  have an operator switch the rule off.

The declared type is still *recorded*, as a tri-state that cannot carry attacker text into a log:

| `declaredType` evidence | Meaning |
| --- | --- |
| `agrees` | names a concrete type in the same family as the extension |
| `disagrees` | names a concrete type in a different family |
| `opaque` | `application/octet-stream` |
| `absent` | missing or empty |

Anything else — a malformed value, a value containing control characters, a value longer than 100
characters — is recorded as `opaque`. The rule never emits the header value itself. Evidence records
the normalized name, and the same discipline applies to every other client-supplied string.

### Classification and scores

The rule runs only when the final extension maps to a family that has a signature, the sample holds
at least 16 bytes, and the leading bytes match **no** signature accepted for that family. It then
classifies what the bytes actually are:

| Observed content | Score | `observedContent` | Applies to |
| --- | --- | --- | --- |
| Text carrying a script marker | 70 | `script` | every signature-bearing extension |
| `MZ` or ELF at offset 0 | 70 | `nativeExecutable` | image, audio/video, font and PDF extensions only |
| Text with no script marker | 40 | `text` | every signature-bearing extension except legacy Office |
| A different but recognized family | — | *(silent)* | |
| Unrecognized binary | — | *(silent)* | |
| Fewer than 16 bytes, or an empty sample | — | *(silent)* | |

Order matters. Recognized families are checked before the text tiers, so a PDF named `.jpg` is silent
rather than being reported as text.

Two exclusions are the reason the rule is usable at all:

- **Containers are exempt from `nativeExecutable`.** A self-extracting `.zip`, `.7z` or `.rar`
  legitimately begins with `MZ`. Reporting them would flag an ordinary archive.
- **Legacy Office extensions are exempt from the `text` tier.** Exporting an HTML table or a CSV under
  an `.xls` name is endemic in reporting plugins and analytics exports. It is a bug in the exporter,
  not an attack. `.xls`, `.doc` and `.ppt` remain eligible for the `script` tier.

### Argument for the scores

Neither tier blocks alone. That is deliberate: this rule reports a *disagreement*, and a disagreement
always has a benign explanation somewhere in the long tail of upload clients.

- **70** — `script` and `nativeExecutable` — sits below the default `BlockThreshold` of 80, so it
  produces `Observe` on its own. Combined with `PHP-CONTENT-001` at 75 it saturates the cap at 100 and
  blocks, which is correct: a file named `photo.jpg` whose leading bytes are PHP text is a webshell
  with an image name. Combined with `WP-UPLOAD-001` in an embedded position at 50 it also blocks.
- **40** — `text` — produces `Observe` alone and reaches 80 only in combination. It is a weaker
  claim: the file is not what it says it is, and it is human-readable.

The combination that deserves a warning in the operator documentation is **`text` 40 plus
`FILE-NAME-001` 60, which is exactly 100 and blocks.** `FILE-NAME-001` fires on legacy clients that
submit a full local path, so an upload from such a client of a text file with a binary extension would
be blocked in Block mode. It is a narrow intersection of two unusual behaviours, but it is real, and
it is the reason the `text` tier scores 40 rather than 70.

### The false positives, and how each is avoided

| Case | Outcome | Why |
| --- | --- | --- |
| SVG, TXT, CSV, JSON, XML — no magic number | silent | listed as signature-less; the rule has no expectation to violate |
| An extension we have never seen | silent | `TryGetExpectedFamily` returns `false` and the rule stops |
| Camera and phone JPEGs with unusual EXIF | silent | every JPEG variant — JFIF, EXIF, progressive, MPO, motion photo — begins `FF D8 FF`; metadata cannot change the first three bytes |
| `.docx`, `.xlsx`, `.pptx` and `.odt`, which are ZIP underneath | silent | one `Zip` family covers all of them, so the rule never compares OOXML against ODF |
| HEIC or WebP saved under a `.jpg` name | silent | recognized as another family, and cross-format renames are endemic: Chrome's "save image as", iOS shares, Android galleries |
| A truncated upload | silent | the signature sits at offset 0 and the sample is a leading sample, so truncation removes only the tail |
| **Chunk 2..N of a chunked upload** | silent | the middle of a media file has no signature at offset 0, but it is *binary*, and unrecognized binary is silent by construction |
| A self-extracting archive | silent | containers are exempt from `nativeExecutable` |
| An HTML or CSV export named `.xls` | silent | legacy Office extensions are exempt from the `text` tier |
| A `.jpg` whose body is a base64 data URI from a broken uploader | `text`, 40 | genuinely a broken upload; `Observe`, never a block on its own |

The chunked-upload row is the load-bearing one. WPShield caps a request at 6 MiB, so any large media
upload **must** arrive as plupload chunks to pass at all, and every chunk after the first is a file
part named `photo.jpg` with no signature where one is mandatory. The rule is blind to the chunk
fields, because `MultipartInspectionOutcome` exposes only a field count. This is precisely why
"unrecognized bytes where a signature is mandatory" is **not** a finding.

That choice costs something, and it should be stated plainly. A webshell written in UTF-16 without a
byte order mark, or one whose PHP marker sits past the sample window, is unrecognized binary and stays
silent. An unrecognizable blob sitting in `wp-content/uploads` is inert on IIS; it becomes dangerous
only in combination with a second bug. Trading that residual case for silence on every chunk of every
large upload is the right trade, and it is the difference between a rule an operator keeps and a rule
an operator turns off.

One evasion the rule does close: when the sample begins with a UTF-16 byte order mark, `FF FE` or
`FE FF`, the script marker search is repeated over a UTF-16 decode with that endianness. A
BOM-prefixed UTF-16 PHP file named `photo.jpg` therefore scores 70, even though `PHP-CONTENT-001`,
which searches a UTF-8 decode, misses it entirely. UTF-16 without a byte order mark remains a gap.

### Evidence

| Key | Value |
| --- | --- |
| `normalizedName` | `NormalizedFile.BaseName` |
| `presentedExtension` | `NormalizedFile.Extension`, reusing `WP-UPLOAD-002`'s key |
| `expectedFormat` | the family token the extension claims: `jpeg`, `zip`, `isoBaseMedia`, and so on |
| `observedContent` | `script`, `nativeExecutable` or `text` |
| `marker` | the matched member of our own closed marker set, such as `<?php` or `MZ`; omitted for `text` |
| `declaredType` | `agrees`, `disagrees`, `opaque` or `absent` |
| `sampleLength` | our own count of the bytes examined |

No sample bytes, no raw name, no header value. A single `MessageKey` with the tier in
`observedContent` follows `WP-UPLOAD-001`, which uses one key and reports `position` in evidence. A
localizer can branch on `observedContent` when the message catalogue lands.

---

## `PHP-CONTENT-002` — the polyglot

**Class:** `PhpPolyglotUploadRule`. **MessageKey:** `Findings.PhpPolyglotUpload`.

### The failure it addresses

`GIF89a;` followed by a PHP script is a valid GIF followed by a PHP script. `getimagesize()` accepts
it. Every signature check accepts it. `FILE-TYPE-001` accepts it, because the signature genuinely
matches the extension. It is the standard bypass for WordPress upload validation, and it has been for
a decade.

The only thing that distinguishes it from a photograph is *where the PHP marker sits relative to the
image's own structure*.

### The scoring arithmetic, worked out first

`PHP-CONTENT-002` is a strict subset of `PHP-CONTENT-001`. Both look for `<?php` and `<?=` inside the
same bounded sample, so **whenever `-002` fires, `-001` has already fired.** The engine sums findings
and caps the total at 100.

With `-001` contributing 75, any additional finding worth **5 points or more** carries the request to
80 and blocks. There is no score at which `PHP-CONTENT-002` is a moderate signal. It is a
block-or-not switch, and its only tuning knob is **precision**, not points.

That settles the suppression question. `-002` does not need to suppress `-001`, and could not: the
engine evaluates rules independently and clamps negative scores to zero. Saturating at 100 is the
intended outcome for the case `-002` fires on. What `-002` must do instead is refuse to fire on
anything it cannot prove.

### The detection

`PHP-CONTENT-002` fires when **all** of the following hold:

1. The sample begins with a signature from the **`getimagesize()` set**: `Gif`, `Png`, `Jpeg`, `Bmp`,
   or `Riff` carrying the `WEBP` form. These are exactly the formats WordPress's own image validation
   accepts, which is exactly what the bypass targets.
2. A validated PHP marker — `<?php`, or `<?=` past the printable guard — appears in the sample at an
   offset beyond the signature.
3. A bounded structural walk **proves** that the marker lies outside the data the format itself
   declares.

If the walk cannot prove it, the rule is silent. It never falls upward to a weaker tier.

| Family | Proof | Cost |
| --- | --- | --- |
| `Riff` / WebP | the marker offset is at or beyond 8 plus the size declared in bytes 4–7 | one 32-bit read |
| `Bmp` | the marker offset is at or beyond the file size declared in bytes 2–5 | one 32-bit read |
| `Gif` | a block walk from the header, past the logical screen descriptor and any global colour table; proof is the marker at or after the `3B` trailer | a few dozen bounded steps |
| `Png` | a chunk walk of 4-byte length, 4-byte type, data, 4-byte CRC; proof is the marker at or after the end of `IEND` | bounded by the sample |
| `Jpeg` | a segment walk of `FF xx` plus a 2-byte length, skipping the length-less markers; proof is the marker at or after `FF D9` | bounded by the sample |

`Tiff`, `Ico`, `IsoBaseMedia` and `Matroska` are excluded. TIFF declares no total length and its IFD
chain is a pointer graph; ISO base media's `mdat` box runs far past any sample. Neither offers a cheap
proof, and neither is the format the WordPress bypass uses.

`Zip` is excluded for a different and more important reason: **installing a plugin or a theme is
uploading a ZIP archive full of PHP.** `/wp-admin/update.php?action=upload-plugin` is a legitimate
administrative workflow, and a ZIP entry stored without compression puts literal PHP source in the
first bytes of the archive. PDF is excluded too — a PDF *about* PHP contains `<?php` as prose, and a
`.pdf` is not executed by a FastCGI handler in any case.

The rule ignores the file name entirely. A polyglot is dangerous under every name: `avatar.gif` when
the attacker plans to reach it through an include, and `shell.php` when the attacker is defeating a
check that only calls `getimagesize()`. Making the rule content-only also means it composes cleanly.
`shell.php` with a GIF header collects `WP-UPLOAD-001` at 90 as well, and `FILE-TYPE-001` stays silent
because it has nothing to disagree with.

### The XMP and EXIF false positive

This is the case that decides whether the rule is shippable. A JPEG's APP1 segment can hold an XMP
packet, which is XML and genuinely opens with `<?xpacket begin=`. IPTC captions, EXIF `UserComment`
and XMP `dc:description` are free text and may contain anything a photographer, a stock library or a
screenshot tool put there.

Three things keep the rule quiet:

1. **`<?xpacket` and `<?xml` are not PHP markers.** The marker set is `<?php` and `<?=` only, exactly
   as in `PHP-CONTENT-001`. An ordinary XMP packet matches nothing at all. This alone handles the
   overwhelming majority of photographs.
2. **A marker inside a metadata segment is never proof.** The structural walk knows where JPEG `APPn`
   and `COM` segments, PNG `tEXt`, `iTXt` and `zTXt` chunks, and GIF comment extensions end. A marker
   inside any of them fails condition 3 and the rule stays silent — even though embedding a webshell
   in EXIF is a genuine technique. That case is left to `PHP-CONTENT-001` at 75, an `Observe`:
   recorded for an operator to look at, never a block. A metadata field is *allowed* to contain
   arbitrary text, so a rule that blocks on its contents is a rule that eventually takes a working
   site offline.
3. **`<?=` needs the printable guard**, or roughly one image in four thousand becomes a blocked
   upload.

The consequence is that a photograph with any metadata whatsoever — including a screenshot of PHP
code taken by a developer and uploaded to their own blog, with the code in an XMP caption — produces
`PHP-CONTENT-001` at 75 and nothing else. That is the designed outcome, and the tests must assert it
by score, not merely by the absence of a `PHP-CONTENT-002` finding.

### The score

**85.** It blocks alone at the default `BlockThreshold` of 80, and saturates at 100 alongside
`PHP-CONTENT-001`.

Blocking alone is justified because the finding is a *proof*, not a heuristic: the file carries a
valid image signature, and PHP source appears at an offset the image's own structure says is past its
end. No encoder appends `<?php` after a GIF trailer or a PNG `IEND`. Trailing data after a JPEG `EOI`
is common — Samsung and Google motion photos append an entire MP4 — but trailing data *containing a
PHP open tag* is not.

85 rather than 100 is a deliberate gradation against `IIS-CONFIG-001`, which is definitional rather
than structural. It also gives an operator who raises `BlockThreshold` to 90 a meaningful position:
the polyglot alone would then observe, while the polyglot together with `PHP-CONTENT-001` would still
block.

### Known limits

The structural walk sees only the sample. For a real photograph with an appended payload, `EOI` sits
hundreds of kilobytes past the 4096-byte window, so nothing is proven — and `PHP-CONTENT-001` will not
fire either, because the payload is outside the sample too. `PHP-CONTENT-002` therefore catches
*minimal-image* polyglots: the seven-byte `GIF89a;` stub, the 43-byte one-by-one GIF, the
four-byte-header JPEG. Those are the shapes the published bypasses actually use, because an attacker
wants the smallest carrier that survives validation. Large-carrier polyglots need a sampling strategy
that also reads the tail of the body, which is an M4 question, not an M2 one.

### Evidence

| Key | Value |
| --- | --- |
| `normalizedName` | `NormalizedFile.BaseName`, empty when the part carried no file name |
| `container` | `gif`, `png`, `jpeg`, `bmp` or `webp` |
| `region` | `afterTrailer`, `afterIend`, `afterEoi` or `beyondDeclaredLength` |
| `marker` | `<?php` or `<?=`, from our own closed set |
| `markerOffset` | our own computed integer |

No surrounding bytes are recorded. `markerOffset` is safe because it is a number WPShield computed,
not text the client supplied.

---

## Interaction summary

| Payload | Findings | Sum | Action at default thresholds |
| --- | --- | --- | --- |
| Photograph whose XMP metadata contains `<?php` | `PHP-CONTENT-001` 75 | 75 | Observe |
| Photograph with an ordinary XMP packet | none | 0 | Allow |
| `photo.jpg` whose body is PHP text | `FILE-TYPE-001` 70 + `PHP-CONTENT-001` 75 | 100 | **Block** |
| `photo.jpg` whose body is BOM-prefixed UTF-16 PHP | `FILE-TYPE-001` 70 | 70 | Observe |
| `photo.jpg` whose body is an HTML page | `FILE-TYPE-001` 40 | 40 | Observe |
| `photo.png` whose body starts with `MZ` | `FILE-TYPE-001` 70 | 70 | Observe |
| `avatar.gif` = `GIF89a;` plus a PHP marker | `PHP-CONTENT-002` 85 + `PHP-CONTENT-001` 75 | 100 | **Block** |
| `shell.php` = `GIF89a;` plus a PHP marker | `WP-UPLOAD-001` 90 + `-002` 85 + `-001` 75 | 100 | **Block** |
| Chunk 2 of a chunked JPEG | none | 0 | Allow |
| HEIC bytes named `photo.jpg` | none | 0 | Allow |
| `report.xls` that is really an HTML export | none | 0 | Allow |
| `../notes.jpg` that is really text | `FILE-TYPE-001` 40 + `FILE-NAME-001` 60 | 100 | **Block**, the known rough edge |

---

## Test plan

### Benign fixtures that must stay silent

Realistic WordPress, Elementor and Google Site Kit traffic. Every fixture is a synthetic byte array
built in the test. None is a real media file, and none is a working payload.

| Fixture | Leading bytes | Expectation |
| --- | --- | --- |
| `photo.jpg`, JFIF | `FF D8 FF E0 00 10` then `JFIF` | both rules silent |
| `photo.jpg`, EXIF plus an XMP packet | `FF D8 FF E1`, `Exif`, then `<?xpacket begin=` | both rules silent, total score 0 |
| `photo.jpg` whose XMP holds `<?php echo 'synthetic marker';` | marker inside APP1 | `-002` null, `FILE-TYPE-001` null, engine score exactly 75, action `Observe` |
| `banner.png` with a `tEXt` chunk holding the same marker | valid IHDR, tEXt, IDAT, IEND | `-002` null, score 75 |
| `animation.gif` with a comment extension holding the same marker | a `21 FE` block before the trailer | `-002` null, score 75 |
| `logo.webp` | `RIFF`, size, `WEBP` | silent |
| `icon.svg` | `<svg xmlns=` | silent, signature-less extension |
| `elementor-template.json` | `{"version":` | silent |
| `elementor-icons.woff` and `.woff2` | `wOFF`, `wOF2` | silent |
| `elementor-kit-export.zip` | `PK` local header | silent |
| `site-kit-export.csv` | `Date,Sessions` | silent |
| `analytics-report.pdf` | `%PDF-1.7` | silent |
| `document.docx`, `spreadsheet.xlsx`, `presentation.pptx`, `report.odt` | `PK` local header | silent, no cross-family mismatch |
| `video.mp4` | box size then `ftypisom` | silent |
| `video.webm` | `1A 45 DF A3` | silent |
| `audio.mp3` with an ID3 tag, and a second with a raw `FF FB` frame sync | | both silent |
| `font.ttf` | `00 01 00 00` | silent |
| `photo.jpg` carrying HEIC bytes, `ftypheic` | | silent, cross-format rename |
| `screenshot.png` carrying WebP bytes | | silent, cross-format rename |
| **Chunk 2 of a chunked JPEG**: named `photo.jpg`, sample of mid-file entropy bytes including `FF 00` stuffing | | silent |
| `photo.jpg` with an eight-byte unrecognized sample | | silent, below the decision floor |
| `photo.jpg` with an empty sample | | silent |
| `report.xls` that is an HTML export | `<html><table>` | silent, legacy Office text exemption |
| `installer.zip` that is self-extracting | `MZ` | silent, container `nativeExecutable` exemption |
| `presentación-española.pptx`, `日本語のファイル.png` | valid signatures | silent, Unicode names change nothing |
| `photo.jpg` declared `application/octet-stream` | valid JPEG | silent |
| `photo.jpg` declared `image/png` | valid JPEG | silent, the declared type never triggers |
| A PHP-tutorial PDF containing `<?php` in a stream | `%PDF-` | `FILE-TYPE-001` null, `-002` null, `-001` 75, `Observe` — accepted noise, asserted so a future change to it is deliberate |

### Evasions that must fire

| Fixture | Expected |
| --- | --- |
| `photo.jpg` whose body is `<?php echo 'synthetic marker';` | `FILE-TYPE-001` 70 `script`; with `-001`, engine score 100 |
| `photo.jpg` whose body is a UTF-16LE byte order mark plus the same marker | `FILE-TYPE-001` 70; `-001` silent, which proves the BOM path |
| `photo.png` whose body starts with `MZ` and padding | `FILE-TYPE-001` 70 `nativeExecutable` |
| `report.docx` whose body is PHP text | `FILE-TYPE-001` 70 `script` |
| `notes.jpg` whose body is an HTML document | `FILE-TYPE-001` 40 `text` |
| `avatar.gif` = `GIF89a;` plus `<?php echo 'synthetic marker';` | `-002` 85, `region` = `afterTrailer`; `FILE-TYPE-001` **null**, which proves there is no triple counting |
| `avatar.png` = minimal IHDR, IDAT, IEND, marker appended after `IEND` | `-002` 85, `region` = `afterIend` |
| `avatar.jpg` = `FF D8 FF D9` plus the marker | `-002` 85, `region` = `afterEoi` |
| `avatar.webp` = a RIFF whose declared size ends before the marker | `-002` 85, `region` = `beyondDeclaredLength` |
| `avatar.bmp` = a BMP whose declared file size ends before the marker | `-002` 85, `region` = `beyondDeclaredLength` |
| `avatar.gif` = a valid GIF, its trailer, `<?=`, then 16 printable bytes | `-002` fires |
| `avatar.gif` = a valid GIF, its trailer, `<?=`, then 16 binary bytes | `-002` **null**, which proves the printable guard |
| `polyglot.php` = `GIF89a;` plus a PHP marker | `WP-UPLOAD-001` 90 + `-002` 85 + `-001` 75, capped at 100 |
| `photo.php.jpg` whose body is PHP text | `WP-UPLOAD-001` 50 + `WP-UPLOAD-002` 30 + `FILE-TYPE-001` 70 + `-001` 75, capped at 100 |

Every synthetic marker is `<?php echo 'synthetic marker';`, matching the existing fixtures. No test
constructs a working webshell, and no test writes a file to disk.

### Structural tests

- Both rules must call `cancellationToken.ThrowIfCancellationRequested()` **before** any early return,
  so they satisfy the existing `Rules_HonorCancellation` theory, which passes a context with no
  sample. Both must be added to that theory and to `BenignUploads_ProduceNoFindingFromAnyRule`.
- Both must call `ArgumentNullException.ThrowIfNull(context)`, matching the newer rules.
- Both must hoist `context.NormalizedFile` into a local. It recomputes on every access by design.
- Neither may allocate a string from the sample. `PHP-CONTENT-001` decodes the whole sample as UTF-8
  for every file; adding two more decodes would triple that cost per upload. The shared byte-level
  search in `FileSignatures` exists so that all three rules can converge on it later.
- A fuzz-style test should feed random byte arrays of 0 to 4096 bytes under a rotation of benign
  extensions and assert that `PHP-CONTENT-002` never fires and that `FILE-TYPE-001` never reports
  `script` or `nativeExecutable`.

## Open dependencies

- `GatewayConfigurationValidator` should reject a `MultipartInspectionOptions.SampleBytes` value under
  512. Below that floor the text classification cannot run and the `%PDF-` tolerance is lost, so a
  configuration would silently disable content inspection while appearing to enable it.
- Both rules must be registered in the gateway's rule set alongside the six existing rules, and in
  `src/WPShield.Service/Program.cs`, which still constructs the list by hand.
- `docs/en/m2-upload-rules.md` and `docs/es/m2-reglas-carga.md` need two new rows in their rule
  tables, and the roadmap checkbox for `FILE-TYPE-001` and `PHP-CONTENT-002` closes with them.

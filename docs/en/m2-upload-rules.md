# Upload rules and file name normalization

WPShield inspects the name an upload will actually have on disk, not the name the client typed. This
document explains why that distinction matters on Windows, what each rule detects, and where each
rule can be wrong.

## Why normalization comes first

The original implementation compared `Path.GetExtension(fileName)` against a list of PHP extensions.
That check is correct on paper and evadable in practice, because Windows and NTFS normalize several
forms before a file is written:

| Submitted name | `Path.GetExtension` | Reaches disk as | Old rule |
| --- | --- | --- | --- |
| `shell.php` | `.php` | `shell.php` | blocked |
| `shell.php.` | *(empty)* | `shell.php` | **passed** |
| `shell.php ` | `.php ` | `shell.php` | **passed** |
| `shell.php::$DATA` | `.php::$DATA` | `shell.php` | **passed** |
| `photo.php.jpg` | `.jpg` | `photo.php.jpg` | **passed** |
| `web.config` | `.config` | `web.config` | **passed** |
| `shell.aspx` | `.aspx` | `shell.aspx` | **passed** |

`NormalizedFileName` performs the same collapse the file system would, in this order:

1. Remove control characters, including embedded `NUL`, which truncates names in native APIs.
2. Keep only the final path segment, discarding any `../` or `..\` prefix.
3. Cut at the first `:`, removing NTFS alternate data stream suffixes such as `::$DATA`.
4. Trim trailing dots and spaces, which Windows strips silently on write.
5. Split the result into **every** extension segment, lowercased.

Each removal is recorded as a flag, so `FILE-NAME-001` can report what was stripped without a rule
having to re-parse the raw name.

> [!IMPORTANT]
> Do not assume WordPress will sanitize the name for you. The vulnerable plugin endpoints that cause
> upload incidents are precisely the ones that write files without calling `sanitize_file_name()`.
> That is the reason WPShield inspects the request at all.

## Rules

| Rule ID | Signal | Score | Blocks alone |
| --- | --- | --- | --- |
| `IIS-CONFIG-001` | Upload is named `web.config` | 100 | Yes |
| `WP-UPLOAD-001` | PHP-executable extension, final position | 90 | Yes |
| `WP-UPLOAD-001` | PHP-executable extension, embedded position | 50 | No |
| `IIS-UPLOAD-001` | IIS-executable extension, final position | 90 | Yes |
| `IIS-UPLOAD-001` | IIS-executable extension, embedded position | 50 | No |
| `PHP-CONTENT-002` | Valid image signature with PHP source proven past the image's own data | 85 | Yes |
| `PHP-CONTENT-001` | `<?php` or `<?=` in the bounded sample | 75 | No |
| `FILE-TYPE-001` | Extension claims a binary format, bytes carry a script marker | 70 | No |
| `FILE-TYPE-001` | Extension claims a document or media file, bytes are `MZ` or ELF | 70 | No |
| `FILE-TYPE-001` | Extension claims a binary format, bytes are plain text | 40 | No |
| `FILE-NAME-001` | Structural anomaly in the name | 60 | No |
| `WP-UPLOAD-002` | Executable extension disguised behind a benign one | 30 | No |

Scores are summed **within one file** and capped at 100. The default site thresholds are
`ObserveThreshold` 30 and `BlockThreshold` 80.

When a request carries several files, the gateway takes the **maximum** score across them, never the
sum: twenty benign files at 30 each would otherwise reach 600 and block a request in which nothing is
wrong. See [bounded multipart inspection](m2-multipart-inspection.md) for how these rules are reached
on live traffic, and for what the gateway does with the result.

### `IIS-CONFIG-001` — web.config upload

The highest-confidence rule WPShield ships, and the one a Linux-oriented protection layer does not
have. IIS reads `web.config` from every directory it serves and applies it to that directory and its
children. An attacker who writes one into `wp-content/uploads` can register a handler mapping that
executes files of their choosing, re-enable script execution an operator disabled, or relax
authorization for the directory. It turns an arbitrary file write into remote code execution without
uploading a single script.

The rule matches the exact reserved name only, after normalization, so `web.config.`, `WEB.CONFIG`,
`web.config::$DATA` and `../web.config` are all caught while an unrelated `app.config` download is
not affected.

**False positives:** none expected. No WordPress workflow uploads a `web.config` in a request body.

### `WP-UPLOAD-001` — PHP-executable extension

Covers `php`, `php3`–`php8`, `phps`, `pht`, `phtm`, `phtml` and `phar`, matched against every
extension segment rather than only the last.

**False positives:** an embedded match scores 50 rather than 90 because `readme.php.txt` is
structurally identical to `photo.php.jpg` and cannot be separated from it by name alone. Combined
with `WP-UPLOAD-002` such a name reaches 80 and would be blocked, so stay in Monitor mode until you
have reviewed your own upload traffic.

### `IIS-UPLOAD-001` — IIS-executable extension

Covers `aspx`, `asp`, `ashx`, `asmx`, `ascx`, `axd`, `cshtml`, `vbhtml`, `razor`, `svc`, `soap`,
`rem`, `asax` and `master`. An `.aspx` file in a writable uploads directory runs as the application
pool identity, which is a strictly larger capability than a PHP shell.

**False positives:** a WordPress site has no legitimate reason to accept an ASP.NET handler through
an upload endpoint. A site that genuinely distributes such files as downloads should stay in Monitor
mode for that path.

### `WP-UPLOAD-002` — disguised extension

Fires when an executable segment exists in a non-final position. It contributes a deliberately small
score because it is a disguise signal rather than proof of execution, and only matters combined with
`WP-UPLOAD-001` or `IIS-UPLOAD-001` reporting the same name.

**False positives:** ordinary multi-extension names never match, because the rule requires an
executable segment rather than merely more than one segment. `archive.tar.gz`, `style.min.css`,
`jquery.min.js` and `report.2024.xlsx` are all silent.

### `FILE-NAME-001` — structurally unsafe name

Reports what normalization had to remove: `pathSeparator`, `alternateDataStream`,
`trailingDotsOrSpaces`, `controlCharacter`, `reservedDeviceName`, `excessiveLength`,
`emptyAfterNormalization`.

**False positives:** Unicode file names are not flagged, only control characters are. Some browsers
and legacy clients submit a full local path instead of a bare name, so `pathSeparator` can fire on
legitimate traffic. This is the main reason the rule scores 60 and cannot block on its own.

### `PHP-CONTENT-001` — PHP tag in the sample

**Known limitation, not a defect.** The rule searches a bounded UTF-8 sample. It can be evaded by
placing the tag beyond the sample window, by encoding the file as UTF-16, or by splitting the tag
across the sample boundary. It also does not detect `<?` short tags, because `short_open_tag` is off
by default in modern PHP and matching it would flag every XML document. Treat this rule as a
supporting signal, never as the sole reason to block.

### `FILE-TYPE-001` — extension and content disagree

Every other rule above reasons about the *name*. This one reasons about the *bytes*, because
`photo.jpg` is a perfect name and the name rules have nothing to say about it. WordPress decides what
an upload is from its extension, and `wp_check_filetype_and_ext()` consults the real bytes for only a
handful of types; a plugin endpoint that writes the file itself consults nothing.

The single trigger is **final extension versus leading bytes**. The final segment is the claim the
file makes about itself: it is what the IIS static handler maps to a MIME type and what WordPress
stores in the attachment record. An executable segment in a non-final position is a different
question, already answered by `WP-UPLOAD-001` and `WP-UPLOAD-002`.

Three tiers can fire, and none of them blocks alone:

| Tier | Condition | Score |
| --- | --- | ---: |
| `script` | A validated script marker — `<?php`, `<?=`, `<%`, `<script`, `#!/` — where a binary format was claimed. Also searched over a UTF-16 decode when the sample opens with a byte order mark | 70 |
| `nativeExecutable` | A self-corroborating `MZ` or ELF header where an image, audio, video, font or PDF extension was claimed | 70 |
| `text` | Human-readable text where a binary format was claimed, with no marker found | 40 |

70 is Observe on its own and reaches 100 combined with `PHP-CONTENT-001`'s 75, which is the correct
outcome for a `photo.jpg` whose leading bytes are PHP.

**The declared `Content-Type` never triggers a finding.** Browsers derive a part's `Content-Type`
from the same extension through the operating system registry, so on legitimate traffic it carries no
information the extension did not already carry — and curl, wp-cli, mobile applications and the
plupload fallback all legitimately send `application/octet-stream`. It is recorded in evidence as a
four-state token (`agrees`, `disagrees`, `opaque`, `absent`) and nothing more, so no attacker-supplied
header text reaches a log.

**False positives.** The rule is silent by construction on the cases that generate them, and each
silence has a stated cost:

- **Chunked uploads.** With a 6 MiB request cap, every large media upload must arrive as plupload
  chunks, and chunk 2 onward is a part named `photo.jpg` with no signature at offset 0. This is why
  unrecognized bytes are *never* a finding — the load-bearing decision in the whole rule. It costs a
  webshell written in UTF-16 without a byte order mark, and one whose marker sits past the sample
  window.
- **Cross-format renames.** HEIC saved as `.jpg`, WebP as `.png`, JPEG as `.webp`. Chrome's "save
  image as", iOS shares and Android galleries produce these constantly and the file is still a benign
  image, so recognized-but-different is silent. Matching by family also means `.docx`, `.xlsx`,
  `.pptx` and `.odt` never disagree with each other, since all four are one ZIP family.
- **Self-extracting archives.** A `.zip`, `.7z` or `.rar` legitimately begins with `MZ`, so the
  `nativeExecutable` tier applies only to image, audio, video, font and PDF extensions. The cost is
  that an executable renamed `invoice.doc` passes silently.
- **Reporting-plugin exports.** Writing an HTML table or CSV under an `.xls` name is endemic in
  reporting and analytics plugins. It is a bug in the exporter, not an attack, so legacy Office
  extensions are exempt from the `text` tier — though not from the `script` tier.
- **Signature-less and unknown formats.** SVG, TXT, CSV, JSON, XML, HTML and TAR have no magic
  number, so there is no expectation to violate; an extension WPShield has never seen makes no claim
  at all. Both are silent.
- **The one combination that blocks benign traffic.** The `text` tier at 40 plus `FILE-NAME-001` at
  60 is exactly 100. `FILE-NAME-001` fires on legacy clients that submit a full local path, so a
  text-bodied file with a binary extension from such a client would be blocked in Block mode. It is
  a narrow intersection of two unusual client behaviours, and it is the reason the `text` tier scores
  40 rather than 70. Stay in Monitor mode until you have reviewed your own upload traffic.

### `PHP-CONTENT-002` — PHP appended past the end of a valid image

`GIF89a;` followed by a PHP script is a valid GIF followed by a PHP script. `getimagesize()` accepts
it, every signature check accepts it, and `FILE-TYPE-001` accepts it because the signature genuinely
matches the extension. It has been the standard bypass for WordPress upload validation for a decade,
and the only thing separating it from a photograph is **where the PHP marker sits relative to the
image's own structure**.

The rule fires only when all three of the following hold:

1. The sample opens with a signature from the `getimagesize()` set — GIF, PNG, JPEG, BMP, or RIFF
   carrying the `WEBP` form. These are exactly the formats WordPress's own image validation accepts,
   which is exactly what the bypass targets.
2. A bounded structural walk establishes where the container's data ends: a GIF block walk to the
   `3B` trailer, a PNG chunk walk to the end of `IEND`, a JPEG segment walk to `FF D9`, or the file
   length a BMP or RIFF header declares.
3. A validated PHP marker appears at or beyond that boundary.

If the walk cannot establish the boundary, the rule is silent. It never falls back to a weaker tier.

**Why it is proof-based rather than heuristic.** This rule is a strict subset of `PHP-CONTENT-001`:
both search the same bounded sample for `<?php` and `<?=`, so whenever this one fires, the other's 75
is already on the board. The engine sums and caps at 100, which means *any* co-firing score of 5 or
more carries the request past the default block threshold of 80. There is no score at which this rule
is a moderate signal — it is a block-or-not switch whose only tuning knob is precision. So the firing
condition was narrowed to a structural proof rather than the score being tuned down. 85 rather than
100 keeps a gradation below `IIS-CONFIG-001`, which is definitional, and gives an operator who raises
`BlockThreshold` to 90 a meaningful position.

The file name is ignored entirely. A polyglot is dangerous under every name, and being content-only
means the rule composes with the name rules instead of double-counting with them. The normalized name
is still recorded in evidence so an operator can find the part.

**False positives.** The case that decides whether this rule is shippable is the photograph with
metadata, and three things keep it quiet. `<?xpacket` and `<?xml` are not PHP markers — the set is
`<?php` and `<?=` only — so an ordinary XMP packet matches nothing. A marker inside a metadata segment
is structurally below the boundary the walk establishes, so a JPEG `APPn` or `COM` segment, a PNG
`tEXt`, `iTXt` or `zTXt` chunk and a GIF comment extension are walked over and never searched: a
developer who screenshots PHP code and uploads it with the code in an XMP caption gets
`PHP-CONTENT-001` at 75, an Observe, and nothing from this rule. And `<?=` is believed only when the
following sixteen bytes read as printable text, without which roughly one image in four thousand
would become a blocked upload.

ZIP and PDF are excluded from the container set entirely — installing a plugin or theme *is*
uploading a ZIP full of PHP, and a PDF about PHP contains the open tag as prose — as are TIFF, ICO,
ISO base media and Matroska, none of which offers a cheap proof and none of which is the format the
bypass uses.

**Known limit.** The walk sees only the bounded sample. For a real photograph with an appended
payload, the JPEG `EOI` sits hundreds of kilobytes past the sample window, so nothing is established
and this rule is silent — as is `PHP-CONTENT-001`, since the payload is outside the sample too. What
this rule catches is the *minimal-carrier* polyglot: the seven-byte `GIF89a;` stub, the small
one-by-one GIF, the four-byte JPEG. Those are the shapes the published bypasses actually use, because
an attacker wants the smallest carrier that survives validation. Closing the large-carrier case needs
a sampling strategy that also reads the tail of the body, which is not something a rule can fix.

## Worked example

Submitting `..\..\photo.php.jpg.` with a PHP tag in the body produces:

```json
{
  "SiteId": "wordpress-one",
  "Score": 100,
  "RecommendedAction": "Observe",
  "Findings": [
    { "RuleId": "WP-UPLOAD-001", "Score": 50,
      "Evidence": { "extension": ".php", "position": "embedded", "normalizedName": "photo.php.jpg" } },
    { "RuleId": "WP-UPLOAD-002", "Score": 30,
      "Evidence": { "executableExtension": ".php", "presentedExtension": ".jpg" } },
    { "RuleId": "FILE-NAME-001", "Score": 60,
      "Evidence": { "anomalies": "pathSeparator,trailingDotsOrSpaces" } },
    { "RuleId": "PHP-CONTENT-001", "Score": 75 }
  ]
}
```

The action is `Observe` rather than `Block` because the example site runs in Monitor mode. Evidence
always reports the normalized name, never the raw one, so a name carrying control characters cannot
reach a log consumer intact.

## Adding a rule

A new rule must arrive with a stable untranslated ID, the signals it combines, its score and the
reasoning behind it, an explicit false-positive analysis, benign test fixtures that must stay silent,
and English and Spanish documentation. Use harmless synthetic markers in tests. Never commit a
working webshell.

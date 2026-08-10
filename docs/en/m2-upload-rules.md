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
| `PHP-CONTENT-001` | `<?php` or `<?=` in the bounded sample | 75 | No |
| `FILE-NAME-001` | Structural anomaly in the name | 60 | No |
| `WP-UPLOAD-002` | Executable extension disguised behind a benign one | 30 | No |

Scores are summed per request and capped at 100. The default site thresholds are `ObserveThreshold`
30 and `BlockThreshold` 80.

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

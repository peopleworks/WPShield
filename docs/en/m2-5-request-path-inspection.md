# Request path inspection

WPShield inspects the request line of every request, before anything reads a body.

Through M2 it inspected only `multipart/form-data` bodies. That covers the moment a webshell arrives
and nothing else — and a shell already on disk is not uploaded, it is **fetched**, with a plain `GET`
that carries no body for an upload rule to look at. The two halves of the problem need two families
of rule: one refuses the write, this one refuses the read.

## Where this came from

Not from a threat model. From a compromised WordPress site on IIS, whose server logs recorded the
exploitation traffic in full. Six webshells were recovered. Every request that reached one was an
ordinary `GET` or `POST` to an existing `.php` file. **Not one of them carried a body**, so not one of
them was visible to any rule WPShield had.

The locations tell you what the rules must cover:

| Where the shell was | Caught by |
| --- | --- |
| Beside a vendored code editor's JavaScript, under `static/` | `WP-PATH-002` |
| Beside a slider skin's stylesheets, under `static/` | `WP-PATH-002` |
| A second copy beside the same editor's JavaScript | `WP-PATH-002` |
| In the media library, from an incident four years earlier | `WP-PATH-001` |
| A second one in the media library, same vintage | `WP-PATH-001` |
| **In the plugin's own PHP directory, beside its real files** | **Nothing. See below.** |

Five of six reach the default block threshold from the request line alone. The sixth does not, and
that is written into the test suite as an asserted gap rather than left as an impression.

## The rules

### `WP-PATH-001` — executable requested from the uploads tree

Score **100**, which blocks on its own.

Fires when a request would execute a script from `wp-content/uploads`, `wp-content/upgrade` or
`wp-content/updraft`. Those directories are data: WordPress writes media and archives into them and
serves them back as bytes. Nothing in core, and no correct plugin, routes execution through them.

Plugins do *place* PHP under `uploads` — All-In-One WP Security keeps firewall settings there — but
such files are reached with `include` from PHP, never over HTTP. Refusing the HTTP request takes
nothing away, which is what justifies a score that blocks alone.

### `WP-PATH-002` — executable requested from an asset-only directory

Score **100**, which blocks on its own.

Fires when a request would execute a script from below one of:

```
dist  build  _next  out  node_modules  bower_components  static  fonts  webfonts  img  images
```

Every name there denotes a directory that exists to hold bytes a browser fetches verbatim. A script
inside one is either an intruder or a packaging accident, and in both readings no caller needs the
request to succeed.

**What is deliberately missing matters more than what is present.** `assets`, `css`, `js`, `media`
and `vendor` are the names most people would add next, and all five are excluded. Older plugins
genuinely serve generated stylesheets and scripts from PHP — `css/style.php` and `js/script.php` are
a real, if unfashionable, pattern — and `vendor` is a Composer tree that some plugins expose. Adding
them would put a blocking score on traffic that works today, and a security tool that breaks a
working site gets switched off, taking the rules that were right with it.

The score rests on that narrowness. The moment a name is added for which "a script here cannot have a
legitimate HTTP caller" is not true, the score is wrong and the addition is the bug.

### `IIS-PATH-001` — unsafe path form

Score **60**, which observes and does not block alone.

Reports what normalization had to undo: a `..` segment, a backslash acting as a separator, an NTFS
alternate data stream suffix, trailing dots or spaces, embedded control characters, a path past the
bounds, or a second percent-decode that produced a different path. Each of these makes the path that
reaches disk differ from the path that was inspected, which is the entire technique.

60 matches `FILE-NAME-001` deliberately. On its own an odd path shape is worth recording rather than
refusing: sloppy clients and old caching layers produce paths that need tidying. Its real job is the
log line — an operator who sees `traversal` or `doubleEncoded` is looking at reconnaissance, whether
or not this attempt reached anything.

## Normalization

Rules never match the raw request target. They match `InspectionContext.NormalizedPath`, which
reduces a path to what a Windows web server would actually resolve.

| Input | Normalizes to |
| --- | --- |
| `/WP-Content/Uploads/Shell.PHP` | `/wp-content/uploads/shell.php` |
| `/wp-content\uploads\shell.php` | `/wp-content/uploads/shell.php` |
| `/wp-content/uploads/shell.php.` | `/wp-content/uploads/shell.php` |
| `/wp-content/uploads/shell.php::$DATA` | `/wp-content/uploads/shell.php` |
| `/wp-content/uploads/nested/../shell.php` | `/wp-content/uploads/shell.php` |
| `/wp-content//uploads//shell.php` | `/wp-content/uploads/shell.php` |

### Every segment, and every extension position

`/wp-content/uploads/shell.php/logo.jpg` executes `shell.php`. With `cgi.fix_pathinfo` enabled — the
default on many Windows PHP-FastCGI installations — PHP walks back to the last component that exists
on disk and hands the rest to the script as `PATH_INFO`. A rule that looked at the last segment would
see an image.

`/wp-content/uploads/shell.php.jpg` is the same reasoning one level down, and the same reasoning the
upload rules already apply to file names: check every extension segment, not only the final one.

### Two views

The host hands over a path it has percent-decoded once. Some IIS URL Rewrite chains decode again, so
`%252e%252e%252f` arrives here as the inert-looking `%2e%2e%2f` and becomes traversal one decode
later — at a point where nothing is inspecting.

So a second view is built when, and only when, one more decode changes the path. Rules evaluate both
and take the first result, literal view first.

This is the same shape as the two file-name views, and for the same reason: modelling only the
normalization the inspector performs, rather than the one the backend performs, is how `web.con{f}ig`
scored zero against a rule documented as having no false positives.

**What is not modelled**, stated rather than discovered later: no third decode, and no 8.3 short-name
expansion, which needs the filesystem and cannot be answered from a path alone.

## Cost

One normalization plus three rule evaluations per request, all string work bounded by 64 segments of
255 characters. The second view is built only when the path contains a percent sign and only when
decoding changes it, so ordinary traffic pays for one pass.

Nothing here buffers, parses a body, or takes a sample. A refusal is answered from the request line,
which means a blocked webshell request costs strictly less than a forwarded one.

## Order in the pipeline

```
resolve site → size limit → request path rules → multipart inspection → forward
```

Path inspection runs before the body is touched. A request refused here never reaches the buffering
step, and a site in `Disabled` mode skips both.

## What this does not cover

- **A shell in a directory that legitimately contains PHP.** The sixth shell in the incident sat in
  its plugin's own PHP directory under a name one character from a real one. Nothing about the path
  distinguishes it. Catching that needs knowledge of which files a plugin version actually ships, or
  behaviour over time — and a heuristic tuned to match that one name would be fitting the rule to the
  sample.
- **Query strings.** Only the path is inspected. `Path` and never `Path + QueryString`, so that
  "never log a full query string" is satisfied at the source.
- **Request bodies.** Unchanged from M2: only `multipart/form-data` is inspected.
- **Response content.** The exploitation traffic in the incident was distinguishable by its
  *responses* — 200 with a 24-byte body for a probe, 500 for the payload. WPShield does not look at
  responses at all.

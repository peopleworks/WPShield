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

## The exposure family

The three rules above answer "is someone running a shell". These nine answer a different question:
**is someone asking this site for a file that gives the server away?** A scan sends the same requests
to every site on a host — WordPress, .NET, Blazor alike — and before this family, none of them met a
rule.

They were chosen against a week of real IIS logs from a shared Windows host, not from a threat model,
and that choice decided their shape. A rule built from a scanner catalogue's list of paths — `/.env`,
`/.env.production`, `/backend/.env` — missed about **84%** of the `.env` probes in those logs, because
scanners walk every folder name they can guess. So every rule here matches a **segment, in any
position**: a `.env` anywhere, a `.git` folder anywhere.

| Rule | Matches | Score | Requests in the week |
| --- | --- | --- | --- |
| `EXPOSE-PATH-001` | A dotenv segment: `.env`, or `.env` followed by `.` `-` `_` or a digit | **100** | ~94,000 |
| `EXPOSE-PATH-002` | A `.git`, `.svn`, `.hg` or `.bzr` folder | **100** | ~4,900 |
| `EXPOSE-PATH-003` | A credential store or a deploy tool's state: `.aws`, `.config`, `.docker`, `.kube`, `.ssh`, `.vscode`, `.terraform`, `.git-credentials`, `.npmrc`, the `id_rsa` family… | **100** | ~7,500 |
| `EXPOSE-PATH-004` | A backup copy of a named file, final segment: `~`, `.old`, `.orig`, `.save`, `.swp`, and `.bak`/`.backup` after another extension | **100** | ~8,500 |
| `EXPOSE-PATH-005` | A database file or dump: `.sql`, `.sqlite`, `.db`, `.mdb`, `.dump`, and a bare `.bak`/`.backup` | 30 | ~2,100 |
| `IIS-PATH-002` | `web.config` or `launchSettings.json`, any segment | **100** | ~130 |
| `NET-PATH-001` | `appsettings.json` or `appsettings.<env>.json` | 30 | ~1,200 |
| `PHP-PATH-001` | `vendor/phpunit`, or `eval-stdin.php`, anywhere | **100** | ~50 |
| `PHP-PATH-002` | A `phpinfo` or test page: `phpinfo.php`, `info.php`, `test.php`… | 30 | ~14,000 |

Together with the three rules above, about **110,000** requests in that week reach the default block
threshold, and none of them was a legitimate page a block would have broken. Every one a site
answered with a 2xx was a catch-all page that answers any path, an empty answer to a client that had
already disconnected, or a script the path rules exist to refuse.

### The scores, and why three of them only observe

A score of 100 is a claim that the shape has no legitimate HTTP caller, the same claim `WP-PATH-001`
and `WP-PATH-002` make. Three shapes cannot make it, so they observe at 30 and never block alone:

- **`NET-PATH-001`.** A Blazor WebAssembly application loads `appsettings.json` in the browser, on
  every page, by design. Blocking it breaks every such application. Observing it tells an operator the
  file is public — intended on a Blazor site, a leak on a server-side one — and that judgement needs a
  person.
- **`EXPOSE-PATH-005`.** A database file can be published on purpose: a tutorial's sample schema, a
  dataset for download.
- **`PHP-PATH-002`.** Real WordPress installations keep a `test.php` someone still uses.

`.bak` is split between two rules for the same reason. `wp-config.php.bak` is a copy of a source file
and has no caller, so it blocks. `database.bak` on its own is SQL Server's native backup format, which
a site may publish, so it observes.

### What is deliberately silent

The silent cases are asserted as carefully as the firing ones, because each rule is a shape rather
than a prefix precisely to keep them silent:

- `.well-known/acme-challenge/` — certificate renewal. A rule shaped as "any dot-folder" would break
  it on every site.
- `.gitignore`, `.github`, `.gitlab-ci.yml`, `.envrc` — neighbours of the matched names, not the thing.
- `sitemap.xml.gz`, `.zip`, `.tar.gz`, `.7z` — an archive alone is an ordinary download.
- `photo.bak.jpg` — a backup suffix inside a name is not a backup.
- `/_framework/blazor.boot.json`, `/_blazor/negotiate`, `/swagger/`, `/Error`, `/health` — ordinary
  .NET and Blazor traffic, asserted to score zero across the whole family.

**`/admin` is not a rule, on purpose.** It is probed from hundreds of addresses, and it is a real route
on many real sites. A rule that scored it would be scoring a page, not a probe. The same goes for
`/login`, `/dashboard` and `/signin`; the test suite asserts all four score zero, so adding one is a
decision rather than an accident.

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

One normalization plus twelve rule evaluations per request, all string work bounded by 64 segments of
255 characters, and each rule a set lookup per segment. The second view is built only when the path contains a percent sign and only when
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

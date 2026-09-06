# M2 handoff — state at 2026-08-25

Working note, not a published document. Delete it when M2 closes.

Branch `chore/community-readiness`, pushed to origin at `e00afdf`. Working tree clean.
Build: 0 warnings. Tests: **856 passing** (83 Core, 208 Abstractions, 308 Rules.WordPress,
257 Gateway). `dotnet format --verify-no-changes`: clean.

## What landed

| Commit | What |
| --- | --- |
| `2ca8986` | Community readiness: figures, Pages site, NOTICE.md, threat model, release workflow, packaging metadata, plan relocation |
| `479a064` | M2 inspection wired to real traffic, the `MapFallback` routing fix, four parser differentials closed, WordPress normalization view |
| `e00afdf` | Regression tests for all of the above |

### The two findings that mattered most

**The fallback route rejected every path containing a dot.** `app.MapFallback(delegate)`
registers `{*path:nonfile}`, and the `nonfile` constraint refuses any path whose last segment
contains a dot. Measured on the previous build: `GET /wp-login.php` → 404 with the backend
untouched, `GET /wp-login` → 200. Every stylesheet, script and image too. The suite never caught
it because all of its paths were extensionless. It also made M2 unreachable regardless of wiring,
since WordPress uploads post to `/wp-admin/async-upload.php`.

**The rules modelled NTFS normalization, not WordPress's.** `web.con{f}ig` scored 0 and was
allowed — one brace disabled `IIS-CONFIG-001`, the 100-point rule documented as having no expected
false positives. Fixed by evaluating a second normalization view (`sanitize_file_name()`) alongside
the first, most severe wins, with the divergence reported as a `wordpressRewrite` anomaly on
`FILE-NAME-001`.

## What is NOT done

The fix workflow was stopped after its Tests phase. Two phases never ran.

### 1. Independent adversarial re-verification — the important one

The four differentials are closed *and tested*, but nobody has re-attacked the fixed code. The
evidence today is: the code reads correctly, and the regression tests pass. That is not the same as
someone having tried to get past it.

The stopped workflow's phase 3 had two agents with different lenses. Their briefs are worth
reusing verbatim; the script is at
`%TEMP%\claude\C--Proyecto-WPShield\<session>\scratchpad\m2-fix.js` (phase `Re-attack`), and it can
be resumed with `Workflow({scriptPath, resumeFromRunId: 'wf_ad28f1fd-594'})` — the Fix and Tests
agents replay from cache, so only the re-attack and Close phases run.

**Transport lens.** Boundary that is a prefix of another boundary; `--{boundary}` inside file
*content* rather than framing; CRLF vs LF vs bare CR; RFC 2231 continuations (`filename*0=`,
`filename*1=`); overlong UTF-8 and percent-encoding in `filename*`;
`Content-Transfer-Encoding: base64`; nested `multipart/mixed`; declared `Content-Length` that
disagrees with what is sent; and **the new delimiter audit itself** as a DoS or correctness
surface — a body engineered to make the scan expensive, or to make it disagree with what
`MultipartReader` subsequently does. Plus: confirm a real browser-shaped WebKit POST, a plupload
chunked upload and an Elementor-shaped request are still inspected and forwarded, not refused.

**Semantics lens.** Names diverging under the two views in a third direction; IIS short (8.3) forms
such as `SHELL~1.PHP`; Unicode NFC/NFD and full-width forms collapsing to a dangerous extension;
`sanitize_file_name()` on names that become empty or a bare extension; WordPress's own uniqueness
suffixing (`shell-1.php`) reintroducing a form the rules did not see. Then the content rules: a
valid signature at offset 0 with the PHP marker beyond `SampleBytes`; a format family the signature
table excludes; the documented ZIP/PDF exclusions.

### 2. Documentation of what shipped

None of this is written down yet, and the concepts are now load-bearing:

- **Parser differentials**, EN and ES, in `docs/*/m2-*inspection*.md`. This is the most important
  idea in the design and it is undocumented. A contributor adding a parser feature has no way to
  know what they must not reopen.
- **The two normalization views**, in the upload-rules documents. An operator seeing a
  `wordpressRewrite` anomaly cannot currently look up what it means. The `web.con{f}ig` example is
  the clearest demonstration of why one view is not enough.
- **`THREAT_MODEL.md`** and `docs/es/modelo-de-amenazas.md`. Line 244 covers only the direction
  where WordPress does too little; the inverse — WordPress's sanitization *creating* a dangerous
  name — needs to be a named threat. Parser differential deserves to be a threat class in its own
  right. Both languages must stay in step.
- **`AGENTS.md`** invariants: `Complete` means the parse consumed the buffer; a part-header line
  beginning with whitespace is `Malformed`; the multipart declaration check must not depend on a
  strict full-header parse; extension rules evaluate against both normalization views. Each with
  one line on the attack it answers, because each of these, if reverted, reopens a measured hole.
- **`CHANGELOG.md`** entries for the differentials, in the existing prose style.

### 3. Known-open, lower severity

- **F5** — `docs/en/m2-multipart-inspection.md` recommends `ReadTimeoutSeconds: 120` for slow
  clients, and separately notes the timeout is what bounds how long a buffer is pinned. The two
  paragraphs do not cross-reference. Pinned memory ≈ attacker bandwidth × timeout, and
  `MaxConcurrentConnections` is unbounded. Worth stating together.
- **`og:image` points at `assets/social-preview.svg`.** Most social platforms do not render SVG
  og:images, so link previews may show no image. Needs a PNG twin and one line changed in
  `site/index.html`'s head.

## Roadmap position

M2 is functionally complete and honestly tested. It is not *closed* until the re-attack runs,
because the milestone's value is a claim about attackers, and that claim has not been tested
against the fixed code by anything other than its own tests.

M3 (rate limiting) still needs `Gateway:TrustedProxies` first — ADR 0001 requires it, and per-IP
limiting is meaningless until the gateway can resolve the real client address.

## Merge

Nothing merged to `main`. Recommended order once the re-attack is green:

1. The `MapFallback` fix deserves visibility on its own — it is currently inside `479a064` because
   it lives in `GatewayApplication.cs` entangled with the M2 wiring, but the PR description should
   lead with it. It fixes a total routing failure and is the highest-value single change here.
2. `2ca8986` (community) can merge independently at any time. It touches no gateway code.
3. M2 and its fixes after the re-attack reports CLOSED.

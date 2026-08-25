# WPShield Agent Instructions

WPShield is an open-source defensive security gateway for WordPress sites hosted on Windows Server and IIS.

## Required workflow

Before modifying code:

1. Read `README.md`, `ROADMAP.md`, `THREAT_MODEL.md`, `SECURITY.md`, this file, and the scoped
   instructions under `.github/instructions/` that match the paths you are about to touch, plus the
   relevant source and tests. `ROADMAP.md` is the published plan and wins wherever the working plan
   in `docs/es/plan-de-desarrollo.md` disagrees with it.
2. Inspect git status without discarding existing work.
3. State the proposed implementation plan.
4. Make the smallest cohesive change.
5. Run restore, build, and tests.
6. Add tests for new behavior.
7. Update English and Spanish documentation.
8. Show changed files and validation results.
9. Do not commit or push unless explicitly requested.

## Safety requirements

- Implement defensive functionality only.
- Keep `Monitor` as the default protection mode.
- Never expose the gateway publicly during M1 or M2.
- Never modify IIS, certificates, DNS, firewall rules, or Windows services automatically.
- Never log credentials, cookies, authorization headers, nonces, tokens, full query strings, or complete request bodies.
- Reject unknown hosts; do not configure a default backend.
- Remove the whole untrusted forwarding set, not only `X-Forwarded-For`, `-Proto` and `-Host`. It
  also includes `Forwarded`, every other `X-Forwarded-*` variant, the client-address family
  (`X-Real-IP`, `X-Client-IP`, `X-Cluster-Client-IP`, `True-Client-IP`, `CF-Connecting-IP`,
  `Fastly-Client-IP`, `X-Azure-*`) and the path-override headers `X-Original-URL` and
  `X-Rewrite-URL`, which are authentication-bypass vectors against IIS URL Rewrite.
- Never commit real hostnames, internal ports, or deployment topology. Use RFC 2606 `.example`
  placeholders; operator values belong in the gitignored `appsettings.Local.json`.
- Configuration must never appear to reload when it does not.
- Do not store suspicious uploads on disk.
- Do not create weaponized webshell samples. Use harmless synthetic markers in tests.
- Keep management and health interfaces restricted to loopback unless a later milestone explicitly designs authenticated access.

## Engineering standards

- Target .NET 10.
- Enable nullable reference types and treat warnings as errors.
- Use central package management.
- Keep `WPShield.Core` independent from ASP.NET Core and YARP where possible.
- Preserve explainable rule results and stable, untranslated rule IDs.
- Never match a rule against a raw client-supplied file name. Use `InspectionContext.NormalizedFile`,
  which strips control characters, directory prefixes, NTFS alternate data stream suffixes, and the
  trailing dots and spaces Windows removes on write. Check every extension segment, not only the
  last one, and report the normalized name as evidence rather than the raw one.
- Treat IIS-executable artifacts as dangerous as PHP. A `web.config` upload is remote code execution
  on IIS, and `.aspx`, `.ashx`, `.asmx` and `.ascx` run as the application pool identity.
- Do not assume WordPress sanitizes upload names. The vulnerable plugin endpoints that cause upload
  incidents are exactly the ones that never call `sanitize_file_name()`.
- Use cancellation tokens for asynchronous I/O.
- Bound every request size, stream, sample, buffer, section count, and timeout.
- **Never write a request body to disk.** Buffering in memory is bounded by
  `Gateway:MaximumRequestBytes`, applies only to `multipart/form-data` bodies, and exists because
  Block mode has to decide before forwarding — a network stream cannot be read twice, so the choice
  is between a bounded buffer and having no Block mode for uploads at all. Keep disk-freedom
  *structural*: the buffer type references no file API, so there is no disk path to prove
  unreachable. Do not reintroduce `FileBufferingReadStream` or any type whose spill-to-disk is
  disabled by a threshold value — a guarantee a future edit can undo by changing one number is not
  this guarantee.
- **Non-multipart traffic must never pay the buffering cost.** A request that is not multipart, or
  whose site is `Disabled`, or which arrives while inspection is switched off, must keep streaming
  straight through with no body held. Ordinary WordPress page traffic must not start paying for
  uploads it does not contain.
- **A reader limit breach must fail in the safe direction.** Exceeding a file, field, header,
  boundary or name limit, and failing to parse a body that declared `multipart/form-data`, are
  findings — never a silent forward. "The reader gave up" must never become "the reader waved it
  through", or an attacker buys an uninspected forward by prefixing a payload with dummy parts.
  Monitor forwards and warns; Block refuses.
- **Inspection evidence uses the normalized name only.** Never the raw file name, the field name,
  the sample, or a header value. Evidence is rendered into log lines, and a raw name can carry
  control characters, ANSI escapes and newlines straight into a log consumer or a terminal.
- Add unit tests and appropriate integration tests.
- Use English for code identifiers and localize user-facing messages.
- Preserve multi-site isolation.
- `WPShield.Abstractions`, `WPShield.Core` and `WPShield.Rules.WordPress` must stay free of ASP.NET
  Core, YARP, IIS and Windows-only dependencies. The Linux CI leg builds and tests exactly those
  three so the claim is falsifiable rather than asserted.

## Distribution

The project's own documentation says WPShield is not approved for production traffic. Distribution
must not contradict that, because a download is read by more people than a warning is.

- Nothing publishes to NuGet. No `PackAsTool`, no `ToolCommandName`, no `PackageId`, no
  `IsPackable=true`. A `dotnet tool install -g` route installs a security gateway for people who
  never opened the README, and a published package identifier cannot be withdrawn afterwards.
- Releases are prereleases until M7 completes, and none is ever marked "latest". GitHub keeps a
  prerelease out of the releases badge, out of the sidebar link and out of `/releases/latest`, so
  the default path a stranger takes through this repository does not end at a runnable gateway.
  Removing `prerelease: true` before M7 is the single change that undoes that.
- If a release attaches a built artifact, the artifact file name, the release body and the assembly
  metadata must each say it is a research preview not approved for production traffic — the file
  name most of all, because a zip gets renamed, forwarded and unpacked months later by someone who
  never saw the release page. Builds are unsigned until M6, so a checksum ships beside the archive.
- No installer and no container image. A Linux container is not a deployment target for a gateway
  whose rules encode an IIS attack surface, and shipping one would imply otherwise.
- `site/index.html` must carry the research-preview warning above the fold — before any capability
  description and without scrolling. The landing page is read by evaluators who will never open the
  README, so it is the page where that warning has to be unmissable, not a callout further down.
- Assembly and package metadata must not describe WPShield as production-ready, and the assembly
  version must match the version declared in `Directory.Build.props`.

## Documentation and figures

- Figures ship as light/dark pairs: `docs/assets/<name>-light.svg` and `docs/assets/<name>-dark.svg`,
  referenced through `<picture>` with `prefers-color-scheme`. Never update one variant without the
  other. A single-variant edit is invisible in review and leaves half the readers looking at a figure
  that contradicts the text.
- Alt text states the figure's argument in a full sentence, not its title. A figure whose argument
  only exists in the pixels is unavailable to a screen reader and to every renderer that is not
  GitHub.
- A figure must never depict real topology. Placeholder hostnames and loopback ports only, exactly
  as in configuration examples.
- Third-party names (Microsoft, Windows Server, IIS, Microsoft Defender, WordPress, Elementor,
  Google Site Kit) are used only to identify the software WPShield interoperates with. Affiliation
  and trademark statements live in `NOTICE.md`; do not restate or contradict them elsewhere.

## Validation commands

```powershell
dotnet restore WPShield.slnx
dotnet build WPShield.slnx --configuration Release --no-restore
dotnet test WPShield.slnx --configuration Release --no-build
dotnet format WPShield.slnx --verify-no-changes
git diff --check
```

## Commit convention

```text
feat(scope): description
fix(scope): description
test(scope): description
docs(language): description
security(scope): description
refactor(scope): description
```

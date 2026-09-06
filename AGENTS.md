# WPShield Agent Instructions

WPShield is an open-source defensive security gateway for WordPress sites hosted on Windows Server and IIS.

## Required workflow

Before modifying code:

1. Read `README.md`, `ROADMAP.md`, `THREAT_MODEL.md`, and relevant source files.
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
- Avoid buffering complete uploads in memory.
- Add unit tests and appropriate integration tests.
- Use English for code identifiers and localize user-facing messages.
- Preserve multi-site isolation.

## Validation commands

```powershell
dotnet restore WPShield.slnx
dotnet build WPShield.slnx --configuration Release --no-restore
dotnet test WPShield.slnx --configuration Release --no-build
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

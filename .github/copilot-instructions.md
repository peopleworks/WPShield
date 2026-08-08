# WPShield repository instructions

WPShield is an open-source, multilingual defensive gateway for WordPress sites hosted on Windows Server and IIS. It intercepts HTTP requests before IIS, PHP, and WordPress, applies bounded inspection, and emits explainable findings. It complements Microsoft Defender; it is not an antivirus, EDR, general malware scanner, or volumetric DDoS solution.

## Architecture

- `WPShield.Abstractions` contains stable, platform-independent inspection contracts.
- `WPShield.Core` contains site resolution, configuration, policies, scoring, redaction, and action calculation. Keep it independent from ASP.NET Core and YARP where possible.
- `WPShield.Rules.WordPress` contains WordPress-specific, explainable defensive rules.
- `WPShield.Gateway` is the loopback-only Kestrel/YARP gateway responsible for explicit host routing, safe forwarding, request correlation, health checks, and future pre-forward inspection.
- Future projects cover observability, local management, and Windows Service hosting.
- A single instance may protect multiple sites. Preserve strict site isolation and never use a default backend.

## Security and privacy invariants

- `Monitor` is the default. `Block` requires explicit per-site configuration.
- Unknown hosts fail closed with HTTP 421.
- During M1 and M2, listeners and administrative endpoints remain on loopback.
- Never alter IIS, public ports 80/443, certificates, DNS, firewall rules, or Windows services automatically.
- Discard untrusted inbound `X-Forwarded-*` values and generate trusted forwarding headers.
- Never log authorization values, cookies, passwords, WordPress nonces, API keys, OAuth values, complete query strings, complete bodies, or complete upload content.
- Never write suspicious uploads to disk or buffer complete uploads in memory.
- Bound request sizes, buffers, samples, section counts, headers, and timeouts. Honor cancellation.
- Use harmless synthetic markers in tests; do not add weaponized payloads.
- Keep stable rule IDs untranslated and expose detailed evidence only to authorized administrators.

## Engineering workflow

Before editing, read `AGENTS.md`, `README.md`, `ROADMAP.md`, `THREAT_MODEL.md`, applicable path instructions, and relevant implementation and tests. Inspect git status and preserve unrelated work. Make one cohesive change, add tests for behavior, and update both `docs/en` and `docs/es` when behavior or operations change. Do not commit or push unless explicitly requested.

Use .NET 10, nullable reference types, warnings as errors, central package management, English code identifiers, and localized user-facing text.

## Validation

```powershell
dotnet restore WPShield.slnx
dotnet build WPShield.slnx --configuration Release --no-restore
dotnet test WPShield.slnx --configuration Release --no-build
git diff --check
```

## Milestone state

- M0 foundation and CI are complete.
- M1 has a loopback-only multi-site gateway prototype.
- M1.1 gateway hardening and M1.2 synthetic integration tests are complete. Local IIS validation remains deferred to M1.3.
- Do not implement M2 multipart inspection until the M1 acceptance criteria pass.
- Public activation is deferred until synthetic and IIS validation, privacy review, bypass/rollback documentation, and stable Monitor operation are complete.

## Commits

Use Conventional Commit subjects such as `feat(gateway): ...`, `test(gateway): ...`, `security(logging): ...`, and `docs(en): ...`.

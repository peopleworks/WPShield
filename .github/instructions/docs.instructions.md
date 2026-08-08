---
applyTo: "docs/**/*.md"
---

# Documentation instructions

- Keep operational and architectural documentation equivalent in `docs/en` and `docs/es`.
- Document safe defaults, prerequisites, limits, Monitor/Block behavior, privacy implications, rollback, and bypass steps where applicable.
- Never include production credentials, tokens, internal secrets, or customer request data.
- Clearly distinguish implemented behavior from planned behavior.
- State that M1 and M2 listeners remain loopback-only and that automation must not modify IIS, DNS, certificates, firewall rules, Windows services, or public ports.
- Use stable, untranslated rule IDs while localizing explanations and administrator-facing messages.
- Keep commands suitable for PowerShell on Windows.

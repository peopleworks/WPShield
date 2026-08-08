---
applyTo: "src/WPShield.Rules.WordPress/**/*.cs"
---

# Security rule instructions

- Rules are defensive, deterministic, explainable, and safe to evaluate against bounded samples.
- Each finding must use a stable rule ID, score, message key, minimal safe evidence, recommended action, site ID, and request ID where supported by the contracts.
- Document the signals, risk, expected false positives, and recommended action in English and Spanish.
- Do not block based only on generic words such as `eval` or `system`; combine high-confidence signals.
- Do not trust filenames, extensions, declared MIME types, or client-provided paths. Normalize safely and compare independent signals.
- Never include full upload content, secrets, paths supplied by a client, or other sensitive data in findings or logs.
- Do not persist samples. Keep reads bounded and compatible with streaming inspection.
- Add benign positive, negative, boundary, and false-positive tests for every rule.
- A rule capable of blocking must remain observational in `Monitor` mode and require explicit authorization for `Block` mode.

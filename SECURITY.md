# Security policy

WPShield is an early security research project. It is **not approved for production traffic**, and
the README status table records exactly what does and does not work today.

## Reporting a vulnerability

**Never report an exploitable vulnerability through a public issue.** A public report tells an
attacker before it tells a maintainer, and WPShield users run it in front of live WordPress sites.

Use [private vulnerability reporting](https://github.com/peopleworks/WPShield/security/advisories/new).

Please include:

- The affected version or commit.
- Reproduction steps using safe synthetic data.
- The impact, including which of the project invariants it breaks.
- A proposed mitigation, if you have one.

Never submit real credentials, session cookies, malicious payload collections, private customer data,
or production logs without sanitizing them first. Do not attach working webshells or weaponized
payloads; a harmless synthetic marker is enough to demonstrate a detection gap.

## What counts as a vulnerability

WPShield's security value rests on a set of invariants. A way to break any of these is a
vulnerability, not a feature request:

- An upload that reaches a backend without being evaluated by the rules that should have seen it.
- A file name form that reaches disk as an executable script while inspection sees something benign.
- A request that reaches a backend the operator did not assign to its hostname.
- An untrusted forwarding or path-override header surviving to the backend.
- Credentials, cookies, authorization values, nonces, tokens, full query strings, request bodies or
  upload content appearing in logs or in evidence.
- A suspicious upload being written to disk.
- A configuration that makes the gateway listen publicly during M1 or M2, or that silently applies
  differently from what the operator wrote.
- Blocking behavior occurring on a site configured in Monitor mode.

A rule that misses an attack it was never designed to catch is a gap; open a
[feature proposal](https://github.com/peopleworks/WPShield/issues/new?template=feature_request.yml).
A rule that blocks legitimate traffic is a
[false positive report](https://github.com/peopleworks/WPShield/issues/new?template=false_positive.yml),
and it is treated seriously: taking a working site offline is a real harm.

## Response

This is a volunteer project with no response-time guarantee. Reports that break an invariant above
are prioritized over everything else on the roadmap.

## Scope

Out of scope: the security of WordPress itself, of third-party plugins, of IIS, or of a host that was
already compromised. WPShield complements Microsoft Defender and normal WordPress hardening; it does
not replace them, and it is not an antivirus, an EDR, a stored-file malware scanner, or volumetric
DDoS mitigation.

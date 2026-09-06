# Security policy

WPShield is an early security research project. It is **not approved for production traffic**, and
the README status table records exactly what does and does not work today.

## Supported versions

There are no releases yet, so there is nothing to support and nothing to backport to. The only
supported version is the current `main` branch. Report against a commit hash; a report against a
fork or a stale branch will be checked against `main` before anything else.

When releases begin they will be prereleases until M7, and this section will name the versions that
receive fixes.

## Reporting a vulnerability

**Never report an exploitable vulnerability through a public issue.** A public report tells an
attacker before it tells a maintainer, and WPShield users run it in front of live WordPress sites.

Use [private vulnerability reporting](https://github.com/peopleworks/WPShield/security/advisories/new).
If that form does not open for you — private reporting is a repository setting, and settings drift —
email **peopleworks@gmail.com** with `WPSHIELD SECURITY` in the subject instead. Do not fall back to
a public issue.

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

## Scope

In scope: the gateway, the inspection engine, the rules, the startup validation, the configuration
model, and the operator documentation that describes any of them. A documented behavior that the
code does not actually have is in scope too — the status table being honest is a security property
of this project, not a courtesy.

Out of scope:

- **Anything that only works once the gateway is publicly exposed.** During M1 and M2 the gateway is
  loopback-only, and startup validation refuses a non-loopback listener on purpose. A finding that
  begins "first, bind it to a public address" describes a configuration the project forbids and the
  code rejects. A way to *defeat* that refusal, on the other hand, is very much in scope — that is
  the invariant above, not an exception to it.
- **The security of WordPress itself, of third-party plugins, of PHP, or of IIS.** Report those to
  their own maintainers. WPShield encodes publicly-known attack surface; it does not own it.
- **A host that was already compromised.** WPShield inspects requests. It cannot un-ring that bell.
- **Missing capabilities that the README marks `Planned` or `Not approved`.** Upload inspection
  covers `multipart/form-data` only; urlencoded forms, JSON, XML-RPC, `application/octet-stream`
  PUTs and archive contents are uninspected, and nothing bounds concurrent buffered inspections.
  The status table says so, so none of those is a vulnerability report.

WPShield complements Microsoft Defender and normal WordPress hardening; it does not replace them, and
it is not an antivirus, an EDR, a stored-file malware scanner, or volumetric DDoS mitigation.

## Response

This is a volunteer project with no response-time guarantee. What you can expect: an acknowledgement
that the report arrived and where it stands, rather than silence. A fix usually takes longer than an
acknowledgement, and you will be told which it is waiting on. Reports that break an invariant above
are prioritized over everything else on the roadmap.

If you would like credit in the advisory, say so. If you would rather stay anonymous, that is fine
too.

## Safe harbour

Research conducted in good faith against **your own instance** is welcome, and no maintainer of this
project will pursue or support a complaint against you for it. Good faith means:

- You test against your own installation or a synthetic laboratory — never against someone else's
  site, and never against a WordPress installation you do not administer.
- You stay within the loopback laboratory the documentation describes. Exposing an instance publicly
  to test it is neither necessary nor in scope.
- You do not access, modify, destroy or exfiltrate data that is not yours, and you stop at the point
  where you have demonstrated the issue.
- You report privately and give a reasonable window before disclosing publicly.

This project cannot grant you authorisation over infrastructure it does not control. Testing a
WPShield instance that belongs to somebody else is that party's decision, not ours, and nothing here
authorises it.

## Offensive use

The rules in this repository describe attack surface so it can be detected. Using any part of the
project to attack a system you do not own is out of scope, unwelcome, and a violation of the
[Code of Conduct](CODE_OF_CONDUCT.md). No working exploit code is distributed here and none will be
accepted.

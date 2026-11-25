# Evaluation reference

[Español](../es/referencia-evaluacion.md) · [Documentation index](../README.md)

## How it compares

An evaluator is choosing between real, shipping alternatives. The table below compares **design position**, not measured detection rates: WPShield has not been benchmarked against any of these products, and it would be dishonest to imply otherwise.

| | WPShield | WordPress security plugins<br/>(Wordfence, Sucuri, …) | ModSecurity + OWASP CRS | Cloudflare / Azure Front Door WAF |
| --- | --- | --- | --- | --- |
| **Where it runs** | Reverse proxy on the Windows host, ahead of IIS and PHP | Inside WordPress as PHP; some can also run as a PHP prepend ahead of WordPress | Web-server module, ahead of the application | Upstream, before traffic reaches your network |
| **Production-ready today** | **No — research preview, loopback only** | Yes | Yes | Yes |
| **Windows and NTFS file name collapse** | Every rule matches the normalized name | Not part of the documented model; these products target Linux and Apache hosting | The Core Rule Set is written for Linux hosting | Not applicable — no view of the filesystem |
| **IIS handler mappings and `web.config` uploads** | `IIS-CONFIG-001`, `IIS-UPLOAD-001` | Not documented | Not covered by the Core Rule Set | Not applicable |
| **Rule updates** | None. Rules ship in this repository and change by pull request | Vendor threat feed, updated continuously | Core Rule Set releases plus vendor feeds | Managed by the vendor, updated continuously |
| **Volumetric and DDoS protection** | None, and none planned | Limited | None | Yes — this is what they are for |
| **Scanning files already on disk** | None, and out of scope | Yes | No | No |
| **Findings carry a stable ID and evidence** | Yes: rule ID, score, message key, evidence | Varies | Yes, though tuning the Core Rule Set is its own discipline | Vendor event IDs, limited detail |
| **Cost** | Free, MIT | Free tier plus a paid feed | Free and open source | Paid above a free tier |

**Where each of them is stronger than WPShield.** All three are production-ready and have been for years; WPShield is not, and says so on every page it has. Wordfence and its peers carry a threat-intelligence feed, a file scanner, login protection and an install base measured in millions — WPShield has none of that and is not competing for it. ModSecurity with the OWASP Core Rule Set is a mature, widely audited engine covering injection, traversal, protocol anomalies and a great deal more that WPShield does not attempt; its weakness on this platform is deployment, because the IIS module has seen little maintenance and the rules assume Linux hosting. Cloudflare and Azure Front Door absorb volumetric attacks, terminate TLS and filter bots before traffic reaches you at all, which no host-local component can do.

**What WPShield adds is narrow and specific**: a request path on the Windows host that knows how Windows writes a file name, and that `web.config` and `.aspx` are executable there. If you need protection today, deploy one of the products above. WPShield is worth watching if the failure mode you care about is an upload that a Linux-oriented rule set was never written to see.

**IIS Request Filtering is the closest thing already on your server**, it is free, and it should be enabled regardless. It filters the requested URL — extensions, hidden segments, verbs, query length — and it does not read POST bodies, so a `web.config` submitted as a multipart file part through a vulnerable plugin endpoint is not something it inspects. The two are complementary rather than alternatives.

## Recent security work

> This summary was written before the first release. See the [changelog](../../CHANGELOG.md) for subsequent work.

WPShield has not been released, so there is no version to summarise. There is, however, a body of closed holes worth surfacing — each one found and fixed in this repository, and each recorded in [CHANGELOG.md](../../CHANGELOG.md) with the reasoning behind it:

- **Four file name evasions that defeated `WP-UPLOAD-001`.** `shell.php.`, `shell.php `, `shell.php::$DATA` and `photo.php.jpg` all reach disk as executable scripts on Windows and all passed the previous extension check. Rules now match a Windows-aware normalization.
- **`IIS-CONFIG-001`**, which detects a `web.config` upload — an arbitrary file write turned into remote code execution on IIS, with no script involved.
- **`IIS-UPLOAD-001`**, covering the fourteen extensions IIS executes as the application pool identity.
- **The full untrusted forwarding set is now removed**, not three headers: every `X-Forwarded-*` variant, RFC 7239 `Forwarded`, the client-address family, and the path-override headers `X-Original-URL` and `X-Rewrite-URL`, which are authentication-bypass vectors against IIS URL Rewrite.
- **Bounded request bodies**, with early rejection of an oversized `Content-Length` and streamed enforcement for bodies of unknown length.
- **Production topology removed from the public repository**, and startup now fails closed when real hostnames appear beside the shipped placeholders — the signature of a partially applied configuration overlay.

## Related projects

WPShield is one of four PeopleWorks tools. They do not compose into a pipeline — they share a language, a platform and a house style rather than a workflow:

| Project | What it is for |
| --- | --- |
| [**SQLDiff**](https://github.com/peopleworks/SqlSchemaDiff) | Compares two SQL Server databases and writes the migration script that makes one match the other, preserving the rows already in the target. |
| [**SyncJob**](https://github.com/peopleworks/syncjob) | Moves the rows rather than the schema: full-refresh and incremental SQL Server data synchronization, as a CLI command or a Windows Service, with an audit record per run. |
| [**XAF Logic Explainer**](https://github.com/peopleworks/XAFLogicExplainer) | Reads a DevExpress XAF application with Roslyn and tells an AI coding agent what *that* application actually does — entities, controllers, actions, business rules, navigation and Model Editor customizations. |
| **WPShield** *(this repo)* | Inspects HTTP requests before they reach IIS, PHP and WordPress on Windows Server. |

All four are .NET, MIT-licensed, Windows-first, and built by PeopleWorks.

If WPShield ever needs a compose story, its real companions are Microsoft Defender and IIS Request Filtering rather than any of the above — see [how it compares](#how-it-compares).

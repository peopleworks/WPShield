# Notice

This project is licensed under the [MIT License](LICENSE). This file records what WPShield is, what
it contains, and what it does not contain with respect to the third parties it names. **It is not
part of the license terms.**

## Relationship to WordPress

WPShield inspects HTTP requests destined for WordPress sites. It is an **independent community
project**: not affiliated with, endorsed by, sponsored by, or supported by the WordPress Foundation,
Automattic Inc., or any plugin or theme vendor.

The name is descriptive of what the project protects, not a claim of association. WPShield is not an
official WordPress project, is not distributed through the WordPress plugin directory, and is not a
WordPress plugin at all — it is a reverse proxy that runs outside WordPress and never loads inside
it.

**Questions about WordPress itself do not belong in this repository's issues.** WordPress core,
plugin and theme behavior, PHP configuration, and site administration are supported by
[WordPress.org support](https://wordpress.org/support/) and by each plugin's own vendor.
[SECURITY.md](SECURITY.md) places the security of WordPress, of third-party plugins, of IIS, and of an
already-compromised host explicitly out of scope. A vulnerability in WordPress or in a plugin should be
reported to that project, not here.

## Relationship to Microsoft

WPShield targets WordPress hosted on Windows Server behind IIS, and is built on .NET. It is an
**independent community project**: not a Microsoft product, and not affiliated with, endorsed by, or
supported by Microsoft Corporation.

WPShield **complements Microsoft Defender and normal WordPress hardening; it does not replace
them.** It is not an antivirus, not an EDR, not a stored-file malware scanner, and not volumetric DDoS
mitigation. It inspects requests in flight and never scans, quarantines, or removes files on disk.
Turning Defender off because WPShield is running would leave the host less protected than before.

## What this repository does not contain

- **No WordPress source code**, and no WordPress installation is required to build or run the project
  or its tests.
- **No PHP interpreter and no PHP code.** WPShield reasons about what a PHP handler *would* execute;
  it never executes anything itself.
- **No Microsoft product source code**, and no license beyond the freely available .NET SDK is needed
  to build it.
- **No working exploits, webshells, or weaponized payloads.** The rules encode publicly known attack
  surface — executable upload extensions, Windows file name normalization, the effect of a
  `web.config` written into a served directory — in order to *detect* it. Test fixtures use harmless
  synthetic markers. See the [threat model](THREAT_MODEL.md) for what is detected and what is not.
- **No customer data, production logs, credentials, or certificates.**
- **No production deployment topology.** Every configuration example uses the RFC 2606 documentation
  hostnames `wordpress-one.example` and `wordpress-two.example` with loopback destinations. Real
  hostnames and destinations belong in `appsettings.Local.json`, which is ignored by git and is never
  copied into a published artifact.

## Third-party dependencies

WPShield builds on .NET 10. The runtime and framework libraries it uses — the .NET runtime, ASP.NET
Core and Kestrel, reached through the `Microsoft.NET.Sdk` and `Microsoft.NET.Sdk.Web` project SDKs —
are published by Microsoft under the **MIT License**.

Package versions are pinned centrally in `Directory.Packages.props`. The complete set of NuGet
packages the repository references:

| Package | Version | License | Used by | Why |
| --- | --- | --- | --- | --- |
| [`Yarp.ReverseProxy`](https://github.com/dotnet/yarp) | 2.3.0 | MIT | `WPShield.Gateway` | The forwarding engine. The only third-party component in the request path. |
| [`Microsoft.AspNetCore.TestHost`](https://asp.net/) | 10.0.0 | MIT | `WPShield.Gateway.Tests` | In-process host for the gateway integration suite. |
| [`Microsoft.NET.Test.Sdk`](https://github.com/microsoft/vstest) | 17.14.1 | MIT | all test projects | Test platform. |
| [`xunit`](https://github.com/xunit/xunit) | 2.9.3 | Apache-2.0 | all test projects | Test framework. |
| [`xunit.runner.visualstudio`](https://github.com/xunit/visualstudio.xunit) | 3.1.4 | Apache-2.0 | all test projects | Test adapter. Referenced with `PrivateAssets="all"`. |

Only `Yarp.ReverseProxy` ships in a runtime artifact. Everything else is a build-time or test-time
dependency.

`WPShield.Abstractions`, `WPShield.Core` and `WPShield.Rules.WordPress` reference no NuGet package at
all. That is deliberate: those three projects are platform-independent and are verified on Linux in
continuous integration so the claim stays falsifiable.

## Trademarks

*WordPress* is a registered trademark of the WordPress Foundation. *WooCommerce*, *Jetpack* and
*Automattic* are trademarks of Automattic Inc. *Elementor* is a trademark of Elementor Ltd.
*Google* and *Site Kit* are trademarks of Google LLC. *Microsoft*, *Windows*, *Windows Server*,
*Internet Information Services (IIS)*, *Microsoft Defender*, *Azure*, *.NET* and *GitHub* are
trademarks of Microsoft Corporation. *PHP* is a trademark of The PHP Group. *Cloudflare* is a
trademark of Cloudflare, Inc. *Claude* is a trademark of Anthropic.

All are used here only to identify the software WPShield protects, runs on, or interoperates with. No
endorsement is claimed or implied.

## Defensive use

WPShield is written to defend systems its operator is responsible for. The rules describe attack
surface so that it can be recognized; they are not instructions, and no runnable attack technique is
distributed here.

Using this project, or knowledge taken from it, against a system you do not operate and are not
authorized to test is outside the purpose of the project, outside the scope of any support offered
here, and a violation of the [Code of Conduct](CODE_OF_CONDUCT.md).

# WPShield

WPShield (Windows Power Shield) watches IIS and WordPress sites on Windows Server so you can see the requests that reach your sites, follow failed logons to the host and ask an assistant about the recorded evidence.

> [!IMPORTANT]
> **Research preview. WPShield is not approved for production traffic.** Keep the gateway on loopback during M1 and M2 and leave public IIS bindings in place.

[Command center](#command-center) · [Attacks on the host](#attacks-on-the-host) · [Requests to the sites](#requests-to-the-sites) · [Ask about it](#ask-about-it) · [Español](docs/es/)

## Command center

The desktop opens on the **Command center**, with collector coverage, logon and IIS evidence,
health, posture and firewall exposure on one screen. The captures below use a synthetic evidence
store. [Desktop guide](docs/en/operator-reference.md#desktop-command-center) · [Regenerate the captures](docs/en/operator-reference.md#regenerate-desktop-screenshots)

![The command center highlights an IIS PHP observation and an open SMB port while showing the collector, health and posture readings beside them.](docs/assets/screenshots/command-center-en.png)

## Attacks on the host

The desktop’s **Attacks** view shows failed RDP, SMB and other network logons from the last 24 hours and updates live. The **7 d** and **30 d** views use the evidence store. Address labels help identify known sources in the desktop and in `wpshield attacks`. [Attacks guide](docs/en/network-sensor-design.md#attacks)

![The Attacks view groups failed logons by source and network, with labels and would-block decisions beside the matching addresses.](docs/assets/screenshots/attacks-en.png)

## Requests to the sites

The desktop’s **Web** tab shows which IIS logs were read, groups findings by address and highlights
`WEB-OBS-001`, a PHP response outside WordPress entry points. [Web tab guide](docs/en/operator-reference.md#desktop-web-tab)

![The Web tab shows an unreadable IIS site above the timeline and highlights a recorded PHP observation in red.](docs/assets/screenshots/web-en.png)

In the lab, the gateway sits in front of IIS and runs in **Monitor** by default. It records findings for executable uploads, `web.config` and suspicious request paths. [Gateway reference](docs/en/gateway-reference.md)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/site-requests-dark.svg">
  <img src="docs/assets/site-requests-light.svg" alt="In Monitor mode, the gateway forwards the request to its assigned IIS site and records the upload rule that fired.">
</picture>

<details>
<summary>Protection, Settings and Audit references</summary>

![Protection shows the collector and its active would-block decisions while WPShield is in Monitor mode.](docs/assets/screenshots/protection-en.png)

![Settings shows the demo allow-list, its audit history and the controls that require a reason before saving.](docs/assets/screenshots/settings-en.png)

![Audit references shows the coverage of a synthetic audit and previews the JSON for the selected record.](docs/assets/screenshots/audit-references-en.png)

</details>

## Ask about it

Use the read-only `wpshield mcp` server with Claude Desktop or Claude Code to ask about failed logons, source history and gaps in recorded evidence. [MCP setup and what leaves the host](docs/en/mcp-server.md)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/ask-evidence-dark.svg">
  <img src="docs/assets/ask-evidence-light.svg" alt="An assistant asks about a synthetic address and receives its recorded history and coverage from the read-only evidence store.">
</picture>

## Quick start

1. Download the research-preview ZIP and matching `.sha256` file from [Releases](https://github.com/peopleworks/WPShield/releases) when available. The CLI steps require `wpshield.exe`. If Releases is empty or offers only the gateway, [build the gateway and CLI together on a machine with the SDK](docs/en/operator-reference.md#build-the-release-to-carry-to-the-server).
2. Replace `preview.zip` with the archive’s filename. Compare the displayed hash with the matching `.sha256` file before extracting.

   ```powershell
   Get-FileHash -LiteralPath .\preview.zip -Algorithm SHA256
   ```

3. On the lab host, open an elevated PowerShell session in the extracted folder. Run the read-only preflight and review its report before evaluating the gateway.

   ```powershell
   .\wpshield.exe preflight
   ```

4. To watch live logons from a source checkout on the lab host, start the desktop from an elevated prompt and open **Attacks**.

   ```powershell
   dotnet run --project src/WPShield.Desktop -c Release
   ```

   Or, from the extracted folder, collect from an elevated prompt while the WPShield service is stopped or absent. Run the query in a second elevated prompt after evidence is recorded. If the service is already collecting, use the query by itself.

   ```powershell
   .\wpshield.exe evidence collect
   .\wpshield.exe attacks --range 24h
   ```

## Current limits

- Host-level blocking is unavailable on `main`. ADR 0006 is accepted and the enforcer is under review in [PR #86](https://github.com/peopleworks/WPShield/pull/86).
- Production traffic remains outside the approved scope. During M1 and M2, run the gateway on loopback only.

## Status

| Capability | Status |
| --- | --- |
| Host observation | Desktop Attacks, CLI history and a local evidence store |
| Site request inspection | Loopback gateway with Monitor as the default |
| Assistant queries | Read-only MCP over the local evidence store |
| Validation | Tested in CI |

See the [roadmap](ROADMAP.md) for milestones, validation and production activation criteria.

## Documentation and project links

- [Documentation index in English and Spanish](docs/README.md) · [Documentación en español](docs/es/)
- [Project site](https://peopleworks.github.io/WPShield/) · [Changelog](CHANGELOG.md) · [Support](SUPPORT.md)
- [Contributing](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) · [Security policy](SECURITY.md) · [Threat model](THREAT_MODEL.md)
- [MIT License](LICENSE) · [Third-party notices](NOTICE.md) · Created by [Pedro Hernández at PeopleWorks](https://github.com/peopleworks)

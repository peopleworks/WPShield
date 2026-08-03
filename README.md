# WPShield

Open-source, multilingual protection for WordPress sites hosted on Windows Server and IIS.

> **Project status:** early foundation / research prototype. Do not place WPShield in front of a production site yet.

## Goals

- Protect one or many WordPress sites hosted on the same Windows Server.
- Inspect inbound HTTP requests before they reach WordPress.
- Start safely in **Monitor** mode and support an explicit **Block** mode later.
- Produce explainable findings instead of opaque verdicts.
- Keep the detection engine independent from IIS and the future reverse proxy.
- Make rules, translations, documentation, and integrations easy to extend.

## Non-goals

WPShield is not an antivirus, EDR, replacement for Microsoft Defender, or general-purpose DDoS mitigation service.

## Repository layout

- `src/WPShield.Abstractions` — stable contracts for rules and findings.
- `src/WPShield.Core` — site resolution and rule evaluation.
- `src/WPShield.Rules.WordPress` — initial WordPress-focused rules.
- `src/WPShield.Service` — first executable host and configuration example.
- `tests` — unit tests for the engine and rules.
- `docs/en`, `docs/es` — multilingual documentation.

## First local run

Requires the .NET 10 SDK.

```powershell
dotnet restore
dotnet build --configuration Release
dotnet test --configuration Release
dotnet run --project src/WPShield.Service
```

`WPShield.Service` resolves its default `appsettings.json` from the compiled application directory, so the command works when launched from the repository root. An explicit configuration file can also be supplied after `--`:

```powershell
dotnet run --project src/WPShield.Service -- src/WPShield.Service/appsettings.json
```

## Safety

The current bootstrap does **not** proxy traffic and does **not** change IIS. The first executable only validates configuration and demonstrates the engine.

## License

MIT. See [LICENSE](LICENSE).

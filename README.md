<div align="center">

# WPShield

**WPShield — Windows Power Shield.** An open-source security gateway for Windows Server and IIS.

<sub>The name states a direction. <b>The eleven rules today read uploads and request paths</b>: one is
WordPress-specific, five consult WordPress's own filename rewrite as a second opinion, and five are
plain Windows, IIS, PHP and filename rules that fire on a site that has never run WordPress.
<b>Nothing yet reads the .NET application surface</b> — no rule looks for <code>.env</code>,
<code>.git</code>, a backup left in a web root, or an exposed admin path.
<a href="docs/en/adr/0004-what-wpshield-stands-for.md">ADR 0004</a> records the gap, and a correction
to what it originally claimed.</sub>

**[See how it works →](https://peopleworks.github.io/WPShield/)**

[![Build](https://github.com/peopleworks/WPShield/actions/workflows/build.yml/badge.svg)](https://github.com/peopleworks/WPShield/actions/workflows/build.yml)
[![Status: research preview](https://img.shields.io/badge/status-research%20preview-orange?style=flat-square)](ROADMAP.md)
[![License](https://img.shields.io/github/license/peopleworks/WPShield?style=flat-square&color=blue)](LICENSE)
[![.NET 10](https://img.shields.io/badge/.NET-10.0-512BD4?style=flat-square&logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![Windows Server and IIS](https://img.shields.io/badge/Windows%20Server-IIS-0078D4?style=flat-square&logo=windows&logoColor=white)](https://learn.microsoft.com/iis/)
[![WordPress](https://img.shields.io/badge/WordPress-multi--site%20hosting-21759B?style=flat-square&logo=wordpress&logoColor=white)](https://wordpress.org/)
[![GitHub stars](https://img.shields.io/github/stars/peopleworks/WPShield?style=flat-square&logo=github)](https://github.com/peopleworks/WPShield/stargazers)
[![by PeopleWorks](https://img.shields.io/badge/by-PeopleWorks-636f61?style=flat-square)](https://mvp.microsoft.com/en-US/mvp/profile/24060a02-dbc6-44ec-bca5-c213ff9835c5)

[Choose an operator task](docs/en/operator-reference.md#choose-an-operator-task) · [What a finding looks like](docs/en/gateway-reference.md#what-a-finding-looks-like) · [Architecture](docs/en/gateway-reference.md#architecture) · [How it compares](docs/en/evaluation-reference.md#how-it-compares) · [Getting started](docs/en/operator-reference.md#getting-started) · [Roadmap](docs/en/operator-reference.md#roadmap) · [Contributing](#contributing) · [Security](SECURITY.md) · [Español](docs/es/)

</div>

> [!IMPORTANT]
> WPShield is an early research preview. Do not place it in front of a production site yet. During M1 and M2, the gateway must remain bound to loopback and must not replace public IIS bindings.

## Documentation

[English and Spanish documentation index](docs/README.md)

- [Gateway reference](docs/en/gateway-reference.md) · [Referencia del gateway](docs/es/referencia-gateway.md)
- [Operator reference](docs/en/operator-reference.md) · [Referencia del operador](docs/es/referencia-operador.md)
- [Evaluation reference](docs/en/evaluation-reference.md) · [Referencia de evaluación](docs/es/referencia-evaluacion.md)

[Roadmap](ROADMAP.md) · [Security policy](SECURITY.md) · [Support](SUPPORT.md) · [Changelog](CHANGELOG.md)

## Contributing

Community contributions are welcome, especially in these areas:

- Safe gateway validation and synthetic integration tests.
- Bounded streaming and multipart parsing.
- Explainable WordPress rules with benign test fixtures.
- Rules for the .NET-on-IIS surface — `.env`, `.git`, stray backups, exposed admin paths — chosen
  against real request logs rather than a threat model. See [ADR 0004](docs/en/adr/0004-what-wpshield-stands-for.md),
  exit condition 1.
- False-positive research for legitimate WordPress and plugin behavior.
- English and Spanish documentation and localization.
- Windows Server, IIS, Elementor, and Google Site Kit compatibility testing.
- Privacy-preserving observability and operational guidance.

Before opening a pull request:

1. Read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [AGENTS.md](AGENTS.md).
2. Keep the change focused and defensive.
3. Add or update tests.
4. Document false-positive and operational risks.
5. Update both English and Spanish documentation for user-facing behavior.
6. Run the full validation commands from [Getting started](docs/en/operator-reference.md#getting-started).

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

WPShield is available under the [MIT License](LICENSE). See [NOTICE.md](NOTICE.md) for third-party trademarks and the project's position on defensive use.

## Credits

Created by **Pedro Hernández — PeopleWorks**,
[Microsoft MVP for .NET](https://mvp.microsoft.com/en-US/mvp/profile/24060a02-dbc6-44ec-bca5-c213ff9835c5).

Built on [.NET 10](https://dotnet.microsoft.com/) · [ASP.NET Core and Kestrel](https://learn.microsoft.com/aspnet/core/fundamentals/servers/kestrel) · [YARP](https://github.com/dotnet/yarp), the only third-party component in the request path · [xUnit](https://xunit.net/)

Built for the people who keep WordPress running on Windows Server — *para quienes sostienen WordPress sobre Windows Server e IIS.*

Repo: <https://github.com/peopleworks/WPShield>

<p align="center">
  <sub><b>WPShield</b> • Defensive inspection for WordPress on Windows Server and IIS</sub><br>
  <sub><b>Research preview.</b> Not approved for production traffic — see the <a href="ROADMAP.md">roadmap</a> for what must be true first.</sub><br>
  <sub>© 2026 PeopleWorks</sub>
</p>

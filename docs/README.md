# WPShield documentation · Documentación de WPShield

Every document that describes user-visible behaviour exists in English and Spanish. That is a project
rule rather than a courtesy: an operator who cannot read the limits in their own language is the
operator who puts a research preview in front of production traffic by mistake. Add a document in one
language and its counterpart belongs in the same change.

Cada documento que describe comportamiento visible para el usuario existe en inglés y en español. Es
una regla del proyecto, no una cortesía: el operador que no puede leer los límites en su idioma es el
que termina poniendo una vista previa de investigación delante del tráfico de producción sin
quererlo. Si agrega un documento en un idioma, su equivalente entra en el mismo cambio.

This index mirrors the Documentation table in the [repository README](../README.md); the two lists
change together, so that a reader who arrives from the README and a reader who opens this folder see
the same set.

| Topic · Tema | English | Español |
| --- | --- | --- |
| Threat model · Modelo de amenazas | [Threat model](../THREAT_MODEL.md) | [Modelo de amenazas](es/modelo-de-amenazas.md) |
| Architecture · Arquitectura | [Architecture](en/architecture.md) | [Arquitectura](es/arquitectura.md) |
| Operator configuration · Configuración del operador | [Operator configuration](en/operator-configuration.md) | [Configuración del operador](es/configuracion-operador.md) |
| M1 laboratory gateway · Gateway M1 de laboratorio | [Laboratory gateway](en/m1-lab-gateway.md) | [Gateway de laboratorio](es/m1-gateway-laboratorio.md) |
| M2 request limits · Límites de solicitud M2 | [Bounded request controls](en/m2-request-limits.md) | [Controles limitados de solicitud](es/m2-limites-solicitud.md) |
| M2 multipart inspection · Inspección multipart M2 | [Bounded multipart inspection](en/m2-multipart-inspection.md) | [Inspección multipart acotada](es/m2-inspeccion-multipart.md) |
| M2 upload rules · Reglas de carga M2 | [Upload rules](en/m2-upload-rules.md) | [Reglas de carga](es/m2-reglas-carga.md) |
| ADR 0001 — production traffic path · Ruta de tráfico en producción | [Production traffic path](en/adr/0001-production-traffic-path.md) | [Ruta de tráfico en producción](es/adr/0001-ruta-de-trafico-en-produccion.md) |

The threat model's English original sits at the repository root, because `README.md`, `SECURITY.md`
and `AGENTS.md` all point readers there; its Spanish translation lives here with the other pairs.

El original en inglés del modelo de amenazas está en la raíz del repositorio, porque `README.md`,
`SECURITY.md` y `AGENTS.md` remiten allí; su traducción al español vive aquí, con los demás pares.

## Working documents · Documentos de trabajo

Not every file here is a user-facing document. This one is planning, and it is deliberately unpaired.

No todo archivo aquí es documentación para el usuario. Este es planificación, y no tiene par a
propósito.

| Document · Documento | Language · Idioma | What it is · Qué es |
| --- | --- | --- |
| [Plan maestro de desarrollo](es/plan-de-desarrollo.md) | Español | Internal planning: milestone design that is not built yet, acceptance criteria, and the intended order of work. Its public English counterpart is [ROADMAP.md](../ROADMAP.md), which wins wherever the two disagree · Planificación interna: diseño aún no construido, criterios de aceptación y orden previsto de trabajo. Su equivalente público en inglés es ROADMAP.md, que manda donde discrepen |
| [M2 inspection pipeline design](en/m2-inspection-pipeline-design.md) | English | Design note recording the decisions behind the M2 gateway pipeline and the alternatives rejected. What shipped is documented in [bounded multipart inspection](en/m2-multipart-inspection.md), which wins wherever the two disagree · Nota de diseño con las decisiones de la tubería M2 del gateway y las alternativas descartadas; manda el documento de inspección multipart |
| [M2 content rules design](en/m2-content-rules-design.md) | English | Design note for `FILE-TYPE-001` and `PHP-CONTENT-002`: the signature table, the scoring arithmetic, and the fixtures that must stay silent. Shipped behaviour is documented in [upload rules](en/m2-upload-rules.md) · Nota de diseño de las dos reglas de contenido; el comportamiento publicado está en las reglas de carga |

## Project-wide references · Referencias del repositorio

These live at the repository root · Estos viven en la raíz del repositorio:

- [README.md](../README.md) — what works today, and what does not yet.
- [ROADMAP.md](../ROADMAP.md) — the canonical milestone list.
- [THREAT_MODEL.md](../THREAT_MODEL.md) — protected assets, trust boundaries, threats, safeguards.
- [SECURITY.md](../SECURITY.md) — how to report a vulnerability, and what counts as one.
- [SUPPORT.md](../SUPPORT.md) — where to ask, and what not to paste when you do.
- [CONTRIBUTING.md](../CONTRIBUTING.md) — the checklist a rule must pass.
- [CHANGELOG.md](../CHANGELOG.md) — what changed, and why it mattered.
- [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) — the conduct rules and the reporting contact.
- [NOTICE.md](../NOTICE.md) — trademarks, third-party marks, and the defensive-use statement.
- [AGENTS.md](../AGENTS.md) — the single copy of the invariants every contributor and agent follows.

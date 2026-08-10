# WPShield — Plan Maestro de Desarrollo

| Campo | Valor |
| --- | --- |
| Proyecto | WPShield |
| Repositorio | https://github.com/peopleworks/WPShield |
| Estado actual | M0 completado; M1 Gateway multisitio en desarrollo |
| Plataforma objetivo inicial | Windows Server 2022 o superior, IIS 10, WordPress y PHP/FastCGI |
| Gateway de laboratorio | `http://127.0.0.1:10000` |

> **Nota sobre datos de despliegue.** Este documento es público. Los nombres de host
> reales, los puertos internos, las versiones exactas del sistema operativo y el
> inventario de plugins de una instalación concreta constituyen información de
> reconocimiento y **no deben aparecer aquí**. Use los marcadores
> `wordpress-one.example` y `wordpress-two.example`. Los valores reales van en
> `DEVELOPMENT_PLAN.local.md` y en `appsettings.Local.json`, ambos ignorados por git.

---

## 1. Visión del producto

**WPShield** será una plataforma abierta, multisitio y multidioma para proteger instalaciones WordPress alojadas en Windows Server e IIS.

### Propósito

Interceptar solicitudes HTTP antes de que lleguen a IIS, PHP o WordPress para:

- Detectar cargas potencialmente ejecutables.
- Detectar contenido PHP disfrazado de imagen o documento.
- Rechazar hosts desconocidos.
- Aplicar límites de tamaño.
- Reducir tráfico automatizado abusivo.
- Generar evidencia explicable.
- Complementar Microsoft Defender, no reemplazarlo.

### Definición pública

> WPShield is an open-source, multilingual protection gateway for WordPress sites hosted on Windows Server and IIS.

### WPShield no es

- Un antivirus.
- Un EDR.
- Un reemplazo para Microsoft Defender.
- Una solución completa contra DDoS.
- Un escáner general de malware almacenado.
- Un sistema ofensivo.
- Un sustituto de las actualizaciones de WordPress, plugins o temas.

---

## 2. Entorno objetivo inicial

```text
Windows Server 2022 o superior
IIS 10
WordPress sites: 2
PHP mediante FastCGI
Public ports: 80 and 443
Cloudflare: No
ARR: pendiente de decisión (ver ADR 0001)
URL Rewrite: Sí
Gateway laboratory port: 127.0.0.1:10000
Maximum legitimate upload: 5 MB
```

### Sitios iniciales

Marcadores públicos. La asignación real vive en `appsettings.Local.json`.

```text
wordpress-one.example
wordpress-two.example
```

### Plugins que requieren pruebas explícitas

```text
Elementor
Google Site Kit
```

### Topología de laboratorio

```text
Local test client
        │
        ▼
WPShield Gateway
127.0.0.1:10000
        │
        ├── wordpress-one.example
        │         ▼
        │   IIS 127.0.0.1:8081
        │
        └── wordpress-two.example
                  ▼
            IIS 127.0.0.1:8082
```

Durante el laboratorio, los bindings públicos de IIS en `80` y `443` deben permanecer intactos.

---

## 3. Principios obligatorios

### 3.1 Seguridad por defecto

- El modo predeterminado siempre será `Monitor`.
- `Block` debe habilitarse explícitamente por sitio.
- Un host desconocido debe fallar cerrado con HTTP `421`.
- WPShield no debe mantener un backend predeterminado.
- Los endpoints administrativos deben escuchar solamente en loopback inicialmente.
- Nunca se confiará en encabezados `X-Forwarded-*` recibidos desde Internet.
- WPShield eliminará esos encabezados y generará valores propios.
- Nunca se registrarán cookies, credenciales, tokens, nonces o cuerpos completos.
- Los uploads sospechosos no se escribirán en disco.
- Los listeners M1 y M2 permanecerán limitados a loopback.

### 3.2 Cambios pequeños y verificables

Cada iteración debe:

1. Tener un objetivo único.
2. Compilar sin warnings.
3. Ejecutar todas las pruebas.
4. Agregar pruebas para el comportamiento nuevo.
5. Actualizar documentación.
6. Mantener compatibilidad con lo existente.
7. Tener un commit independiente.
8. No tocar producción automáticamente.

### 3.3 Explicabilidad

Cada detección debe proporcionar internamente:

```text
RuleId
Score
MessageKey
Evidence segura
RecommendedAction
SiteId
RequestId
```

Los detalles exactos de las reglas no deben devolverse al visitante, porque podrían facilitar la evasión. Deben quedar disponibles únicamente para administradores autorizados.

### 3.4 Privacidad

Los registros no deben contener:

```text
Authorization
Cookie
Set-Cookie
WordPress nonce
Passwords
API keys
OAuth codes
Request body completo
Contenido completo de upload
Query string completa
```

### 3.5 Internacionalización

Separar siempre:

- Idioma de la interfaz.
- Idioma del mensaje administrativo.
- Identificador estable de regla.

Los identificadores de reglas no se traducen:

```text
WP-UPLOAD-001
PHP-CONTENT-001
HTTP-HOST-001
HTTP-SIZE-001
```

---

## 4. Configuración de GitHub Copilot CLI

### 4.1 Archivo raíz `AGENTS.md`

Crear `AGENTS.md` en la raíz del repositorio con este contenido:

```markdown
# WPShield Agent Instructions

WPShield is an open-source defensive security gateway for WordPress sites hosted on Windows Server and IIS.

## Required workflow

Before modifying code:

1. Read README.md, ROADMAP.md, THREAT_MODEL.md and relevant source files.
2. Inspect git status.
3. State the proposed implementation plan.
4. Make the smallest cohesive change.
5. Run restore, build and tests.
6. Add tests for new behavior.
7. Update English and Spanish documentation.
8. Show changed files and validation results.
9. Do not commit or push unless explicitly requested.

## Safety requirements

- Defensive functionality only.
- Default to Monitor mode.
- Never expose the gateway publicly during M1 or M2.
- Never modify IIS, certificates, DNS, firewall or Windows services automatically.
- Never log credentials, cookies, authorization headers, nonces, tokens, full query strings or complete request bodies.
- Reject unknown hosts.
- Do not trust inbound X-Forwarded-* headers.
- Do not store suspicious uploads on disk.
- Do not create weaponized webshell samples.
- Use harmless synthetic markers in tests.

## Engineering standards

- Target .NET 10.
- Enable nullable reference types.
- Treat warnings as errors.
- Use central package management.
- Keep WPShield.Core independent from ASP.NET Core and YARP when possible.
- Keep rule results explainable.
- Use cancellation tokens for asynchronous I/O.
- Bound all buffers and request sizes.
- Avoid buffering complete uploads in memory.
- Add unit tests and appropriate integration tests.
- Use English for code identifiers.
- Localize user-facing messages.
- Preserve multi-site isolation.

## Validation commands

dotnet restore WPShield.slnx
dotnet build WPShield.slnx --configuration Release --no-restore
dotnet test WPShield.slnx --configuration Release --no-build
git diff --check

## Commit convention

feat(scope): description
fix(scope): description
test(scope): description
docs(language): description
security(scope): description
refactor(scope): description
```

### 4.2 Archivo `.github/copilot-instructions.md`

Debe contener:

- Visión y alcance del producto.
- Arquitectura general.
- Comandos de validación.
- Restricciones de seguridad y privacidad.
- Convención de commits.
- Requisito de documentación bilingüe.
- Política de no modificar producción.
- Estado de los milestones.

### 4.3 Instrucciones específicas por ruta

Crear:

```text
.github/instructions/csharp.instructions.md
.github/instructions/tests.instructions.md
.github/instructions/docs.instructions.md
.github/instructions/security-rules.instructions.md
```

Ejemplo de encabezado para instrucciones C#:

```yaml
---
applyTo: "**/*.cs"
---
```

### 4.4 Verificación en Copilot CLI

Desde la raíz del repositorio:

```powershell
cd C:\Proyecto\WPShield
copilot
```

Dentro de Copilot CLI:

```text
/instructions
```

Verificar que Copilot CLI haya detectado `AGENTS.md`, `.github/copilot-instructions.md` y las instrucciones específicas por ruta.

---

## 5. Arquitectura objetivo

```text
WPShield.Abstractions
        │
        ▼
WPShield.Core
        │
        ├── WPShield.Rules.WordPress
        ├── WPShield.Gateway
        ├── WPShield.Observability
        ├── WPShield.Management
        └── WPShield.Service
```

### 5.1 `WPShield.Abstractions`

Contratos estables:

```text
IInspectionRule
InspectionContext
InspectionResult
RuleFinding
InspectionAction
```

No debe depender de:

- ASP.NET Core.
- YARP.
- IIS.
- Windows.
- Bases de datos.

### 5.2 `WPShield.Core`

Responsabilidades:

- Motor de reglas.
- Puntuación.
- Resolución multisitio.
- Configuración y validación.
- Políticas.
- Redacción de datos.
- Cálculo de acciones.

### 5.3 `WPShield.Rules.WordPress`

Responsabilidades:

- Extensiones ejecutables PHP.
- Etiquetas PHP.
- Discrepancias de MIME.
- Nombres peligrosos.
- Archivos con múltiples extensiones.
- Rutas específicas de WordPress.
- Reglas explicables.

### 5.4 `WPShield.Gateway`

Responsabilidades:

- Kestrel.
- YARP.
- Resolución por `Host`.
- Inspección previa.
- Forwarding.
- Rechazo y respuestas seguras.
- Correlation ID.
- Health checks.
- Respuestas localizadas.

### 5.5 `WPShield.Observability`

Responsabilidades futuras:

- Logs estructurados.
- Métricas.
- Persistencia operativa.
- Retención.
- Exportación.
- Integración con Windows Event Log.

### 5.6 `WPShield.Management`

Responsabilidades futuras:

- Dashboard local.
- Administración de sitios.
- Estado de reglas.
- Eventos.
- Activación de `Monitor` y `Block`.
- Inglés y español.

---

## 6. Estado actual

### M0 — Foundation

**Estado:** completado

- Solución .NET 10.
- Abstracciones.
- Core.
- Site resolver.
- Modos de protección.
- Motor de puntuación.
- Primeras reglas.
- Pruebas.
- Documentación inicial.
- GitHub Actions.

### M1 — Gateway HTTP multisitio

**Estado:** prototipo funcional

- Puerto local `10000`.
- YARP.
- Dos dominios.
- Dos destinos internos previstos.
- Rechazo de hosts desconocidos.
- Health checks.
- Request ID.
- Encabezados reenviados generados por WPShield.
- Restricción de escucha a loopback.

---

## 7. Roadmap completo

## M1.1 — Endurecimiento del Gateway

### Objetivo

Convertir el prototipo actual en una base confiable antes de inspeccionar uploads.

### Tareas

- Agregar pruebas unitarias de validación de configuración.
- Probar hosts con mayúsculas y puertos.
- Probar hosts duplicados.
- Rechazar destinos que no sean HTTP o HTTPS.
- Rechazar configuraciones sin sitios.
- Rechazar destinos públicos durante el modo laboratorio.
- Validar que un `Destination` no apunte al propio Gateway.
- Añadir protección contra bucles.
- Verificar que los health endpoints no se reenvían.
- Añadir manejo seguro de excepciones.
- Devolver HTTP `502` consistente si el backend no está disponible.
- Añadir timeout configurable.
- Añadir apagado ordenado.
- Probar encabezados y Request ID.
- Evitar logs de query strings.
- Añadir pruebas de integración con servidores sintéticos.

### Criterios de aceptación

```text
dotnet build -> success
dotnet test -> success
Unknown host -> 421
Unavailable backend -> 502
Health live -> 200
Health ready -> 200 or 503
Gateway only binds to loopback
No credentials appear in logs
```

---

## M1.2 — Backends sintéticos y pruebas de integración

### Objetivo

Probar el proxy sin tocar WordPress ni IIS.

### Proyectos previstos

```text
tests/WPShield.TestBackend.One
tests/WPShield.TestBackend.Two
tests/WPShield.Gateway.IntegrationTests
```

Cada backend sintético debe devolver información segura:

```json
{
  "backend": "one",
  "host": "example.test",
  "scheme": "http",
  "requestId": "synthetic-id"
}
```

### Pruebas

- Un host llega exclusivamente al backend uno.
- Otro host llega exclusivamente al backend dos.
- Un host desconocido no alcanza ningún backend.
- Los encabezados reenviados falsos son reemplazados.
- El Request ID llega al backend.
- Path y query se preservan.
- GET, HEAD y POST sencillos funcionan.
- Un backend lento provoca timeout.
- Un backend caído devuelve `502`.
- Los tests usan puertos dinámicos.
- Los tests no usan `80`, `443`, `8081`, `8082` ni `10000`.

---

## M1.3 — Integración local con IIS

### Objetivo

Enviar tráfico local por WPShield hacia los sitios reales sin tocar el tráfico público.

### Bindings previstos

```text
wordpress-one.example
127.0.0.1:8081

wordpress-two.example
127.0.0.1:8082
```

### Pruebas obligatorias

- Página principal.
- `/wp-admin/`.
- Login sin registrar credenciales.
- Recursos CSS y JavaScript.
- Imágenes.
- REST API.
- Elementor.
- Google Site Kit.
- Redirecciones.
- Canonical URLs.
- HTTP HEAD.
- Archivos legítimos.
- Errores 404.
- Cookies de sesión.
- WordPress cron.
- Ajax administrativo.

### Regla operativa

No eliminar ni modificar los bindings públicos `80/443` durante M1.3.

---

## M2 — Inspección multipart por streaming

Esta es la etapa central de WPShield.

## M2.1 — Límites de solicitud

### Configuración inicial

```text
MaximumRequestBytes: 6 MB
MaximumUploadBytes: 5 MB
MaximumFilesPerRequest: 10
MaximumFormFields: 100
InspectionSampleBytes: 64 KB initially
```

El margen de 6 MB permite la envoltura multipart de una carga legítima de 5 MB.

### Comportamiento

- `Content-Length` superior al máximo: rechazo temprano.
- Solicitud chunked: contador durante streaming.
- Timeout durante lectura.
- Cancelación si el cliente se desconecta.
- Nunca copiar toda la solicitud a memoria.
- Nunca escribir uploads temporales en disco.

### Acciones

```text
Monitor -> registrar y permitir cuando sea operativamente seguro
Block -> responder 413 cuando exceda límites configurados
```

Los límites absolutos de seguridad podrían aplicarse incluso en `Monitor` si continuar representa agotamiento de recursos. Esa excepción debe documentarse explícitamente.

---

## M2.2 — Parser multipart seguro

### Requisitos

- Validar boundary.
- Limitar longitud del boundary.
- Limitar número de secciones.
- Limitar encabezados por sección.
- Normalizar filename.
- Usar solamente el nombre base.
- Rechazar caracteres de control.
- Detectar nombres vacíos.
- Detectar nombres excesivamente largos.
- No confiar en `Content-Type`.
- No confiar en la extensión.
- No almacenar archivos.

### Pruebas

- Upload sencillo.
- Varios archivos.
- Boundary malformado.
- Sección truncada.
- Filename con rutas.
- Filename Unicode.
- Filename con patrones inválidos.
- Content-Type ausente.
- Solicitud superior al límite.
- Cliente desconectado.
- Encabezados excesivos.

---

## M2.3 — Modelo de inspección por archivo

Extender `InspectionContext` para representar:

```text
SiteId
Host
Method
Path
FileName
NormalizedFileName
Extension
DeclaredContentType
DetectedContentType
FileLength
Sample
RequestId
```

No debe incluir contenido completo.

---

## M2.4 — Reglas de alta confianza

### `WP-UPLOAD-001`

Extensión ejecutable PHP:

```text
.php
.php3
.php4
.php5
.php7
.php8
.phtml
.phar
```

### `WP-UPLOAD-002`

Extensiones múltiples sospechosas:

```text
photo.jpg.php
document.pdf.phtml
```

### `PHP-CONTENT-001`

Etiqueta PHP dentro del contenido:

```text
<?php
<?=
```

### `PHP-CONTENT-002`

Contenido PHP declarado como imagen.

### `FILE-TYPE-001`

Firma de archivo incompatible con MIME declarado.

### `FILE-NAME-001`

Nombre con ruta, caracteres de control o normalización peligrosa.

### Requisito contra falsos positivos

No bloquear archivos únicamente por contener una palabra como `eval` o `system`. Las reglas deben combinar señales y documentar posibles falsos positivos.

---

## M2.5 — Flujo Monitor/Block

```text
Request arrives
      │
      ▼
Resolve site
      │
      ▼
Check absolute limits
      │
      ▼
Inspect upload stream
      │
      ▼
Evaluate rules
      │
      ├── Allow
      ├── Observe
      └── Block
      │
      ▼
Forward only when allowed
```

### En `Monitor`

- Analizar.
- Registrar.
- Enviar al backend.
- Nunca presentar una página de bloqueo por una detección heurística.

### En `Block`

- Bloquear únicamente reglas autorizadas para bloqueo.
- Responder `403`, `413` o `415`, según la política.
- No enviar el cuerpo al backend.
- No guardar el archivo.
- Registrar evidencia mínima y segura.

---

## M3 — Rate limiting y comportamiento automatizado

### Objetivo

Reducir ataques repetitivos sin intentar resolver DDoS volumétrico.

### Políticas iniciales

- Rate limit por IP y sitio.
- Política distinta para login.
- Política distinta para XML-RPC.
- Política distinta para uploads.
- Protección contra ráfagas.
- Lista temporal de IPs bloqueadas.
- Expiración automática.
- Excepciones configurables.
- Compatibilidad con IPv4 e IPv6.

### Endpoints sensibles

```text
/wp-login.php
/xmlrpc.php
/wp-admin/admin-ajax.php
/wp-json/
/wp-admin/async-upload.php
```

### Precaución

`admin-ajax.php` recibe tráfico legítimo de Elementor y otros plugins. Nunca debe bloquearse únicamente por ruta.

---

## M4 — Observabilidad

### Eventos

```text
GatewayStarted
GatewayStopped
RequestAllowed
RequestObserved
RequestBlocked
UnknownHostRejected
RequestTooLarge
UploadInspected
RuleMatched
BackendUnavailable
ConfigurationRejected
```

### Almacenamiento inicial

- JSON Lines local.
- Rotación diaria.
- Límite de tamaño.
- Retención configurable.
- Directorio no público.
- Permisos restringidos.

### Nunca almacenar

- Uploads completos.
- Passwords.
- Cookies.
- Authorization.
- Formularios completos.
- Tokens OAuth.
- Nonces.
- PII innecesaria.

### Métricas

```text
Requests per site
Allowed requests
Observed requests
Blocked requests
Matched rules
Upload bytes inspected
Backend errors
Inspection duration
Proxy duration
Rate-limit events
```

---

## M5 — Dashboard multidioma

### Acceso inicial

```text
127.0.0.1 only
```

### Acceso futuro

- Autenticación Windows.
- Grupo local de administradores de WPShield.
- Protección CSRF.
- Sesiones seguras.
- Sin acceso público directo.

### Vistas

- Resumen.
- Sitios.
- Eventos.
- Reglas.
- Configuración.
- Salud.
- Versiones.
- Exportación.
- Diagnóstico.

### Idiomas iniciales

```text
English
Español
```

---

## M6 — Windows Service y publicación

### Entregables

- Publicación `win-x64`.
- Despliegue autocontenido.
- Servicio de Windows.
- Cuenta de servicio con privilegios mínimos.
- Directorio de configuración.
- Directorio de logs.
- Script de instalación.
- Script de desinstalación.
- Script de actualización.
- Script de rollback.
- Checksums.
- Versionado.

### Cuenta de servicio

No ejecutar inicialmente como administrador permanente. Evaluar:

```text
LocalService
NetworkService
Dedicated local service account
```

Aplicar permisos mínimos para:

- Leer configuración.
- Escribir logs.
- Escuchar los puertos requeridos.
- Conectarse a los destinos IIS.
- Escribir en Windows Event Log si se habilita.

---

## M7 — Activación pública segura

No realizar un cambio masivo. Seguir estas fases:

```text
Fase 1: Laboratorio sintético
Fase 2: Loopback -> WPShield -> IIS
Fase 3: Sitio de prueba en Monitor
Fase 4: Un sitio real en Monitor
Fase 5: Ambos sitios en Monitor
Fase 6: Reglas de alta confianza en Block
Fase 7: Políticas avanzadas selectivas
```

### Requisitos antes de producción

- Backups verificados.
- Procedimiento de rollback.
- Acceso administrativo alternativo.
- Monitorización.
- Pruebas Elementor.
- Pruebas Google Site Kit.
- Pruebas de upload.
- Pruebas HTTPS.
- Pruebas REST.
- Pruebas login.
- Pruebas de actualización.
- Pruebas de cron.
- Pruebas de redirección.
- Pruebas de rendimiento.

---

## M8 — Comunidad y lanzamiento abierto

### Archivos obligatorios

```text
README.md
LICENSE
SECURITY.md
CONTRIBUTING.md
CODE_OF_CONDUCT.md
ROADMAP.md
THREAT_MODEL.md
SUPPORT.md
CHANGELOG.md
AGENTS.md
```

### Configuración de GitHub

- Issue templates.
- Feature request.
- Bug report.
- False-positive report.
- Private vulnerability reporting.
- Pull request template.
- CodeQL.
- Dependabot.
- Branch protection.
- Required CI.
- Signed releases.
- Release notes bilingües.
- Checksums.

### Requisitos para reglas comunitarias

Cada nueva regla debe incluir:

- Rule ID.
- Descripción.
- Señales utilizadas.
- Riesgo.
- Posibles falsos positivos.
- Acción recomendada.
- Pruebas benignas.
- Documentación EN/ES.
- Compatibilidad mínima.

---

## 8. Estrategia de ramas y commits

### Ramas

```text
main
feature/m1-gateway-hardening
feature/m2-multipart-inspection
feature/m3-rate-limiting
feature/m4-observability
feature/m5-dashboard
feature/m6-windows-service
```

### Convención de commits

```text
feat(gateway): reject recursive destinations
test(gateway): cover unknown host routing
feat(inspection): add bounded multipart reader
security(logging): redact sensitive request metadata
docs(es): document multipart monitor mode
docs(en): document multipart monitor mode
```

### Antes de cada commit

```powershell
dotnet restore WPShield.slnx
dotnet build WPShield.slnx --configuration Release --no-restore
dotnet test WPShield.slnx --configuration Release --no-build
git diff --check
git status
```

---

## 9. Definition of Done

Una tarea no está terminada hasta que:

- Compila sin warnings.
- Todas las pruebas pasan.
- Tiene pruebas nuevas para el comportamiento nuevo.
- No introduce secretos.
- No registra datos sensibles.
- Mantiene `Monitor` como valor seguro.
- Mantiene compatibilidad multisitio.
- Actualiza documentación.
- Actualiza ambos idiomas cuando corresponda.
- Explica falsos positivos.
- Explica rollback cuando existe impacto operativo.
- El diff fue revisado.
- GitHub Actions queda verde.

---

## 10. Prompts recomendados para Copilot CLI

## Prompt 1 — Instrucciones y planificación del repositorio

```text
We are continuing development of WPShield, an open-source multilingual defensive gateway for WordPress sites hosted on Windows Server and IIS.

Current environment:
- .NET 10
- Windows Server 2022 Standard target
- IIS 10
- Two WordPress sites
- wordpress-one.example
- wordpress-two.example
- WPShield laboratory gateway on http://127.0.0.1:10000
- Future IIS loopback destinations will be 127.0.0.1:8081 and 127.0.0.1:8082
- Maximum legitimate upload is 5 MB
- Elementor and Google Site Kit must remain compatible
- Current gateway must remain loopback-only
- Production ports 80 and 443 must not be modified

First task: establish the repository instructions and planning foundation.

1. Inspect the entire repository, including README.md, ROADMAP.md, THREAT_MODEL.md, source projects, tests and workflows.
2. Inspect git status and do not discard existing work.
3. Create a root AGENTS.md with project purpose, architecture, defensive-security restrictions, privacy requirements, build/test commands, documentation requirements and commit conventions.
4. Create .github/copilot-instructions.md with repository-wide context.
5. Create path-specific instruction files for C# source, tests, documentation and security rules.
6. Update ROADMAP.md with milestones M1.1 through M8, using the existing architecture and preserving completed work.
7. Do not implement multipart inspection yet.
8. Run restore, Release build and Release tests.
9. Report all changed files and validation results.
10. Do not commit or push until I explicitly request it.

Security requirements:
- Defensive use only.
- Never create weaponized payloads.
- Never log credentials, cookies, authorization headers, WordPress nonces, OAuth values, complete query strings or complete request bodies.
- Never write suspicious uploads to disk.
- Monitor mode remains the default.
- Unknown hosts fail closed.
- The gateway remains bound only to loopback.
- Never modify IIS, DNS, certificates, firewall settings or Windows services automatically.
```

## Prompt 2 — M1.1 Gateway Hardening

```text
Implement milestone M1.1: Gateway Hardening.

Before editing:
- Read AGENTS.md and all applicable Copilot instruction files.
- Inspect the current gateway implementation and tests.
- Present a concise implementation plan.

Requirements:
- Validate that at least one site exists.
- Reject duplicate hosts.
- Reject unsupported destination URI schemes.
- Reject a destination that points back to the WPShield listener.
- Preserve loopback-only listener enforcement.
- Ensure health endpoints are never proxied.
- Return a consistent privacy-safe 502 response when a backend is unavailable.
- Do not return internal exception details to clients.
- Add unit and integration tests.
- Do not log query strings, cookies, authorization values or request bodies.
- Update English and Spanish documentation.
- Preserve existing behavior and port 10000.
- Run restore, Release build and Release tests.
- Show the diff summary and validation results.
- Do not commit or push.
```

## Prompt 3 — M1.2 Backends sintéticos

```text
Implement milestone M1.2: synthetic gateway integration testing.

Create safe local synthetic backends for site-one and site-two. Do not use IIS or the real WordPress sites.

Add integration tests proving:
- each configured host reaches only its assigned backend;
- unknown hosts return 421 and reach no backend;
- spoofed inbound X-Forwarded-* headers are replaced;
- X-WPShield-Request-ID reaches the backend;
- method, path and query are forwarded correctly;
- unavailable backend returns a privacy-safe 502;
- backend timeout is handled correctly;
- health endpoints remain local and are not proxied.

Use dynamically allocated test ports to avoid collisions.
Do not use ports 80, 443, 8081, 8082 or 10000 in automated tests.
Run all validation commands and do not commit or push.
```

## Prompt 4 — Revisión antes del commit

```text
Review the current uncommitted WPShield changes as a security-focused maintainer.

Tasks:
1. Read AGENTS.md and applicable instruction files.
2. Inspect git status and the complete diff.
3. Look for security regressions, privacy leaks, unbounded buffers, missing cancellation, proxy loops, host-routing mistakes, sensitive logging, false-positive risks and missing tests.
4. Correct only confirmed problems.
5. Run restore, Release build, Release tests and git diff --check.
6. Summarize changed files, tests and remaining risks.
7. Propose one Conventional Commit message.
8. Do not commit or push.
```

---

## 11. Flujo de trabajo recomendado

```text
1. Definir milestone y criterios de aceptación.
2. Entregar un prompt específico a Copilot CLI.
3. Copilot CLI inspecciona y presenta el plan.
4. Copilot CLI modifica la carpeta local.
5. Copilot CLI ejecuta restore, build y tests.
6. Revisar git diff y resultados.
7. Corregir problemas confirmados.
8. Ejecutar validación final.
9. Crear commit pequeño y descriptivo.
10. Hacer push.
11. Verificar GitHub Actions.
12. Comenzar el siguiente milestone solamente cuando CI esté verde.
```

### Información útil para revisión externa

Cuando sea necesario revisar una iteración, compartir:

```powershell
git status
git diff --stat
git diff --check
dotnet test WPShield.slnx --configuration Release
```

También se puede compartir el resumen de Copilot CLI y cualquier error de CI.

---

## 12. Orden inmediato de ejecución

```text
1. Crear instrucciones del repositorio.
2. Completar M1.1 Gateway Hardening.
3. Completar M1.2 Synthetic Backends.
4. Validar M1.3 con IIS sin tocar 80/443.
5. Diseñar e implementar M2 Multipart Inspection.
6. Añadir M3 Rate Limiting.
7. Añadir M4 Observability.
8. Añadir M5 Dashboard.
9. Empaquetar M6 Windows Service.
10. Realizar activación gradual M7.
11. Preparar lanzamiento comunitario M8.
```

---

## 13. Regla operativa final

WPShield no se instalará delante del tráfico público hasta que:

- Los tests sintéticos estén completos.
- El gateway haya sido probado contra IIS por loopback.
- Elementor y Google Site Kit funcionen correctamente.
- Los logs hayan sido revisados para evitar datos sensibles.
- Exista un procedimiento documentado de bypass y rollback.
- El modo `Monitor` haya operado de manera estable.
- GitHub Actions esté completamente verde.

La velocidad del proyecto es importante, pero la prioridad es proteger los sitios sin convertir el gateway en un nuevo punto de falla.

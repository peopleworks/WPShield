# Referencia del operador

[English](../en/operator-reference.md) · [Índice de documentación](../README.md)

## Elegir una tarea del operador

| Pregunta | Primer comando | Requisitos y evidencia |
| --- | --- | --- |
| ¿Qué regla se activó en mi sitio WordPress en IIS? | `wpshield watch --plain` | Arranca el gateway en Monitor sobre loopback y lee la [evidencia de solicitudes](evidencia-solicitudes.md). |
| ¿Qué puertos locales están en uso? | `wpshield network-monitor --listeners` | Usa `--protocol tcp --local-address 127.0.0.1` para sockets TCP en loopback IPv4. Añade `--port-hints` para nombres convencionales o `--owners` para el PID. [Inventario](diseno-sensor-red.md#inventario-de-puertos-locales) |
| ¿Puedo ver los puertos en una ventana? | `dotnet run --project src/WPShield.Desktop -c Release` | Ventana para TCP y UDP con el nombre del proceso si su hora de inicio confirma el PID. Busca dirección, puerto, PID, proceso o nombre de puerto. [Monitor de escritorio](diseno-sensor-red.md#monitor-de-escritorio) |
| ¿Quién intenta acceder al servidor? | Abre **Ataques** en el escritorio | Fallos de RDP, SMB y de red de las últimas 24 horas, con actualizaciones en vivo, totales, cronología y detalle por origen. **7 d** y **30 d** usan el almacén de evidencia. Requiere permisos de administrador y avisa si faltan. [Ataques](diseno-sensor-red.md#ataques) |
| ¿Qué registró IIS por sitio y dirección? | Abre **Ataques → Web** en el escritorio | Revisa la cobertura y los remedios, y filtra por periodo o sitio. Selecciona una dirección para ver reglas, observaciones y rutas depuradas. [Pestaña Web del escritorio](#pestaña-web-del-escritorio) |
| ¿Quién intentó acceder la semana pasada? | `wpshield attacks --range 7d` | Totales y orígenes principales desde el almacén, o historial de un origen con `--source`. Identifica agregados por hora y muestra periodos sin cobertura como «sin datos». Ejecuta con elevación y usa `--json` para scripts. [Historial](diseno-sensor-red.md#historial-de-ataques-desde-la-línea-de-comandos) |
| ¿Qué mostraron los logs web: quién sondeó mis sitios, y respondió un PHP que no debía? | `wpshield web --range 24h` | Leído del log W3C de IIS de cada sitio por `wpshield evidence collect`: primero la cobertura por sitio (un sitio que nadie pudo leer dice por qué, con el remedio), después las peticiones por hora, las mismas reglas de ruta que ejecuta el gateway y las observaciones `WEB-OBS-001` a `-003` (PHP que responde fuera de los puntos de entrada de WordPress, POST de inicio de sesión y XML-RPC). Solo evidencia: no se decide nada con ella. Nunca lee la consulta, el referer ni el nombre de usuario. Ejecuta con elevación; `--site`, `--source`, `--json`. [Evidencia web](diseno-sensor-red.md#evidencia-web-desde-los-logs-de-iis) |
| ¿Qué pools de aplicaciones se ejecutan como administrador, qué sitios web ejecutan PHP y qué raíces web tienen permisos amplios de escritura o se solapan con carpetas FTP? | `wpshield audit` (elevado) | Enumera los sitios WordPress que deben conservar PHP y advierte cuando otros sitios web lo ejecutan, incluso mediante asignaciones a nivel de sitio. Cambia la contraseña de una cuenta solo después de migrar todos los pools que la usan. Aplica los remedios a mano. [Auditoría](auditoria.md) |
| ¿Cómo está este servidor: reinicios, postura, exposición, sesiones, qué ejecuta? | `wpshield host` (elevado) | Los datos del host que fotografía el recolector (ADR 0013): salud con los reinicios inesperados y su código de pantallazo y el nivel de parches (compilación, versión del kernel, última actualización acumulativa y los días transcurridos), sitios de IIS, la postura del audit ("grupos como administrador: N de M"), puertos en escucha con su exposición *según las reglas del Firewall de Windows* (rojo para SMB, RPC, SQL Server, MySQL, PostgreSQL, VNC y WinRM abiertos a cualquier dirección), sesiones RDP con su dirección de origen, y las cuentas, servicios y tareas que no son de Microsoft, con lo que cambió. Los argumentos nunca se guardan, solo marcas; los nombres completos de las cuentas solo se comparan, nunca se guardan. Cada dato muestra su antigüedad y estado; `--live` lee ahora y no escribe nada. Solo lectura: nada del servidor cambia. [Datos del host](datos-del-host.md) |
| ¿Qué bloquearía WPShield y por qué? | `wpshield decisions --active` | Los registros del motor de decisiones en Monitor: no se bloquea nada. `would-block`, `protected`, `refused`, `report` y `expire`, con la regla, los recuentos y el vencimiento; sin `--active`, los de un rango con su cobertura. Los umbrales y la lista de permitidas son ajustes `defense.*`. Ejecuta con elevación y usa `--json` para scripts. [Decisiones](diseno-sensor-red.md#decisiones-monitor) |
| ¿Qué está haciendo WPShield en este servidor ahora? | Abre **Protección** en el escritorio | Si el recolector registra (según el almacén de evidencia), el servicio `WPShield` al lado (solo lectura), el modo (Monitor: no se bloquea nada), qué sensores registran y los registros del motor de decisiones vigentes, de las últimas 24 horas y de 30 días, con búsqueda. Cada recuento es `—` si nadie pudo mirar, nunca 0. [Protección](diseno-sensor-red.md#protección) |
| ¿Puedo etiquetar o permitir una dirección donde la veo? | Selecciónala en **Ataques** y elige **Etiquetar…** o **Permitir…** | Asigna la etiqueta de esa dirección exacta, o añade la dirección exacta (nunca su red) a `defense.allow` tras una confirmación que dice que el motor nunca decidirá contra ella y avisa con recuentos si parece un atacante. Requiere elevación y un motivo, y se registra como un cambio de Ajustes. [Etiquetar y Permitir](diseno-sensor-red.md#ataques) |
| ¿Cómo pongo un nombre a la dirección de mi oficina? | Abre **Ajustes** en el escritorio, o `wpshield settings set labels.addresses --value-file labels.json --reason "..."` | Las etiquetas aparecen en la CLI y en Ataques. Solo anotan direcciones. La ventana edita cada ajuste sin archivo JSON; **Mi conexión actual** añade la dirección que este servidor ve para tu sesión de Escritorio remoto. Cambiar un ajuste requiere elevación y un motivo, y se registra quién lo hizo, por qué y cuándo surte efecto. [Ventana de ajustes](diseno-sensor-red.md#ventana-de-ajustes) · [Ajustes](diseno-sensor-red.md#ajustes) |
| ¿Puedo preguntar a un asistente? | `wpshield mcp`, iniciado por Claude Desktop o Claude Code | MCP de solo lectura para totales, orígenes, historial, cronología, cobertura y decisiones registradas. Trabaja sin puertos. El asistente requiere elevación en el servidor y envía las respuestas a su proveedor de modelo. Los nombres de cuentas requieren autorización en los ajustes. [Servidor MCP](servidor-mcp.md) |
| ¿Puede WPShield escribirme un resumen de los ataques? | `wpshield analyst digest`, después de `wpshield analyst status` | Un analista de IA opcional, apagado por defecto, con su propia clave de Anthropic o del Relay de PeopleWorks tomada del entorno de su cuenta. Lee la evidencia con las herramientas de solo lectura del servidor MCP y escribe un informe que es una opinión, no evidencia; nunca bloquea ni cambia nada. La evidencia va al proveedor que elija. Acotado por ejecución y por día UTC; también `investigate <ip>` y `ask "..."`. Consola elevada. [Analista de IA](analista.md) |
| ¿Cuánto tráfico usa un adaptador? | Abre **Tráfico por adaptador** | Compara bytes recibidos y enviados por segundo en una interfaz de Windows sin depender de Npcap. [Monitor de escritorio](diseno-sensor-red.md#monitor-de-escritorio) |
| ¿Cuánto tráfico pasa por ciertos puertos TCP o UDP? | Abre **Tráfico por puerto** | Escribe o selecciona puertos y elige un adaptador de captura. La gráfica muestra bytes IP por segundo y cobertura por intervalo. Requiere Npcap y elevación. [Historial de tráfico](diseno-sensor-red.md#historial-de-tráfico) |
| ¿Cómo copio un registro de una auditoría guardada? | Abre **Referencias de auditoría** | Abre un JSON de WPShield, selecciona con las flechas y copia con Ctrl+C. [Referencias de auditoría](diseno-sensor-red.md#referencia-de-auditoría-seleccionada) |
| ¿Qué tráfico entra y sale? | `wpshield network-monitor --flows --interfaces Ethernet --all-ports` | Identifica el dispositivo con `wpshield network-monitor --list-interfaces` y usa Npcap con permisos de administrador. [Flujos del servidor](diseno-sensor-red.md#vista-de-flujos-del-servidor) |
| ¿Qué registro confirma un acceso? | `wpshield network-monitor --sql-instance MSSQLSERVER --json` | Lee el registro Aplicación para SQL Server. Para RDP, añade `--rdp-port` y el puerto local a una captura que lo incluya. [Evidencia de acceso](diseno-sensor-red.md#evidencia-de-inicios-de-sesión-por-escritorio-remoto) |

Un acceso SQL puede verificarse por instancia aunque el flujo TCP asociado permanezca `unknown`.

### Pestaña Web del escritorio

Ejecuta `wpshield evidence collect` con elevación en el servidor IIS para llenar el almacén.
En el escritorio, abre **Ataques → Web** o inicia el ejecutable con `--web`. La pestaña abre
el almacén de evidencia en modo de solo lectura. Si el almacén es anterior al esquema 2, el
recolector actual lo migra al abrirlo para escritura. Después, actualiza la pestaña.

Selecciona **1 h**, **6 h**, **24 h**, **7 d** o **30 d** y elige **Todos los sitios** o un sitio por
nombre. **En vivo** vuelve a leer el almacén cada 10 segundos mientras la pestaña está abierta.
**Actualizar** lo lee bajo demanda. La cobertura enumera los sitios cuyos logs no se pudieron leer
y los remedios registrados. Los huecos aparecen como **sin datos**. Los totales de peticiones y
direcciones abarcan horas completas. La gráfica muestra hallazgos de reglas y `WEB-OBS-001` por
intervalo. La tabla por dirección muestra los POST de inicio de sesión y XML-RPC como agregados
por hora. La tarjeta roja de `WEB-OBS-001` cuenta las respuestas 2xx de PHP fuera de los puntos de
entrada de WordPress, una señal de posible actividad de un web shell.

Selecciona una dirección para ver la hora, el sitio, el método, la ruta normalizada, el estado y
los identificadores registrados. **Etiquetar…** y **Permitir…** usan el mismo editor de ajustes
elevado y auditado que **Ataques**. La evidencia web sirve para revisión y no genera decisiones
ni bloqueos.

## Estado del proyecto

| Capacidad | Estado | Detalle |
| --- | --- | --- |
| Base .NET 10 y CI | Disponible | Tipos anulables, advertencias como errores, paquetes centrales, CodeQL, formato y verificación del núcleo portable en Linux |
| Resolución multisitio | Disponible | Rechaza hosts desconocidos y carece de destino predeterminado |
| Motor de inspección | Disponible | IDs estables, puntuación y acción en Monitor o Block |
| Reglas de carga WordPress e IIS | Disponible | Normalización de Windows, extensiones ejecutables, `web.config`, extensiones disfrazadas, anomalías estructurales, firma incompatible y políglotas imagen/PHP |
| Gateway HTTP de loopback | Prototipo | Kestrel y YARP en `127.0.0.1:10000` |
| Endurecimiento del gateway | Disponible | Validación al arrancar, errores 502 seguros e integración multisitio sintética |
| Límites de solicitud | Disponible | 6 MiB de forma predeterminada, máximo de 64 MiB y HTTP 413 tanto al inicio como durante la transmisión |
| Inspección multipart acotada | Disponible | Retención en memoria dentro del límite y límites para archivos, campos, cabeceras, frontera, nombres y plazos. Si se agota la concurrencia, Monitor reenvía y advierte y Block devuelve 429 |
| Inspección de otros cuerpos | Planificada | Formularios urlencoded, JSON, XML-RPC, PUT con `application/octet-stream` y otros subtipos `multipart/*` se transmiten directamente |
| Inspección de archivos comprimidos | Planificada | Los ZIP de plugins o temas quedan fuera de la cobertura. El trabajo carece de hito asignado |
| Límite de cargas concurrentes | Disponible | `Gateway:Multipart:MaximumConcurrentInspections` vale 10 de forma predeterminada y admite hasta 50. Monitor reenvía y advierte y Block responde 429 |
| Monitor de tráfico del servidor | Vista previa | `wpshield network-monitor --flows` muestra endpoints TCP/UDP, bytes e iniciador por adaptador. Los resultados identifican estado de captura y puertos. Las auditorías de accesos muestran ventana UTC y motivo si la fuente falta. `--history` muestra tasas y huecos. `--rdp-port` aporta evidencia RDP y `--sql-instance` permite consultar accesos SQL incluso sin captura. [Alcance](diseno-sensor-red.md#vista-de-flujos-del-servidor) |
| Bloqueo de paquetes en el servidor | No disponible | La CLI rechaza `network-filter`. El reemplazo está en el [PR #86](https://github.com/peopleworks/WPShield/pull/86). |
| Monitor de eventos de seguridad | Disponible | `wpshield security-monitor` informa fuerza bruta RDP y fallos repetidos desde el registro de seguridad de Windows |
| Aplicación de bloqueos según hallazgos | Planificada | La biblioteca de integración tiene una lista en memoria. La CLI emite los hallazgos para observación |
| Limitación de tasa y observabilidad | Parcial | Presupuestos de ventana fija por cliente, sitio y regla. Logs estructurados y pruebas de redacción. Continúa el trabajo M3/M4 |
| Trazabilidad de evidencia | Disponible | Los eventos finales versionados correlacionan hallazgos, versiones, configuración activa, completitud y resultado del reenvío |
| Pérdidas de evidencia y exportaciones | Disponible | Diagnósticos de cola llena, lotes fallidos y etapas omitidas. El PDF señala huecos conocidos y `wpshield preview --format community` exporta agregados de un sitio con etiqueta sintética |
| Evidencia offline de accesos IIS | Vista previa | `wpshield iis-login` lee un log W3C copiado y da referencias de solicitudes autenticadas, desafíos compatibles y rechazos de logon de Windows. [Cobertura](evidencia-accesos-iis.md) |
| Vista previa offline de políticas | Disponible | `wpshield preview` compara puntuaciones registradas con umbrales candidatos para un sitio. Entrada acotada y exclusiones explícitas, salida JSON agregada sin cambios de configuración ni reevaluación del contenido |
| Monitor de puertos de escritorio | Vista previa | Inventario local de Windows, bilingüe y de solo lectura. El panel web de administración queda para M5 |
| Activación en producción | Sin aprobar | Requiere la validación M1–M6 y la activación controlada M7 |

Consulta el [plan publicado](../../ROADMAP.md) y el [modelo de amenazas](modelo-de-amenazas.md) antes de evaluar el proyecto.

## Primeros pasos

### Requisitos

- [SDK .NET 10](https://dotnet.microsoft.com/download)
- Git
- PowerShell
- Windows Server e IIS para el laboratorio local documentado.

Clona y valida el repositorio:

```powershell
git clone https://github.com/peopleworks/WPShield.git
cd WPShield
dotnet restore WPShield.slnx
dotnet build WPShield.slnx --configuration Release --no-restore
dotnet test WPShield.slnx --configuration Release --no-build
```

Consulta el [desglose por proyecto de las pruebas](../en/operator-reference.md#prerequisites). La duración depende de la máquina y las pruebas del gateway incluyen plazos y cancelación.

### Compilar el artefacto para el servidor

Desde una máquina de compilación con el SDK:

```powershell
.\publish.cmd
```

Genera una compilación autónoma `win-x64` del servicio del gateway y `wpshield.exe` en un directorio de `artifacts\` con un ZIP y su SHA-256. El script llama a `wpshield publish`, que excluye `appsettings.Local.json`, comprueba la versión y verifica que los ejecutables compartan el runtime. Copia el artefacto al servidor, verifica el SHA-256 y ejecuta `wpshield preflight`.

### Ejecutar la demostración de inspección

```powershell
dotnet run --project src/WPShield.Service
```

Imprime el JSON del [ejemplo de hallazgo](referencia-gateway.md#cómo-se-ve-un-hallazgo). Usa la configuración del directorio compilado. Para elegir otro archivo:

```powershell
dotnet run --project src/WPShield.Service -- src/WPShield.Service/appsettings.json
```

### Ejecutar el gateway de laboratorio M1

> [!WARNING]
> Usa solo loopback con backends sintéticos o locales preparados. Mantén el puerto 10000 fuera del acceso público y conserva los puertos públicos de IIS 80 y 443.

```powershell
dotnet run --project src/WPShield.Gateway
```

Antes de aceptar solicitudes, el gateway imprime el enrutamiento efectivo. Lee la tabla porque la configuración solo se aplica al arrancar.

```text
info: WPShield.Gateway.Configuration[0]
      Gateway configuration resolved 2 site(s).
info: WPShield.Gateway.Configuration[0]
      Configured site. SiteId=wordpress-one Hosts=wordpress-one.example, www.wordpress-one.example Destination=http://127.0.0.1:8081/ Mode=Monitor
info: WPShield.Gateway.Configuration[0]
      Configured site. SiteId=wordpress-two Hosts=wordpress-two.example, www.wordpress-two.example Destination=http://127.0.0.1:8082/ Mode=Monitor
```

Comprueba la salud local:

```powershell
curl.exe http://127.0.0.1:10000/_wpshield/health/live
curl.exe http://127.0.0.1:10000/_wpshield/health/ready
```

Prueba el enrutamiento explícito:

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/
curl.exe -i -H "Host: unknown.example" http://127.0.0.1:10000/
```

El host desconocido devuelve HTTP 421. Un host configurado requiere su backend en el destino indicado. Si falta, el gateway devuelve HTTP 502.

Lee la [guía del gateway de laboratorio M1](m1-gateway-laboratorio.md) antes de usar IIS.

## Antes de evaluar en un servidor que te importa

- [ ] El gateway escucha en loopback y los bindings públicos 80 y 443 siguen intactos.
- [ ] Los hostnames, puertos y destinos reales van en `appsettings.Local.json`, que Git ignora y la publicación excluye.
- [ ] Cada sitio permanece en `Monitor` hasta revisar una semana de sus cargas. Los falsos positivos de la [guía multipart](m2-inspeccion-multipart.md) se convierten en rechazos con `Block`.
- [ ] La tabla de arranque coincide con el enrutamiento previsto, fila por fila.
- [ ] En este laboratorio aislado, detener el proceso no afecta al tráfico público porque IIS sigue intacto. Si IIS reenvía a WPShield, deshabilita la regla de reescritura de WPShield para desviarlo antes de detener el proceso.
- [ ] Los logs se revisan antes de guardarlos o compartirlos para comprobar que no incluyan credenciales, cookies, nonces ni consultas completas.
- [ ] `dotnet test WPShield.slnx --configuration Release` pasa sobre el commit evaluado.
- [ ] Se han leído el [modelo de amenazas](modelo-de-amenazas.md) y los límites de cobertura.

## Estructura del repositorio

```text
WPShield/
|-- src/
|   |-- WPShield.Abstractions/       Contratos de inspección estables
|   |-- WPShield.Core/               Resolución de sitios y evaluación de reglas
|   |-- WPShield.Rules.Windows/      Reglas de Windows e IIS, portables
|   |-- WPShield.Rules.WordPress/    Reglas que requieren conocimiento de WordPress
|   |-- WPShield.Service/            Demostración del motor
|   |-- WPShield.Logging/            Logs JSON Lines fuera del gateway
|   |-- WPShield.Gateway/            Gateway HTTP M1 de loopback
|   `-- WPShield.NetworkSensor/     Captura pasiva de metadatos con Npcap
|   `-- WPShield.WebEvidence/       Sensor de logs W3C de IIS: reglas de ruta y observaciones (portable)
|-- tests/                           Proyectos xUnit
|-- scripts/                         Triage y validación IIS de solo lectura
|-- assets/                          Imágenes de portada y redes sociales
|-- docs/
|   |-- assets/                       Pares de figuras claras y oscuras
|   |-- en/                           Documentación en inglés
|   `-- es/                           Documentación en español
|-- site/                            Landing de GitHub Pages
|-- .github/                         CI, plantillas y guías
|-- ROADMAP.md                       Hitos
`-- THREAT_MODEL.md                  Supuestos y salvaguardas
```

## Plan de desarrollo

| Hito | Objetivo | Estado |
| --- | --- | --- |
| M0 | Base, contratos, CI y guías | Completo salvo el esquema de configuración y mensajes de validación localizados |
| M1 | Gateway multisitio de loopback endurecido y pruebas sintéticas | En curso |
| M2 | Límites, inspección multipart y reglas de alta confianza | En curso |
| M3 | Presupuestos por cliente, sitio y regla, y límites de retención de búferes | Parcial. Quedan políticas y excepciones |
| M4 | Eventos, métricas, rotación y retención con privacidad | Planificado |
| M5 | Panel multilingüe de loopback | Planificado |
| M6 | Servicio Windows de privilegios mínimos y releases firmados | Planificado |
| M7 | Activación gradual en producción, primero en Monitor | Planificado |
| M8 | Paquetes comunitarios y preparación del proyecto para distribución | Planificado |

Los criterios de aceptación y las tareas están en el [plan publicado](../../ROADMAP.md). Consulta también el [plan de trabajo en español](plan-de-desarrollo.md).

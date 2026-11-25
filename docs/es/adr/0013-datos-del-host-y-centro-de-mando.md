# ADR 0013 — Datos del host y centro de mando

- **Estado:** Propuesta
- **Deciden:** Pedro Hernández (mantenedor)
- **Afecta a:** el recolector de evidencia, `WPShield.Evidence`, `wpshield` (un verbo nuevo, `host`,
  y `audit`), el servidor MCP y el analista, y el escritorio

## Contexto

La evidencia de WPShield responde "quién está atacando". El mantenedor también quiere saber "cómo
está este servidor", en una sola pantalla con relojes: un centro de mando. El servidor del incidente
sigue mostrando por qué hace falta:

- **Se reinicia solo.** En octubre de 2026, un volcado de memoria del kernel atribuyó cuatro
  reinicios al código de parada 0x133 (`DPC_WATCHDOG_VIOLATION`), dentro de un controlador de filtrado
  de red de terceros. El 2026-11-25 volvió a reiniciarse mientras corría un script de solo lectura.
  Nadie se entera hasta que alguien abre el Visor de eventos.
- **Su postura cambia despacio, a mano.** `wpshield audit` encontró 80 de 81 grupos de aplicaciones
  corriendo como el Administrator local. El plan es moverlos uno a uno, y nada muestra el avance
  ("1 de 80") ni un grupo que vuelva atrás.
- **Su exposición solo se conoce por un script suelto.** En noviembre de 2026, SMB, tres motores de
  base de datos, VNC y WinRM estaban abiertos a cualquier dirección. Eso salió de un script corrido
  una vez, en un chat.
- **La persistencia vive en el inventario.** El triaje del 2026-11-01 revisó a mano tareas
  programadas, servicios y cuentas. Una tarea o un servicio que aparezca entre dos triajes pasa
  desapercibido.

El servidor MCP y el analista (ADR 0008 y 0010) solo pueden responder sobre evidencia. Si se les
pregunta "¿está sano este servidor?", no tienen nada que leer.

El ADR 0011 fijó el patrón que este sigue: una sola fuente, leída una vez, acotada, y mostrada igual
en todas las superficies.

## Decisión

**WPShield tendrá una capa de datos del host, de solo lectura. El recolector la lee con una
cadencia fija y guarda instantáneas acotadas en el almacén de evidencia. La CLI, el centro de mando
del escritorio, el servidor MCP y el analista responden todos a partir de esas instantáneas. Nada en
esta capa cambia el host.**

### 1. Los datos

| Dato | Qué contiene | Fuente | Elevación |
| --- | --- | --- | --- |
| `host_health` | Tiempo encendido y último arranque. Reinicios inesperados de los últimos 30 días, cada uno con su código de parada cuando lo hay. CPU, memoria y espacio libre por volumen fijo, marcando el volumen que guarda los logs de IIS. Tamaño del almacén de evidencia | `GetTickCount64`; eventos 41 (Kernel-Power), 6008 (apagado inesperado) y 1001 (`BugCheck` de WER, que trae el código) del registro System; `GetSystemTimes`, `GlobalMemoryStatusEx`, `DriveInfo`; tamaño del archivo del almacén y de su WAL | No. El registro System se puede leer por defecto |
| `iis_sites` | Por sitio: ID, nombre, estado, bindings (protocolo, puerto, nombre de host, si es loopback), grupo, **tipo** de identidad del grupo (`ApplicationPoolIdentity`, un usuario concreto, `LocalSystem`, ...) y si esa identidad es administradora local. Cobertura de logs por sitio, del sensor web (ADR 0011) | El lector de la configuración de IIS que ya usan `audit`, `preflight` y el sensor web, en solo lectura; `WebEvidenceQueries.Sites()` | Sí. Sin ella, el dato queda en `needs-elevation` |
| `iis_posture` | El último resumen del audit: ID, severidad y número de elementos de cada hallazgo, más los recuentos de los relojes, como los grupos con derechos de administrador frente al total | Los propios chequeos del audit (`AuditRunner`), en solo lectura; véase la sección 3 | Sí |
| `listening_ports` | Puerto, protocolo, dirección local (cualquiera, una concreta o loopback), ejecutable del proceso y un veredicto de exposición | Las tablas de escuchas TCP y UDP (`LocalListenerInventory`, que ya nombra el proceso dueño) y la política activa del firewall | El nombre del proceso y algunas reglas necesitan elevación; lo que no se pudo leer queda `unknown` |
| `rdp_sessions` | Sesiones actuales (ID, estado, usuario, hora de inicio) e inicios y reconexiones RDP de los últimos 7 días, cada uno con su dirección de origen | `WTSEnumerateSessions` para el estado; eventos 21 y 25 de LocalSessionManager para las direcciones (como `OwnConnection`) | No para el registro de eventos. Algunos detalles de sesión la necesitan |
| `host_inventory` | Tres clases: `accounts`, `services` y `tasks` | Véase la sección 1.3 | Sí. Sin elevación, las tareas salen como `partial` |
| *salientes* (aplazado) | Conexiones de los procesos web hacia Internet | Necesita un sensor propio; véase la sección 1.4 | — |

#### 1.1 El veredicto de exposición

Para cada escucha, el veredicto sale de las **reglas de entrada habilitadas en los perfiles activos
del firewall**:

- `open-to-any`: una regla que permite el tráfico cubre el puerto, desde cualquier dirección remota;
- `restricted`: las reglas que permiten el tráfico solo cubren algunas direcciones remotas;
- `blocked`: una regla de bloqueo cubre el puerto, o ninguna regla lo permite y la acción de entrada
  por defecto es bloquear;
- `local-only`: la escucha está atada a loopback;
- `unknown`: no se pudo leer la política.

El veredicto lleva la etiqueta **"según las reglas del Firewall de Windows"** y nunca se presenta como
"alcanzable desde Internet". En el mismo camino hay otros filtros y callouts de WFP que también
deciden: un controlador de filtrado de red, un producto de seguridad del equipo, el firewall
perimetral de un proveedor. Por eso un proceso que escucha no queda demostrado como alcanzable, y una
regla que permite el tráfico no demuestra que los paquetes lleguen.

#### 1.2 Los reinicios inesperados son eventos, no solo un recuento

Cada reinicio inesperado se registra una sola vez, como un evento de evidencia de clase
`host.unexpected-restart`. Los duplicados se reconocen por el ID de registro del evento de System. El
detalle guarda la hora, el evento de origen y el código de parada con su nombre
(`0x133 DPC_WATCHDOG_VIOLATION`). El primer arranque lee los últimos 30 días, así que la historia
está ahí desde el principio. Los arranques siguientes solo leen lo nuevo. El recuento de 30 días del
reloj es una consulta sobre estos eventos, y sobrevive a que el registro System se vacíe o se
sobrescriba.

#### 1.3 El inventario, sin secretos

Solo se listan los elementos que **no son de Microsoft**. Para servicios y tareas, eso significa que
el binario no está firmado con Authenticode por Microsoft. Se omiten las tareas bajo `\Microsoft\`
cuya acción es un binario firmado por Microsoft.

- **Cuentas:** nombre, si está habilitada, si pertenece a Administradores o a Usuarios de Escritorio
  remoto, último inicio de sesión, antigüedad de la contraseña y si nunca caduca. No se leen ni el
  nombre completo ni la descripción.
- **Servicios:** nombre, nombre para mostrar, estado, modo de inicio, cuenta con la que corre y ruta
  del ejecutable. La firma del ejecutable se informa como `signed by <sujeto>`, `unsigned` o
  `not checked`.
- **Tareas:** ruta y nombre, estado, principal con el que corre, última y próxima ejecución, y la ruta
  del ejecutable de la acción con su firma.

**Los argumentos nunca se guardan ni se muestran.** Los argumentos de un servicio o de una tarea
pueden llevar una contraseña o un token, y un comando codificado es la carga del atacante. En su
lugar, el dato registra **marcas**, calculadas en el equipo y descartadas después:

- `has-arguments`;
- `encoded-command` (`-enc`, `-EncodedCommand`);
- `contains-url`;
- `user-writable-path` (el ejecutable, o una ruta en los argumentos, está bajo una carpeta en la que
  pueden escribir los usuarios o `Everyone`).

El texto de los argumentos nunca llega al almacén, a una línea de log ni a una respuesta.

**La verificación de firmas está acotada.** Los resultados de `WinVerifyTrust` se guardan en caché
por ruta, tamaño y fecha de última escritura. Cada instantánea verifica como máximo 300 binarios; el
resto queda `not checked` hasta la siguiente.

Un cambio entre dos instantáneas del inventario se registra como un evento de clase
`host.inventory-change`: un elemento añadido, quitado, o con otro ejecutable, otra cuenta u otra
firma. Esa es la señal de "apareció una tarea". Complementa al pack `wpshield.persistence` (ADR
0012), que ve el evento cuando se registra. El inventario ve el estado, incluido lo que se creó
mientras nada vigilaba.

#### 1.4 Las conexiones salientes, aplazadas a su propio ADR

Malwarebytes vio a `php-cgi.exe` conectarse a la dirección del atacante el 2026-11-19, después de la
limpieza. Es el dato del host más valioso de todos, y **no** está en este ADR. Una instantánea de la
tabla TCP cada pocos minutos no ve una llamada que dura dos segundos. Verlas de forma fiable exige un
sensor: una sesión ETW sobre el proveedor de red del kernel, o un muestreo frecuente de la tabla TCP.
Cualquiera de los dos trae sus propios costes, permisos y límites. Tendrá su propio ADR. Mientras
tanto, el centro de mando muestra el panel como **"todavía no se mide"**, para que la ausencia nunca
se lea como "no sale nada".

### 2. Honesto con lo que no pudo leer

Cada dato lleva:

- su **hora de lectura**;
- un **estado**: `ok`, `partial`, `needs-elevation`, `unreadable` o `not-measured`;
- para cualquier estado distinto de `ok`, una **razón** y el **remedio**, como ya hacen `audit` y
  `preflight`.

Una instantánea con más de tres veces su cadencia se muestra como **desactualizada**, con su
antigüedad. Un dato que no se pudo leer nunca se presenta como vacío: cero reinicios inesperados y
"no se pudo leer el registro System" no deben parecerse.

### 3. Instantáneas, cadencia y almacenamiento

**El recolector toma las instantáneas; los lectores nunca provocan una lectura en vivo.** Consultar
en vivo sería el diseño equivocado:

- El escritorio se refresca cada 5 segundos. Enumerar tareas y verificar firmas a ese ritmo haría del
  monitor el proceso más pesado del host.
- Una tendencia necesita historia: "grupos movidos, semana a semana" y "reinicios en 30 días" no
  pueden salir de lecturas en vivo.
- Todas las superficies muestran la misma instantánea con la misma hora de lectura, así que la CLI,
  el escritorio y el analista no pueden contradecirse.
- Un modelo nunca puede hacer que WPShield sondee el host. Las herramientas MCP y el analista solo
  leen instantáneas guardadas.

**Cadencia:**

| Dato | Cadencia |
| --- | --- |
| `host_health` | cada 5 minutos. Los reinicios inesperados se leen al arrancar y cada 15 minutos |
| `iis_sites`, `listening_ports`, `rdp_sessions` | cada 15 minutos |
| `iis_posture` | al arrancar y cada 6 horas |
| `host_inventory` | al arrancar y cada 6 horas |

**De dónde sale la postura.** El recolector corre él mismo los chequeos del audit, en solo lectura y
con su cadencia. La CLI le entrega el lector del audit, igual que le entrega la lista de sitios de
IIS (ADR 0011, tal como se construyó). Así el reloj de "grupos movidos" avanza sin que el operador
tenga que acordarse de correr nada. Un `wpshield audit` manual también registra su resumen como
instantánea de postura.

Escribir esa fila en el almacén del propio WPShield no es un cambio en el servidor. La última línea
del audit pasa a ser: "Nothing on this server was changed. A summary was recorded in WPShield's
evidence store." Si el almacén no se puede abrir, el audit corre igual y dice que el resumen no se
registró.

**Almacenamiento: esquema 3, aditivo.** Un almacén escrito por una versión anterior conserva todas
sus filas, como exige AGENTS.md desde el esquema 2, y una prueba abre con el código nuevo un almacén
de esquema 2 escrito literalmente:

- `host_snapshots`:
  - columnas: dato, clase, hora de captura, estado, razón y una carga JSON de como máximo 256 KB;
  - se guardan: la última instantánea de cada dato, todas las instantáneas de postura durante
    400 días (cuatro al día) y las demás durante 7 días.
- `host_health_hourly`: CPU media y pico, memoria libre mínima y espacio libre mínimo por volumen,
  durante 90 días. De ahí salen las tendencias.
- Los eventos `host.unexpected-restart` y `host.inventory-change`, que siguen la retención actual de
  `events`.

**Límites:**

- como máximo 2.000 elementos por clase de inventario y 500 escuchas por instantánea;
- todo nombre y ruta se limpia y se acota a 256 caracteres;
- como máximo 500 eventos `host.inventory-change` al día por clase; a partir de ahí se cuentan sin
  guardarse, y el desborde queda registrado;
- un presupuesto de tiempo por instantánea. Un dato que lo supera se guarda como `partial`, nunca a
  medio escribir.

**Dónde corre primero.** Igual que el sensor web, los datos del host empiezan en `evidence collect`,
que corre elevado. Llevarlos al servicio, bajo `NT SERVICE\WPShield`, exige una tabla de permisos por
dato con sus remedios, y vendrá en una enmienda cuando el recolector del servicio lea también los
logs de IIS.

### 4. Nunca cambia nada

El ADR 0005 y AGENTS.md se aplican sin excepciones. Ningún dato, verbo, herramienta ni panel detiene,
arranca, borra ni reconfigura un servicio, una tarea, una cuenta, una regla del firewall, un ajuste de
IIS o un archivo. Todo lo que se vea mal viene con un remedio, que es texto impreso para que una
persona lo haga a mano. Una acción futura de cualquier tipo necesitaría su propio ADR y una
confirmación fuera del modelo (ADR 0008, sección 2).

### 5. Lo que sale del host

Los nombres de sitios, de cuentas, de servicios y de tareas, las rutas de los ejecutables y las
direcciones de origen del RDP son **detalles del host**. Una lista de ellos es un mapa del servidor
para quien la lea. Cada resultado de herramienta va al proveedor del modelo del asistente (ADR 0008,
sección 7), así que estos detalles necesitan su propio interruptor.

**Un ajuste auditado nuevo, `mcp.host_details`** (por defecto `false`, `NextStart`). Por qué no
`mcp.detailed_records`:

- Ese ajuste gobierna el **detalle de la evidencia**: intentos sueltos y los nombres de cuenta que
  probaron los atacantes. Este gobierna **el inventario del propio host**: qué corre, como quién y
  desde dónde.
- Un operador que permite el detalle de los registros para una investigación no debería exportar,
  sin darse cuenta, también el mapa del servidor.
- El ADR 0010 rechazó "una segunda definición de lo que sale del host" para el mismo contenido. Este
  es contenido distinto, así que un interruptor aparte es la forma honesta. La sección 7 del ADR 0008
  gana un párrafo que lo nombra.

**Con `mcp.host_details` en false**, las herramientas devuelven:

- recuentos, estados, veredictos y relojes ("80 de 81 grupos corren como administrador", "3 servicios
  con un binario sin firmar");
- números de puerto, protocolos y veredictos de exposición;
- el **nombre de archivo** del ejecutable de un proceso que escucha (`mysqld.exe`), sin su ruta,
  porque un veredicto de exposición no significa nada sin él;
- horas de reinicio y códigos de parada.

Los nombres de sitios, cuentas, servicios y tareas, las rutas y las direcciones de origen del RDP se
sustituyen por `"withheld"`, y la respuesta dice qué ajuste los liberaría.

**Con el ajuste en true**, se devuelven. Todo valor que nombra algo se devuelve bajo `untrusted` (ADR
0008, sección 3). En un host comprometido, el atacante elige los nombres de las tareas, los nombres
para mostrar de los servicios y las rutas de los ejecutables.

La CLI y el escritorio lo muestran todo. Son superficies locales, y nada de lo que muestran sale del
host.

### 6. Superficies

**CLI:**

```text
wpshield host [health|sites|posture|ports|sessions|inventory <accounts|services|tasks>] [--live] [--json]
```

Sin argumentos imprime, en una pantalla, el resumen de todos los datos a partir de las últimas
instantáneas, cada uno con su antigüedad y su estado. `--live` lee el host directamente y no escribe
nada. Es para cuando el recolector no está corriendo, y la salida dice que es una lectura en vivo.

**Herramientas MCP.** Los esquemas estrictos del analista (ADR 0010) admiten como máximo 24
parámetros opcionales entre todas las herramientas y 16 de tipo unión, y todavía tienen que caber las
herramientas web del ADR 0011. Por eso:

- `host_health`, `iis_sites`, `iis_posture` y `listening_ports` **no tienen parámetros**;
- `rdp_sessions` tiene un único rango opcional **con nombre** (`24h` o `7d`);
- `host_inventory` tiene un enum **obligatorio**, `kind` (`accounts`, `services` o `tasks`). Es una
  herramienta en lugar de tres, y un enum obligatorio no gasta nada del presupuesto de opcionales;
- ninguna acepta una ruta, un nombre, un comando ni una consulta;
- no se ofrecen rangos explícitos `from`/`to`. Si alguna vez hace falta uno, la reducción del analista
  lo deja fuera, como hace hoy `ExplicitRangeTools`;
- la prueba que ya fija el presupuesto de parámetros opcionales cubre las herramientas nuevas. Hace
  fallar la compilación antes de que falle una petición en el proveedor.

Todas son de solo lectura y no destructivas, así que la guarda del analista
(`McpAnalystTools.RequireReadOnly`) las acepta sin cambios.

**El centro de mando del escritorio** es una pantalla de inicio con paneles. Cada panel muestra la
hora de lectura de su fuente y se pone gris cuando le faltan datos o están desactualizados. **El gris
nunca es verde.**

| Panel | Muestra | Fuente | Cuando no hay datos |
| --- | --- | --- | --- |
| WPShield | Recolector corriendo, cobertura de cada sensor (registro de seguridad, RDP, logs de IIS "N de M sitios leídos") y antigüedad del registro más reciente | Cobertura de la evidencia, sitios del sensor web | "El recolector no corre desde ..." en rojo; un sensor que no cubre dice por qué |
| Ataques RDP/SMB | Intentos por minuto frente a la mediana horaria de 7 días; decisiones en vigor (Monitor); la red más activa | Evidencia, `decisions` | Los huecos se dibujan como "sin datos", como en Ataques |
| Web | Peticiones por minuto, hallazgos de reglas, POST a login y a xmlrpc. **`WEB-OBS-001`**: rojo si es mayor que cero; verde solo si se leyeron todos los sitios durante todo el rango | Evidencia web (ADR 0011) | Con cobertura incompleta, la luz de `WEB-OBS-001` se pone gris, nunca verde |
| Salud del servidor | Tiempo encendido; **reinicios inesperados en 30 días, con sus códigos de parada**; CPU, memoria y disco, con tendencias | `host_health`, `host_health_hourly`, eventos de reinicio | Instantánea desactualizada o ilegible: gris, con antigüedad y razón |
| Postura | **Grupos movidos: N de M**, con barra de progreso y su historia; PHP mapeado a nivel servidor; carpetas de sitios escribibles; solapes con FTP; hora de la última instantánea de postura | `iis_posture` | "Todavía no hay instantánea de postura" en gris, con el remedio (arrancar el recolector elevado o correr `wpshield audit`) |
| Exposición | Cada escucha abierta a cualquier dirección, con su veredicto. En rojo SMB (139, 445), RPC (135), SQL Server (1433), MySQL (3306, 33060), PostgreSQL (5432), VNC (5900) y WinRM (5985, 5986) cuando están abiertos a cualquiera | `listening_ports` | Los veredictos `unknown` se listan como desconocidos, nunca como cerrados |
| Analista | Activado o apagado; ejecuciones y tokens de entrada de hoy frente a `analyst.daily_runs` y `analyst.daily_input_tokens`; hora del último informe | Almacén del analista (ADR 0010) | Apagado se muestra como apagado, no como error |
| Salientes | — | Aplazado (sección 1.4) | Siempre "todavía no se mide: necesita un sensor propio" |

La ventana se construye **después de que este ADR se acepte y la capa de datos del host esté
fusionada**, sobre la API de lectura de esa capa. Es el mismo orden que la vista web, que esperó a su
sensor.

## Consecuencias

- **Las preguntas de los dos últimos meses tienen respuesta en una pantalla:**
  - ¿Se cayó otra vez, y con qué código?
  - ¿Cuántos grupos siguen siendo administradores?
  - ¿Qué está abierto al mundo?
  - ¿Apareció un servicio o una tarea?
- **El analista puede razonar sobre el host**, a partir de instantáneas guardadas y, por defecto, sin
  que los nombres del host salgan de él.
- **El recolector trabaja más.** Las cadencias y el presupuesto por instantánea lo mantienen acotado,
  y la primera semana lo mide.
- **El almacén crece una cantidad fija.** Las instantáneas se podan, y la salud por horas ocupa poco.
- **Un controlador de filtrado de terceros todavía puede hacer que un veredicto de exposición sea
  incorrecto.** Por eso el veredicto nombra su fuente.
- **Las conexiones salientes siguen invisibles** hasta que se escriba su ADR. El panel lo dice.

## Alternativas consideradas

- **Sysmon.** Datos excelentes, incluidas las conexiones de red por proceso. Pero instala un
  controlador de kernel y una configuración en un servidor de producción, y este host ya ha pagado
  por ese tipo de cambio. Puede volver como fuente opcional en el ADR de las conexiones salientes.
- **WMI para todo.** Una sola API, pero lenta en un host cargado, propensa a que se corrompa su
  repositorio, y es el mismo subsistema que usan los atacantes para persistir. Las API nativas de
  arriba son más rápidas y más acotadas. WMI queda como alternativa, de solo lectura, si hiciera falta.
- **Un agente de monitorización** (Zabbix, Wazuh, `windows_exporter` de Prometheus). Maduro, pero es
  otro agente con su propia escucha y su propio canal de actualizaciones en un servidor expuesto. No
  habla la evidencia de WPShield ni sus reglas de honestidad, y sus relojes estarían en una segunda
  consola. Más adelante puede llegar una exportación de las instantáneas de WPShield hacia una
  herramienta así, como un lector más.
- **Lecturas en vivo en cada petición.** Más simple, pero no hay tendencias, el escritorio se vuelve
  pesado, las superficies se contradicen, y un modelo podría hacer que se sondee el host. Rechazada
  por las razones de la sección 3.
- **Reutilizar `mcp.detailed_records`.** Rechazada en la sección 5: gobierna otro contenido.

## Cuándo revisar esta decisión

- Tras dos semanas en el servidor del incidente: la CPU y el tiempo del recolector por instantánea,
  el crecimiento del almacén, y cuántas veces se agota el presupuesto de verificación de firmas.
- Cuando se escriba el ADR del sensor de conexiones salientes: conectar aquí su panel y su
  herramienta.
- Cuando el recolector del servicio lea los logs de IIS: añadirle los datos del host, con la tabla de
  permisos por dato.
- Cuando exista el grupo lector dedicado del ADR 0007: reconsiderar qué datos puede leer un
  escritorio sin elevación.

# ADR 0006 — Bloqueo en la capa de red dentro de WPShield

- **Estado:** Aceptado el 2026-11-24: WPShield bloquea a nivel de servidor por sí mismo, solo en modo
  Block. El **mecanismo** se enmendó ese mismo día; véase
  [Enmienda: la Plataforma de filtrado de Windows en lugar de WinDivert](#enmienda-2026-11-24-la-plataforma-de-filtrado-de-windows-en-lugar-de-windivert).
  El pull request que implementa este ADR sigue como borrador hasta sustituir el mecanismo de bloqueo y
  superar la validación de la enmienda.
- **Deciden:** Pedro Hernández (mantenedor)
- **Sustituye a:** la mitad de red de la decisión del [ADR 0002](0002-defensa-fuerza-bruta-a-nivel-de-host.md)
  (RDP, FTP, SMTP, SQL y SMB "corresponden al proyecto hermano"). La mitad HTTP del ADR 0002 se
  mantiene.
- **Afecta:** `AGENTS.md`, `ROADMAP.md` (M2.7, M2.8 y la declaración inicial),
  `.github/instructions/docs.instructions.md`, y `wpshield network-filter`

## Contexto

El ADR 0002 dejó el bloqueo de direcciones fuera de WPShield porque la única forma que conocía de
bloquear una dirección era escribir reglas del Firewall de Windows, y una regla de cortafuegos escrita
por una herramienta es exactamente lo que un servidor compartido no puede permitirse: persiste cuando
la herramienta muere, sobrevive a un reinicio y, cuando está equivocada, deja al administrador fuera
de la misma sesión que usaría para arreglarla. El ADR 0002 también dijo cómo deshacer esa decisión: a
propósito, en su propio cambio, nunca como efecto secundario de añadir una funcionalidad.

Ese efecto secundario ocurrió. El 2026-10-20 `WPShield.NetworkFilter` llegó a `main` con M2.7 y M2.8
marcados como hechos en la hoja de ruta y el ADR 0002 sin tocar. Leído contra la API de WinDivert 2.2,
no podía bloquear nada, y habría sido peligroso si hubiera podido:

- Abría su handle con `WINDIVERT_FLAG_SNIFF`, que **copia** los paquetes. "Descartar" una copia no
  hace nada; el original ya iba de camino.
- Sus declaraciones de `WinDivertRecv` y `WinDivertSend` no coincidían con la API (las reales reciben
  la longitud como `UINT*` y un `WINDIVERT_ADDRESS*` de 80 bytes), y reinyectaba cada paquete con una
  longitud de 65.536 bytes.
- Su filtro predeterminado, `tcp.Inbound`, no es un campo de WinDivert, así que `WinDivertOpen` falla
  con el error 87 antes de que ocurra nada más. Ese accidente es la única razón de que fuera
  inofensivo.
- Su regla de tasa contaba **paquetes** y bloqueaba por encima de 120 por minuto, cifra que supera una
  sola carga de página de WordPress. Sin lista de permitidos en el filtro, habría bloqueado a los
  visitantes de todos los sitios del host y, con ellos, la propia sesión RDP del administrador.
- Su analizador leía los números de puerto en little-endian.

Mientras tanto, la evidencia a favor de querer esta capacidad se hizo más fuerte. Cuatro semanas de
Malwarebytes Web Access Control en el host de producción registraron **6.150 conexiones entrantes
bloqueadas desde 344 direcciones**, **el 17 % de ellas hacia servicios que no son HTTP**: PostgreSQL,
MySQL, SQL Server, SMB, WinRM, FTP, VNC y correo. El gateway de WPShield nunca ve ese tráfico. Y la
alternativa comercial tampoco está libre de riesgo: el mismo host se cayó repetidamente con
`DPC_WATCHDOG_VIOLATION`, rastreado hasta `mwac.sys`, un componente de kernel que inspecciona cada
conexión entrante. El operador quiere un bloqueador en la capa de red que pueda leer y que no pueda
tumbar el host.

## Decisión

**WPShield puede descartar paquetes entrantes procedentes de direcciones de su propia lista de
bloqueo**, siempre que se cumpla todo lo que sigue. Cada punto se impone en código y está cubierto por
pruebas; ninguno es un consejo.

### 1. El tráfico benigno nunca pasa por WPShield

La aplicación de los bloqueos usa handles de WinDivert abiertos con **`WINDIVERT_FLAG_DROP`**, cuyo
filtro coincide solo con las direcciones de la lista de bloqueo. El controlador descarta esos paquetes
en el kernel. Nada más coincide, así que nada más se desvía, y **no hay reinyección en ningún punto
del código**: no existe ninguna declaración de `WinDivertSend` a la que llamar.

La observación usa un handle aparte, abierto con **`WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY`**
y el filtro `inbound and !loopback and tcp.Syn and !tcp.Ack`: intentos nuevos de conexión TCP
entrante, nada más. Recibe copias. Un observador lento, detenido o caído pierde copias, nunca tráfico.

Esta es la propiedad que le faltaba al diseño del 2026-10-20, y la razón de que no pudiera volverse
seguro arreglando sus errores: un filtro que desvía y reinyecta hace pasar cada paquete de cada sitio
por un proceso en modo usuario, y entonces un proceso colgado es una caída del host.

### 2. Los bloqueos viven exactamente lo que vive el proceso

Ninguna regla de cortafuegos, ningún valor en el registro de Windows, ningún archivo. Un bloqueo es un
filtro sobre un handle de kernel que pertenece al proceso de WPShield. Cuando el proceso termina, se
cae, se detiene o la máquina se reinicia, el handle se cierra y todos los bloqueos desaparecen.

Ese es el **interruptor de hombre muerto** del ADR 0002, obtenido de la vida del handle en lugar de
una tarea programada que elimine reglas. Es más fuerte, porque no queda nada detrás que eliminar, y no
instala nada que la herramienta de triage marcaría, con razón, como persistencia.

**El riesgo residual, dicho sin rodeos:** un proceso que se *cuelga* sin terminar mantiene sus
bloqueos actuales hasta que alguien lo mata, y mientras está colgado no puede hacer expirar las
entradas dinámicas. Esos bloqueos solo pueden cubrir direcciones que no estén en la lista de
permitidos (sección 3).

### 3. La lista de permitidos va antes que cualquier bloqueo

El primer mecanismo del ADR 0002, aplicado dos veces:

- Una dirección de la lista de permitidos nunca puede entrar en el conjunto de bloqueo. Se rechaza una
  dirección individual que esté en la lista de permitidos; se rechaza un rango que contenga una
  dirección permitida.
- El constructor de filtros vuelve a excluir las direcciones permitidas cuando escribe los filtros
  DROP, de modo que un defecto en una sola capa no basta.

Y la guarda contra el encierro: **el modo Block se niega a arrancar** cuando la lista de permitidos
está vacía, y cuando cualquier conexión TCP establecida con el puerto RDP del host viene de una
dirección que no está en la lista de permitidos. El puerto se lee del registro de Windows
(`RDP-Tcp\PortNumber`); nunca se da por hecho que sea el 3389. Un operador que arranca el modo Block
por RDP tiene que nombrar la dirección desde la que está conectado, y si no lo ha hecho, la
herramienta se la nombra.

La comprobación al arrancar no basta por sí sola, porque un administrador puede reconectarse desde
una dirección nueva con el proceso ya en marcha. Por eso la guarda vuelve a ejecutarse con cada
bloqueo dinámico nuevo: se rechaza una dirección que en ese momento tenga una conexión con el puerto
RDP, y cuando las conexiones no pueden leerse el bloqueo también se rechaza, porque "nadie pudo mirar"
no es "no hay nadie".

### 4. Monitor es el modo predeterminado

**Monitor nunca abre un handle DROP.** No es una bandera que se comprueba antes de cada descarte: el
componente que aplica los bloqueos ni siquiera se construye. Monitor registra a quién *habría*
bloqueado y por qué, y así es como una semana en un host real convierte un umbral plausible en uno
defendible. Block es el `--mode Block` explícito.

### 5. El grado de la evidencia decide quién puede añadir un bloqueo

Una dirección bloqueada queda bloqueada para **todos los sitios del host**, y por eso el origen de un
bloqueo importa aquí más que en el gateway.

| Origen | ¿Falsificable? | Puede añadir un bloqueo en modo Block |
| --- | --- | --- |
| Dirección o rango nombrado por el operador (`--block`) | No | Sí |
| Registro de Seguridad: inicios de sesión fallidos repetidos (`WP-SEC-001`, `WP-SEC-002`) | No: el inicio de sesión falló después de completarse el handshake TCP | Sí, con un TTL |
| Intentos de conexión por minuto (`WP-NET-002`) | **Sí**: la dirección de origen de un SYN es la que el remitente haya escrito | Solo con `--syn-rules-may-block` |
| Puertos distintos por minuto (`WP-NET-003`) | **Sí** | Solo con `--syn-rules-may-block` |

`--syn-rules-may-block` se documenta como lo que es: permite que cualquiera capaz de enviar SYN
falsificados consiga que se bloquee durante el TTL cualquier dirección que no esté en la lista de
permitidos, incluido el rastreador de un buscador.

### 6. Los bloqueos expiran y el conjunto está acotado

Los bloqueos dinámicos expiran tras un TTL (60 minutos por omisión; un hallazgo repetido lo prolonga).
Los bloqueos nombrados por el operador duran toda la vida del proceso. El conjunto admite como máximo
1.000 entradas por omisión; cuando está lleno, los bloqueos dinámicos nuevos se rechazan y se
registran, y nunca se desaloja una entrada del operador para hacer sitio.

### 7. WPShield nunca carga un controlador de kernel como efecto secundario

Todos los handles se abren con **`WINDIVERT_FLAG_NO_INSTALL`**. Si el controlador no está cargado, el
comando lo dice y se detiene. Cargarlo es una acción del operador nombrada en la línea de comandos
(`--install-driver`), porque el controlador de WinDivert es un servicio distinto de WPShield y
`AGENTS.md` mantiene esos cambios manuales salvo que el operador los nombre.

Lo que WinDivert hace a continuación está leído de su código fuente (`dll/windivert.c`), no supuesto:
registra un servicio de controlador de kernel de inicio manual (demand-start) llamado `WinDivert`, lo
inicia y **lo marca para su eliminación en el acto**. El registro no sobrevive a `sc stop WinDivert`
ni a un reinicio, así que nada queda instalado en el host. El precio es que `--install-driver` vuelve a
hacer falta en la primera ejecución después de cada reinicio, y un futuro servicio que arranque con el
sistema tendrá que pasarlo a sabiendas.

WinDivert **no viene incluido**. Es LGPLv3, y el operador descarga la 2.2.2 de la publicación oficial
del proyecto y la comprueba contra los valores SHA-256 del diseño del filtro de red. Su
`WinDivert.dll` de modo usuario no tiene firma; su controlador de kernel lleva un certificado EV de
firma de código que Sectigo emitió a una empresa, no al autor de WinDivert. Toda copia de la
publicación oficial 2.2.2 trae ese mismo controlador, así que lo que importa comprobar es que el
archivo del operador sea ese archivo. `WinDivert.dll` se carga únicamente desde el directorio del
ensamblado de WPShield, nunca desde `PATH` ni desde el directorio de trabajo: el proceso corre
elevado, y una búsqueda de DLL que alcance un directorio con permiso de escritura es una escalada de
privilegios.

### 8. Autoprueba antes de Block

Antes de que se abra el primer handle DROP, cada filtro generado se compila con
`WinDivertHelperCompileFilter` y se evalúa con `WinDivertHelperEvalFilter` contra paquetes sintéticos:
una dirección de la lista de bloqueo debe coincidir; una dirección permitida y otra sin relación no
deben coincidir; la primera y la última dirección de cada rango deben coincidir, y las direcciones
justo fuera de él no. **El modo Block se niega a arrancar si falla cualquier comprobación.** `--check`
ejecuta la misma prueba sin elevación y sin el controlador, porque ambas funciones auxiliares son
funciones corrientes en modo usuario de `WinDivert.dll`.

Así es como pueden incluirse los rangos aunque la documentación de WinDivert no explique cómo ordena
la comparación de direcciones: se le pregunta a la biblioteca real, en la máquina que la va a
ejecutar, antes de confiar en ella.

### 9. Todo está acotado

Un filtro DROP contiene como máximo 200 de los 256 objetos que permite WinDivert
(`WINDIVERT_FILTER_MAXLEN`); un conjunto de bloqueo mayor se reparte entre varios handles. El estado
por origen del observador tiene un tope y desaloja el origen visto menos recientemente, porque una
avalancha de SYN con orígenes falsificados aleatorios no debe hacer crecer un diccionario sin límite. Los hallazgos se
registran una vez por origen y umbral, no una vez por paquete.

## Qué cambia en los invariantes

- La regla de `AGENTS.md` según la cual nunca se cambia infraestructura que el operador no nombró
  **se mantiene**. El filtro de red no escribe ninguna regla del Firewall de Windows y no deja nada
  detrás; la instalación del controlador se nombra.
- La declaración inicial de `ROADMAP.md` y `docs.instructions.md` decían que ningún hito modifica
  reglas de cortafuegos automáticamente. Ahora dicen lo que es cierto: WPShield nunca escribe reglas
  del Firewall de Windows, y su filtro de red descarta paquetes solo de su propia lista de bloqueo,
  solo en modo Block y solo mientras se ejecuta. Redefinir en silencio "regla de cortafuegos" para que
  la frase vieja siga sonando cierta es la evasión de la que avisaba el ADR 0002, así que lo que cambia
  es la frase.
- El reparto HTTP del ADR 0002 se mantiene: los ataques de credenciales contra `wp-login.php` y
  XML-RPC corresponden al M3 del gateway, en línea, donde la dirección real del cliente ya está
  resuelta.

## Consecuencias

- **El código de kernel de WinDivert está en la ruta de los paquetes para el tráfico que coincide con
  sus filtros.** Es un controlador de terceros, firmado; WPShield no distribuye código de kernel. La
  evaluación de filtros por paquete está acotada a 256 objetos por handle. Los handles DROP solo
  existen mientras hay bloqueos; el filtro del observador son cuatro comprobaciones.
- **Los bloqueos de red afectan a todo el host.** El aislamiento por sitio del gateway no se extiende
  a ellos, y por eso existe la sección 5. Un evento de bloqueo nombra `WP-NET-001`, la lista de
  bloqueo, y registra en `requested_by` el hallazgo que lo pidió, de modo que el log dice a la vez qué
  se hizo y por qué.
- **Aún no validado contra el controlador.** Todo lo anterior está construido contra la API
  documentada de la 2.2.2 y probado a través de un controlador simulado. La primera ejecución contra
  un controlador real le corresponde al operador, primero en una máquina de desarrollo, nunca primero
  en el host de producción.

## Alternativas consideradas

- **Reglas del Firewall de Windows a través de la API NetSecurity.** Persisten tras caídas y
  reinicios, que es el modo de fallo por encierro que describió el ADR 0002, y son justo lo que
  `AGENTS.md` mantiene manual.
- **El proyecto hermano que propuso el ADR 0002.** Sigue siendo una forma válida. Su razón de existir
  era que bloquear significaba cambios persistentes en el cortafuegos; los descartes ligados a la vida
  de un handle eliminan esa razón, y el operador quiere una sola herramienta.
- **Desviar y reinyectar (el diseño del 2026-10-20).** Descartado en la sección 1.

## Enmienda (2026-11-24): la Plataforma de filtrado de Windows en lugar de WinDivert

La decisión se mantiene: WPShield bloquea direcciones en todo el servidor, solo en modo Block, bajo las
secciones 2 a 6 y 9. Cambia el **mecanismo** de las secciones 1, 7 y 8 y la primera consecuencia.
Esas secciones siguen describiendo el bloqueo con WinDivert que este pull request implementa hoy; se
reescriben en el cambio que lo sustituya.

**El bloqueo pasa a la Plataforma de filtrado de Windows (WFP)** (`fwpuclnt.dll`: `FwpmEngineOpen0`,
`FwpmSubLayerAdd0`, `FwpmFilterAdd0`), en una sesión abierta con `FWPM_SESSION_FLAG_DYNAMIC`.

Por qué:

- **La sección 2 se conserva tal cual.** Microsoft documenta que todo objeto añadido en una sesión
  dinámica se borra cuando la sesión termina, incluso si la aplicación falla
  ([FWPM_SESSION0](https://learn.microsoft.com/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0),
  [buenas prácticas de WFP](https://learn.microsoft.com/windows/win32/fwp/best-practices)). Un bloqueo
  sigue siendo un objeto del kernel que pertenece al proceso, y al terminar el proceso se levantan
  todos.
- **Sin controlador de kernel de terceros.** El motor de filtrado base y el motor de filtros vienen con
  Windows. No hay `--install-driver`, ni DLL sin firmar, ni dudas sobre quién firmó el controlador, ni
  nada que reinstalar tras reiniciar ni que descargar.
- **El servidor que protege este proyecto ya ejecuta un controlador de red de terceros** (la protección
  del equipo) que lo ha hecho caer. Añadir otro, para una función que solo tiene que descartar tráfico
  de direcciones conocidas, es un riesgo sin beneficio equivalente.
- **Sin el límite de 200 objetos por filtro.** Los filtros de WFP llevan condiciones de dirección y
  prefijo directamente.
- RdpGuard, el producto con el que se compara el operador, documenta que bloquea mediante la
  Plataforma de filtrado y no con reglas del Firewall de Windows
  ([preguntas frecuentes de RdpGuard](https://rdpguard.com/faq.aspx)).

Qué cambia:

- **Sección 1.** Los filtros de bloqueo viven en `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` y `_V6`, en una
  subcapa de WPShield, y solo coinciden con direcciones de la lista de bloqueo que no estén en la lista
  de permitidos. El tráfico benigno sigue sin llegar a ningún proceso de usuario, y sigue sin haber
  reinyección: WFP no ofrece ninguna.
- **El observador de SYN se va con WinDivert.** `WP-NET-002` y `WP-NET-003` pierden su fuente. Las
  peticiones de bloqueo vienen de sensores de registros cuya dirección de origen confirmó un
  establecimiento TCP: 4625 del registro de seguridad para los tipos de inicio de sesión 3 y 10,
  RdpCoreTS 140, SQL Server 18456, FTP 530, y el inicio de sesión y XML-RPC de WordPress a través del
  gateway. La sección 5 se mantiene. Las reglas basadas en SYN pueden volver más adelante mediante ETW,
  siempre detrás de `--syn-rules-may-block`.
- **La sección 7** se cumple sola: no hay controlador que cargar. La regla de importación sigue:
  `fwpuclnt.dll` se resuelve solo desde `System32`.
- **Sección 8.** Antes del primer bloqueo, el modo Block abre una sesión dinámica, añade un filtro para
  una dirección RFC 5737, lo vuelve a leer enumerando, comprueba la exclusión de la lista de
  permitidos y lo borra. Si falla algún paso, Block no arranca. Añadir un filtro requiere permisos de
  administrador, así que `--check` sin elevación solo puede validar cómo se construyen los filtros.
- **No es una regla de firewall.** Los filtros dinámicos de WFP no aparecen en la consola del Firewall
  de Windows ni en `Get-NetFirewallRule`, así que el "las reglas de firewall siguen siendo manuales"
  del ADR 0005 no cambia. Aparecen en `netsh wfp show filters`. La documentación del operador debe
  decir dónde mirarlos, porque quien busque un bloqueo en la consola del firewall no lo encontrará.

Validación antes de publicar el modo Block, en una máquina virtual Windows Server desechable y nunca
primero en el servidor de producción:

1. Un filtro en la subcapa de WPShield rechaza una conexión TCP nueva desde una dirección de prueba a
   un puerto que abre una regla de *permitir* del Firewall de Windows. Anotar qué pasa con una regla
   marcada "invalidar reglas de bloqueo".
2. `taskkill /F` sobre el proceso borra todos los filtros de WPShield en menos de un segundo.
3. Una sesión RDP ya establecida desde una dirección permitida sobrevive al bloqueo de otra dirección.
4. 10 000 filtros: tiempo de alta, memoria del motor de filtrado base y latencia al abrir conexiones.
5. Un producto de protección de terceros con su propio filtrado de red activo a la vez: sin caídas, y
   sus propios bloqueos sin cambios.
6. **Qué identidad puede añadir filtros.** El servicio corre como `NT SERVICE\WPShield`, nunca como
   `LocalSystem`. Si esa cuenta no puede añadir filtros, decidir entre un proceso de bloqueo que
   arranca un administrador (como `network-filter` hoy) y conceder acceso al SID del servicio con
   `FwpmEngineSetSecurityInfo0`, que es un ajuste del servidor y por tanto manual.

## Cuándo revisar esta decisión

- Si el punto 1 de la validación muestra que una regla del Firewall de Windows puede invalidar el
  bloqueo de WPShield, documentarlo como limitación y hacer que el modo Block lo informe. No añadir
  reglas de firewall para compensarlo.
- Si la autoprueba o la primera ejecución real muestran que WinDivert no ordena los rangos de
  direcciones como se espera, se eliminan los rangos y solo se incluyen direcciones exactas.
- Si este ADR se rechaza, `network-filter` se reduce a Monitor (el observador) y la ruta DROP se
  borra, en lugar de quedarse detrás de una bandera.

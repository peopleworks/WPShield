# ADR 0006 — Bloqueo en la capa de red dentro de WPShield

- **Estado:** Propuesto
- **Deciden:** Mantenedores de WPShield
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

## Cuándo revisar esta decisión

- Si la autoprueba o la primera ejecución real muestran que WinDivert no ordena los rangos de
  direcciones como se espera, se eliminan los rangos y solo se incluyen direcciones exactas.
- Si este ADR se rechaza, `network-filter` se reduce a Monitor (el observador) y la ruta DROP se
  borra, en lugar de quedarse detrás de una bandera.

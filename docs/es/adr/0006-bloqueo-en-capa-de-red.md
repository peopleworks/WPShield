# ADR 0006 — Bloqueo en la capa de red dentro de WPShield

- **Estado:** Aceptado el 2026-11-24. El modo Block usa la Plataforma de filtrado de Windows (WFP).
  La implementación sigue en vista preliminar hasta superar la validación en una VM desechable.

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

El kernel autoriza el tráfico entrante mediante un filtro `FWP_ACTION_BLOCK` por dirección
o prefijo admitido, en `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` o `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6`.
Cada filtro pertenece a la subcapa de WPShield y usa `FWPM_CONDITION_IP_REMOTE_ADDRESS`.
El valor IPv4 contiene la dirección y la máscara en el orden de bytes del host. El valor IPv6
usa `FWP_V6_ADDR_AND_MASK`. WPShield entrega la política a WFP y el tráfico permanece en la pila
de red de Windows.

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

Monitor informa de los bloqueos propuestos sin abrir ninguna sesión WFP. Block se solicita con
`--mode Block`.

### 5. El grado de la evidencia decide quién puede añadir un bloqueo

Los bloqueos afectan a todo el servidor. El operador puede designar direcciones o rangos para
bloquear durante la sesión. Un bloqueo automático requiere un registro de una fuente de confianza
y una dirección remota confirmada por un handshake TCP completo. Los bloqueos dinámicos tienen TTL.

El adaptador del registro de Seguridad acepta inicios de sesión fallidos (4625, tipos 3 y 10) con
un hallazgo Block de `WP-SEC-001` o `WP-SEC-002`. El comando independiente aplica las entradas del
operador. RdpCoreTS 140, SQL Server 18456, FTP 530 y los inicios de sesión de WordPress y XML-RPC
observados por la puerta de enlace son fuentes admisibles cuando se confirma la dirección TCP.
Conectar el motor de decisión del ADR 0009 requiere un ADR propio. Se retiraron el observador SYN
y sus dos reglas.

### 6. Los bloqueos expiran y el conjunto está acotado

Los bloqueos dinámicos expiran tras un TTL (60 minutos por omisión; un hallazgo repetido lo prolonga).
Los bloqueos nombrados por el operador duran toda la vida del proceso. El conjunto admite como máximo
1.000 entradas por omisión; cuando está lleno, los bloqueos dinámicos nuevos se rechazan y se
registran, y nunca se desaloja una entrada del operador para hacer sitio.

### 7. Se utiliza la pila de red de Windows

`FwpmEngineOpen0` abre una sesión con `FWPM_SESSION_FLAG_DYNAMIC`. `FwpmSubLayerAdd0` añade la subcapa
de WPShield (`93a54814-5f1d-44f3-b2ba-f4df18dfe12f`) y `FwpmFilterAdd0` añade los filtros. Ambos
objetos son dinámicos. Se omiten los indicadores de persistencia y de arranque. Todas las
importaciones de `fwpuclnt.dll` usan `DefaultDllImportSearchPaths(System32)`. Base Filtering
Engine viene con Windows y no hace falta instalar un controlador adicional.
[Duración de una sesión dinámica](https://learn.microsoft.com/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0)

### 8. Autoprueba antes de Block

Antes de aplicar bloqueos del operador o de registros, el proceso abre una sesión dinámica y añade
un filtro para una dirección RFC 5737 ajena a la lista de permitidos. Comprueba que el conjunto y
el constructor de filtros excluyen una entrada permitida. Recupera el filtro mediante enumeración,
verifica capa, subcapa, acción y dirección, y lo elimina. Si falla un paso, Block se niega a arrancar
y cierra la sesión. `wpshield network-filter --check` ejecuta la prueba nativa y comunica el resultado
para la identidad actual de Windows.

### 9. Todo está acotado

El conjunto admite 1.000 bloqueos por defecto y hasta 10.000. Se admiten hasta 1.000 entradas
permitidas. WFP usa un filtro por prefijo seleccionado. La enumeración lee hasta 16.384 filtros en
lotes de 64 y falla si no encuentra el filtro de prueba dentro de ese límite. Los cambios se aplican
en transacciones. Si falla una actualización, se cierra la sesión para evitar que un fallo de
borrado deje bloqueos caducados activos.

## Consecuencias

- La consola del Firewall de Windows y `Get-NetFirewallRule` no muestran los filtros dinámicos.
  Consúltalos con `netsh wfp show filters`.
- WPShield no escribe reglas del Firewall de Windows ni modifica IIS, DNS, certificados ni servicios.
  Se mantiene la decisión HTTP del ADR 0002. Los ataques contra credenciales de WordPress quedan en M3.
- `WP-NET-001` identifica los eventos de bloqueo y `requested_by` identifica el origen.
- Se descartaron las reglas persistentes del Firewall de Windows y el desvío y reinyección de
  paquetes a favor de filtros dinámicos en el kernel.

## Enmienda del 2026-11-24 y aceptación en VM

La enmienda adoptó WFP en lugar de WinDivert. El Base Filtering Engine de Windows conserva la
garantía ligada a la vida del proceso y se prescinde del controlador adicional y del observador.
El [guion de validación en VM](../validacion-filtro-red-vm.md) detalla los seis puntos de aceptación.
El PR sigue en borrador hasta superarlos en una VM desechable de Windows Server.

1. Prueba el arbitraje con una regla de permiso normal y anota el resultado de **Invalidar reglas de bloqueo**.
2. Termina el proceso y comprueba que los filtros de WPShield desaparecen en menos de un segundo.
3. Verifica que una sesión RDP establecida y permitida sobrevive a un bloqueo de otra IP.
4. Mide el tiempo de alta, la memoria de BFE y la latencia de conexión con 10.000 filtros.
5. Verifica la estabilidad de la protección de terceros y que sus propios bloqueos siguen activos.
6. Comprueba un administrador elevado y `NT SERVICE\WPShield`. Si el servicio carece de acceso, se
   usa el proceso iniciado por el administrador. Cambiar los descriptores de acceso de WFP es un
   ajuste manual del servidor y requiere una decisión aparte.

## Cuándo revisar esta decisión

Si una política de Firewall puede prevalecer sobre WPShield, documenta la limitación y haz que
Block la indique. Si las pruebas de rangos difieren de los límites prometidos, admite solo
direcciones exactas.

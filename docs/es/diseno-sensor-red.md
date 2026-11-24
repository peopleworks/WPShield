# WPShield.NetworkSensor — Diseño (Español)

WPShield.NetworkSensor es un **componente separado, opcional y exclusivo de Windows** que captura
metadatos de red en los puertos que el operador nombre (por ejemplo `80` y `443`) para que el
operador pueda ver qué tráfico llega al host. **No es** el gateway HTTP, **no está** en el camino
de las solicitudes y **nunca** modifica IIS.

## Monitor de escritorio

Desde la raíz del repositorio, en Windows con el SDK de .NET 10 y el entorno de ejecución de escritorio, ejecute:

```powershell
dotnet run --project src/WPShield.Desktop -c Release -- --es
```

Seleccione TCP o UDP en la barra lateral o busque por dirección, puerto exacto, PID, nombre del
proceso o nombre convencional del puerto. Las tarjetas muestran la hora de lectura, la cobertura y
los recuentos de IPv4 e IPv6. La columna de propietario muestra el proceso y su PID, por ejemplo
`sqlservr · 4120`. En cada actualización se consultan hasta 4096 PID distintos entre TCP y UDP.
El nombre aparece en la columna y en la búsqueda solo si el proceso se inició antes de la
lectura del propietario de esa fila. Si Windows reutilizó el PID y el proceso es posterior, o
si las horas coinciden, la fila conserva el PID observado e indica el motivo. La vista distingue
un proceso que no pudo leer de un PID que quedó fuera del límite de consultas. Al pasar el puntero
sobre la columna se muestra la hora de la lectura. Pulse **Actualizar** o active **Cada 5 s**. Al
cerrar la ventana termina la consulta periódica. La vista lee las tablas locales en memoria y
funciona sin Npcap, sin permisos de administrador y sin servidor HTTP.
Use `--en` para abrir la ventana en inglés.

Los nombres que vienen de Windows (adaptadores, dispositivos de captura, procesos) se muestran con
los caracteres de control y de formato bidireccional sustituidos por `�`, y se conservan las letras
acentuadas. Si una lectura falla de forma inesperada, la ventana muestra un aviso y sigue abierta.

**En un servidor sin el SDK de .NET,** genere una copia autocontenida en una máquina de desarrollo y
lleve la carpeta; no se instala nada en el servidor:

```powershell
dotnet publish src/WPShield.Desktop -c Release -r win-x64 --self-contained true -o artifacts\wpshield-desktop
```

Ejecute `WPShield.Desktop.exe` desde esa carpeta en la sesión de escritorio del servidor (Windows
Server con Experiencia de escritorio). Solo **Tráfico por puertos** necesita Npcap y permisos de
administrador.

### Ataques

Abra **Ataques** para ver quién intenta entrar en este servidor y falla. La vista lee las últimas 24
horas de inicios de sesión fallidos y luego sigue los nuevos en vivo:

- **4625 del registro de seguridad**, para cualquier tipo de inicio. Escritorio remoto con NLA y SMB
  fallan como tipo 3, Escritorio remoto sin NLA como tipo 10 y la autenticación básica de IIS como
  tipo 8.
- **RdpCoreTS 140** (`Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational`). Con NLA,
  Windows suele escribir el 4625 sin la dirección del cliente; el registro propio de Escritorio remoto
  sí la trae. Un 4625 y un 140 del mismo intento, con menos de dos segundos de diferencia, se cuentan
  una vez: se conserva el que tiene dirección y, si ambos la tienen, el 4625, porque indica la cuenta.

Las tarjetas muestran los intentos fallidos, las direcciones de origen distintas, la proporción de
intentos a nombres de cuenta que no existen (adivinan nombres; no es un usuario conocido
equivocándose) y la última hora. La línea de tiempo separa en cada intervalo las cuentas inexistentes
del resto, para 1 hora, 6 horas o 24 horas. Elija un origen para abrir su panel: las cuentas que
probó, sus intentos en el tiempo, otras direcciones que atacan desde la misma red /24 (IPv4) o /64
(IPv6) y sus últimos intentos. **Esc** o **✕** lo cierran. La búsqueda acepta una dirección, una red
como `203.0.113.0/24` o una cuenta.

Lo que la vista no hace:

- **Mostrar un tablero vacío como si nadie atacara.** Leer el registro de seguridad requiere permisos
  de administrador. Sin ellos las tarjetas muestran `—`, un aviso dice que la ventana no pudo mirar y
  **Abrir como administrador** la vuelve a abrir con permisos en esta vista. El resto del monitor
  sigue funcionando sin elevación.
- **Mostrar como cero el tiempo no leído.** En un servidor con mucho tráfico el registro de seguridad
  puede cubrir solo horas. Los intervalos anteriores al registro más antiguo que queda, o a donde se
  detuvo la lectura por sus límites (20 000 registros o 10 segundos por registro), se dibujan como
  **sin datos**, y el aviso indica desde cuándo hay datos. Ampliar el registro de seguridad es un
  ajuste manual del servidor.
- **Fiarse de los nombres de cuenta.** Los eligió el atacante. Se limpian de caracteres de control y
  de formato y se limitan a 64 caracteres antes de guardarlos o mostrarlos.
- **Decidir ni bloquear nada.** Lee y muestra. Los registros en vivo se aplican una vez por segundo y
  la memoria guarda como máximo 100 000 registros: descarta los más antiguos y mueve con ellos la
  línea de **sin datos**.

### Tráfico por adaptador

Abra **Tráfico por adaptador** y seleccione una interfaz de Windows. Cada par de barras muestra
los bytes recibidos y enviados por segundo en todo el adaptador. Ambas direcciones comparten la
misma escala. Pase el puntero sobre un intervalo para ver su hora UTC y sus tasas. Para investigar
flujos individuales o puertos específicos, use la [vista de flujos](#vista-de-flujos-del-servidor).

La primera lectura establece el punto de partida. Cada dos segundos se consulta cuánto han aumentado
los contadores y se divide esa diferencia por el tiempo transcurrido. Una lectura fallida, un contador
que retrocede, una discontinuidad del reloj o una demora superior a cinco segundos se marcan en ámbar.
Dos lecturas iguales miden cero. **Pausar gráfica** congela la imagen mientras continúa la medición.
Al reanudar se muestran las últimas 30 observaciones. Cambiar de adaptador inicia un historial nuevo.
Cerrar la ventana de tráfico detiene la medición.

## Inventario de puertos locales

Este comando permite ver qué direcciones y puertos tienen un socket TCP en escucha o un socket UDP
asociado antes de elegir los puertos de una captura. Consulta una vez las tablas locales de Windows
y funciona sin Npcap.

```powershell
wpshield network-monitor --listeners
wpshield network-monitor --listeners --ports 443,1433,3389 --json
wpshield network-monitor --listeners --protocol tcp --local-address 127.0.0.1 --ports 443 --owners
```

Si se omite `--ports`, la consulta abarca todos los puertos locales. El filtro admite entre 1 y 64
números. Cada protocolo tiene su propia hora UTC, estado de lectura y lista de direcciones y puertos
sin duplicados. El campo `Binding` indica `loopback`, `wildcard` (todas las direcciones locales de
esa familia) o `specific` (una dirección concreta). IPv6 conserva el identificador de ámbito si lo hay.
La salida contiene direcciones locales y está destinada al operador.

Use `--protocol tcp` o `--protocol udp` para leer una sola tabla. Con `--local-address` puede buscar
la dirección IPv4 o IPv6 exacta a la que se vinculó el socket, incluido el ámbito IPv6 numérico,
por ejemplo `fe80::1%2`. Para ver los comodines, consulte `0.0.0.0` o `::` de forma explícita.
Una búsqueda de `127.0.0.1` muestra solo los sockets vinculados a esa dirección. Los filtros se
combinan antes del límite de filas y de la consulta de PID. Cada tabla ordena las filas por puerto,
familia, dirección numérica e identificador de ámbito. El JSON conserva los filtros solicitados en
`Protocol` y `LocalAddress` incluso cuando la búsqueda queda vacía.

Una tabla `read` puede estar vacía. Una tabla `limited` conserva hasta 4.096 extremos coincidentes
y lleva el motivo `row-limit`. Una tabla `unavailable` lleva el motivo `access-denied` o `query-failed`.
El código de salida es 0 si se leyeron todas las tablas seleccionadas, 2 si el resultado es parcial
y 1 si falló la lectura de todas las tablas seleccionadas o los argumentos son inválidos.

Para comprobar un cambio, repita la consulta con el mismo filtro y compare protocolo, dirección y
puerto en las tablas con estado `read` en ambas lecturas. TCP y UDP se consultan sucesivamente. Un
socket puede aparecer o desaparecer entre lecturas. La accesibilidad desde Internet, el servicio
propietario, el sitio y el resultado de autenticación requieren evidencia independiente.

### Nombres de puertos sin conexión

```powershell
wpshield network-monitor --listeners --ports 443,1433,3389 --port-hints --json
```

Añada `--port-hints` para consultar los nombres convencionales del protocolo y el puerto local
en un catálogo incluido en la CLI. Por ejemplo, TCP 1433 devuelve `ms-sql-s` y TCP 3389 devuelve
`ms-wbt-server`. En JSON, `PortHintCatalog` identifica la versión del catálogo de WPShield.
La lista `PortHints` de cada extremo contiene las coincidencias y sus alias. Una lista vacía
(`unknown` en consola) indica que esa combinación no figura en el catálogo incluido.

La versión `wpshield-iana-v1` cubre 20 números de puerto seleccionados para web, bases de datos,
acceso remoto, correo, FTP, SIP y VPN. La consulta se resuelve localmente, sin DNS ni peticiones
al registro externo. Un proceso puede usar cualquier puerto disponible. Para investigar qué proceso
lo usa, combine la opción con `--owners` y contraste el PID observado y su hora. [Registro de servicios y puertos de IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)

### PID del proceso observado

```powershell
wpshield network-monitor --listeners --ports 443,1433,3389 --owners --json
```

Por cada protocolo y familia IP con extremos en el inventario, la CLI consulta una segunda
tabla local de Windows. Busca la dirección local completa (incluido el ámbito IPv6) y el
puerto. Cada extremo incorpora un objeto `Owner` con `ObservedAtUtc`, `ProcessId` y `Reason`.
Un PID único y distinto de cero identifica el proceso que Windows observó en esa segunda
lectura. El socket puede cambiar de propietario entre consultas y Windows puede reutilizar
el PID cuando un proceso termina. Para atribuir una observación histórica a un proceso actual,
un servicio, un sitio IIS o un inicio de sesión hace falta evidencia adicional.
[Tabla TCP de Windows](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable) · [Tabla UDP de Windows](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable)

`ProcessId` es nulo si el extremo desapareció (`not-observed`), las filas discrepan
(`ambiguous`) o Windows devolvió el PID cero (`pid-unavailable`). Si falla la tabla de
propietarios, los extremos afectados indican `access-denied`, `query-failed`, `invalid-table`
o `table-limit`. Cada tabla usa un búfer de hasta 1 MiB y un máximo de tres intentos. Si falla
su consulta, el resultado es parcial (código 2) y conserva los puertos observados. Una lectura
correcta puede contener extremos cuyo propietario sigue siendo desconocido. Al omitir
`--owners` se omiten las lecturas adicionales y el campo `Owner`.

## Vista de flujos del servidor

Para identificar la interfaz de captura, consulte primero el inventario local.

```powershell
wpshield network-monitor --list-interfaces
wpshield network-monitor --list-interfaces --json
```

Copie el identificador de Npcap de la primera columna en `--interfaces` al iniciar la captura
de flujos. El identificador sigue sirviendo si cambia el nombre del adaptador en Windows.
También se admite un nombre o una descripción que identifique un único adaptador. El inventario
indica si Npcap encuentra direcciones IPv4 o IPv6 locales. Un adaptador sin ellas no permite
determinar el sentido del tráfico. La consulta lee los metadatos sin abrir el adaptador.
Los permisos de captura y la compatibilidad del enlace se comprueban al iniciar la captura.
Una consulta correcta sin dispositivos devuelve `[]` en JSON. Un error de consulta devuelve
el código 1 y escribe en la salida de error. Si el identificador elegido desaparece,
vuelva a consultar la lista y seleccione expresamente la interfaz que quiera observar.

Ejecute la CLI localmente como administrador y con Npcap instalado. Indique el nombre de un
adaptador de Windows y los puertos reales de sus servicios. Los ejemplos usan puertos habituales.

```powershell
wpshield network-monitor --flows --interfaces "Ethernet" --ports 443,1433,3389
wpshield network-monitor --flows --interfaces "Ethernet" --all-ports --json
```

Cada dos segundos la consola muestra hasta 40 flujos recientes, con los extremos local y remoto,
protocolo, última actividad en UTC y bytes IP recibidos y enviados (incluidas las cabeceras IP y
de transporte y las retransmisiones). Ambos sentidos comparten una fila. El SYN inicial observado
identifica al iniciador TCP como `local` o `remote`. En UDP y en conexiones TCP observadas desde
mitad de sesión aparece `unknown`. El filtro de puertos se aplica a ambos extremos. Identificar
el servicio, el sitio o el resultado de un inicio de sesión requiere evidencia adicional. Ctrl+C
detiene la captura e imprime el último resumen.

El JSON incluye todos los flujos retenidos. La tabla conserva hasta 4.096 flujos y caduca tras 60 segundos de inactividad por flujo. La salida
indica cuántos están activos, cuántos paquetes se omitieron al interpretar la trama o el sentido,
cuántos se descartaron por capacidad y qué contador de descartes comunicó el controlador (null en
JSON si está indisponible). Un cero no demuestra cobertura completa. [Contadores de Npcap](https://npcap.com/guide/wpcap/pcap_stats.html)

La captura solicita un máximo de 160 bytes por trama y conserva únicamente metadatos del flujo.
Esta versión cubre TCP/UDP sobre IPv4 e IPv6 básico. Quedan fuera las tramas VLAN, los fragmentos
IP y las cabeceras de extensión IPv6. Si ambos extremos son locales o ninguno lo es, no se puede
asignar un extremo remoto. Los filtros pueden excluir tramas antes de que lleguen a los contadores.
El sentido se determina con las direcciones del adaptador al arrancar. La salida local contiene IP.

### Estado de las fuentes

Cada lectura de tráfico identifica el adaptador (`Interface`), la hora UTC de la lectura
(`Timestamp`) y los puertos TCP/UDP elegidos (`CapturePorts`, una lista vacía para todos los
puertos). Durante la captura, `CaptureStatus` vale `running`. La última lectura indica
`stopped` si el operador la detiene o `interrupted` si el controlador la interrumpe, incluso
con cero flujos y sin activar el historial. Si la captura falla antes de arrancar, el comando
devuelve un error. En modo JSON los diagnósticos se escriben en la salida de error.

Para RDP y SQL, `WindowStart` y `WindowEnd` delimitan en UTC el período consultado. RDP indica
el canal Security y el puerto TCP local elegido. SQL indica el canal Application y el proveedor
de la instancia. Cada consulta tiene su propio `AuditStatus`. Una consulta completada sin
eventos devuelve `read` y deja el resultado del acceso como desconocido. Para `unavailable`,
`UnavailableReason` puede ser `access-denied` o `query-failed`. Para una consulta legible o
limitada el motivo es nulo. Los archivos JSON anteriores pueden omitir estos campos. Las
horas describen la ventana consultada. La cobertura depende de la auditoría habilitada en el servidor.

### Referencia de auditoría seleccionada

En el monitor de escritorio, abra **Referencias de auditoría → Abrir informe** y elija un archivo
con un solo objeto JSON de WPShield. Seleccione una fila con las flechas. La vista previa muestra
el JSON exacto que **Copiar** o **Ctrl+C** coloca en el portapapeles. En RDP y SQL se copian el
canal, el proveedor, la hora UTC y el ID del evento. En IIS se copian el SHA-256 y la longitud del
prefijo del archivo W3C, la línea física y, si corresponde, la línea del desafío de autenticación.

La cobertura procede del informe guardado. En informes anteriores puede figurar como desconocida.
Una lista vacía describe el contenido de ese informe. El escritorio admite hasta 8 MiB y 1.024
referencias por informe, con un plazo de lectura de cinco segundos. Un ID duplicado en una misma
fuente, una referencia inválida o un límite excedido vacían la lista y deshabilitan la copia.

Guarde una sola lectura en JSON. Seleccione el **número de registro** del evento de Windows que
quiera verificar. La fuente identifica el canal aunque haya registros con el mismo número en
RDP y SQL.

```powershell
wpshield network-monitor --sql-instance MSSQLSERVER --json | Set-Content -Encoding UTF8 .\sql.json
wpshield audit-reference --snapshot .\sql.json --source sql --record-id 431
wpshield audit-reference --snapshot .\lectura-flujos.json --source rdp --record-id 125
```

Sustituya los números del ejemplo por los del informe. Si el monitor produjo un archivo JSON
Lines, guarde en UTF-8 la línea JSON original de la lectura que le interesa. El selector admite
un objeto de hasta 8 MiB y lee sus campos sin consultar el servidor. Devuelve únicamente canal,
proveedor, hora UTC y número de registro. La atribución de SQL a un flujo sigue siendo
desconocida. Verifique la referencia en el registro de eventos original del mismo servidor.

El código 0 imprime una referencia JSON. El código 3 significa que esa fuente no contiene el
número solicitado en la lectura, que puede tener cobertura parcial. Un informe inválido, una
sección ausente, coincidencias duplicadas o un error de lectura devuelven 1. Los diagnósticos se
escriben en la salida de error y la salida estándar queda vacía si falla la selección.
[Referencias de archivo y línea en IIS](evidencia-accesos-iis.md#referencia-de-una-línea)

### Historial de tráfico

```powershell
wpshield network-monitor --flows --interfaces "Ethernet" --ports 443,1433,3389 --history --json
```

El historial opcional muestra los bytes IP observados por segundo en cada sentido para el adaptador
y los puertos elegidos. Cuenta después de decodificar el paquete y determinar su sentido, antes de
admitir, caducar o reutilizar un flujo. Si la tabla se llena, los bytes de un flujo nuevo siguen
contando aunque su fila quede fuera. Cada lectura cierra un intervalo. Un reloj monótono mide su
duración y las marcas UTC indican sus límites. El primer intervalo y el último pueden ser breves.
La consola muestra cinco intervalos y el JSON conserva hasta 30 en `History`, o en
`Traffic.History` cuando se solicita auditoría. Las lecturas sucesivas repiten intervalos. Para
compararlos, cuenta cada intervalo una sola vez.

| Cobertura | Interpretación |
| --- | --- |
| `observed` | El contador del controlador estaba disponible en ambos extremos y no se detectaron huecos. Las tasas describen el tráfico seleccionado que el lector pudo decodificar. |
| `unknown` | Faltó el contador del controlador en algún extremo. Las tasas miden los bytes observados. Un cero no demuestra que la red estaba inactiva. |
| `gap` | Hubo paquetes omitidos, aumento o reinicio del contador de descartes, interrupción de captura, más de cinco segundos entre muestras o discrepancia entre los relojes. Las tasas son nulas. Se conservan los bytes y las razones en `GapReasons`. |

Abra **Tráfico por puertos** y escriba entre 1 y 64 números separados por comas en **Puertos TCP/UDP**,
por ejemplo `443,1433,3389`. También puede elegir una entrada en **Lista de puertos** y pulsar
**Añadir puerto**. Repita para combinar puertos o borre un número del campo para quitarlo. La lista
incluye los puertos convencionales de HTTP, HTTPS, SQL Server y RDP y los de la última lectura del
inventario local. Estos últimos llevan la etiqueta **Observado en este equipo**.
Puede preparar la selección en una sesión normal. Para capturar, abra WPShield como administrador
en un equipo Windows con Npcap, indique los puertos en esa sesión, elija un adaptador y pulse
**Iniciar captura**. Un paquete TCP o UDP coincide si alguno
de sus extremos usa un puerto seleccionado. Cada fila representa los bytes IP recibidos y enviados
por segundo en una escala común, con el intervalo más reciente primero. Pase el puntero sobre una
fila para ver las fechas UTC, los bytes observados y los códigos de los huecos de captura. Cuando
hay un hueco, ambas tasas muestran un guion. Si la cobertura es desconocida, se muestran las tasas medidas.

**Pausar gráfica** congela los intervalos visibles mientras continúa la captura. Desmárquelo para
ver los últimos 30 intervalos. **Detener** muestra la lectura final y libera el adaptador. Cerrar
esta ventana también detiene su captura. Los datos permanecen en memoria. Queda pendiente validar
la captura en vivo en Windows Server con Npcap. Para ver los contadores de toda la interfaz sin
Npcap, abra [Tráfico por adaptador](#tráfico-por-adaptador).

### Evidencia de inicios de sesión por Escritorio Remoto

Indique el puerto TCP local configurado para Escritorio Remoto en el servidor observado. La cuenta
que ejecuta el comando necesita acceso de lectura al registro Seguridad de Windows. La directiva
de auditoría de inicio de sesión del servidor determina si Windows registra los éxitos y los fallos.

```powershell
wpshield network-monitor --flows --interfaces "Ethernet" --ports 443,1433,3389 --rdp-port 3389
```

En cada lectura, WPShield consulta hasta 256 eventos de tipo 10 (RemoteInteractive) del último
minuto, empezando por el más reciente. Deben coincidir la IP y el puerto de origen del cliente.
El evento debe ocurrir entre el primer y el último paquete observado, con un único flujo candidato
en el adaptador y puerto TCP local seleccionados y un SYN entrante observado. Windows registra
los éxitos en el evento 4624 y los fallos en el 4625. Cada coincidencia incluye la hora UTC y el
número de registro para buscarla en el Visor de eventos. [Evento 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) · [Evento 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)

- `success`, `failure` y `mixed` indican qué resultados constan en los eventos coincidentes de esa
  lectura. Aparece `unknown` si falta el puerto de origen, la captura comienza a mitad de conexión,
  hay varios candidatos o falta evidencia. Los fallos registrados con otros tipos de inicio de
  sesión quedan fuera de esta vista.
- `AuditStatus` indica `read` al terminar la consulta, `limited` al alcanzar el límite de eventos o
  de tiempo de lectura y `unavailable` si falla la consulta o faltan permisos. El tráfico sigue visible.
- Con `--json`, cada línea contiene `Traffic` y `RdpAudit`. El mismo evento puede aparecer en varias
  lecturas. Su número de registro permite contarlo una sola vez dentro del mismo registro Seguridad.
  La salida incluye las direcciones de los extremos y omite los nombres de cuenta y los mensajes
  del evento. El registro de Windows omite el extremo de destino, de modo que la coincidencia es
  única solo entre los flujos capturados. La actividad dentro de la sesión y la atribución a un
  sitio IIS requieren otras fuentes.

Para validarlo en un Windows Server de pruebas con Npcap, inicie el monitor antes de un acceso
autorizado por Escritorio Remoto. Abra **Visor de eventos → Registros de Windows → Seguridad**
y compare el número de registro, la hora UTC, la IP y el puerto de origen con el flujo mostrado.
Anote si la lectura del registro terminó y si hubo descartes en la captura. Si Windows omite
el puerto de origen, el resultado esperado es `unknown`. Esa prueba verifica el caso de evidencia
incompleta y deja pendiente la comprobación de una coincidencia positiva.

### Evidencia de inicios de sesión de SQL Server

La consulta lee el último minuto de **Registros de Windows → Aplicación** para una instancia local
del motor de SQL Server. La consulta independiente solo requiere permiso de lectura del registro
Aplicación. Funciona sin Npcap ni credenciales de SQL. Use `MSSQLSERVER` para la instancia
predeterminada. Para otra instancia, copie el sufijo del origen `MSSQL$<nombre>` que muestra el
Visor de eventos y respete las mayúsculas y minúsculas.

```powershell
wpshield network-monitor --sql-instance MSSQLSERVER --json
wpshield network-monitor --flows --interfaces "Ethernet" --ports 1433,3389 --rdp-port 3389 --sql-instance Example
```

Los eventos 18453, 18454 y 18455 acreditan un inicio de sesión exitoso. El 18456 acredita un
fallo. Su disponibilidad depende de la auditoría y el registro configurados en el servidor. El
lector selecciona el proveedor de la instancia y solo lee metadatos. Cada fila muestra el ID
del evento, el número de registro de Aplicación, la hora UTC y el resultado. El resultado
corresponde a la instancia. `FlowAttribution` queda como `unknown` incluso si solo un flujo TCP
usó su puerto habitual. La salida omite usuarios, mensajes del evento y sentencias SQL.
[Eventos de SQL Server](https://learn.microsoft.com/en-us/sql/relational-databases/errors-events/database-engine-events-and-errors-18000-to-18999) · [Proveedores del registro Aplicación](https://learn.microsoft.com/en-us/sql/relational-databases/performance/view-the-windows-application-log-windows-10)

La ventana admite hasta 256 registros coincidentes, del más reciente al más antiguo, con un
presupuesto de lectura de 500 ms. `ObservedOutcome` resume los registros obtenidos como
`success`, `failure`, `mixed` o `unknown`. Si la consulta termina sin coincidencias, el
resultado es desconocido, también si el proveedor está ausente. La consulta independiente
devuelve 0 para `read`, 2 para `limited` y 1 para `unavailable` o argumentos inválidos.
Con `--flows --json`, los datos aparecen bajo `SqlAudit`, junto a `Traffic` y el `RdpAudit`
opcional. Un mismo registro puede aparecer en ventanas consecutivas. Para validar en un servidor
de pruebas con auditoría existente, compare canal, proveedor, número de registro y hora UTC con
un inicio de sesión conocido en el Visor de eventos. El comando conserva la configuración de auditoría.

## Por qué debe ser separado

| Preocupación | WPShield.Gateway (M1/M2) | WPShield.NetworkSensor (propuesto) |
|---|---|---|
| Posición | Proxy inverso inline, solo loopback | Captura pasiva, proceso separado |
| Privilegios | Usuario normal, listener en loopback | Administrador, controlador Npcap |
| ¿Modifica IIS? | No | No |
| ¿Ve cuerpos de solicitud? | Solo muestras acotadas de multipart | Nunca |
| ¿Ve cadenas de consulta? | Nunca las registra | Nunca las registra |
| Exposición predeterminada | Loopback `127.0.0.1:10000` | Ninguna hasta que el operador lo habilite |

Mezclar un controlador de captura de paquetes dentro del gateway HTTP rompería la invariante de
loopback-only, requeriría privilegios de kernel dentro del camino de solicitud y tentaría a
inspeccionar cuerpos completos — todo prohibido por AGENTS.md y THREAT_MODEL.md.

## Responsabilidades del modo de metadatos HTTP

1. **Capturar solo metadatos.** IP origen/destino, puerto origen/destino, método HTTP, ruta de
   solicitud (cadena de consulta eliminada), código de estado de respuesta, tamaño del cuerpo,
   marca de tiempo y nombre de interfaz de red.
2. **Filtrar solo por puertos nombrados por el operador.** Un filtro BPF restringe la captura a
   los puertos listados en la configuración (predeterminado: ninguno — el sensor no captura nada
   hasta que se configure).
3. **Nunca capturar cuerpos completos, credenciales, cookies, encabezados de autorización,
   nonces, tokens ni cadenas de consulta completas.** Esto es estructural, no un umbral que se
   pueda bajar después.
4. **Emitir eventos en el sobre de log del gateway** (`timestamp`, `level`, `category`,
   `message`, `state`) para que un reporte forense y un log del gateway se correlacionen con los
   mismos nombres de campo.
5. **Falla cerrado.** Si falta Npcap, no hay elevación o la configuración es inválida, el sensor
   se niega a iniciar y escribe un mensaje de bloqueo claro.

## Lo que NO hace

- No vincula puertos 80/443 ni cambia los enlaces de IIS.
- No modifica reglas de URL Rewrite, ARR, grupos de aplicaciones ni ninguna configuración de IIS.
- No instala Npcap silenciosamente; el operador lo instala explícitamente.
- No ejecuta en modo promiscuo a menos que el operador lo elija explícitamente.
- No inspecciona, bufferiza ni almacena cuerpos de solicitud/respuesta.
- No bloquea tráfico. Solo observa e informa.
- No reemplaza los logs de IIS, Microsoft Defender ni un WAF.

## Configuración (`appsettings.NetworkSensor.json` o variables `WPSHIELD_NETWORKSENSOR_*`)

```json
{
  "NetworkSensor": {
    "Enabled": false,
    "Interfaces": [ "Ethernet", "vEthernet (WSL)" ],
    "Ports": [ 80, 443 ],
    "PromiscuousMode": false,
    "MaxEventsPerSecond": 1000,
    "OutputPath": "C:\\WPShield\\Logs\\network.ndjson",
    "Rotation": {
      "MaxFileSizeBytes": 104857600,
      "RetentionDays": 30
    }
  }
}
```

- `Enabled` predeterminado `false`. El sensor no captura nada hasta que se habilite explícitamente.
- `Interfaces`, cuando está presente, limita la captura a esos nombres de adaptador. Cuando está
  vacío, se usan todos los adaptadores que coincidan con el filtro de puertos.
- `Ports` es obligatorio cuando está habilitado. Lista vacía = no captura nada.
- `PromiscuousMode` predeterminado `false`. `true` es una elección explícita del operador,
  registrada como evento de nivel blocker.
- `MaxEventsPerSecond` limita la tasa de emisión para que el sensor no se convierta en un
  amplificador de ruido.
- `OutputPath` es un archivo que el sensor escribe; es la única escritura que hace el componente.

## Modelo de evento (JSON Lines, sobre del gateway)

Cada línea emitida es un objeto JSON:

```json
{
  "timestamp": "2026-10-20T14:32:07.1234567Z",
  "level": "Information",
  "category": "WPShield.NetworkSensor",
  "message": "Solicitud HTTP observada",
  "state": "observed",
  "requestId": "ns-1a2b3c4d-...",
  "interface": "Ethernet",
  "srcIp": "192.0.2.10",
  "dstIp": "192.0.2.1",
  "srcPort": 51422,
  "dstPort": 443,
  "method": "POST",
  "path": "/wp-admin/admin-ajax.php",
  "statusCode": 200,
  "bodySizeBytes": 12450,
  "tls": true
}
```

Solo campos seguros para la privacidad. `path` es la ruta de solicitud **sin** la cadena de
consulta. Nunca aparecen `Authorization`, `Cookie`, `Set-Cookie`, contenido del cuerpo ni cadena
de consulta completa.

## Contratos (C#)

Estos contratos viven en `WPShield.NetworkSensor` y hacen referencia solo a
`WPShield.Abstractions` para tipos compartidos cuando proceda.

```csharp
namespace WPShield.NetworkSensor;

public sealed class NetworkSensorConfiguration
{
    public bool Enabled { get; init; }
    public IReadOnlyList<string> Interfaces { get; init; } = [];
    public IReadOnlyList<int> Ports { get; init; } = [];
    public bool PromiscuousMode { get; init; }
    public int MaxEventsPerSecond { get; init; } = 1000;
    public string OutputPath { get; init; } = string.Empty;
    public RotationConfiguration Rotation { get; init; } = new();
}

public sealed class RotationConfiguration
{
    public long MaxFileSizeBytes { get; init; } = 100_000_000;
    public int RetentionDays { get; init; } = 30;
}

public sealed record NetworkEvent
{
    public required DateTimeOffset Timestamp { get; init; }
    public required string Level { get; init; }
    public required string Category { get; init; }
    public required string Message { get; init; }
    public required string State { get; init; }
    public required string RequestId { get; init; }
    public required string InterfaceName { get; init; }
    public required string SourceIp { get; init; }
    public required string DestinationIp { get; init; }
    public required int SourcePort { get; init; }
    public required int DestinationPort { get; init; }
    public required string HttpMethod { get; init; }
    public required string Path { get; init; } // cadena de consulta eliminada
    public required int StatusCode { get; init; }
    public required long BodySizeBytes { get; init; }
    public required bool Tls { get; init; }
}

public interface INetworkSensor : IAsyncDisposable
{
    Task StartAsync(CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
    bool IsRunning { get; }
}

public interface INetworkEventSink
{
    Task WriteAsync(NetworkEvent @event, CancellationToken cancellationToken);
}
```

## Flujo de captura

```
El operador habilita NetworkSensor
        │
        ▼
Validar configuración (puertos no vacíos, Npcap presente, elevación)
        │
        ▼
Construir filtro BPF: "tcp port 80 or tcp port 443"
        │
        ▼
Abrir captura en vivo en interfaces seleccionadas (sin modo promiscuo por defecto)
        │
        ▼
Para cada paquete:
  ├─ Analizar Ethernet/IP/TCP
  ├─ Si el puerto destino no está en la lista configurada → omitir
  ├─ Intento de análisis HTTP ligero (método, ruta, estado, tamaño)
  ├─ Eliminar cadena de consulta de la ruta
  ├─ Emitir NetworkEvent al receptor (JSON Lines)
  └─ Aplicar cubeta de tokens MaxEventsPerSecond
        │
        ▼
Rotar archivo de salida al alcanzar el límite de tamaño; purgar archivos más antiguos que RetentionDays
```

## Requisitos de seguridad

- **Npcap es una dependencia externa.** El sensor la referencia pero nunca la descarga ni la instala.
- **Se requiere elevación.** El proceso debe ejecutarse como Administrador. Falta de elevación es un bloqueador de inicio, no un modo degradado.
- **Sin cambios de cuenta de servicio privilegiados.** El sensor no crea servicios de Windows, no cambia ACLs ni modifica IIS.
- **Los eventos son escrituras de solo añadido.** La rotación reemplaza archivos pero nunca edita contenido existente.
- **Sin captura predeterminada.** `Enabled: false` y `Ports` vacío significa que no se observa ningún paquete.

## Integración con los hitos (milestones)

| Hito | Relación |
|---|---|
| M4 Observabilidad | Los eventos de NetworkSensor alimentan la misma corriente de eventos estructurados; los patrones de rotación/retención se alinean. |
| M5 Dashboard | Vista de solo loopback en el dashboard de eventos de NetworkSensor; autenticación de Windows antes de cualquier uso remoto. |
| M7 Activación controlada | Si WPShield se coloca eventualmente frente a IIS vía ARR (M7), el gateway ya ve tráfico HTTP; NetworkSensor es visibilidad complementaria en capa de red, no redundante. |

## Fuera del alcance de este diseño

- Inyección o bloqueo de paquetes.
- Descifrado de cargas TLS (solo metadatos del handshake: `tls: true`).
- Firmas de prevención de intrusiones.
- Integración con interna de WordPress (base de datos, `wp_options`, etc.).

## Pasos siguientes

1. Agregar `src/WPShield.NetworkSensor/` con destino `net10.0-windows`.
2. Agregar SharpPcap + PacketDotNet a `Directory.Packages.props`.
3. Implementar enlace y validación de configuración.
4. Implementar construcción de filtro BPF y bucle de captura en vivo.
5. Implementar receptor de eventos JSON Lines con rotación.
6. Agregar pruebas unitarias para validación de configuración, eliminación de cadena de consulta y serialización de eventos.
7. Agregar prueba de integración con un servidor HTTP sintético local y captura en loopback (requiere Npcap en la pierna de CI).
8. Escribir `docs/en/network-sensor-design.md` como espejo de este documento.

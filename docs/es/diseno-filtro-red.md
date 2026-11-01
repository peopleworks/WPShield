# WPShield.NetworkFilter — Diseño (Español)

`wpshield network-filter` vigila las conexiones TCP entrantes nuevas y, en modo **Block**, descarta
los paquetes de las direcciones de su lista de bloqueo. **El tráfico normal nunca pasa por
WPShield**: el observador recibe copias, y los bloqueos son filtros de WinDivert que el controlador
aplica en el kernel. Detener el comando levanta todos los bloqueos a la vez. La decisión que lo
respalda es el [ADR 0006](adr/0006-bloqueo-en-capa-de-red.md); esta página explica cómo funciona y
cómo ejecutarlo.

> **Estado: construido contra la API documentada de WinDivert 2.2.2 y probado a través de un
> controlador simulado. Todavía no se ha ejecutado contra un controlador real.** Ejecútelo primero en
> una máquina de desarrollo, siguiendo el plan de pruebas del final de esta página, nunca primero en
> un host de producción.

## Por qué existe

Cuatro semanas de Malwarebytes Web Access Control en un host de producción registraron 6.150
conexiones entrantes bloqueadas desde 344 direcciones, el 17 % de ellas hacia servicios que el
gateway nunca ve: PostgreSQL, MySQL, SQL Server, SMB, WinRM, FTP, VNC y correo. El mismo host se cayó
repetidamente con `DPC_WATCHDOG_VIOLATION` en `mwac.sys`, un componente de kernel que inspecciona
cada conexión entrante. El filtro de red es la alternativa abierta y legible, construida para que no
pueda tumbar el host.

## Cómo está construido

```text
paquete entrante
  │
  ├─ handles DROP (prioridad 1000) ── filtro: inbound and !loopback and (ip.SrcAddr == … or …)
  │     si coincide → se descarta en el kernel. No se recibe nada, no se reinyecta nada.
  │
  ├─ handle del observador (prioridad 0, SNIFF | RECV_ONLY) ── filtro: inbound and !loopback and tcp.Syn and !tcp.Ack
  │     recibe una COPIA de cada intento de conexión nuevo → WP-NET-002, WP-NET-003 → hallazgos
  │
  └─ el paquete original sigue hacia IIS, SQL Server, … sin tocar
```

| Parte | Responsabilidad |
| --- | --- |
| `NetworkFilterService` | Orden de arranque y rechazos, el hilo del observador, las solicitudes de bloqueo, el mantenimiento cada cinco segundos. |
| `BlockSet` | El único lugar donde se crea un bloqueo. Aplica la lista de permitidos, el TTL y el tope. |
| `DivertFilterBuilder` | Escribe los filtros solo a partir de direcciones ya analizadas; reparte los conjuntos grandes entre varios handles. |
| `NetworkEnforcer` | Es dueño de los handles DROP; las actualizaciones son make-before-break (abre los nuevos antes de cerrar los viejos). Solo existe en modo Block. |
| `NetworkFilterSelfTest` | Compila y evalúa cada filtro con la biblioteca real antes de que arranque el modo Block. |
| `LockoutGuard` | Rechaza el modo Block cuando la sesión RDP del operador correría peligro. |
| `WinDivertDriver` | P/Invoke a `WinDivert.dll`, transcrito de `windivert.h`. Sin `WinDivertSend`. |

## Propiedades de seguridad

Cada una se impone en código y está cubierta por una prueba.

- **Monitor es el modo predeterminado y nunca abre un handle DROP.** Registra `would-block` por cada
  bloqueo que habría hecho.
- **No existe reinyección.** `WinDivertSend` no está declarado, y una prueba comprueba que nunca lo
  estará.
- **Los bloqueos viven exactamente lo que vive el proceso.** Ninguna regla del Firewall de Windows,
  ningún valor en el registro de Windows, ningún archivo. Una parada, una caída o un reinicio cierran
  los handles y levantan todos los bloqueos.
- **La lista de permitidos se aplica dos veces**: al añadir un bloqueo y otra vez al escribir los
  filtros. Se rechaza un rango de bloqueo que contenga una dirección permitida.
- **El modo Block se niega a arrancar** con la lista de permitidos vacía, cuando una dirección
  conectada al puerto RDP (leído de `RDP-Tcp\PortNumber`) no está en la lista de permitidos, o cuando
  falla la autoprueba. Mientras se ejecuta, se rechaza un bloqueo dinámico nuevo para cualquier
  dirección que en ese momento tenga una conexión RDP, y se rechaza también cuando las conexiones no
  pueden leerse.
- **La evidencia de SYN no bloquea por omisión.** `WP-NET-002` y `WP-NET-003` ven intentos de
  conexión, cuyo origen cualquiera puede falsificar; solo bloquean con `--syn-rules-may-block`.
- **El controlador nunca se carga como efecto secundario.** Los handles se abren con
  `WINDIVERT_FLAG_NO_INSTALL`; `--install-driver` es la excepción explícita, y lo que deja detrás no
  sobrevive a un reinicio (véase *Requisitos previos*).
- **`WinDivert.dll` se carga solo desde el directorio de WPShield**, nunca desde `PATH` ni desde el
  directorio de trabajo.
- **Todo está acotado**: 200 objetos de filtro por handle (el límite de WinDivert es 256), 1.000
  bloqueos por omisión y 10.000 como máximo, 50.000 orígenes rastreados con desalojo del menos
  recientemente visto, y una línea de log por origen y umbral en vez de una por paquete.

## Reglas

| ID | Señal | Puntuación | Efecto predeterminado |
| --- | --- | --- | --- |
| `WP-NET-001` | Dirección en la lista de bloqueo. Los eventos `blocked` y `expired` llevan este ID, con el hallazgo que pidió el bloqueo en `requested_by` | 100 | Descartada (modo Block) |
| `WP-NET-002` | Intentos de conexión nuevos por origen y minuto (umbral predeterminado 60) | 60 en el umbral, 80 a 2×, 100 a 4× | Se observa; solo bloquea con `--syn-rules-may-block` |
| `WP-NET-003` | Puertos de destino distintos por origen y minuto (umbral predeterminado 20) | 60 en el umbral, 80 a 2×, 100 a 3× | Se observa; solo bloquea con `--syn-rules-may-block` |

Falsos positivos esperables: `WP-NET-002` con una dirección NAT compartida muy concurrida, un
rastreador o un monitor de disponibilidad; `WP-NET-003` con un escáner de vulnerabilidades que el
operador ejecuta a propósito. Añádalos a la lista de permitidos.

## Requisitos previos

1. **WinDivert 2.2.2**, descargado por el operador desde la publicación oficial
   (`github.com/basil00/WinDivert/releases`, `WinDivert-2.2.2-A.zip`). Copie `WinDivert.dll` y
   `WinDivert64.sys` de su carpeta `x64` al directorio de programa de WPShield, junto a
   `wpshield.exe`. WPShield no los incluye ni los descarga; WinDivert es LGPLv3.

   Compruebe los archivos antes de copiarlos. `WinDivert.dll` no tiene firma, y `WinDivert64.sys`
   lleva una firma EV que Sectigo emitió a `成都密思听科技有限公司` (Sichuan, CN), no al autor de
   WinDivert; los metadatos del propio controlador dicen `Copyright © Basil 2011-2022`. Toda copia de
   la publicación oficial trae ese mismo controlador, así que lo que importa es que el suyo sea ese
   archivo. `Get-FileHash <archivo> -Algorithm SHA256` debe imprimir exactamente:

   | Archivo | SHA-256 |
   | --- | --- |
   | `WinDivert-2.2.2-A.zip` (405.137 bytes) | `63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15` |
   | `x64\WinDivert.dll` | `C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2` |
   | `x64\WinDivert64.sys` | `8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2` |

   Son de la publicación oficial, descargada el 2026-11-01; el valor del controlador coincide además
   con el registro público de ese mismo archivo en un escáner independiente. Algunos antivirus marcan
   WinDivert como herramienta de hacking, porque también lo usan trampas de juegos y malware; cuente
   con ello antes de copiarlo a un host.
2. **Elevación de administrador**, salvo para `--check`.
3. **El controlador cargado.** Una ejecución con `--install-driver` permite que WinDivert registre e
   inicie su servicio de controlador de kernel `WinDivert`. WinDivert marca ese servicio para su
   eliminación en el momento en que arranca (leído de su código fuente, `dll/windivert.c`), así que
   desaparece tras `sc stop WinDivert` o un reinicio y no queda nada instalado. Por esa misma razón,
   `--install-driver` vuelve a hacer falta en la primera ejecución después de cada reinicio.

## Cómo ejecutarlo

```powershell
# 1. Sin elevación ni controlador: ¿evalúa la biblioteca real los filtros de WPShield como se espera?
wpshield network-filter --check --allow 203.0.113.50 --block 198.51.100.0/24

# 2. Monitor: no descarta nada, informa de a quién bloquearía. Déjelo corriendo varios días.
wpshield network-filter --allow 203.0.113.50 --output C:\ProgramData\WPShield\logs\network-filter.jsonl

# 3. Block: descarta las direcciones nombradas mientras siga en ejecución.
wpshield network-filter --mode Block --allow 203.0.113.50 --block 198.51.100.0/24 `
    --output C:\ProgramData\WPShield\logs\network-filter.jsonl
```

`--allow` y `--block` aceptan listas separadas por comas y pueden darse una sola vez cada una; una
opción repetida se rechaza en lugar de quedarse en silencio solo con el último valor. Un bloqueo no
puede ser más amplio que `/16` (IPv4) o `/48` (IPv6), ni nombrar direcciones de loopback, de enlace
local, de multidifusión, de difusión o no especificadas. Una dirección escrita con bits de host
activados (`198.51.100.7/24`) se rechaza, y el error nombra la red que se habría querido decir.

Los eventos van a la consola y, con `--output`, a un archivo JSON Lines con el sobre de log del
gateway (`timestamp`, `level`, `category: WPShield.NetworkFilter`, `message`, `state`). El
vocabulario de `state.action` es fijo: `started`, `stopped`, `self-test-failed`, `observed`,
`would-block`, `not-blocked-spoofable-evidence`, `blocked`, `expired`, `refused-allow-listed`,
`refused-block-set-full`, `refused-unblockable-address`, `refused-rdp-client`,
`enforcement-updated`, `enforcement-failed`, `observer-failed`.

## Marcha atrás y bypass

Detenga el comando (Ctrl+C, o terminando el proceso). Todos los bloqueos se levantan en ese momento,
porque los bloqueos son handles y los handles se cierran con el proceso. No hay nada más que deshacer.
Para descargar también el controlador, ejecute `sc stop WinDivert` cuando ningún proceso tenga abierto
un handle de WinDivert; el servicio ya estaba marcado para su eliminación, así que detenerlo lo
elimina. Un reinicio hace lo mismo.

## Qué no hace

- No toca el Firewall de Windows, IIS, el DNS, los certificados ni ningún servicio que no sea el
  controlador WinDivert que el operador carga con `--install-driver`.
- No persiste ningún bloqueo, ni restaura bloqueos después de un reinicio.
- No inspecciona cargas útiles, no descifra TLS y no mira tráfico UDP, ICMP ni saliente.
- Todavía no actúa sobre el registro de Seguridad. `WPShield.Integration` puede convertir un hallazgo
  del registro de Seguridad en una solicitud de bloqueo, pero no está conectado al comando: el lector
  del registro de Seguridad reproduce el registro entero al arrancar y lo mantiene en memoria, lo que
  bloquearía cada dirección que alguna vez falló un inicio de sesión. Se conectará cuando el lector se
  suscriba solo a eventos nuevos.

## Primera ejecución en una máquina de desarrollo

1. Copie los archivos x64 de WinDivert 2.2.2 junto a `wpshield.exe`. Ejecute `--check` sin
   elevación. Todas las líneas deben decir `PASS`. **Hecho el 2026-11-01 en una máquina de
   desarrollo: pasaron las 28 comprobaciones** contra la `WinDivert.dll` x64 oficial, sin elevación y
   sin controlador. Los pasos 2 a 5 no se han ejecutado.

   `RealWinDivertSelfTest` ejecuta la misma comprobación desde la suite de pruebas cuando
   `WinDivert.dll` está en `tests/WPShield.NetworkFilter.Tests/bin/Release/net10.0-windows/` (el
   proyecto de pruebas apunta a `net10.0-windows`, no a `net10.0`). Sin el archivo, la prueba sale
   antes de tiempo y se reporta como *aprobada*, así que una aprobación en CI no dice nada sobre la
   biblioteca.
2. Elevado: `wpshield network-filter --install-driver --allow <su dirección>` (Monitor). Desde otra
   máquina, conéctese a unos cuantos puertos de esta. Deben aparecer líneas `observed`; no se descarta
   nada.
3. Elevado: `--mode Block --allow <su dirección> --block <la dirección de una segunda máquina>`. Desde
   la segunda máquina, una conexión debe agotar ahora el tiempo de espera; desde la suya, debe
   funcionar.
4. Termine el proceso desde el Administrador de tareas, no con Ctrl+C. Desde la segunda máquina, la
   conexión debe volver a funcionar de inmediato: ese es el interruptor de hombre muerto.
5. Solo entonces considere el host de producción, en modo Monitor, durante al menos una semana.

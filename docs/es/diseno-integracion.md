# WPShield.Integration — Diseño (Español)

`WPShield.Integration` conecta `WPShield.SecurityMonitor` con `WPShield.NetworkFilter`. Contiene un
solo tipo, `NetworkFilterBlockListSink`, un `ISecurityEventSink` que convierte un hallazgo del registro
de Seguridad con acción Block en una solicitud de bloqueo al filtro de red.

> **Estado: todavía no está conectado a ningún comando.** Véase *Por qué no está conectado* más abajo.

## Qué hace

```text
Registro de Seguridad 4625 ─► SecurityEventMonitor ─► WP-SEC-001 / WP-SEC-002, hallazgo (Block)
                                                         │
                                                         ▼
                                        NetworkFilterBlockListSink.Publish
                                                         │  dirección tomada del campo IpAddress del evento
                                                         ▼
                          NetworkFilterService.RequestBlock(address, rule, EvidenceGrade.Authenticated)
```

El receptor no decide nada. Si una solicitud se convierte en bloqueo lo decide
`NetworkFilterService.RequestBlock`, el único lugar donde se crean bloqueos ([ADR 0006](adr/0006-bloqueo-en-capa-de-red.md)):

- El modo Monitor registra `would-block` y no bloquea nada.
- Una dirección de la lista de permitidos se rechaza, diga lo que diga el hallazgo.
- Se rechazan el loopback, las direcciones no especificadas y las demás que no pueden bloquearse
  (`127.0.0.1`, `::1`, `-`).
- La evidencia del registro de Seguridad se clasifica como `Authenticated`: el inicio de sesión falló
  después de completarse el handshake TCP, así que la dirección respondió a paquetes y no estaba
  falsificada. Por eso puede añadir un bloqueo en modo Block sin `--syn-rules-may-block`. El bloqueo
  lleva el TTL dinámico (60 minutos por omisión).

## Por qué no está conectado

`SecurityEventMonitor` lee el registro de Seguridad con un `EventLogReader` que empieza en el evento
más antiguo y lo reúne todo en una lista en el primer escaneo. En un host con un registro de Seguridad
de 2 GB eso es una lectura a memoria sin límite, y cada dirección que alguna vez acumuló suficientes
inicios de sesión fallidos en una ventana de cinco minutos quedaría bloqueada al arrancar. El ADR 0002
ya dijo cómo debe consumirse el registro de Seguridad: suscribirse a los eventos nuevos
(`EventLogWatcher` con `readExistingEvents: false`), no leer el archivo. El receptor se conectará a
`network-filter` cuando el lector haga eso.

Hay otros dos límites del monitor que importan a quien vaya a conectarlo:

- `WP-SEC-001` cuenta solo `LogonType 10`. Con Network Level Authentication, que es lo predeterminado
  en RDP, los inicios de sesión RDP fallidos se registran como `LogonType 3`. `WP-SEC-002`, que cuenta
  cada 4625 por dirección, es la regla que los ve.
- La `AllowList` propia del monitor es una comparación exacta de cadenas. La autoridad es la lista de
  permitidos del filtro de red; el receptor no depende de la del monitor.

## Requisitos de seguridad

- La dirección se lee del campo `IpAddress` del evento y se analiza; nada de lo que haya tecleado un
  atacante (el nombre de usuario, el nombre de la estación de trabajo) llega a un filtro, a una línea
  de log ni a un mensaje de error.
- El receptor nunca bloquea directamente y no guarda estado propio.

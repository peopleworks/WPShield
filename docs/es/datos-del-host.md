# Datos del host

[English](../en/host-facts.md) · [Índice de la documentación](../README.md) ·
[ADR 0013](adr/0013-datos-del-host-y-centro-de-mando.md)

La evidencia de WPShield responde "quién ataca este servidor". Los datos del host responden "cómo está
este servidor": su salud y sus reinicios inesperados, sus sitios de IIS y su postura, qué escucha en la red y
qué admiten las reglas del firewall, quién tiene una sesión, y qué cuentas, servicios y tareas que no son de
Microsoft tiene.

Los datos del host son **de solo lectura**. Ningún dato, comando ni foto detiene, arranca, borra ni
reconfigura nada del servidor. Cada remedio es un texto para que una persona lo aplique a mano.

## De dónde salen

`wpshield evidence collect`, elevado, toma las fotos y las guarda en el almacén de evidencias (esquema 3).
`wpshield host` las lee. Un modelo nunca hace que WPShield sondee el servidor: las herramientas MCP de la
siguiente fase solo leerán fotos guardadas.

| Dato | Qué contiene | Se lee de | Cadencia | Necesita elevación |
| --- | --- | --- | --- | --- |
| `host_health` | Tiempo encendido, CPU, memoria, espacio libre por volumen fijo (marcando el de los logs de IIS), tamaño del almacén | `GetTickCount64`, `GetSystemTimes`, `GlobalMemoryStatusEx`, `DriveInfo` | 5 minutos | No |
| Nivel de parches (en `host_health`) | `CurrentBuild`, `UBR` y `DisplayVersion`; la versión del archivo del kernel; la última actualización acumulativa correcta con su fecha y los días transcurridos; instalaciones fallidas en 30 días | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, ProductVersion de `ntoskrnl.exe`, eventos 19 y 20 de `WindowsUpdateClient/Operational` | 5 minutos | No |
| Reinicios inesperados | Cada caída una vez, con su código (`0x133 DPC_WATCHDOG_VIOLATION`) | Log de Sistema 41, 6008 y 1001, agrupados por caída | Al arrancar y cada 15 minutos | No |
| `iis_sites` | ID, nombre, estado, bindings, grupo y **tipo** de identidad del grupo | El lector de IIS de solo lectura que usa `wpshield audit` | 15 minutos | Sí |
| `iis_posture` | Los ID, severidades y recuentos del audit, y "grupos como administrador: N de M" | Las propias comprobaciones del audit, de solo lectura | Al arrancar, cada 6 horas y tras cada `wpshield audit` manual | Sí |
| `listening_ports` | Protocolo, puerto, enlace, ejecutable dueño y veredicto de exposición | Las tablas de escucha TCP y UDP y la política del firewall (COM, solo lectura) | 15 minutos | Para nombres de procesos y algunas reglas |
| `rdp_sessions` | Sesiones actuales; inicios y reconexiones RDP de 7 días con su dirección de origen | `WTSEnumerateSessions`; LocalSessionManager 21 y 25 | 15 minutos | No |
| `host_inventory` cuentas | Nombre, habilitada, pertenencia a Administradores y a Usuarios de escritorio remoto, último inicio, edad de la contraseña | `NetUserEnum`, `NetLocalGroupGetMembers` | Al arrancar y cada 6 horas | Sí |
| `host_inventory` servicios | Servicios Win32 que no son de Microsoft: estado, inicio, cuenta, ejecutable, firma, marcas | La clave de servicios del registro y el administrador de servicios | Al arrancar y cada 6 horas | Sí |
| `host_inventory` tareas | Tareas programadas que no son de Microsoft: ruta, estado, principal, última y próxima ejecución, ejecutable, firma, marcas | El Programador de tareas (COM, solo lectura) | Al arrancar y cada 6 horas | Sí |

Las conexiones salientes de los procesos web (`w3wp.exe`, `php-cgi.exe`) **todavía no se miden**: una foto
no ve una llamada de dos segundos. Tendrán su propio ADR y su propio sensor.

### Nivel de parches: hechos, nunca un veredicto

La compilación del registro, la versión del archivo del kernel y el log de Windows Update pueden no
coincidir: un volcado de memoria puede mostrar un kernel más antiguo que las actualizaciones que lista el
historial. `wpshield host health` muestra los tres juntos, dice cuándo la revisión del archivo del kernel
difiere del `UBR` del registro y cuenta los días desde la última actualización acumulativa correcta. Un log
de Windows Update ilegible dice `unknown`, nunca "ninguno"; "not found in the Windows Update log" dice
hasta cuándo llega el log. WPShield no tiene una fuente sin conexión de la última compilación, así que
nunca califica un servidor de desactualizado.

## Honesto con lo que no pudo leer

Cada foto lleva su hora de lectura y un estado: `ok`, `partial`, `needs-elevation`, `unreadable` o
`not-measured`. Cualquier estado que no sea `ok` dice el motivo y el remedio. Una foto con más de tres veces
su cadencia se muestra como **stale** (vieja). Un dato nunca leído dice "no snapshot yet". Cero reinicios y
"no se pudo leer el log de Sistema" nunca se parecen.

## Exposición, según las reglas del Firewall de Windows

Cada puerto en escucha recibe un veredicto de las reglas de entrada habilitadas de los perfiles en vigor:
`open-to-any` (abierto a cualquiera), `restricted` (restringido), `blocked` (bloqueado), `local-only` (solo
loopback) o `unknown` (no se pudo leer la política). El veredicto siempre va etiquetado **"según las reglas
del Firewall de Windows"** y nunca se presenta como "alcanzable": otros filtros de red, un producto de
seguridad o el firewall del proveedor también deciden.

Ante la duda, el veredicto se inclina a abierto: una regla limitada a un programa cuya ruta no se pudo leer
se toma como aplicable, y una lista de direcciones remotas es "restringida" salvo que sea `*` o `Internet`.

**Rojo:** SMB (139, 445), RPC (135), SQL Server (1433), MySQL (3306, 33060), PostgreSQL (5432), VNC (5900) y
WinRM (5985, 5986) cuando están abiertos a cualquier dirección. Restringidos a las direcciones que los
necesitan, no salen en rojo. El remedio es restringir la regla a mano, nunca esconder el aviso.

## El inventario nunca guarda secretos

- **Los argumentos nunca se guardan ni se muestran.** Pueden llevar una contraseña o un token, y un comando
  codificado es la carga del atacante. Se reducen a marcas y se descartan: `has-arguments`,
  `encoded-command`, `contains-url`, `user-writable-path`.
- **Solo lo que no es de Microsoft.** Un servicio o tarea cuyo binario firma Microsoft queda fuera, **salvo**
  que ejecute un intérprete (`cmd.exe`, `powershell.exe`, `mshta.exe`, `rundll32.exe`...) o lleve una marca
  `encoded-command`, `contains-url` o `user-writable-path`: `cmd /c powershell -enc ...` también lo firma
  Microsoft. Los servicios alojados en `svchost.exe` se juzgan por su `ServiceDll`.
- **Las firmas tienen límite.** Se comprueban las firmas Authenticode incrustadas y de catálogo con
  `WinVerifyTrust`, sin comprobar revocación, en caché por ruta, tamaño y hora de escritura, como máximo 300
  por foto. El resto dice `not-checked` hasta la siguiente foto.
- **Nunca se leen contraseñas ni descripciones.** Los nombres completos de las cuentas se leen en memoria
  para una comparación y se descartan (abajo).
- **Los cambios son eventos.** Un elemento añadido, quitado o cambiado (ejecutable, cuenta o firma) entre dos
  fotos se registra como `host.inventory-change`, como máximo 500 al día por tipo; los demás se cuentan.

### ¿Conocen los atacantes los nombres de tus cuentas?

En cada foto de cuentas, el recolector compara en memoria los nombres probados en los inicios de sesión
fallidos (los intentos de los últimos 30 días que aún se guardan en detalle, que son 14 días con el
`retention.raw_days` por defecto) con los **nombres completos** de las cuentas locales, sin distinguir
mayúsculas, acentos ni espacios. Solo guarda si alguno coincidió y cuántos:
"attackers try a real account's full name: YES (2)". Los nombres completos nunca se guardan, ni se registran,
ni se muestran. Una coincidencia significa que los nombres salieron de este servidor, por su pantalla de
inicio de sesión o por una intrusión.

## Comandos

```text
wpshield host                                  cada dato con su antigüedad y estado
wpshield host health                           tiempo encendido, reinicios con su código, CPU, memoria, volúmenes
wpshield host sites | posture | ports | sessions
wpshield host inventory accounts|services|tasks
wpshield host ... --json                       un documento JSON
wpshield host ... --live                       lee ahora, no escribe nada (ejecútalo elevado)
```

`wpshield audit` también registra su resumen (ID, severidades y recuentos, nunca nombres) como una foto de
postura en el propio almacén de WPShield. Es una escritura en WPShield, no en el servidor, y el audit lo dice
en su última línea. Una corrida incompleta (sin elevación, IIS ilegible) no se registra.

## Almacén

El esquema 3 añade `host_snapshots` (JSON acotado, máximo 256 KB por foto) y `host_health_hourly`. Los
reinicios y los cambios de inventario son filas de `events`. Retención: siempre se conserva la foto más
reciente de cada dato; las de postura, 400 días; las demás, 7 días; la salud por hora, 90 días.

La migración es aditiva y de un solo sentido: en cuanto una versión con esquema 3 abre el almacén, las
versiones anteriores lo rechazan. Actualiza la CLI y el escritorio juntos, y ejecuta
`wpshield evidence collect` una vez antes de abrir el escritorio.

## Qué sale del servidor

Las superficies locales (`wpshield host`, el escritorio) lo muestran todo; nada de lo que enseñan sale del
servidor. Lo que sale es lo que un asistente le pide a `wpshield mcp` o al analista de IA: las herramientas
`host_health`, `iis_sites`, `iis_posture`, `listening_ports`, `rdp_sessions` y `host_inventory`
([servidor MCP](servidor-mcp.md)). Responden solo desde estas instantáneas y respetan el ajuste auditado
`mcp.host_details` (apagado por defecto): apagado, devuelven recuentos, estados, veredictos, números de
puerto, nombres de archivo de ejecutables, horas de reinicio y códigos de pantallazo, y `withheld` en lugar
de nombres, rutas y direcciones; encendido, los nombres vuelven como texto no confiable. `wpshield mcp` lee
el ajuste al arrancar.

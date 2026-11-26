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
| Nivel de parches (en `host_health`) | `CurrentBuild`, `UBR` y `DisplayVersion`; la versión del archivo del kernel; la última actualización acumulativa correcta con su fecha y los días transcurridos; instalaciones fallidas en 30 días; cuando el log de actualizaciones no nombra ninguna acumulativa, la revisión más reciente instalada y su fecha | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, ProductVersion de `ntoskrnl.exe`, eventos 19 y 20 de `WindowsUpdateClient/Operational`, `Win32_QuickFixEngineering` | 5 minutos | No |
| Horizonte de los logs (en `host_health`) | Para los logs de Sistema, Seguridad y Aplicación: tamaño máximo, número de registros, registro más antiguo y el evento que llena los 5.000 más nuevos | El servicio de registro de eventos, en solo lectura | 5 minutos | Para el log de Seguridad |
| Reinicios inesperados | Cada caída una vez, con su código (`0x133 DPC_WATCHDOG_VIOLATION`) | Log de Sistema 41, 6008 y 1001, agrupados por caída | Al arrancar y cada 15 minutos | No |
| `iis_sites` | ID, nombre, estado, bindings, grupo y **tipo** de identidad del grupo | El lector de IIS de solo lectura que usa `wpshield audit` | 15 minutos | Sí |
| `iis_posture` | Los ID, severidades y recuentos del audit, y "grupos como administrador: N de M" | Las propias comprobaciones del audit, de solo lectura | Al arrancar, cada 6 horas y tras cada `wpshield audit` manual | Sí |
| `listening_ports` | Protocolo, puerto, enlace, ejecutable dueño, veredicto de exposición y, para un puerto abierto a cualquiera, las reglas que lo abren | Las tablas de escucha TCP y UDP y la política del firewall (COM, solo lectura) | 15 minutos | Para nombres de procesos y algunas reglas |
| `rdp_sessions` | Sesiones actuales; inicios y reconexiones RDP de 7 días con su dirección de origen | `WTSEnumerateSessions`; LocalSessionManager 21 y 25 | 15 minutos | No |
| `host_inventory` cuentas | Nombre, habilitada, pertenencia a Administradores y a Usuarios de escritorio remoto, último inicio, edad de la contraseña | `NetUserEnum`, `NetLocalGroupGetMembers` | Al arrancar y cada 6 horas | Sí |
| `host_inventory` servicios | Servicios Win32 que no son de Microsoft: estado, inicio, cuenta, ejecutable, firma, marcas, y si alguno está atascado en un bucle de arranque | La clave de servicios del registro, el administrador de servicios y los registros de control de servicios del log de Sistema de 24 horas | Al arrancar y cada 6 horas | Sí |
| `host_inventory` tareas | Tareas programadas que no son de Microsoft: ruta, estado, principal, última y próxima ejecución, ejecutable, firma, marcas | El Programador de tareas (COM, solo lectura) | Al arrancar y cada 6 horas | Sí |

Las conexiones salientes de los procesos web (`w3wp.exe`, `php-cgi.exe`) **todavía no se miden**: una foto
no ve una llamada de dos segundos. Tendrán su propio ADR y su propio sensor.

### Nivel de parches: hechos, nunca un veredicto

La compilación del registro, la versión del archivo del kernel y el log de Windows Update pueden no
coincidir: un volcado de memoria puede mostrar un kernel más antiguo que las actualizaciones que lista el
historial. `wpshield host health` muestra los tres juntos, dice cuándo la revisión del archivo del kernel
difiere del `UBR` del registro y cuenta los días desde la última actualización acumulativa correcta. Una
revisión del kernel un poco **por debajo** del `UBR` es normal (no toda actualización reemplaza
`ntoskrnl.exe`) y se dice así, como un hecho. Un log de Windows Update ilegible dice `unknown`, nunca
"ninguno"; "not found in the Windows Update log" dice hasta cuándo llega el log.

Lo que se instala desde un paquete o con una herramienta de gestión no escribe ningún evento de instalación
en ese log. Cuando no nombra ninguna actualización acumulativa, `wpshield host health` añade la revisión más
reciente instalada según `Win32_QuickFixEngineering` (su ID y su fecha, etiquetados con esa fuente), así que
"not found" viene acompañado de la última actualización que Windows registró. WPShield no tiene una fuente
sin conexión de la última compilación, así que nunca califica un servidor de desactualizado.

### Hasta dónde llegan los logs

Una caída solo se puede contar mientras su registro siga en el log de Sistema. `wpshield host health`
muestra, para los logs de Sistema, Seguridad y Aplicación, hasta dónde llega cada uno, su tamaño y qué evento
lo llena:

```text
System log        reaches back 6 h (20.0 MB, 63,818 records); 99.7% of the newest 5,000 records are 7036 Service Control Manager
```

Esa línea es un servicio en bucle de arranque expulsando los registros de caídas de un log de 20 MB. Un log
que no llega a una semana se señala con el remedio manual, `wevtutil sl <log> /ms:<bytes>`. El log de
Seguridad necesita elevación; sin ella dice `unknown (access-denied)`, nunca vacío.

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

**El programa dueño del puerto.** El recolector abre el proceso dueño para leer su ruta. Un proceso que se
niega incluso a eso, como hacen algunos procesos de servicio ante un recolector elevado, se nombra con el nombre
de imagen que guarda el propio kernel, que no necesita acceso al proceso, y solo cuando ese nombre corresponde a
una letra de unidad. Un puerto cuyo programa sigue sin poder nombrarse dice
`unknown`.

Ante la duda, el veredicto se inclina a abierto. Con el programa desconocido, una regla que permite y está
limitada a un programa se toma como aplicable, y una que bloquea y está limitada a uno, no: un veredicto nunca
es `blocked` por una regla que quizá no aplica. Una lista de direcciones remotas es "restringida" salvo
que sea `*` o `Internet`.

Una regla de usuario (las que instalan las apps de la tienda) y una de contenedor de aplicación admiten
tráfico solo para su propia app: no abren un puerto que es del kernel (`System`), como el 139 y el 445. Un
propietario que nadie pudo leer conserva todas las reglas.

**Rojo:** SMB (139, 445), RPC (135), SQL Server (1433), MySQL (3306, 33060), PostgreSQL (5432), VNC (5900) y
WinRM (5985, 5986) cuando están abiertos a cualquier dirección. Restringidos a las direcciones que los
necesitan, no salen en rojo. El remedio es restringir la regla a mano, nunca esconder el aviso.

**Qué regla lo abre.** Para cada puerto abierto a cualquiera, la foto nombra las reglas que permiten y
admiten cualquier dirección, cinco como máximo: `wpshield host ports` las imprime bajo cada puerto rojo, y
`--all` bajo todo otro puerto abierto a cualquiera. Una regla para cualquier puerto se marca `[any port]`, y
una limitada a un programa `[program rule, any port]`. En el Firewall de Windows basta una regla que permita,
así que una regla de programa que admite cualquier dirección en cualquier puerto anula una regla de puerto
restringida por dirección: restringe todas las reglas de la lista. Cuando no hace falta ninguna regla, la
línea dice por qué: el firewall está apagado en un perfil activo, o la acción de entrada por defecto permite.

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
- **Un nombre de programa sin carpeta se busca donde lo busca Windows.** Una tarea que ejecuta `xcopy` o
  `sc.exe` sin carpeta se juzga para `user-writable-path` en la carpeta del sistema y luego en las carpetas
  de `PATH`, nunca en la carpeta desde la que se arrancó el recolector. Un nombre que no se encuentra no se
  juzga.
- **Los servicios atascados en un bucle de arranque se marcan.** `not-running`: configurado para arrancar
  automáticamente pero en arranque pendiente, en pausa, o detenido tras un evento de fallo en 24 horas.
  `start-pending`: esperando arrancar. `flapping`: diez o más cambios de estado (evento 7036 de Sistema) en la
  última hora. Un servicio en bucle llena el log de Sistema y expulsa los registros de caídas; detenerlo o
  arreglarlo se hace a mano.
- **Las tareas tranquilas de Microsoft se agrupan.** `wpshield host inventory tasks` agrupa en una línea con
  su recuento las tareas bajo `\Microsoft\Windows\`, firmadas por Microsoft, que aparecen solo porque ejecutan
  un intérprete de scripts y no llevan más marca que `has-arguments`. Se siguen leyendo y guardando; `--all`
  las muestra.

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
wpshield host health                           tiempo encendido, reinicios con su código, CPU, memoria, volúmenes,
                                               nivel de parches, hasta dónde llegan los logs
wpshield host sites | posture | ports | sessions
wpshield host ports --all                      las reglas detrás de todo puerto abierto a cualquiera
wpshield host inventory accounts|services|tasks
wpshield host inventory tasks --all            también las tareas tranquilas de Microsoft
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

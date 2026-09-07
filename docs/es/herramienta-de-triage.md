# Herramienta de triage

`scripts/Invoke-WPShieldTriage.ps1` examina sitios WordPress en un servidor Windows con IIS e informa
qué hay en disco que no debería estar, cuándo se usó cada artefacto por última vez, y **a cuál de
ellos WPShield rechazaría realmente una petición.**

Lee. Nunca borra, pone en cuarentena, renombra, mueve ni repara nada, y nunca ejecuta un archivo que
encuentra.

## De dónde salió esto

Las reglas de WPShield venían de un modelo de amenazas. Esta herramienta, y las reglas `WP-PATH-*`
contra las que informa, vienen de un incidente: un sitio WordPress real sobre IIS con seis webshells,
cuyos registros de IIS aún conservaban el tráfico de explotación completo. El triage se hizo a mano,
en un par de horas, con PowerShell improvisado. Este script es ese trabajo, generalizado — porque la
próxima persona que encuentre un archivo extraño en un WordPress sobre Windows no debería tener que
reinventarlo.

Lo más útil de aquella tarde no fue la lista de shells. Fue la frase *"cada petición que llegó a uno
de estos no llevaba cuerpo, así que WPShield no habría podido ver nada"*. Esa medición es la que
produjo la [inspección de la ruta de la solicitud](m2-5-inspeccion-ruta-solicitud.md), y es la razón
por la que esta herramienta informa de la cobertura del gateway en vez de limitarse a listar
archivos.

## Cómo ejecutarla

```powershell
# Primero, en un servidor que no conoce: que se examinaria?
.\scripts\Invoke-WPShieldTriage.ps1 -DiscoverOnly

# Despues, la ejecucion.
.\scripts\Invoke-WPShieldTriage.ps1 -OutputPath .\triage.jsonl
```

> **Ejecutarlo desde `cmd.exe`.** Un `.ps1` no es ejecutable desde el símbolo del sistema: escribir su
> nombre allí lo abre en un editor o reporta un comando no reconocido, según la asociación de
> archivos. Hay que llamar al intérprete de forma explícita, desde un símbolo **elevado**:
>
> ```
> powershell -NoProfile -ExecutionPolicy Bypass -File C:\temp\Invoke-WPShieldTriage.ps1 -OutputPath C:\temp\triage.jsonl
> ```

Ejecútela como administrador. Un intérprete sin privilegios no puede leer la configuración de IIS, no
puede leer los registros de IIS y no ve todos los archivos de la raíz web; la herramienta lo dice y
continúa en vez de fallar, pero el informe queda entonces incompleto de maneras que ella misma no
puede describir del todo.

Sin `-SitePath`, la herramienta le pregunta a IIS por sus sitios y busca WordPress en la raíz de cada
uno y un directorio más abajo. Nada del servidor se supone ni se codifica de antemano.

| Parámetro | Para qué sirve |
| --- | --- |
| `-SitePath` | Una o más raíces de WordPress. Omite el descubrimiento. |
| `-IisLogPath` | Raíz de los registros de IIS. Por omisión `C:\inetpub\logs\LogFiles`. Pase `''` para omitir la correlación. |
| `-OutputPath` | Dónde va el informe JSON Lines. |
| `-RecentDays` | Hasta dónde llegan las comprobaciones de fechas y el barrido de registros. Por omisión 30. |
| `-MaximumFileBytes` | Bytes leídos por archivo PHP, repartidos entre su inicio y su final. Por omisión 65536. |
| `-MaximumFilesScanned` | Límite de archivos examinados por sitio. Por omisión 200000. |
| `-MaximumLogBytes` | Límite de bytes de registro leídos. Por omisión 1 GiB. |
| `-MaximumFindings` | Límite de hallazgos emitidos. Por omisión 5000. |
| `-DiscoverOnly` | Lista los sitios y termina. |

Todos los límites tienen valor por omisión, y el informe avisa cuando alguno se alcanzó en vez de
detenerse en silencio. Una herramienta forense que trunca calladamente es peor que una que se niega a
arrancar.

## Qué comprueba

| ID | Qué informa |
| --- | --- |
| `TRIAGE-001` | Un archivo ejecutable dentro de `wp-content/uploads`, `upgrade` o `updraft`. Esos directorios son datos. |
| `TRIAGE-002` | Un archivo ejecutable dentro de un directorio que existe para servirse tal cual — `dist`, `static`, `node_modules`, `img` y el resto de la lista de activos. |
| `TRIAGE-003` | Un `web.config` por debajo de la raíz del sitio. En IIS un `web.config` puede añadir un mapeo de manejador, así que escribir uno decide qué ejecuta el servidor. |
| `TRIAGE-004` | Un nombre de archivo que Windows acepta pero no almacena literalmente: punto o espacio final, sufijo de flujo de datos alternativo, carácter de control. |
| `TRIAGE-005` | PHP que puede ejecutar código elegido en tiempo de ejecución, y donde o bien una petición alcanza ese código o bien está ofuscado. |
| `TRIAGE-006` | Un archivo oculto cuyo nombre es una marca de tiempo Unix — marcador de un dropper, y la forma que inició el incidente de arriba. |
| `TRIAGE-007` | Un archivo ejecutable creado *después* de escribirse el contenido que guarda. Uno es una herramienta de respaldo; cientos en un árbol de plugins es un reescritor masivo recorriendo el sitio. |
| `TRIAGE-008` | Las peticiones que los registros de IIS recuerdan haber llegado a un artefacto marcado: cuántas, cuándo empezaron y terminaron, desde qué direcciones, con qué métodos y códigos de estado. |
| `TRIAGE-009` | Plugins y temas instalados, con sus versiones. |
| `TRIAGE-010` | **Host.** Una tarea programada registrada hace poco, que oculta su línea de comandos, o que ejecuta algo de fuera de Windows. |
| `TRIAGE-011` | **Host.** Una cuenta local cuya contraseña se fijó hace poco, y quién está en el grupo de administradores. |
| `TRIAGE-012` | **Host.** Un servicio de Windows cuyo binario vive en un directorio temporal, de usuario o web. |
| `TRIAGE-013` | **Host.** Claves de arranque automático. |
| `TRIAGE-014` | **Host.** Código ejecutable escrito hace poco en un directorio de paso como `C:\Windows\Temp`. |
| `TRIAGE-015` | **Host.** Las detecciones propias de Microsoft Defender: la familia, **los archivos que encontró**, cuándo, y si lo consiguió. |

### Por qué `TRIAGE-005` no es una simple lista de nombres de función

Porque una lista de nombres de función produce un informe que nadie lee. El núcleo de WordPress llama
a `base64_decode`. La mitad del ecosistema de plugins lo llama. Una comprobación que se dispara con
eso informa de varios cientos de archivos en un sitio sano, y el operador aprende a ignorar la
herramienta.

Así que los marcadores se agrupan por lo que *significan* — una forma de ejecutar código elegido en
tiempo de ejecución, entrada controlada por la petición que puede alcanzarlo, y las costumbres de
quien esconde lo que hace un archivo — y un archivo solo se informa cuando esas cosas se combinan en
algo que un archivo legítimo no tiene motivo para ser: un sumidero al que llega una petición, un
sumidero envuelto en un decodificador, u ofuscación lo bastante densa como para que el autor
estuviera ocultando y no comprimiendo.

El *lookbehind* de cada patrón importa más de lo que parece: sin él, `$database->exec(...)` — PDO
corriente, presente en muchísimos archivos legítimos — coincide con el sumidero `exec`, y ese solo
falso positivo sería la mayor fuente de ruido de toda la comprobación.

### Por qué `TRIAGE-009` no trae base de datos de vulnerabilidades

Porque una lista de CVE incrustada en un script queda obsoleta el día en que se escribe, y el
operador que confía en una lista vieja está peor que el que consulta la versión. La herramienta
informa nombres y versiones y dice dónde comprobarlos. En el incidente del que salió esto, una sola
línea — la versión del plugin de slider — fue lo que identificó la puerta de entrada.


## Las comprobaciones de host, y por qué van aparte

Todo lo demás de esta herramienta mira dentro de un sitio WordPress. Ese es el alcance correcto para
una herramienta que lleva WordPress en el nombre, y es el alcance equivocado para la pregunta que el
operador tiene de verdad, que es *«¿sigo comprometido?»*.

Un webshell es un punto de apoyo, no el conjunto. En el incidente del que sale esta herramienta, el
intruso ya estaba escribiendo en `C:\Windows\Temp` — fuera de la raíz web, fuera de todas las demás
comprobaciones, y sin que detener el sitio lo tocara. **Detener IIS cierra la puerta por la que
entraron y no hace nada con una tarea programada, un servicio, una clave de arranque o una cuenta.**

```powershell
.\scripts\Invoke-WPShieldTriage.ps1 -IncludeHost -OutputPath .\triage.jsonl
```

`-IncludeHost` es opcional porque responde a una pregunta distinta del resto del script y necesita
elevación para responderla bien. **El resumen siempre dice si se ejecutó**, porque una sección
ausente en silencio se lee exactamente igual que una sección que no encontró nada — el mismo
principio que la verificación previa aplica a una configuración de IIS ilegible.

Sigue siendo de solo lectura. Nada se desactiva, se borra ni se repara.

### Lo que enseñó la primera ejecución real

Estas comprobaciones se escribieron desde un modelo de amenazas, y la primera ejecución sobre un
Windows Server real encontró tres defectos en ellas — la misma lección que este proyecto reaprende
una y otra vez, y la razón por la que las familias de reglas derivadas de comportamiento medido son
las que aguantan.

**`TRIAGE-010` hacía la pregunta equivocada.** «¿La acción ejecuta un intérprete?» se disparó
dieciséis veces en un servidor limpio, y las dieciséis eran tareas de mantenimiento de Microsoft:
`PcaPatchDbTask`, `Autochk\Proxy`, el recolector de diagnóstico de disco, todas `rundll32` contra una
DLL del sistema. Dieciséis falsos positivos y cero verdaderos es peor que no tener comprobación,
porque enseña al operador a saltarse la sección. El error fue describir un *mecanismo* en vez de una
*intención* — Windows usa `rundll32` en todas partes. Lo que parece la tarea de un intruso es una
línea de comandos codificada u oculta, un binario donde un binario no debería estar, o un intérprete
ejecutando algo que no forma parte de Windows. Esas son ahora las razones, y el mismo servidor
reporta seis en vez de dieciséis, cada una con su motivo.

**`TRIAGE-011` no reportó absolutamente nada** — ni cuentas, ni grupo, ni error. Un `catch` vacío
había convertido un fallo en silencio, y eso se lee exactamente igual que un resultado limpio. Ahora
reporta el fallo como hallazgo. Arreglarlo destapó de inmediato el fallo que había debajo:
`Get-LocalGroupMember` rechaza el nombre cualificado `BUILTIN\Administrators`, así que el grupo se
obtiene con `Get-LocalGroup -SID`, que esquiva a la vez la cualificación y el idioma.

**`TRIAGE-015` usaba el cmdlet equivocado.** `Get-MpThreat` nombra la familia pero devuelve un
`Resources` vacío; las rutas y las fechas viven en `Get-MpThreatDetection`, que a su vez identifica
la amenaza solo por un id numérico. La comprobación reportaba seis amenazas sin decir de qué archivo
era ninguna, que es justo lo que el operador necesita. Ahora une las dos, y quita el prefijo
`file:_` que Defender pone en la ruta — dejarlo le entrega al operador una ruta que no existe.

La pertenencia al grupo se resuelve desde el SID conocido y no desde el nombre `Administrators`,
porque el grupo es `Administradores` en un Windows en español y una comprobación escrita contra el
nombre inglés no encuentra nada allí — y reporta esa ausencia en la dirección tranquilizadora.

## El veredicto del gateway

Esta es la parte que vale la pena. Cada hallazgo de archivo lleva el veredicto que las reglas de ruta
de WPShield devolverían para una petición HTTP a ese archivo, calculado con las mismas listas de
directorios, las mismas listas de extensiones, la misma suma de puntajes y los mismos dos umbrales
que usa el gateway.

| Veredicto | Significado |
| --- | --- |
| `blocked` | El gateway rechaza la petición de plano. |
| `observed` | Puntúa y queda registrado, pero se reenvía. Por debajo del umbral de bloqueo. |
| `not-covered` | **El archivo es ejecutable y ninguna regla de ruta se dispara.** El gateway reenvía una petición que alcanza código. Un hueco real. |
| `not-applicable` | Las peticiones a este archivo no son la forma en que hace daño, así que una familia de reglas que decide sobre peticiones ejecutables no tiene nada que decir sobre él. |

El resumen termina con la cuenta de cada uno, e imprime las rutas `not-covered` completas:

```
Would WPShield refuse a request to the executable artifacts above?
  blocked outright: 11
  scored but forwarded: 0
  not covered by any request-path rule: 1

WPShield would forward a request to each of these. Gateway coverage is not containment:
  ...\wp-content\plugins\exampleslider\wp\import1.php
```

`not-applicable` existe para que `not-covered` siga significando algo. Un `web.config` subido es
ejecución remota de código en IIS, pero no porque alguien lo pida: IIS lo lee por su cuenta y aplica
los mapeos de manejador que declara. Contarlo como hueco de las reglas de ruta inflaría el único
número sobre el que se espera que el lector actúe, con un caso que ninguna regla de ruta podría
cerrar jamás. Lo que cubre un `web.config` son las [reglas de carga](m2-reglas-carga.md), en el
momento en que el archivo llega.

**Una herramienta que solo listara lo que su propio producto atrapa sería un anuncio.** El número de
arriba se imprime porque a veces no es cero, y en el incidente que produjo esta herramienta no lo
era.

## Qué contiene el informe, y qué deliberadamente no

Los hallazgos se escriben como JSON Lines **en el mismo sobre que usa el registro del propio
gateway** — `timestamp`, `level`, `category`, `message`, `state` — con las marcas de tiempo en el
mismo formato. Un informe de triage y un registro del gateway pueden leerse con un solo analizador,
ordenarse juntos como texto y correlacionarse por los mismos nombres de campo.

```json
{"timestamp":"2026-09-06T20:22:17.9506873+00:00","level":"Warning","category":"WPShield.Triage",
 "message":"A PHP file can execute code chosen at runtime, and either a request reaches that code or it is obfuscated.",
 "state":{"ruleId":"TRIAGE-005","requestPath":"/wp-content/plugins/example/wp/import1.php",
          "executionSinks":["eval"],"requestInputs":["post"],"obfuscation":["base64_decode"],
          "gatewayVerdict":"not-covered","gatewayScore":0,"gatewayRuleIds":[],
          "sha256":"2B17DF...","sizeBytes":88}}
```

**Ningún contenido de archivo. Ni un byte.** Un informe de triage se escribe para adjuntarse a un
hilo de soporte o a una incidencia pública, y un informe que reproduce la carga útil distribuye el
webshell a todo el que lo lea. Los nombres de marcador, tamaños, hashes y fechas identifican un
archivo sin volver a publicarlo. Para leer un archivo, ábralo usted, en un editor, en una máquina que
no lo vaya a ejecutar.

**Nada fuera de ASCII.** Toda cadena se escapa al rango ASCII imprimible, de modo que un nombre de
archivo recuperado de un servidor en el que otra persona ha estado escribiendo no puede llevar un
carácter de control ni una secuencia de escape ANSI hasta una terminal, un visor de registros o un
navegador mostrando una incidencia. Es el mismo razonamiento que el gateway aplica a la evidencia de
sus reglas, aplicado a un informe que va a viajar más lejos.

Algo que el informe *sí* lleva son direcciones IP de cliente, en `TRIAGE-008`. Son el sentido de esa
comprobación — es lo que un operador bloquea y lo que necesita un reporte de abuso — pero son también
el único campo del informe que es dato personal de alguien, así que conviene pensarlo un momento
antes de pegar un informe en una incidencia pública.

## Qué no hace

- **No le dice que un sitio está limpio.** Lee lo que hay en disco hoy. Un intruso que limpió deja un
  disco que parece sano, y la herramienta dirá que lo parece. Una ejecución sin hallazgos es ausencia
  de evidencia.
- **No enumera flujos de datos alternativos.** `TRIAGE-004` informa de un sufijo de flujo en un
  *nombre*, pero la herramienta no le pregunta a cada archivo si lleva flujos ocultos: eso es una
  llamada al sistema adicional por archivo en un árbol con decenas de miles. Un archivo que esconde
  una carga útil en un flujo no se informa.
- **No lee la base de datos.** El contenido inyectado en `wp_posts` o `wp_options`, y la cuenta de
  administrador que añade un atacante, le son invisibles.
- **No decide nada.** Los hallazgos son un punto de partida. Lea usted cada archivo.
- **No limpia.** Por diseño, y de forma permanente. Borrar un webshell antes de entender cómo llegó
  elimina la evidencia y deja abierta la entrada.

Sobre ese último punto, el consejo del incidente del que salió esto sigue en pie: ante un compromiso
de cualquier antigüedad, en un servidor que ejecuta otras aplicaciones, **reconstruir en vez de
desinfectar.** Shells presentes durante años, en una máquina que no se puede inventariar por
completo, no se pueden dar por eliminados.

## Cómo se mantiene honesta la herramienta

`scripts/Test-WPShieldScripts.ps1` corre en CI en cada push y cada pull request, y exige cinco cosas.
Cada una existe por un defecto que ocurrió de verdad.

**Todos los scripts se analizan sintácticamente**, bajo PowerShell 7 *y* bajo Windows PowerShell 5.1
— que es lo que tiene un Windows Server sin instalarle nada. Que PowerShell 7 acepte un script no es
prueba de que 5.1 lo vaya a aceptar.

**Todos los scripts son ASCII puro.** Windows PowerShell 5.1 lee un `.ps1` sin marca de orden de
bytes como ANSI, así que una raya larga en UTF-8 llega como dos caracteres, uno de los cuales es una
comilla tipográfica que PowerShell trata como delimitador de cadena. La paridad de comillas se rompe
en silencio y el analizador reporta un error cien líneas más abajo, en código correcto. Este mismo
defecto llegó a entregar un script de triage que no arrancaba.

**La herramienta de triage no tiene ninguna vía de escritura salvo su propio informe.** Se recorre su
AST buscando todo cmdlet y todo miembro .NET capaz de escribir, se exige que cada
`[System.IO.File]::Open` pida acceso solo de lectura, y se permite exactamente un `StreamWriter`.
Digámoslo con claridad: esto es un *inventario*, no una prueba. La garantía equivalente del gateway —
que ningún cuerpo de petición puede llegar al disco — sí está probada, recorriendo las referencias de
tipos del ensamblado en busca de cualquier API de archivos. Para un script no existe nada tan fuerte,
porque PowerShell puede llamar a un cmdlet cuyo nombre calcula en tiempo de ejecución. Por eso la
comprobación prohíbe además las dos construcciones que harían el inventario inútil: la invocación a
través de una variable, e `Invoke-Expression`. Sin ellas el inventario es completo para todo lo que
un lector puede ver, que es la versión honesta de la afirmación.

**El vocabulario de reglas no se ha desviado.** La herramienta lleva sus propias copias de las listas
de extensiones y directorios del gateway, porque tiene que correr en un servidor sin runtime de .NET
y sin ninguna compilación de WPShield. Las copias se desvían, y una copia desviada no falla a gritos:
informa calladamente de una cobertura que el gateway no tiene, lo cual es peor que no informar nada.
Así que las listas se comparan, entrada por entrada, contra las fuentes en C#, y se comprueba que las
exclusiones deliberadas de la lista de activos siguen excluidas.

**La herramienta corre, de punta a punta, y llega a los veredictos correctos.** Se construye un
banco de pruebas que reproduce la estructura de directorios del incidente, se escanea y se afirma:
los artefactos en directorios cubiertos vuelven como `blocked`, el que está en el directorio PHP
propio del plugin vuelve como `not-covered`, y una hoja de estilo generada desde PHP se mantiene en
silencio. Esta es la comprobación más importante del archivo, porque es la única que falla cuando el
script no corre en absoluto — que es como se presentaron los dos defectos hallados al escribirlo.

## Véase también

- [Inspección de la ruta de la solicitud](m2-5-inspeccion-ruta-solicitud.md) — las reglas del gateway
  contra las que se informa.
- [Reglas de carga](m2-reglas-carga.md) — lo que cubre un archivo en el momento en que llega.
- [Modelo de amenazas](modelo-de-amenazas.md)

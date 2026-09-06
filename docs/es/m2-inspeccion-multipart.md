# M2: Inspección multipart acotada

Hasta este cambio el motor de inspección nunca se ejecutaba sobre tráfico real. `GatewayApplication`
resolvía el sitio, comprobaba el tamaño de la solicitud y reenviaba; el proyecto `WPShield.Gateway`
ni siquiera referenciaba a `WPShield.Rules.WordPress`. Todas las reglas que este proyecto documenta
se ejecutaban únicamente desde la demostración de consola `WPShield.Service`. En la práctica,
WPShield era un proxy inverso con un límite de tamaño y un rechazo de hosts desconocidos.

Este documento describe qué se ejecuta ahora sobre el tráfico del gateway: qué solicitudes se
inspeccionan, qué se analiza, qué se muestrea, cada límite y su tope, cómo los hallazgos de varios
archivos se convierten en una sola decisión, y con qué responde cada modo. El gateway sigue limitado
a loopback y sigue sin estar aprobado para tráfico de producción.

## Qué solicitudes se inspeccionan

La inspección es deliberadamente estrecha. Una solicitud se almacena en memoria y se inspecciona solo
cuando se cumplen **todas** las condiciones siguientes, comprobadas en este orden en
`UploadInspectionService.EvaluateAsync`:

1. `Gateway:Multipart:Enabled` es `true`.
2. El `Mode` del sitio resuelto no es `Disabled`.
3. El `Content-Length` declarado no es cero.
4. La solicitud declara `multipart/form-data`, ya sea con un boundary que el gateway acepta o con uno
   que rechaza — véase [Boundaries](#boundaries).

Todo lo demás continúa en streaming directo, sin coste de memoria adicional y sin cambio de
comportamiento: solicitudes `GET`, formularios `application/x-www-form-urlencoded`, llamadas REST en
JSON, XML-RPC, `PUT` de `application/octet-stream` y subtipos `multipart/*` distintos de `form-data`.
El tráfico corriente de páginas de WordPress no debe empezar a pagar por cargas que no contiene, y no
lo hace.

> [!IMPORTANT]
> La condición 4 tiene dos desenlaces, no uno. Una solicitud que declara `multipart/form-data` con un
> boundary que el gateway no analizará **no** se trata como tráfico corriente: es un hallazgo. Un
> gateway que reenvía lo que no puede analizar entrega al atacante una evasión de una sola línea: un
> boundary inusual y la solicitud pasa sin inspeccionar mientras IIS y PHP la analizan sin problema.

## Por qué el cuerpo se almacena en memoria, y qué lo acota

Para **bloquear**, el gateway tiene que decidir antes de reenviar. Para **reenviar**, tiene que leer
el cuerpo una segunda vez. Un flujo de red no se puede leer dos veces. Por eso, y solo para
solicitudes multipart, el cuerpo ya acotado se almacena en memoria, se inspecciona y se reenvía desde
ese búfer.

Cuatro propiedades lo hacen seguro, y cada una es una propiedad del código y no de un ajuste:

- **Nunca a disco, por construcción.** El búfer es `PooledRequestBuffer`, un `Stream` de solo lectura
  con posicionamiento sobre una lista de arreglos de 64 KiB alquilados a `ArrayPool<byte>.Shared`. No
  referencia ningún `FileStream`, `File`, `Path` ni archivo mapeado en memoria, así que no hay ruta a
  disco que haya que demostrar inalcanzable. `Microsoft.AspNetCore.WebUtilities.FileBufferingReadStream`
  se descartó exactamente por eso: su volcado a disco se desactiva con un valor de umbral, y una
  garantía que un colaborador futuro puede deshacer editando un número no es la garantía que este
  proyecto promete. Dos pruebas sostienen esa garantía. Una redirige todas las variables de entorno
  de directorio temporal que consulta el framework — incluida `ASPNETCORE_TEMP`, que es la que lee
  `FileBufferingReadStream` —, pasa una batería de cuerpos por el lector y exige que el directorio
  siga vacío. La otra revisa las referencias de tipos del ensamblado del gateway y falla si aparece
  alguno capaz de escribir un archivo, con un control positivo que verifica que el escaneo sí ve
  `MultipartReader`, de modo que un escaneo que no leyera nada no pueda pasar sin demostrar nada.
- **Nunca sin límite.** `RequestBodyLimitStream` ahora se instala *antes* del paso de inspección y no
  justo antes del reenvío, de modo que el vaciado hacia el búfer queda acotado por
  `Gateway:MaximumRequestBytes`. Ese orden es lo importante: un cuerpo chunked que no declara
  `Content-Length` se almacenaría de otro modo sin límite. `PooledRequestBuffer` aplica el mismo tope
  una segunda vez y lanza si se supera.
- **Devuelto en toda vía de salida.** Los bloques vuelven al pool en `Dispose`, invocado desde el
  mismo `finally` de `ForwardRequestAsync` que restaura `HttpRequest.Body` — así que se devuelven en
  éxito, en rechazo, en desconexión del cliente, en timeout y en excepción. `Dispose` es idempotente,
  porque devolver un mismo arreglo al pool dos veces lo entregaría a dos solicitudes concurrentes, y
  el síntoma sería la carga de un visitante apareciendo en la evidencia de otro.
- **Solo para multipart.** Una solicitud que incumple cualquiera de las cuatro condiciones anteriores
  nunca reserva un bloque.

El búfer se divide en bloques en lugar de usar un único arreglo del tamaño exacto porque
`ArrayPool<byte>.Shared` redondea los alquileres al siguiente bucket potencia de dos: alquilar 6 MiB
devuelve un arreglo de 8 MiB, desperdiciando un tercio y dejando una asignación en el montón de
objetos grandes por cada solicitud concurrente. Un bloque de 64 KiB se devuelve exacto y queda por
debajo del umbral de 85.000 bytes de ese montón, y los bloques crecen sin copiar — lo que importa
porque el caso controlado por el atacante es precisamente el cuerpo chunked sin longitud declarada.

### Dos fases, y por qué importa la separación

La tubería primero vacía el cuerpo acotado completo y después analiza el búfer. Esa separación es lo
que permite que toda superación de límite sea un hallazgo mientras Monitor mantiene su promesa de
reenviar la solicitud intacta: una vez completado el vaciado, el cuerpo está completo decida lo que
decida después el analizador, porque analizar no toca la red. Solo un timeout en fase de vaciado
puede dejar un cuerpo parcial, y ese es el único caso que no puede terminar en un reenvío.

## Qué se analiza y qué se muestrea

`MultipartInspectionReader` recorre el cuerpo almacenado con `MultipartReader` y reduce cada parte a
metadatos acotados. Lee cada parte de archivo dos veces: como máximo `SampleBytes` en un arreglo de
trabajo del pool, copiados después a un arreglo privado del tamaño exacto; y después el resto en un
arreglo de trabajo fijo de 8 KiB que se sobrescribe y se descarta. Esa segunda pasada existe solo
para que el recuento de bytes reportado sea exacto: el gateway se entera de cuán grande era la carga
sin llegar a retenerla nunca.

| Forma de la parte | Se trata como | Se cuenta | Se muestrea | Se inspecciona |
| --- | --- | --- | --- | --- |
| Sin parámetro `filename` ni `filename*` | Campo de formulario | Contra `MaximumFieldCount` | **No** | No |
| `filename=""` **y** cuerpo de cero bytes | `<input type="file">` sin seleccionar | Como campo | No | No |
| `filename=""` con cuerpo no vacío | Archivo | Contra `MaximumFileCount` | Sí | Sí |
| Cualquier otro `filename` o `filename*` | Archivo | Contra `MaximumFileCount` | Sí | Sí |

Tres de esas filas evitan un comportamiento predeterminado roto de fábrica:

- **Las partes de campo nunca se muestrean.** Muestrearlas haría que `PHP-CONTENT-001` se disparara
  en cada cuerpo de entrada de WordPress, cada guardado del editor de temas o cada widget de
  constructor de páginas que contenga un fragmento de código.
- **`filename=""` sobre un cuerpo vacío es un input de archivo sin seleccionar.** Los navegadores
  envían exactamente eso por cada input de archivo vacío de un formulario enviado, y PHP registra
  `UPLOAD_ERR_NO_FILE`. Sin esta regla, `FILE-NAME-001` puntuaría 60 por `emptyAfterNormalization` en
  tráfico administrativo rutinario de WordPress: un falso positivo el primer día de uso real.
- **Se leen `filename` y `filename*`, y ambos se inspeccionan.** `Content-Disposition` puede llevar
  los dos y no tienen por qué coincidir. El propio `MultipartSection.AsFileSection()` de ASP.NET Core
  prefiere `filename*`; el manejador multipart de PHP lee solo `filename`. Así que
  `filename*=UTF-8''photo.jpg` junto a `filename="shell.php"` es una solicitud que es deliberadamente
  dos archivos a la vez. Cuando los dos discrepan, el lector emite **ambos** nombres compartiendo una
  sola muestra, de modo que gana el resultado más severo y el diferencial de analizadores se cierra
  en vez de elegir un bando. `AsFileSection()` no se usa, por el mismo motivo.

Una parte cuyo `Content-Disposition` esté ausente, o que lleve **dos** parámetros `filename`, es
`Malformed` y detiene la lectura. Este analizador toma el primero de esos parámetros y el de PHP toma
el último, así que ambos inspeccionarían y escribirían nombres distintos.

Los metadatos se acotan con independencia de la muestra: nombres de archivo a 1024 caracteres,
nombres de campo a 1024, el `Content-Type` declarado de la parte a 256, y las cabeceras de la parte a
`MaximumPartHeaderBytes` repartidas en 16 cabeceras como máximo. Un nombre de archivo por encima de
su tope es en sí mismo una superación de límite y no un truncamiento silencioso: cortar la cola de
`aaaa….php` elimina el `.php` y convierte una detección en una omisión.

## Límites

Todos los valores siguientes se enlazan desde `Gateway:Multipart`. La configuración puede **bajar** un
tope, nunca subirlo. Los topes se aplican dos veces a propósito: `GatewayConfigurationValidator` lanza
al arrancar, de modo que a un operador que pide algo que el gateway no hará se le dice en lugar de
sobrescribirlo en silencio; y `MultipartInspectionReader` vuelve a acotar en el punto de uso, de modo
que un objeto de opciones construido directamente en código no puede levantar un tope saltándose el
validador.

| Configuración | Predeterminado | Rango permitido | Qué acota |
| --- | ---: | ---: | --- |
| `Enabled` | `true` | `true` / `false` | Si se almacena algún cuerpo o corre alguna regla sobre tráfico real |
| `MaximumFileCount` | 20 | 1 a 100 | Partes de archivo inspeccionadas antes de detener la lectura |
| `MaximumFieldCount` | 200 | 1 a 1000 | Partes que no son archivo contadas antes de detener la lectura |
| `MaximumPartHeaderBytes` | 16 KiB (`16384`) | 1 a 32 KiB (`32768`) | `MultipartReader.HeadersLengthLimit` |
| `SampleBytes` | 4096 | **512** a 64 KiB (`65536`) | Bytes iniciales retenidos por archivo para las reglas de contenido |
| `ReadTimeoutSeconds` | 30 | 1 a 120 | Plazo que cubre el vaciado **y** el análisis |

Otros tres límites están fijados en el código en lugar de configurarse: un boundary tiene de 1 a 70
caracteres, una parte puede llevar 16 cabeceras como máximo, y un nombre de archivo se acota a 1024
caracteres.

> [!WARNING]
> `SampleBytes` tiene un piso de **512**, no de 1. Por debajo de 512 bytes la clasificación
> texto-contra-binario se degrada y desaparece la tolerancia de `%PDF-`, de modo que `FILE-TYPE-001`
> y `PHP-CONTENT-002` empezarían a decidir con muestras demasiado cortas para decidir. Sin ese piso,
> un número que parece una perilla de rendimiento desactivaría en silencio dos reglas mientras la
> configuración seguiría diciendo `"Enabled": true`.

### Cuánto cuesta esto en memoria

Es una regresión real frente al gateway anterior a M2, que no retenía memoria de cuerpo por
solicitud. Con los valores predeterminados, una solicitud multipart retiene aproximadamente
**6,15 MiB** durante hasta 30 segundos — como máximo 97 bloques de 64 KiB, más 20 muestras de 4 KiB,
más 12 KiB de trabajo. Con los peores valores configurables legalmente, con `MaximumRequestBytes` en
su tope de 64 MiB y 100 archivos con muestras de 64 KiB, son aproximadamente **70,3 MiB** por
solicitud.

Hoy nada acota el número de solicitudes almacenadas concurrentemente.
`KestrelServerLimits.MaxConcurrentConnections` es ilimitado por defecto y el gateway solo establece
`MaxRequestBodySize`. Como `ReadTimeoutSeconds` acota cuánto tiempo cada solicitud retiene su búfer,
sostener una cantidad dada de memoria fijada le cuesta al atacante una tasa de subida proporcional —
y modesta. Las palancas que existen hoy son:

- `Gateway:MaximumRequestBytes` divide el peor caso directamente. Bajarlo a 2 MiB reduce la
  exposición en cerca de dos tercios.
- `Gateway:Multipart:ReadTimeoutSeconds` acorta la retención y eleva proporcionalmente el ancho de
  banda que el atacante necesita.
- `Kestrel:Limits:MaxConcurrentConnections` como instrumento contundente. **No** está expuesto a
  través de `GatewayOptions` y debe fijarse directamente en la configuración de Kestrel.

Un límite explícito sobre inspecciones almacenadas concurrentes es trabajo de M3. Hasta que llegue,
la restricción a loopback no es solo una afirmación sobre la madurez del proyecto: es además lo único
que acota esta memoria.

## Boundaries

Un boundary se acepta solo en una forma sobre la que el gateway y el backend no puedan discrepar.
Deben cumplirse las cinco condiciones:

1. Exactamente **una** línea de cabecera `Content-Type`. Kestrel no rechaza los duplicados y
   `HttpRequest.ContentType` los une con `", "`. Dos líneas `Content-Type` es un sondeo clásico de
   diferencial de analizadores: si WPShield analiza un valor mientras IIS, ARR o PHP analiza el otro,
   WPShield inspeccionó una solicitud distinta de la que se ejecuta.
2. Tipo de medio exactamente `multipart/form-data`, ordinal y sin distinguir mayúsculas. Los demás
   subtipos `multipart/*` quedan fuera de alcance porque PHP puebla `$_FILES` solo para `form-data`.
3. Un parámetro `boundary`, sin comillas — RFC 2046 exige entrecomillar cuando el boundary contiene un
   espacio, así que quitar las comillas no es opcional.
4. De 1 a 70 caracteres una vez quitadas las comillas.
5. Únicamente `bchars` de RFC 2046, con el espacio prohibido en la última posición. Esta es la
   comprobación que mantiene CR, LF, `"`, `;` y `\` fuera del analizador.

Cualquier otra cosa, **cuando la solicitud declaró `multipart/form-data`**, es `Malformed`.

**Falsos positivos.** RFC 2046 limita un boundary a 70 caracteres, pero el propio
`FormOptions.MultipartBoundaryLengthLimit` de Kestrel tiene 128 por defecto y es probable que PHP
acepte también la forma larga. Un cliente de API a medida con un generador de boundaries inusual que
produzca de 71 a 128 caracteres queda por tanto rechazado por WPShield y aceptado por todo lo que lo
rodea. Esa franja es toda la superficie de falsos positivos de esta regla. El modo Monitor la registra
como Warning con el valor observado antes de que Block pueda convertirla en un rechazo.

## Cómo los hallazgos de varios archivos se convierten en una decisión

`InspectionEngine.InspectAsync` ejecuta cada regla registrada contra un archivo y suma los hallazgos,
limitando el total a 100. El gateway combina después los resultados por archivo:

- **El puntaje es el máximo entre archivos, y se usa solo para registro.** Sumar entre archivos
  dejaría que veinte archivos benignos de 30 cada uno alcanzaran 600 y bloquearan una solicitud en la
  que nada está mal — y `FILE-NAME-001` puntúa 60 y se dispara con los nombres de ruta local completa
  que envían algunos clientes antiguos, así que tres de ellos cruzarían el umbral de bloqueo por sí
  solos. El máximo también da gratis "un archivo de 90 bloquea sin importar qué lo acompañe", y niega
  el ataque de dilución en el sentido contrario.
- **La acción es el `RecommendedAction` más severo entre archivos, leído directamente del motor y
  nunca vuelto a derivar del puntaje.** El motor ya aplica los umbrales *y* la degradación de
  Monitor a Observe. Una segunda implementación en el gateway es exactamente donde una edición futura
  olvida la degradación y Monitor empieza a bloquear en silencio.

Superar un límite, o no poder analizar, es **en sí mismo** un hallazgo, emitido bajo el
pseudoidentificador de regla del gateway `GATEWAY-MULTIPART-001`. Si "el lector se rindió"
significara "reenvíalo", un atacante podría anteponer a su carga veintiún archivos ficticios y
comprar un reenvío sin inspección para el vigésimo segundo. Una prueba del lector esconde un archivo
peligroso detrás del límite de archivos y verifica que nunca se inspecciona, y dos pruebas de
integración llevan ese mismo cuerpo por todo el gateway: Block responde 415 con
`reason: limit_exceeded` y nunca contacta al backend, mientras que Monitor reenvía el cuerpo byte a
byte y registra el límite en Warning.

## Qué hace cada modo

| Situación | `Disabled` | `Monitor` (predeterminado) | `Block` |
| --- | --- | --- | --- |
| No multipart, o `Enabled: false` | Reenvía, sin búfer | Reenvía, sin búfer | Reenvía, sin búfer |
| Multipart, sin hallazgo | Reenvía, sin búfer | Reenvía desde el búfer | Reenvía desde el búfer |
| Multipart, puntaje igual o superior a `ObserveThreshold` | Reenvía, sin búfer | Reenvía y registra Warning como `Observe` | Reenvía y registra Warning |
| Multipart, puntaje igual o superior a `BlockThreshold` | Reenvía, sin búfer | Reenvía y registra Warning como `Observe` | **403** `upload_blocked` |
| El cuerpo no pudo inspeccionarse por completo: `Malformed`, `LimitExceeded` o timeout de análisis | Reenvía, sin búfer | Reenvía intacto y registra Warning | **415** `multipart_not_inspectable` |
| El cuerpo no llegó completo dentro de `ReadTimeoutSeconds` | Reenvía, sin búfer | **408** `request_timeout` | **408** `request_timeout` |
| El cuerpo superó `Gateway:MaximumRequestBytes` | **413** | **413** | **413** |
| El cliente se desconectó a mitad de la carga | No se escribe nada; se registra Information | No se escribe nada; se registra Information | No se escribe nada; se registra Information |

El 408 aplica también en Monitor, y es deliberado. La promesa de Monitor es que WPShield nunca
bloquea por un *hallazgo*, y un cuerpo a medio llegar no es un hallazgo: es una solicitud que el
cliente no consiguió entregar. Reenviar lo que llegó enviaría a WordPress un cuerpo más corto que su
`Content-Length` declarado, produciendo una carga corrupta y un error de backend que el operador no
puede atribuir a WPShield. El 413 ya sentó ese precedente: los controles absolutos de recursos
aplican en los tres modos.

Una desconexión del cliente no escribe nada, porque la conexión ya se fue, y se registra como
Information en lugar de Error. Un visitante que cierra una pestaña a mitad de carga es algo
corriente; `Error` en este componente debe significar que el gateway está roto.

## Respuestas

WPShield genera ahora una respuesta propia en siete situaciones: las cuatro ya documentadas — `421`
para un host desconocido, `413` para un cuerpo excedido, `502` para un backend inalcanzable y `404`
para una sonda de salud no permitida — más las tres nuevas de M2.

```json
{
  "error": "upload_blocked",
  "requestId": "correlation-id",
  "ruleIds": ["FILE-TYPE-001", "PHP-CONTENT-001", "WP-UPLOAD-001"]
}
```

```json
{
  "error": "multipart_not_inspectable",
  "requestId": "correlation-id",
  "reason": "malformed",
  "ruleIds": ["GATEWAY-MULTIPART-001"]
}
```

```json
{
  "error": "request_timeout",
  "requestId": "correlation-id"
}
```

`reason` es `malformed` cuando el cuerpo no es multipart válido o el boundary fue rechazado, y
`limit_exceeded` cuando un límite de archivos, campos, cabeceras o nombre detuvo la lectura —
incluido un plazo alcanzado mientras se analizaba un cuerpo ya almacenado. `ruleIds` va ordenado, sin
repetidos y acotado a 16.

**Por qué se revelan los identificadores de regla y no el puntaje.** WPShield es de código abierto, y
el catálogo completo de reglas — identificadores, puntajes y lógica de coincidencia — ya está
publicado en el [README](../../README.md) de este repositorio y en las
[reglas de carga](m2-reglas-carga.md). Ocultar los identificadores no protege nada que un atacante no
pueda leer, mientras que el coste de ocultarlos recae por completo en el lado legítimo: un 403 opaco
no le da al dueño del sitio ningún camino desde el navegador hasta la causa, y "me bloqueó el archivo
y no dice por qué" es como se termina apagando una herramienta de seguridad. El puntaje es el caso
opuesto. Un permitir/denegar binario obliga a una búsqueda a ciegas, pero un puntaje numérico
convierte la evasión en escalada de colina, porque cada mutación informa cuánto se acercó. Revelar lo
que está publicado; retener lo que es derivado. Si WPShield llegara a tener paquetes de reglas no
públicos, ese compromiso habría que revisarlo para esas reglas en concreto.

Por eso los cuerpos de rechazo nunca llevan el nombre de archivo crudo ni el normalizado, ni el
nombre de campo, ni la muestra, ni la evidencia, ni el identificador del sitio, ni el destino, ni el
puntaje, ni los umbrales. Tampoco se envía `Retry-After`: implicaría que el rechazo es transitorio e
invitaría a un bucle de reintentos contra una decisión que no va a cambiar.

Toda respuesta que WPShield genera lleva ahora `X-WPShield-Request-ID`, `X-Content-Type-Options:
nosniff` y `Cache-Control: no-store`. Eso es una corrección, no una repetición. `HttpResponse.Clear()`
borra las cabeceras además del código de estado, así que los escritores anteriores de `413` y `502`
borraban ambas cabeceras propias, contradiciendo la promesa documentada de que toda respuesta las
lleva. La vía del `421` nunca llamaba a `Clear()`, y por eso la inconsistencia sobrevivió: la
diferencia era invisible salvo que se compararan dos respuestas de fallo lado a lado.

## Qué registran los logs

Un evento por archivo **con hallazgos**, no uno por hallazgo: una solicitud en los topes absolutos
emitiría si no 100 archivos × 8 reglas = 800 líneas. Cada uno lleva el identificador de solicitud, el
del sitio, el método, la ruta sin su query string, el `PartIndex` asignado por el gateway, el nombre
**normalizado**, el puntaje, la acción, los identificadores de regla y la evidencia.

Un evento de resumen por solicitud inspeccionada registra el recuento de archivos y campos, el estado
de lectura, el puntaje, la acción, los identificadores de regla, los bytes almacenados y si la
solicitud se reenvió o se rechazó — además de `WouldBlock`, que responde a "¿qué pasa si activo Block
en este sitio?" con los registros que el operador ya tiene. Ese es exactamente el sentido de correr
Monitor primero.

Nada en ninguna de las dos líneas lo suministra el atacante. El nombre de archivo crudo, el nombre de
campo, la muestra y todo valor de cabecera están ausentes por construcción: un nombre crudo puede
llevar caracteres de control, secuencias de escape ANSI y saltos de línea directamente a un archivo
de registro o a una terminal, y para eso existe `NormalizedFileName`. Dos pruebas de integración
verifican que ni los registros ni el cuerpo de rechazo contienen un nombre crudo, una muestra, una
query string o un valor de cabecera.

## Configuración

```json
{
  "Gateway": {
    "Urls": ["http://127.0.0.1:10000"],
    "AllowRemoteHealthChecks": false,
    "ActivityTimeoutSeconds": 100,
    "MaximumRequestBytes": 6291456,
    "Multipart": {
      "Enabled": true,
      "MaximumFileCount": 20,
      "MaximumFieldCount": 200,
      "MaximumPartHeaderBytes": 16384,
      "SampleBytes": 4096,
      "ReadTimeoutSeconds": 30
    }
  },
  "Sites": [
    {
      "Id": "wordpress-one",
      "Hosts": ["wordpress-one.example", "www.wordpress-one.example"],
      "Destination": "http://127.0.0.1:8081",
      "Mode": "Monitor",
      "ObserveThreshold": 30,
      "BlockThreshold": 80
    }
  ]
}
```

Un valor fuera de rango impide el arranque en lugar de acotarse, con un mensaje que nombra la
configuración y su rango:

```text
Gateway:Multipart:MaximumFileCount must be between 1 and 100.
Gateway:Multipart:MaximumFieldCount must be between 1 and 1000.
Gateway:Multipart:MaximumPartHeaderBytes must be between 1 and 32768 bytes.
Gateway:Multipart:SampleBytes must be between 512 and 65536 bytes.
Gateway:Multipart:ReadTimeoutSeconds must be between 1 and 120 seconds.
```

El gateway imprime en cada arranque los límites que realmente aplicará, y lo dice en voz alta cuando
la inspección está apagada:

```text
info: WPShield.Gateway.Configuration
      Multipart upload inspection enabled. MaximumRequestBytes=6291456 MaximumFileCount=20 MaximumFieldCount=200 MaximumPartHeaderBytes=16384 SampleBytes=4096 ReadTimeoutSeconds=30
warn: WPShield.Gateway.Configuration
      Multipart upload inspection is DISABLED by configuration. No upload rule will run on live traffic.
```

`Gateway:Multipart` es un objeto JSON y no un arreglo, así que la fusión elemento a elemento de
arreglos descrita en [configuración del operador](configuracion-operador.md) no le aplica: una capa
de override que fija un valor multipart deja el resto en sus valores de fábrica.

> [!IMPORTANT]
> La configuración no se recarga en caliente. Estas opciones se validan una sola vez al arrancar y se
> capturan para toda la vida del proceso. Reinicie el gateway para aplicar un cambio y lea la línea
> anterior para confirmar que tuvo efecto.

## Trampas operativas

Tres condiciones son las que con más probabilidad encontrará el tráfico legítimo. Cada una registra
Warning con el valor observado en modo Monitor, de forma que el operador la ve antes de que Block
pueda convertirla en un rechazo.

- **Un cliente lento con una carga grande recibe un 408.** Treinta segundos contra un cuerpo de
  6 MiB implican un piso sostenido de unos 205 KiB/s. Un cliente móvil o satelital subiendo una
  imagen a tamaño completo puede quedar por debajo. Subir `ReadTimeoutSeconds` a 120 baja el piso a
  unos 51 KiB/s. Esta es la condición con más probabilidad de generar tráfico de soporte.
- **Un constructor de páginas o un plugin de formularios puede superar los 200 campos.** La mayoría
  de los formularios administrativos grandes de WordPress son `application/x-www-form-urlencoded` y
  nunca llegan a este código, pero un formulario grande enviado *con* un archivo adjunto llega como
  multipart. `MaximumFieldCount` llega hasta 1000.
- **Un boundary de 71 a 128 caracteres se rechaza.** Véase [Boundaries](#boundaries).

Los falsos positivos propios de cada regla están documentados en
[reglas de carga](m2-reglas-carga.md). Permanezca en modo Monitor hasta haber revisado el tráfico de
cargas de su propio sitio.

## Qué sigue sin hacer M2

Dicho claramente, porque una línea de estado que diga "inspección multipart: disponible" invita al
lector a suponer más de lo que es cierto:

1. **No se inspecciona ningún cuerpo que no sea multipart.** `application/x-www-form-urlencoded`,
   JSON, XML-RPC y los `PUT` de `application/octet-stream` pasan sin tocarse.
2. **Los subtipos `multipart/*` distintos de `form-data` pasan de largo**, porque PHP puebla
   `$_FILES` solo para `form-data`.
3. **Las partes de campo de formulario nunca se inspeccionan**, por diseño — véase el razonamiento
   anterior.
4. **Nunca se abre el contenido de un archivo comprimido.** Una carga `.zip` de plugin o tema que
   contenga un webshell no se detecta, y instalar un plugin es una vía de carga legítima de
   WordPress. Es la mayor laguna aislada y todavía no tiene hito asignado.
5. **Solo se examinan los primeros `SampleBytes` de cada archivo.** Un marcador colocado más allá de
   la ventana de muestreo no se ve, y tampoco la cola de un poliglota de portador grande.
6. **Nada acota las inspecciones almacenadas concurrentes.** Véase
   [Cuánto cuesta esto en memoria](#cuánto-cuesta-esto-en-memoria).
7. **Solo se inspeccionan solicitudes.** Los cuerpos de respuesta nunca se leen.

## Reversión

Ponga `Gateway:Multipart:Enabled` en `false` y reinicie el gateway. Toda solicitud pasará entonces en
streaming como antes de M2: no se almacena ningún cuerpo, no se toma ninguna muestra y ninguna regla
de carga corre sobre tráfico real. El aviso de arranque anterior lo dirá en cada inicio. Es una vía
de escape para incidentes, no una perilla de ajuste — un gateway con la inspección desactivada es un
proxy inverso con un límite de tamaño.

No modificar bindings públicos de IIS, DNS, certificados, firewall ni servicios de Windows.

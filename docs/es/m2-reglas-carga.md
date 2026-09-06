# Reglas de carga y normalización de nombres de archivo

WPShield inspecciona el nombre que la carga tendrá realmente en disco, no el que escribió el cliente.
Este documento explica por qué esa distinción importa en Windows, qué detecta cada regla y dónde cada
regla puede equivocarse.

## Por qué la normalización va primero

La implementación original comparaba `Path.GetExtension(fileName)` contra una lista de extensiones
PHP. Esa comprobación es correcta sobre el papel y evadible en la práctica, porque Windows y NTFS
normalizan varias formas antes de escribir el archivo:

| Nombre enviado | `Path.GetExtension` | Llega a disco como | Regla anterior |
| --- | --- | --- | --- |
| `shell.php` | `.php` | `shell.php` | bloqueaba |
| `shell.php.` | *(vacío)* | `shell.php` | **pasaba** |
| `shell.php ` | `.php ` | `shell.php` | **pasaba** |
| `shell.php::$DATA` | `.php::$DATA` | `shell.php` | **pasaba** |
| `photo.php.jpg` | `.jpg` | `photo.php.jpg` | **pasaba** |
| `web.config` | `.config` | `web.config` | **pasaba** |
| `shell.aspx` | `.aspx` | `shell.aspx` | **pasaba** |

`NormalizedFileName` reproduce el mismo colapso que haría el sistema de archivos, en este orden:

1. Elimina caracteres de control, incluido el `NUL` incrustado, que trunca nombres en las API nativas.
2. Conserva solo el último segmento de ruta, descartando prefijos `../` o `..\`.
3. Corta en el primer `:`, eliminando sufijos de flujo de datos alternativo NTFS como `::$DATA`.
4. Recorta puntos y espacios finales, que Windows elimina en silencio al escribir.
5. Divide el resultado en **todos** los segmentos de extensión, en minúsculas.

Cada eliminación se registra como una marca, de modo que `FILE-NAME-001` puede informar qué se quitó
sin que ninguna regla tenga que volver a analizar el nombre crudo.

> [!IMPORTANT]
> No dé por hecho que WordPress saneará el nombre por usted. Los endpoints de plugins vulnerables que
> provocan incidentes de carga son precisamente los que escriben archivos sin llamar a
> `sanitize_file_name()`. Esa es la razón de que WPShield inspeccione la solicitud.

## Reglas

| ID de regla | Señal | Puntaje | ¿Bloquea sola? |
| --- | --- | --- | --- |
| `IIS-CONFIG-001` | La carga se llama `web.config` | 100 | Sí |
| `WP-UPLOAD-001` | Extensión ejecutable PHP en posición final | 90 | Sí |
| `WP-UPLOAD-001` | Extensión ejecutable PHP en posición intermedia | 50 | No |
| `IIS-UPLOAD-001` | Extensión ejecutable de IIS en posición final | 90 | Sí |
| `IIS-UPLOAD-001` | Extensión ejecutable de IIS en posición intermedia | 50 | No |
| `PHP-CONTENT-002` | Firma de imagen válida con código PHP demostrado más allá de los datos de la propia imagen | 85 | Sí |
| `PHP-CONTENT-001` | `<?php` o `<?=` en la muestra acotada | 75 | No |
| `FILE-TYPE-001` | La extensión declara un formato binario y los bytes llevan un marcador de script | 70 | No |
| `FILE-TYPE-001` | La extensión declara un documento o archivo multimedia y los bytes son `MZ` o ELF | 70 | No |
| `FILE-TYPE-001` | La extensión declara un formato binario y los bytes son texto plano | 40 | No |
| `FILE-NAME-001` | Anomalía estructural en el nombre | 60 | No |
| `WP-UPLOAD-002` | Extensión ejecutable disfrazada tras una inocua | 30 | No |

Los puntajes se suman **dentro de un mismo archivo** y se limitan a 100. Los umbrales por defecto de
un sitio son `ObserveThreshold` 30 y `BlockThreshold` 80.

Cuando una solicitud lleva varios archivos, el gateway toma el **máximo** entre ellos, nunca la suma:
veinte archivos benignos de 30 cada uno alcanzarían si no 600 y bloquearían una solicitud en la que
nada está mal. Véase [inspección multipart acotada](m2-inspeccion-multipart.md) para saber cómo se
alcanzan estas reglas sobre tráfico real y qué hace el gateway con el resultado.

### `IIS-CONFIG-001` — carga de web.config

La regla de mayor confianza que trae WPShield, y la que una capa de protección orientada a Linux no
tiene. IIS lee `web.config` en cada directorio que sirve y lo aplica a ese directorio y a sus hijos.
Un atacante que escriba uno en `wp-content/uploads` puede registrar un mapeo de handler que ejecute
los archivos que él elija, reactivar la ejecución de scripts que el operador deshabilitó, o relajar
la autorización del directorio. Convierte una escritura arbitraria de archivo en ejecución remota de
código sin subir un solo script.

La regla coincide únicamente con el nombre reservado exacto, tras la normalización, de modo que
`web.config.`, `WEB.CONFIG`, `web.config::$DATA` y `../web.config` quedan cubiertos, mientras que la
descarga de un `app.config` no relacionado no se ve afectada.

**Falsos positivos:** ninguno previsto. Ningún flujo de WordPress sube un `web.config` en el cuerpo
de una solicitud.

### `WP-UPLOAD-001` — extensión ejecutable PHP

Cubre `php`, `php3`–`php8`, `phps`, `pht`, `phtm`, `phtml` y `phar`, comparando contra todos los
segmentos de extensión y no solo el último.

**Falsos positivos:** una coincidencia intermedia puntúa 50 en lugar de 90 porque `readme.php.txt` es
estructuralmente idéntico a `photo.php.jpg` y no puede distinguirse solo por el nombre. Combinado con
`WP-UPLOAD-002` ese nombre alcanza 80 y sería bloqueado, así que permanezca en modo Monitor hasta
haber revisado su propio tráfico de cargas.

### `IIS-UPLOAD-001` — extensión ejecutable de IIS

Cubre `aspx`, `asp`, `ashx`, `asmx`, `ascx`, `axd`, `cshtml`, `vbhtml`, `razor`, `svc`, `soap`,
`rem`, `asax` y `master`. Un archivo `.aspx` en un directorio de cargas con permiso de escritura se
ejecuta con la identidad del grupo de aplicaciones, una capacidad estrictamente mayor que la de un
shell PHP.

**Falsos positivos:** un sitio WordPress no tiene motivo legítimo para aceptar un handler de ASP.NET
por un endpoint de carga. Un sitio que realmente distribuya esos archivos como descargas debería
mantener esa ruta en modo Monitor.

### `WP-UPLOAD-002` — extensión disfrazada

Se dispara cuando existe un segmento ejecutable en posición no final. Aporta un puntaje
deliberadamente pequeño porque es una señal de disfraz y no una prueba de ejecución, y solo importa
combinada con `WP-UPLOAD-001` o `IIS-UPLOAD-001` reportando el mismo nombre.

**Falsos positivos:** los nombres corrientes con varias extensiones nunca coinciden, porque la regla
exige un segmento ejecutable y no simplemente más de un segmento. `archive.tar.gz`, `style.min.css`,
`jquery.min.js` y `report.2024.xlsx` permanecen silenciosos.

### `FILE-NAME-001` — nombre estructuralmente inseguro

Informa lo que la normalización tuvo que eliminar: `pathSeparator`, `alternateDataStream`,
`trailingDotsOrSpaces`, `controlCharacter`, `reservedDeviceName`, `excessiveLength`,
`emptyAfterNormalization`.

**Falsos positivos:** los nombres Unicode no se marcan, solo los caracteres de control. Algunos
navegadores y clientes antiguos envían la ruta local completa en lugar del nombre a secas, así que
`pathSeparator` puede dispararse con tráfico legítimo. Esa es la razón principal de que la regla
puntúe 60 y no pueda bloquear por sí sola.

### `PHP-CONTENT-001` — etiqueta PHP en la muestra

**Limitación conocida, no un defecto.** La regla busca en una muestra UTF-8 acotada. Puede evadirse
colocando la etiqueta más allá de la ventana de muestreo, codificando el archivo en UTF-16 o
partiendo la etiqueta en el límite de la muestra. Tampoco detecta las etiquetas cortas `<?`, porque
`short_open_tag` está desactivado por defecto en PHP moderno y buscarla marcaría todo documento XML.
Trate esta regla como una señal de apoyo, nunca como el único motivo para bloquear.

### `FILE-TYPE-001` — la extensión y el contenido no coinciden

Todas las reglas anteriores razonan sobre el *nombre*. Esta razona sobre los *bytes*, porque
`photo.jpg` es un nombre perfecto y las reglas de nombre no tienen nada que decir al respecto.
WordPress decide qué es una carga a partir de su extensión, y `wp_check_filetype_and_ext()` consulta
los bytes reales solo para un puñado de tipos; un endpoint de plugin que escribe el archivo por su
cuenta no consulta nada.

El único disparador es **la extensión final frente a los bytes iniciales**. El segmento final es la
afirmación que el archivo hace sobre sí mismo: es lo que el handler estático de IIS mapea a un tipo
MIME y lo que WordPress guarda en el registro del adjunto. Un segmento ejecutable en posición no
final es otra pregunta, ya respondida por `WP-UPLOAD-001` y `WP-UPLOAD-002`.

Pueden dispararse tres niveles, y ninguno bloquea por sí solo:

| Nivel | Condición | Puntaje |
| --- | --- | ---: |
| `script` | Un marcador de script validado — `<?php`, `<?=`, `<%`, `<script`, `#!/` — donde se declaró un formato binario. También se busca sobre una decodificación UTF-16 cuando la muestra abre con una marca de orden de bytes | 70 |
| `nativeExecutable` | Una cabecera `MZ` o ELF que se corrobora a sí misma, donde se declaró una extensión de imagen, audio, video, fuente o PDF | 70 |
| `text` | Texto legible por humanos donde se declaró un formato binario, sin marcador encontrado | 40 |

70 es Observe por sí solo y alcanza 100 combinado con los 75 de `PHP-CONTENT-001`, que es el
resultado correcto para un `photo.jpg` cuyos bytes iniciales son PHP.

**El `Content-Type` declarado nunca dispara un hallazgo.** Los navegadores derivan el `Content-Type`
de una parte a partir de la misma extensión mediante el registro del sistema operativo, así que en
tráfico legítimo no aporta información que la extensión no llevara ya — y curl, wp-cli, las
aplicaciones móviles y la vía alternativa de plupload envían legítimamente
`application/octet-stream`. Se registra en la evidencia como un token de cuatro estados (`agrees`,
`disagrees`, `opaque`, `absent`) y nada más, de modo que ningún texto de cabecera suministrado por el
atacante llega a un registro.

**Falsos positivos.** La regla guarda silencio por construcción en los casos que los generan, y cada
silencio tiene un coste declarado:

- **Cargas por fragmentos.** Con un tope de solicitud de 6 MiB, toda carga multimedia grande debe
  llegar como fragmentos de plupload, y del fragmento 2 en adelante cada parte se llama `photo.jpg`
  sin firma en el desplazamiento 0. Por eso los bytes no reconocidos *nunca* son un hallazgo: es la
  decisión que sostiene toda la regla. Cuesta un webshell escrito en UTF-16 sin marca de orden de
  bytes, y otro cuyo marcador quede más allá de la ventana de muestreo.
- **Renombrados entre formatos.** HEIC guardado como `.jpg`, WebP como `.png`, JPEG como `.webp`. El
  "guardar imagen como" de Chrome, los compartidos de iOS y las galerías de Android los producen
  constantemente y el archivo sigue siendo una imagen benigna, así que reconocido-pero-distinto es
  silencio. Comparar por familia también implica que `.docx`, `.xlsx`, `.pptx` y `.odt` nunca
  discrepan entre sí, ya que las cuatro son una misma familia ZIP.
- **Archivos autoextraíbles.** Un `.zip`, `.7z` o `.rar` empieza legítimamente con `MZ`, así que el
  nivel `nativeExecutable` aplica solo a extensiones de imagen, audio, video, fuente y PDF. El coste
  es que un ejecutable renombrado `invoice.doc` pasa en silencio.
- **Exportaciones de plugins de informes.** Escribir una tabla HTML o un CSV bajo un nombre `.xls`
  está extendido en plugins de informes y analítica. Es un error del exportador, no un ataque, así
  que las extensiones antiguas de Office quedan exentas del nivel `text` — aunque no del nivel
  `script`.
- **Formatos sin firma y desconocidos.** SVG, TXT, CSV, JSON, XML, HTML y TAR no tienen número
  mágico, así que no hay expectativa que violar; una extensión que WPShield nunca ha visto no afirma
  nada. Ambos casos son silencio.
- **La única combinación que bloquea tráfico benigno.** El nivel `text` con 40 más `FILE-NAME-001`
  con 60 son exactamente 100. `FILE-NAME-001` se dispara con clientes antiguos que envían la ruta
  local completa, así que un archivo de cuerpo textual con extensión binaria desde un cliente así
  quedaría bloqueado en modo Block. Es una intersección estrecha de dos comportamientos de cliente
  poco habituales, y es la razón de que el nivel `text` puntúe 40 y no 70. Permanezca en modo Monitor
  hasta haber revisado su propio tráfico de cargas.

### `PHP-CONTENT-002` — PHP añadido más allá del final de una imagen válida

`GIF89a;` seguido de un script PHP es un GIF válido seguido de un script PHP. `getimagesize()` lo
acepta, toda comprobación de firma lo acepta, y `FILE-TYPE-001` lo acepta porque la firma coincide
realmente con la extensión. Ha sido la evasión estándar de la validación de cargas de WordPress
durante una década, y lo único que la separa de una fotografía es **dónde queda el marcador PHP
respecto de la estructura de la propia imagen**.

La regla se dispara solo cuando se cumplen las tres condiciones:

1. La muestra abre con una firma del conjunto de `getimagesize()` — GIF, PNG, JPEG, BMP o RIFF con la
   forma `WEBP`. Son exactamente los formatos que acepta la propia validación de imágenes de
   WordPress, que es exactamente lo que ataca la evasión.
2. Un recorrido estructural acotado establece dónde terminan los datos del contenedor: un recorrido
   de bloques GIF hasta el terminador `3B`, un recorrido de chunks PNG hasta el final de `IEND`, un
   recorrido de segmentos JPEG hasta `FF D9`, o la longitud de archivo que declara una cabecera BMP o
   RIFF.
3. Un marcador PHP validado aparece en ese límite o más allá.

Si el recorrido no puede establecer el límite, la regla guarda silencio. Nunca cae a un nivel más
débil.

**Por qué se basa en prueba y no en heurística.** Esta regla es un subconjunto estricto de
`PHP-CONTENT-001`: ambas buscan `<?php` y `<?=` en la misma muestra acotada, así que cuando esta se
dispara, los 75 de la otra ya están sobre la mesa. El motor suma y limita a 100, lo que significa que
*cualquier* hallazgo concurrente de 5 o más cruza el umbral de bloqueo predeterminado de 80. No hay
puntaje con el que esta regla sea una señal moderada: es un interruptor de bloquear o no, cuya única
perilla de ajuste es la precisión. Por eso la condición de disparo se estrechó hasta ser una prueba
estructural, en lugar de bajar el puntaje. 85 y no 100 mantiene una gradación por debajo de
`IIS-CONFIG-001`, que es definicional, y da una posición con sentido al operador que sube
`BlockThreshold` a 90.

El nombre del archivo se ignora por completo. Un poliglota es peligroso bajo cualquier nombre, y ser
solo de contenido hace que la regla componga con las reglas de nombre en vez de contarlas dos veces.
El nombre normalizado se registra igualmente en la evidencia para que el operador pueda localizar la
parte.

**Falsos positivos.** El caso que decide si esta regla es publicable es la fotografía con metadatos, y
tres cosas la mantienen callada. `<?xpacket` y `<?xml` no son marcadores PHP — el conjunto es `<?php`
y `<?=` únicamente — así que un paquete XMP corriente no coincide con nada. Un marcador dentro de un
segmento de metadatos queda estructuralmente por debajo del límite que establece el recorrido, así
que un segmento `APPn` o `COM` de JPEG, un chunk `tEXt`, `iTXt` o `zTXt` de PNG y una extensión de
comentario GIF se recorren sin buscar en ellos: un desarrollador que captura código PHP en pantalla y
lo sube con el código en un pie XMP obtiene `PHP-CONTENT-001` con 75, un Observe, y nada de esta
regla. Y `<?=` solo se cree cuando los dieciséis bytes siguientes se leen como texto imprimible; sin
esa guarda, aproximadamente una imagen de cada cuatro mil se convertiría en una carga bloqueada.

ZIP y PDF quedan excluidos del conjunto de contenedores por completo — instalar un plugin o un tema
*es* subir un ZIP lleno de PHP, y un PDF sobre PHP contiene la etiqueta de apertura como prosa —, al
igual que TIFF, ICO, ISO base media y Matroska, ninguno de los cuales ofrece una prueba barata ni es
el formato que usa la evasión.

**Límite conocido.** El recorrido solo ve la muestra acotada. En una fotografía real con carga
añadida, el `EOI` del JPEG queda cientos de kilobytes más allá de la ventana de muestreo, así que no
se establece nada y esta regla guarda silencio — igual que `PHP-CONTENT-001`, ya que la carga también
queda fuera de la muestra. Lo que esta regla atrapa es el poliglota de *portador mínimo*: el fragmento
`GIF89a;` de siete bytes, el GIF pequeño de uno por uno, el JPEG de cuatro bytes. Esas son las formas
que usan realmente las evasiones publicadas, porque el atacante quiere el portador más pequeño que
sobreviva a la validación. Cerrar el caso de portador grande exige una estrategia de muestreo que lea
además la cola del cuerpo, y eso no es algo que una regla pueda arreglar.

## Ejemplo resuelto

Enviar `..\..\photo.php.jpg.` con una etiqueta PHP en el cuerpo produce:

```json
{
  "SiteId": "wordpress-one",
  "Score": 100,
  "RecommendedAction": "Observe",
  "Findings": [
    { "RuleId": "WP-UPLOAD-001", "Score": 50,
      "Evidence": { "extension": ".php", "position": "embedded", "normalizedName": "photo.php.jpg" } },
    { "RuleId": "WP-UPLOAD-002", "Score": 30,
      "Evidence": { "executableExtension": ".php", "presentedExtension": ".jpg" } },
    { "RuleId": "FILE-NAME-001", "Score": 60,
      "Evidence": { "anomalies": "pathSeparator,trailingDotsOrSpaces" } },
    { "RuleId": "PHP-CONTENT-001", "Score": 75 }
  ]
}
```

La acción es `Observe` y no `Block` porque el sitio de ejemplo corre en modo Monitor. La evidencia
siempre reporta el nombre normalizado, nunca el crudo, de modo que un nombre con caracteres de
control no puede llegar intacto a un consumidor de registros.

## Agregar una regla

Una regla nueva debe llegar con un identificador estable sin traducir, las señales que combina, su
puntaje y el razonamiento detrás, un análisis explícito de falsos positivos, fixtures benignos de
prueba que deban permanecer silenciosos, y documentación en inglés y español. Use marcadores
sintéticos inofensivos en las pruebas. Nunca haga commit de un webshell funcional.

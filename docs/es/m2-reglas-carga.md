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
| `PHP-CONTENT-001` | `<?php` o `<?=` en la muestra acotada | 75 | No |
| `FILE-NAME-001` | Anomalía estructural en el nombre | 60 | No |
| `WP-UPLOAD-002` | Extensión ejecutable disfrazada tras una inocua | 30 | No |

Los puntajes se suman por solicitud y se limitan a 100. Los umbrales por defecto de un sitio son
`ObserveThreshold` 30 y `BlockThreshold` 80.

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

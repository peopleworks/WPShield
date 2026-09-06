# Inspección de la ruta de la solicitud

WPShield inspecciona la línea de solicitud de cada petición, antes de que nada lea un cuerpo.

Hasta M2 solo inspeccionaba cuerpos `multipart/form-data`. Eso cubre el instante en que un webshell
llega y nada más — y un shell que ya está en disco no se sube, se **pide**, con un `GET` común que no
lleva ningún cuerpo que una regla de carga pueda mirar. Las dos mitades del problema necesitan dos
familias de reglas: una rechaza la escritura, esta rechaza la lectura.

## De dónde salió esto

No de un modelo de amenazas. De un sitio WordPress comprometido sobre IIS, cuyos registros del
servidor guardaron el tráfico de explotación completo. Se recuperaron seis webshells. Cada petición
que alcanzó uno fue un `GET` o `POST` ordinario a un archivo `.php` existente. **Ninguna llevaba
cuerpo**, así que ninguna era visible para regla alguna de las que WPShield tenía.

Las ubicaciones dicen qué deben cubrir las reglas:

| Dónde estaba el shell | Lo detecta |
| --- | --- |
| Junto al JavaScript de un editor de código incrustado, bajo `static/` | `WP-PATH-002` |
| Junto a las hojas de estilo de una piel de slider, bajo `static/` | `WP-PATH-002` |
| Una segunda copia junto al JavaScript del mismo editor | `WP-PATH-002` |
| En la biblioteca de medios, de un incidente cuatro años anterior | `WP-PATH-001` |
| Un segundo en la biblioteca de medios, de la misma época | `WP-PATH-001` |
| **En el propio directorio PHP del plugin, junto a sus archivos reales** | **Nada. Ver abajo.** |

Cinco de seis alcanzan el umbral de bloqueo por defecto solo con la línea de solicitud. El sexto no,
y eso quedó escrito en la suite de pruebas como un hueco afirmado en lugar de como una impresión.

## Las reglas

### `WP-PATH-001` — ejecutable pedido desde el árbol de cargas

Puntaje **100**, que bloquea por sí solo.

Dispara cuando una petición ejecutaría un script desde `wp-content/uploads`, `wp-content/upgrade` o
`wp-content/updraft`. Esos directorios son datos: WordPress escribe medios y archivos comprimidos ahí
y los devuelve como bytes. Nada del núcleo, y ningún plugin correcto, enruta ejecución a través de
ellos.

Los plugins sí *colocan* PHP bajo `uploads` — All-In-One WP Security guarda ahí su configuración de
cortafuegos — pero esos archivos se alcanzan con `include` desde PHP, nunca por HTTP. Rechazar la
petición HTTP no le quita nada a nadie, y eso es lo que justifica un puntaje que bloquea solo.

### `WP-PATH-002` — ejecutable pedido desde un directorio solo de recursos

Puntaje **100**, que bloquea por sí solo.

Dispara cuando una petición ejecutaría un script debajo de alguno de:

```
dist  build  _next  out  node_modules  bower_components  static  fonts  webfonts  img  images
```

Cada nombre denota un directorio que existe para contener bytes que el navegador descarga tal cual. Un
script dentro de uno es un intruso o un accidente de empaquetado, y en ambas lecturas ningún llamante
necesita que la petición tenga éxito.

**Lo que falta a propósito importa más que lo que está.** `assets`, `css`, `js`, `media` y `vendor`
son los nombres que casi todo el mundo agregaría después, y los cinco están excluidos. Los plugins
antiguos sí sirven hojas de estilo y scripts generados desde PHP — `css/style.php` y `js/script.php`
son un patrón real, aunque pasado de moda — y `vendor` es un árbol de Composer que algunos plugins
exponen. Agregarlos habría puesto un puntaje de bloqueo sobre tráfico que hoy funciona, y una
herramienta de seguridad que rompe un sitio que funciona se apaga, llevándose consigo las reglas que
sí estaban bien.

El puntaje descansa en esa estrechez. En el momento en que se agregue un nombre para el cual "un
script aquí no puede tener un llamante HTTP legítimo" no sea cierto, el puntaje está mal y la adición
es el defecto.

### `IIS-PATH-001` — forma insegura de ruta

Puntaje **60**, que observa y no bloquea por sí solo.

Reporta lo que la normalización tuvo que deshacer: un segmento `..`, una barra invertida actuando como
separador, un sufijo de flujo de datos alternativo de NTFS, puntos o espacios finales, caracteres de
control incrustados, una ruta fuera de los límites, o un segundo decodificado por porcentaje que
produjo una ruta distinta. Cada una de estas hace que la ruta que llega al disco difiera de la ruta
que se inspeccionó, que es toda la técnica.

60 coincide con `FILE-NAME-001` deliberadamente. Por sí sola, una forma rara de ruta merece registro y
no rechazo: clientes descuidados y capas de caché viejas producen rutas que necesitan aseo. Su trabajo
real es la línea de log — un operador que ve `traversal` o `doubleEncoded` está mirando
reconocimiento, haya alcanzado algo ese intento o no.

## Normalización

Las reglas nunca comparan contra el destino crudo de la petición. Comparan contra
`InspectionContext.NormalizedPath`, que reduce una ruta a lo que un servidor web de Windows
realmente resolvería.

| Entrada | Se normaliza a |
| --- | --- |
| `/WP-Content/Uploads/Shell.PHP` | `/wp-content/uploads/shell.php` |
| `/wp-content\uploads\shell.php` | `/wp-content/uploads/shell.php` |
| `/wp-content/uploads/shell.php.` | `/wp-content/uploads/shell.php` |
| `/wp-content/uploads/shell.php::$DATA` | `/wp-content/uploads/shell.php` |
| `/wp-content/uploads/anidado/../shell.php` | `/wp-content/uploads/shell.php` |
| `/wp-content//uploads//shell.php` | `/wp-content/uploads/shell.php` |

### Cada segmento, y cada posición de extensión

`/wp-content/uploads/shell.php/logo.jpg` ejecuta `shell.php`. Con `cgi.fix_pathinfo` habilitado — lo
predeterminado en muchas instalaciones de PHP-FastCGI sobre Windows — PHP retrocede hasta el último
componente que existe en disco y le entrega el resto al script como `PATH_INFO`. Una regla que mirara
el último segmento vería una imagen.

`/wp-content/uploads/shell.php.jpg` es el mismo razonamiento un nivel más abajo, y el mismo
razonamiento que las reglas de carga ya aplican a los nombres de archivo: revisar cada segmento de
extensión, no solo el final.

### Dos vistas

El host entrega una ruta que ya decodificó una vez. Algunas cadenas de reescritura de IIS decodifican
otra vez, así que `%252e%252e%252f` llega aquí con el aspecto inerte de `%2e%2e%2f` y se convierte en
traspaso de directorio un decodificado después — en un punto donde nada está inspeccionando.

Por eso se construye una segunda vista cuando, y solo cuando, un decodificado más cambia la ruta. Las
reglas evalúan ambas y toman el primer resultado, primero la vista literal.

Es la misma forma que las dos vistas de nombre de archivo, y por la misma razón: modelar solo la
normalización que hace el inspector, en lugar de la que hace el backend, es como `web.con{f}ig` sacó
cero contra una regla documentada como sin falsos positivos.

**Lo que no se modela**, dicho y no descubierto después: ningún tercer decodificado, y ninguna
expansión de nombres cortos 8.3, que necesita el sistema de archivos y no puede responderse desde una
ruta sola.

## Costo

Una normalización más tres evaluaciones de regla por petición, todo trabajo de cadenas acotado a 64
segmentos de 255 caracteres. La segunda vista se construye solo cuando la ruta contiene un signo de
porcentaje y solo cuando decodificar la cambia, así que el tráfico ordinario paga una pasada.

Nada de esto bufferea, parsea un cuerpo ni toma una muestra. Un rechazo se responde desde la línea de
solicitud, lo que significa que una petición de webshell bloqueada cuesta estrictamente menos que una
reenviada.

## Orden en la tubería

```
resolver sitio → límite de tamaño → reglas de ruta → inspección multipart → reenvío
```

La inspección de ruta corre antes de que se toque el cuerpo. Una petición rechazada aquí nunca llega
al paso de buffering, y un sitio en modo `Disabled` se salta ambos.

## Lo que esto no cubre

- **Un shell en un directorio que legítimamente contiene PHP.** El sexto shell del incidente estaba en
  el propio directorio PHP de su plugin, con un nombre a un carácter de uno real. Nada en la ruta lo
  distingue. Detectarlo requiere saber qué archivos trae realmente una versión de un plugin, o
  comportamiento a lo largo del tiempo — y una heurística ajustada para atrapar ese nombre sería
  ajustar la regla a la muestra.
- **Cadenas de consulta.** Solo se inspecciona la ruta. `Path` y nunca `Path + QueryString`, para que
  "nunca registrar una cadena de consulta completa" se cumpla en el origen.
- **Cuerpos de solicitud.** Sin cambios respecto a M2: solo se inspecciona `multipart/form-data`.
- **Contenido de las respuestas.** El tráfico de explotación del incidente era distinguible por sus
  *respuestas* — 200 con un cuerpo de 24 bytes para un sondeo, 500 para la carga útil. WPShield no
  mira las respuestas en absoluto.

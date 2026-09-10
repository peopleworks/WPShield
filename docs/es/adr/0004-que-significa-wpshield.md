# ADR 0004 — Qué significa WPShield, y qué no cubre todavía

- **Estado:** Aceptado
- **Deciden:** Mantenedores de WPShield
- **Afecta:** el nombre, el README, el sitio, y dónde va una regla que no trate de WordPress
- **Corregida:** 2026-09-09 — véase abajo. La decisión sigue en pie; una de sus premisas de hecho no.

## Corrección — 2026-09-09

**La sección de Contexto exagera cuánto del conjunto de reglas trata de WordPress, y esta ADR se
aceptó con ese error dentro.** Se corrige aquí y no en silencio, porque el error es de la misma clase
de defecto sobre la que se escribió la ADR.

### Cómo ocurrió

El inventario detrás de la afirmación original fue un solo comando:

```
grep -rhoE '"(WP|FILE|MULTIPART)-[A-Z]+-[0-9]+"'
```

Buscó los tres prefijos que el autor ya esperaba y encontró exactamente esos tres. **La medición
llevaba su propia conclusión dentro.** Es la misma forma que el preflight que reportaba comprobar una
familia de reglas que no podía reconocer — al que esta misma ADR cita, cuatro secciones más abajo,
como parte de la evidencia de su propia decisión.

### Qué se publica de verdad, regla por regla

| | Reglas | ¿Reportarían algo en un sitio que no es WordPress? |
| --- | --- | --- |
| Acopladas a WordPress | `WP-PATH-001` | **No.** Reconoce por nombre los pares de directorios `wp-content/uploads`, `wp-content/upgrade` y `wp-content/updraft`. |
| Conscientes de WordPress | `WP-UPLOAD-001`, `WP-UPLOAD-002`, `IIS-UPLOAD-001`, `IIS-CONFIG-001`, `FILE-NAME-001` | **Sí.** Deciden sobre la vista NTFS del nombre. La vista de `sanitize_file_name()` es una *segunda* vista que solo agrega hallazgos, y vive en `WPShield.Abstractions`, no en el paquete de WordPress. |
| Sin nada de WordPress dentro | `WP-PATH-002`, `IIS-PATH-001`, `PHP-CONTENT-001`, `PHP-CONTENT-002`, `FILE-TYPE-001` | **Sí.** `PHP-CONTENT-001` es `<?php` o `<?=` en la muestra y nada más. |

`WP-PATH-002` es el caso más agudo. Su lista de directorios es `dist`, `build`, `_next`, `out`,
`node_modules`, `bower_components`, `static`, `fonts`, `webfonts`, `img` e `images` — ni un solo
directorio de WordPress, y `_next` es de Next.js. Lleva un prefijo `WP-` que la condición de salida 3
prohíbe, y ya se publicaba el día en que se escribió esa condición.

### Qué sobrevive a la corrección

La brecha es real y la decisión sigue en pie, pero es una brecha distinta de la registrada. No es que
las reglas solo sepan de WordPress. Son tres cosas:

- **Empaquetado.** Once reglas en un solo ensamblado llamado `WPShield.Rules.WordPress`, cinco de las
  cuales no contienen nada de WordPress. El leg de CI en Linux ya compila y prueba ese paquete sin
  dependencias de Windows, que es evidencia de lo mismo desde el otro lado.
- **Cobertura.** Nada en `src/` fuera de la CLI menciona `.env`, `.git`, `.bak` ni `.sql`. El escaneo
  que llega a los sesenta y seis sitios sigue sin encontrarse ninguna regla. **Esa afirmación era
  cierta y sigue siéndolo**, y es la parte que importaba.
- **Etiquetado.** Un identificador ya publicado miente sobre lo que es.

Las condiciones de salida quedaron replanteadas contra esas tres. La sección de Contexto conserva su
redacción original con el error marcado, porque una ADR que borra sus errores deja de ser un
registro.

## Contexto

El nombre se eligió la primera semana, para un proyecto que inspeccionaba subidas de WordPress detrás
de IIS. Se lamenta desde aproximadamente la segunda, en palabras del propio operador:

> Qué pena que sólo le llame WPShield, debí llamarle IISShield o algo más, porque los ataques van a
> todos los sites aunque no sean WordPress.

Desde entonces el proyecto dejó de ser lo que el nombre describe. **Esto no es un nombre que
envejeció; es la cosa detrás del nombre que fue rediseñada.**

| | Diseño original | Hoy |
| --- | --- | --- |
| Superficie de operador | 5.561 líneas de PowerShell | `wpshield.exe`, verbos, `/?`, argumentos tipados |
| Alcance de la inspección | El sitio | El sitio **y el host** — tareas programadas, servicios, cuentas, autoruns, historial de Defender |
| Fuerza bruta | Sin atender | [ADR 0002](0002-defensa-fuerza-bruta-a-nivel-de-host.md), y rate limiting construido |
| Ruta de tráfico | [ADR 0001](0001-ruta-de-trafico-en-produccion.md), IIS delante | También una opción verificada de binding directo por HTTP.SYS |
| Cómo se sabe que algo funciona | Leyendo el script | Comprobado: orden de los pasos, permisos, disciplina de modos |

De esa lista, ~~**solo el motor de reglas trata de WordPress.**~~ La CLI, el preflight, el instalador,
el triage de host, el limitador de tasa y el registro tratan de Windows y de IIS.

> **La frase tachada es falsa.** De las once reglas publicadas, una está acoplada a WordPress, cinco
> son conscientes de WordPress, y cinco no contienen nada de WordPress. Véase la corrección al inicio
> de este archivo. El resto del párrafo, y la medición de abajo, no se ven afectados.

### La medición que lo vuelve urgente

El servidor para el cual se construyó este proyecto corre **sesenta y seis sitios de IIS. Su propio
preflight detecta dos como WordPress.** Los otros sesenta y cuatro son aplicaciones .NET — una API de
facturación electrónica, un portal de clientes de ERP, un servidor de BI, un relay, un host de
automatización, y cincuenta más.

WPShield hoy le habla a dos de sesenta y seis y le da la espalda al resto. Los ataques no: un escaneo
buscando `.env`, `web.config`, una ruta de administración expuesta o un respaldo olvidado en una raíz
web va contra todos ellos.

## La propuesta

Conservar las letras y cambiar lo que significan. **WPShield = Windows Power Shield.**

No cuesta nada medible: el repositorio conserva su URL, los espacios de nombres conservan su prefijo,
todo enlace existente sigue funcionando, los artefactos publicados conservan su nombre, y un servicio
instalado conserva su identidad. Lo que cambia es lo que el nombre afirma.

## Opciones

### Opción A — Renombrar a algo explícito

`IISShield`, `WinShield` o similar. Compra claridad al precio de cada espacio de nombres, cada enlace
de documentación, el sitio publicado, los nombres de artefacto, el nombre del servicio en cada
instalación existente, y la cuenta `NT SERVICE\WPShield` a la que un operador ya le concedió permisos.

Es una migración grande y enteramente cosmética para un proyecto con trabajo real pendiente, y sería
la segunda migración en una semana para el mismo operador.

### Opción B — Conservar el nombre con el significado "WordPress Shield" y quedarse solo en WordPress

Honesto sobre las reglas y deshonesto sobre todo lo demás. El preflight, el instalador, el triage de
host y el limitador de tasa no son funcionalidades de WordPress ni lo fueron nunca, y un nombre que
describe solo el motor de reglas describe alrededor de una quinta parte del código.

*(Tras la corrección de arriba esta opción queda aún más débil: tampoco sería honesta sobre las
reglas. Diez de las once disparan en un sitio que nunca ha corrido WordPress.)*

Además cierra la dirección que señala la medición, en un servidor donde el nombre estaría protegiendo
dos sitios de sesenta y seis.

### Opción C — Conservar las letras, cambiar lo que significan, y anotar la deuda

**WPShield = Windows Power Shield**, adoptado ya como declaración de dirección, con la distancia entre
el nombre y el código registrada aquí y con condiciones de salida nombradas.

## Decisión

**Opción C**, con una condición que no es negociable.

**El nombre declara una dirección. El README y el sitio deben declarar qué se cubre hoy**, en la
primera pantalla que ve un lector — no en una nota al pie ni implícito en un diagrama de arquitectura.

Esa condición es el punto entero de este ADR, y viene de tres días encontrando el mismo defecto con
ropa distinta:

- un instalador que reportaba haber endurecido un directorio en el que el gateway nunca escribió
- un preflight que reportaba comprobar una familia de reglas que no podía reconocer
- un gateway que se reportaba sano mientras no escribía evidencia alguna

Cada uno era una herramienta afirmando un estado que no había alcanzado. **Un nombre que afirma
protección para todo Windows mientras solo publica reglas de WordPress es ese mismo defecto, en el
tipo de letra más grande posible.** Adoptarlo sin escribir esto sería la versión de ese error que este
proyecto menos merecería.

## Qué vuelve verdadero el nombre

Tres condiciones de salida. Hasta que las tres se cumplan, este ADR es lo que mantiene visible la
promesa.

*Replanteadas el 2026-09-09. Las originales se escribieron contra la premisa falsa corregida al
inicio de este archivo: las condiciones 1 y 2 pedían algo que el código ya había hecho en parte, y la
condición 3 pedía algo que una regla publicada ya estaba violando.*

1. **Las reglas que no tratan de WordPress están empaquetadas donde corresponde, y la superficie .NET
   está cubierta.** Dos mitades, y la primera no es "escribir un segundo paquete" — es *partir el que
   existe*. `WPShield.Rules.Windows` se lleva las cinco reglas que no contienen nada de WordPress; el
   paquete de WordPress conserva `WP-PATH-001` y las cinco que consultan la vista de
   `sanitize_file_name()`. La segunda mitad es la que de verdad falta: **ninguna regla en ningún lado
   lee `.env`, `.git`, un `.bak` o `.sql` olvidado, ni una ruta de administración expuesta**, que es
   justamente todo lo que un escaneo le manda a los sesenta y cuatro sitios. La arquitectura ya
   permite ambas: `WPShield.Abstractions` y `WPShield.Core` están libres de ASP.NET Core, YARP, IIS y
   dependencias de Windows, y un leg de CI en Linux compila y prueba esos dos más el paquete de
   reglas, que es lo que mantiene esa afirmación falsable.

2. **El README y el sitio dicen qué se cubre hoy.** Un lector debe poder enterarse, sin desplazarse,
   de qué superficie alcanzan las reglas — las subidas de WordPress, y la superficie de Windows, IIS,
   PHP y nombres de archivo debajo de ellas — y cuál no alcanzan en absoluto: la superficie de
   aplicaciones .NET que presentan esos sesenta y cuatro sitios.

3. **El esquema de identificadores de regla tiene sitio para ello, y ningún identificador miente.**
   `WP-` significa WordPress y debe seguir significándolo; una familia que no trate de WordPress
   necesita su propio prefijo en vez de archivarse bajo uno que miente sobre ella. **`WP-PATH-002`
   rompe esto hoy** — su lista de directorios es salida de compilación y árboles de paquetes, y su
   prefijo dice WordPress. Renombrar un identificador publicado es un cambio incompatible para todo
   hallazgo almacenado y para cualquier consulta que un operador haya guardado, así que es su propia
   decisión y no un efecto secundario de esta; se nombra aquí para que no se olvide.

## Consecuencias

### `WPShield.Rules.WordPress` conserva su nombre, por una razón peor que la escrita al principio

~~Es un paquete de reglas de WordPress y el nombre es exactamente correcto.~~ **Corregido el
2026-09-09.** El nombre no es correcto: cinco de las once reglas que contiene no llevan nada de
WordPress. Conserva el nombre de todas formas, porque renombrar un ensamblado y partirlo son trabajos
distintos y solo el segundo vale la pena — la condición de salida 1 pide la partición, y después de
ella el paquete que quede sí merecerá el nombre que ya tiene.

### Vale la pena nombrar la ironía en voz alta

"Power Shield" se lee cerca de PowerShell, y la [ADR 0003](0003-herramientas-de-operador-en-dotnet.md)
acaba de borrar 2.668 líneas de él. Es un chiste que el proyecto se ganó más que un problema, pero si
algún lector llegara a entender el nombre como "un escudo escrito en PowerShell", el README habrá
fallado en la condición de salida 2 y ahí es donde se arregla.

### Esto no autoriza que el alcance crezca sin freno

Que el nombre apunte a Windows no significa que todo problema de Windows pertenezca aquí. La
[ADR 0002](0002-defensa-fuerza-bruta-a-nivel-de-host.md) ya decidió que el bloqueo a nivel de
cortafuegos vive en un proyecto hermano y no en este, y esa decisión sigue en pie. Este ADR amplía de
qué pueden tratar las reglas; no amplía lo que hace el gateway.

### Hoy no cambia nada del código

Ninguna regla, ningún umbral, ninguna ruta de tráfico, ningún valor por omisión y ningún espacio de
nombres. Un cambio de nombre que alterara el comportamiento en silencio sería la peor manera posible
de hacerlo.

## Lo que este ADR no decide

- **Qué reglas cubren la superficie .NET.** La condición de salida 1 dice que esa superficie debe
  cubrirse. No dice con qué. Los candidatos son tan obvios que resultan peligrosos — `.env`, `.git`,
  respaldos, rutas de administración — y escogerlos desde un modelo de amenazas es como un conjunto
  de reglas termina puntuando cosas que nadie manda. Se escogen contra los registros reales de este
  servidor, y esa es su propia decisión.
- **A qué se renombra `WP-PATH-002`, y cuándo.** Un identificador de regla publicado aparece en los
  hallazgos almacenados y en lo que un operador haya construido encima. Cambiar uno es un cambio
  incompatible y necesita su propia ADR, una ruta de deprecación, o ambas.
- **Si el repositorio se renombra alguna vez.** La Opción A sigue disponible si las letras llegan a
  confundir más de lo que valen.

## Cuándo revisar esta decisión

Revísela si la condición de salida 1 sigue sin cumplirse cuando el proyecto llegue a su primera
versión. Publicar un 1.0 llamado *Windows Power Shield* que solo sabe de WordPress convertiría una
declaración de dirección en una afirmación, y este ADR existe precisamente para que eso no ocurra en
silencio.

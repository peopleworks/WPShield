# ADR 0004 — Qué significa WPShield, y qué no cubre todavía

- **Estado:** Aceptado
- **Deciden:** Mantenedores de WPShield
- **Afecta:** el nombre, el README, el sitio, y dónde va una regla que no trate de WordPress

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

De esa lista, **solo el motor de reglas trata de WordPress.** La CLI, el preflight, el instalador, el
triage de host, el limitador de tasa y el registro tratan de Windows y de IIS.

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

1. **Un segundo paquete de reglas que no trate de WordPress, publicado y activo por omisión.** La
   arquitectura ya lo anticipa: `WPShield.Abstractions` y `WPShield.Core` están libres de ASP.NET
   Core, YARP, IIS y dependencias de Windows — un leg de CI en Linux compila y prueba exactamente
   esos tres proyectos, que es lo que mantiene esa afirmación falsable. `WPShield.Rules.WordPress` es
   un paquete, no el motor.

2. **El README y el sitio dicen qué se cubre hoy.** Un lector debe poder enterarse, sin desplazarse,
   de que las reglas de hoy son reglas de WordPress y que las herramientas de host no lo son.

3. **El esquema de identificadores de regla tiene sitio para ello.** Hoy todo identificador es `WP-*`,
   `FILE-*` o `MULTIPART-*`. `WP-` significa WordPress y debe seguir significándolo; una familia que
   no trate de WordPress necesita su propio prefijo en vez de archivarse bajo uno que miente sobre
   ella.

## Consecuencias

### `WPShield.Rules.WordPress` conserva su nombre

Es un paquete de reglas de WordPress y el nombre es exactamente correcto. Nada de este ADR lo
renombra — el punto es que pase a ser *uno de* los paquetes de reglas en vez de *el* paquete de
reglas.

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

- **De qué trata el segundo paquete de reglas.** El candidato obvio es la superficie .NET sobre IIS
  que presentan sesenta y cuatro de esos sesenta y seis sitios, y hay evidencia medida disponible para
  ello, pero elegir sus reglas es su propia decisión, tomada contra registros reales y no contra un
  modelo de amenazas. Este proyecto aprendió esa diferencia de forma cara.
- **Si el repositorio se renombra alguna vez.** La Opción A sigue disponible si las letras llegan a
  confundir más de lo que valen.

## Cuándo revisar esta decisión

Revísela si la condición de salida 1 sigue sin cumplirse cuando el proyecto llegue a su primera
versión. Publicar un 1.0 llamado *Windows Power Shield* que solo sabe de WordPress convertiría una
declaración de dirección en una afirmación, y este ADR existe precisamente para que eso no ocurra en
silencio.

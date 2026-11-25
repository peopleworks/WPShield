# ADR 0012 — WPShield Packs: datos, nunca código

- **Estado:** Propuesta
- **Deciden:** Pedro Hernández (mantenedor)
- **Afecta a:** el recolector de evidencia, `WPShield.Evidence`, el servidor MCP y el analista,
  `wpshield`, el escritorio y el directorio `packs/` del repositorio

## Contexto

El mantenedor quiere que otros puedan ampliar WPShield: detecciones nuevas, preguntas nuevas para un
asistente, reglas web nuevas. La forma obvia es un plugin, una biblioteca que alguien escribe y
WPShield carga. Aquí esa forma es un error, por una razón. **WPShield corre elevado.** El servicio, la
CLI elevada y el servidor MCP pueden leer el registro de seguridad, el almacén de evidencia y la
configuración de IIS de todos los sitios. Un plugin cargado en cualquiera de ellos corre con esos
mismos permisos. Un solo plugin malicioso o comprometido sería una puerta trasera instalada por la
propia herramienta de seguridad. Es un ataque a la cadena de suministro, y es justo el tipo de
compromiso que este proyecto existe para ver.

La comunidad de seguridad ya amplía herramientas sin entregar código:

- Los packs de **osquery** son consultas sobre tablas de solo lectura.
- Las reglas **Sigma** describen en YAML detecciones sobre los registros de eventos, y hay miles
  publicadas.
- Las plantillas de **Nuclei** describen las rutas que pide un escáner.

Tienen algo en común: la herramienta las ejecuta con su propio motor. Una regla solo puede pedir lo
que el motor sabe hacer.

MCP ya es ampliable también en la otra dirección. Un cliente como Claude Desktop se conecta a varios
servidores a la vez, así que cualquiera puede correr su propio servidor MCP al lado del de WPShield
sin que WPShield cargue nada.

## Decisión

**Un WPShield Pack es un archivo declarativo. Lo ejecuta el motor propio de WPShield, dentro de una
lista cerrada de capacidades. Un pack nunca contiene, nombra ni provoca código.** El código de
terceros nunca entra en un proceso de WPShield.

### 1. Qué es un pack

Un archivo JSON de como mucho 256 KB, con:

- `id` (en minúsculas, como mucho 24 caracteres), `version`, `title`, `author`, `license` (un
  identificador SPDX), `description` y `sources` (de dónde sale su conocimiento);
- una lista de **capacidades**, cada una de uno de los tipos de abajo.

Los campos y los tipos desconocidos se rechazan, nunca se ignoran. Un pack que WPShield no entiende
del todo no corre a medias.

### 2. Capacidades, una lista cerrada

| Tipo | Qué puede hacer | Qué hace WPShield con él |
| --- | --- | --- |
| `event-detection` | Nombrar un canal de registro de eventos, un conjunto de ids de evento, condiciones sobre campos con nombre (igual, empieza por, termina en, contiene, uno de, una expresión regular acotada) y los campos que se conservan | El recolector lo evalúa sobre los eventos en vivo y registra cada coincidencia en `events` con el tipo `pack.<id>`, solo con los campos declarados, cada uno limpio y acotado |
| `http-path-rule` | Describir formas de ruta sobre la ruta de solicitud normalizada: segmentos exactos, extensiones, sufijos y prefijos, la forma de la familia de exposición | Se evalúa sobre la evidencia de los logs de IIS del ADR 0011. Su puntuación no pasa del umbral de observación: una regla de un pack informa y nunca bloquea sola |
| `mcp-query` | Nombrar una pregunta agregada sobre los eventos del propio pack: recuentos por un campo declarado, sobre una lista cerrada de rangos | Se publica como herramienta MCP de solo lectura `pack_<id>_<nombre>`, agregada, con los valores que puede influir el atacante bajo `untrusted` (ADR 0008) |

**Las expresiones regulares** se compilan con `RegexOptions.NonBacktracking` y un tiempo máximo por
coincidencia, para que un pack no pueda gastar el tiempo del recolector con un patrón patológico.

**Lo que ninguna capacidad puede hacer:**

- ejecutar un programa, un script, PowerShell o un lenguaje de consultas;
- cargar un ensamblado;
- abrir una conexión de red;
- escribir un archivo;
- cambiar un ajuste;
- añadir una decisión o un bloqueo;
- leer nada fuera de su canal, sus campos o sus rutas declarados.

Leer clases WMI y valores del registro es una capacidad para más adelante. Cuando llegue, cubrirá una
lista cerrada de clases, propiedades y claves, en una enmienda que las nombre.

### 3. Confianza: lo que el operador aprueba es exactamente lo que corre

- Los packs viven en `%ProgramData%\WPShield\packs\`, un directorio que crea la instalación con los
  mismos permisos restringidos que el directorio de evidencia.
- `wpshield packs validate <archivo>` comprueba un pack sin instalarlo. `wpshield packs add <archivo>`
  lo valida y lo copia allí. WPShield nunca descarga un pack; el operador trae el archivo.
- **Activar un pack registra su SHA-256.** El ajuste auditado `packs.enabled` asocia el id de cada pack
  al hash que aprobó el operador, con quién y por qué, como todo ajuste. Un archivo cuyo hash ya no
  coincide no se carga, y la discrepancia se informa. Cambiar un pack significa aprobarlo de nuevo.
- Antes de activar un pack, `wpshield packs show <id>` y el escritorio muestran exactamente qué lee:
  - sus canales e ids de evento, y los campos que conserva;
  - las formas de ruta que reconoce;
  - las herramientas MCP que añade.

  Activarlo acepta esa lista, nada más.

### 4. Acotado

Por pack:

- como mucho 100 capacidades;
- como mucho 32 campos conservados por detección, cada uno de como mucho 256 caracteres;
- como mucho 10 000 filas de `events` al día; a partir de ahí las coincidencias se cuentan y no se
  guardan, y el desborde queda registrado;
- un presupuesto de evaluación por vuelta.

Un pack que supera su presupuesto queda suspendido hasta el siguiente arranque, y la suspensión se
informa. No frena al recolector.

### 5. De dónde vienen los packs

- **Los packs incluidos** viven en el repositorio, bajo `packs/`. Se revisan como el código, llevan
  pruebas con eventos sintéticos y los aprueba el mantenedor. El primero es `wpshield.persistence`, que
  busca las formas que dejó el incidente de 2026:
  - un servicio instalado (System 7045);
  - una tarea programada creada o cambiada (Security 4698 y 4702);
  - una cuenta creada o añadida a Administradores (4720, 4732);
  - el registro de seguridad borrado (1102).
- **Los packs de la comunidad** llegan como pull requests a `packs/community/` y se revisan como los
  incluidos, con las mismas pruebas.
- **Los packs propios del operador**, donde quiera, activados por su hash.

### 6. Sigma, por conversión

`wpshield packs import-sigma <regla.yml>` convierte una regla Sigma en un pack `event-detection`. El
resultado es un archivo para revisar, no algo que corre. El convertidor admite un subconjunto
documentado: fuentes de registros de eventos de Windows, modificadores de campo que corresponden a los
operadores de la sección 2, y `and`, `or` y `not` sobre selecciones con nombre. Una regla fuera del
subconjunto se rechaza nombrando la construcción; nunca se convierte a medias. El pack conserva el id,
el autor, las referencias y la licencia de la regla; las reglas de SigmaHQ están bajo la Detection Rule
License, que exige atribución. No está previsto evaluar Sigma de forma nativa. Un solo motor, alimentado
por conversión, es más fácil de acotar y de probar.

### 7. Qué sale del servidor

Los eventos de un pack son evidencia como cualquier otra. Las herramientas MCP que añade un pack siguen
el ADR 0008, sección 7: agregadas por defecto, con registros sueltos solo bajo `mcp.detailed_records`.
El analista (ADR 0010) las ve por las mismas herramientas. Mostrar los campos de un pack antes de
activarlo es lo que permite al operador decidir si esos campos pueden salir del servidor.

## Consecuencias

- **La comunidad puede ampliar detecciones, reglas web y preguntas sin poder ejecutar nada en el
  servidor del operador.** El precio es la expresividad: lo que el motor no sabe expresar, un pack no
  lo puede hacer, y ampliar el motor pasa por revisión.
- **Un pack malicioso todavía puede leer lo que declara.** Un pack que conserve todos los campos del
  registro de seguridad llevaría datos sensibles al almacén, y de ahí a las respuestas de un asistente.
  La lista de campos visible, la aprobación por hash y los límites de los campos son la respuesta. El
  operador sigue teniendo que leer lo que aprueba.
- **Las formas de persistencia del incidente se vuelven visibles** en cuanto se activa el primer pack
  incluido: las tareas programadas, los servicios y las cuentas que se buscaron a mano el 2026-11-01.
- **Ningún pack decide ni bloquea.** Si los hallazgos de un pack deben alimentar una decisión, se
  escribe para ello una regla incluida en el motor, bajo el ADR 0009. Un pack no gana ese poder por
  ser popular.

## Alternativas consideradas

- **Plugins de .NET cargados en WPShield.** Son la opción más expresiva, y son una puerta trasera a la
  cadena de suministro dentro de un proceso elevado. Se descartan por la razón del contexto.
- **Plugins en un proceso aparte, sin privilegios.** Sin privilegios, un plugin no puede leer el
  registro de seguridad ni el almacén, y con ellos vuelve a ser el mismo problema. Quien quiera código
  al lado de WPShield ya puede correr su propio servidor MCP, y el asistente combina los dos.
- **Fragmentos de PowerShell como packs.** Son código con otro nombre, y los scripts de operador del
  propio repositorio ya necesitan un inventario de control solo para seguir siendo de solo lectura.
- **Evaluar Sigma de forma nativa.** Supondría dos motores, dos juegos de límites y dos juegos de
  pruebas. La conversión mantiene uno de cada.

## Cuándo revisar esta decisión

- Cuando se proponga el primer pack de la comunidad: comprobar el formato contra una contribución real.
- Cuando se pida una capacidad que la lista no tiene, primero WMI y el registro: añadirla aquí por su
  nombre, con su lista cerrada, nunca como un tipo general de "leer cualquier cosa".

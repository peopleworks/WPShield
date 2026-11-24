# ADR 0007 — Un almacén local de evidencia, y quién puede leerlo

- **Estado:** Aceptada el 2026-11-24, con la enmienda de abajo el mismo día
- **Deciden:** Pedro Hernández (mantenedor)
- **Afecta a:** `AGENTS.md`, `WPShield.Service`, el monitor de escritorio, la CLI,
  `wpshield uninstall` y un futuro servidor `wpshield mcp`

## Contexto

WPShield no recuerda nada. La vista **Ataques** del escritorio vuelve a leer el registro de seguridad
de Windows cada vez que se abre, y lo que ve en vivo solo dura hasta que se cierra la ventana. En el
servidor de producción que dio origen a este proyecto, el registro de seguridad cubría alrededor de
una semana por el volumen de fuerza bruta, así que una semana es también la historia más larga que
alguien puede ver. Durante el incidente, una tarea programada que borraba los logs de IIS de más de
30 días eliminó la evidencia de cómo llegaron las webshells. La evidencia que solo vive en un registro
que otro rota es evidencia que WPShield no tiene.

Tres funciones necesitan memoria:

1. **Historia más allá de los registros de Windows**: 30 o 90 días de ataques, cuándo se vio una
   dirección por primera vez, si volvió.
2. **El motor de decisión** (ADR 0006): endurecer el bloqueo de una dirección que vuelve exige saber
   que volvió, y cada decisión de bloqueo necesita un historial de qué se decidió y por qué.
3. **Hacer preguntas**: el mantenedor quiere preguntar a un asistente, mediante el Model Context
   Protocol, "¿quién atacó RDP anoche?" o "¿por qué se bloqueó esta dirección?". Eso necesita un
   almacén del que responder y reglas sobre qué puede salir del servidor en una respuesta.

## Decisión

**WPShield guarda una base de datos SQLite local con evidencia de seguridad. La escribe el servicio de
WPShield y la leen el escritorio, la CLI y un futuro servidor MCP.** Es historia. Nunca es la fuente de
una decisión de bloqueo al arrancar.

### 1. Un solo escritor: el servicio

El servicio de WPShield es el único que escribe. Funciona haya o no una ventana abierta, arranca con
Windows y registra sin interrupción; un escritorio que escribiera dejaría huecos cada vez que se
cerrara. El escritorio, la CLI y un servidor MCP abren la base **solo para lectura**.

El servicio corre como `NT SERVICE\WPShield`. Para leer el registro de seguridad esa cuenta debe estar
en el grupo integrado **Lectores del registro de eventos** (`S-1-5-32-573`). Es un ajuste del
servidor: `wpshield preflight` lo informa como bloqueante con el comando que hay que ejecutar, y nada
añade la cuenta por su cuenta.

### 2. Dónde vive y quién puede abrirla

`%ProgramData%\WPShield\evidence\wpshield-evidence.db`, en modo WAL. Los permisos de la carpeta se
**sustituyen, no se amplían** (la regla de todos los directorios de WPShield): control total para
`SYSTEM` y `Administradores`, modificación para `NT SERVICE\WPShield`, nadie más. Concedidos por SID.
Leer la evidencia exige por tanto un proceso elevado, igual que leer el registro de seguridad
directamente; un grupo de aplicaciones web, o el código que corre en él, no puede abrirla.

### 3. Qué guarda

| Tabla | Contenido | Se conserva |
| --- | --- | --- |
| `auth_failures` | Una fila por inicio de sesión fallido: hora UTC, canal e identificador de registro (únicos juntos), dirección y puerto de origen, nombre de cuenta, motivo, tipo de inicio | 14 días, como máximo 5 000 000 filas |
| `hourly_sources` | Por hora, por dirección de origen y por servicio: intentos, intentos a cuentas inexistentes, cuentas distintas | 400 días |
| `decisions` | Cada "bloquearía", bloqueo, expiración, desbloqueo y cambio de la lista de permitidos: hora, dirección o rango, regla, modo, la evidencia que lo pidió, expiración | 400 días |
| `coverage` | Por fuente e intervalo: leído, limitado, no disponible o servicio detenido | lo mismo que los datos que describe |
| `collector_state` | Último identificador de registro leído por canal | — |

Las fuentes posteriores (la evidencia HTTP del gateway, los logs de IIS, SQL Server, FTP) añaden
tablas con las mismas reglas, cada una en su propio cambio.

**Nunca se guarda:** cuerpos de petición, cadenas de consulta, cookies, cabeceras de autorización,
nonces, tokens, contraseñas ni contenidos de archivos. La misma lista que ya rechaza el registro del
gateway. Los nombres de cuenta, los agentes de usuario y las rutas son texto elegido por el atacante:
se limpian de caracteres de control y de formato y se acotan antes de escribirlos, igual que antes de
mostrarlos.

### 4. Acotado, y los huecos quedan registrados

Cada tabla tiene un límite de filas y de antigüedad, y el archivo un límite de tamaño (2 GB por
defecto). Al llegar a un límite se eliminan primero las filas detalladas más antiguas y se conservan
los resúmenes. Cada poda y cada periodo en que el servicio no corría se anota en `coverage`, para que
todas las vistas dibujen **sin datos** donde no se registró nada. Un periodo tranquilo y un periodo
sin registro nunca deben parecer iguales.

### 5. Historia, nunca la fuente de un bloqueo

Al arrancar, el servicio puede ponerse al día desde los registros de Windows (por identificador de
registro, sin duplicar nada). **No** entrega esa historia al motor de decisión y **nunca restaura
bloqueos** desde `decisions`. La garantía del ADR 0006 —un bloqueo vive exactamente lo que vive el
proceso— se mantiene porque el bloqueo empieza con el conjunto vacío y con evidencia que llega después
de arrancar el proceso. Una base que resucitara bloqueos convertiría cada error pasado en uno
permanente.

### 6. Los lectores preguntan; no actúan

El escritorio, la CLI (`wpshield attacks ...`) y un futuro servidor `wpshield mcp` leen a través de
una sola biblioteca de consultas fijas y parametrizadas, con resultados acotados (límites de filas y
rangos de tiempo). Ningún lector acepta SQL libre.

**El servidor MCP** tendrá su propio ADR antes de existir. Este fija las restricciones que hereda:

- **Solo stdio al principio.** El asistente arranca `wpshield mcp` como proceso local; no hay ningún
  puerto de red escuchando, lo que mantiene la regla de que las interfaces de gestión solo atienden
  en loopback. Llegar al almacén desde otra máquina es otra decisión, con autenticación.
- **Solo lectura.** Las herramientas responden preguntas (orígenes principales, historia de una
  dirección, cobertura, decisiones). Ninguna herramienta bloquea, desbloquea ni cambia la
  configuración hasta que un ADR defina cómo una persona confirma la acción fuera del modelo.
- **El texto del atacante es dato, nunca instrucción.** Los nombres de cuenta, las rutas y los agentes
  de usuario llegan al modelo dentro de campos estructurados marcados como no confiables. Un atacante
  que intente entrar como `ignora las instrucciones anteriores` no debe poder dirigir a un asistente
  que lea el resultado. Es la razón principal de que la primera versión no tenga herramientas que
  actúen.
- **Lo que sale del servidor lo decide el operador.** Una respuesta viaja al proveedor del modelo del
  asistente. Los resultados son agregados por defecto; los registros detallados solo se devuelven
  cuando se piden, y la documentación lo dice.

### 7. La desinstalación lo conserva

`wpshield uninstall` conserva el almacén de evidencia salvo que se indique lo contrario, igual que los
logs: desinstalar en pleno incidente es el peor momento para borrar el registro de lo que pasó.

## Consecuencias

- **Una dependencia nueva:** `Microsoft.Data.Sqlite` (MIT) y su paquete nativo de SQLite
  (SQLitePCLRaw, Apache 2.0). Ambos permiten redistribuirlos en la versión MIT de WPShield;
  `NOTICE.md` los menciona.
- **El proyecto del almacén sigue siendo portable.** El esquema, la retención y las consultas viven en
  una biblioteca sin dependencias de Windows, así que la integración continua en Linux los prueba;
  solo el recolector que lee el registro de eventos es exclusivo de Windows.
- **Escrituras en disco en el servidor.** Acotadas por la sección 4, en una carpeta que ninguna otra
  cuenta puede leer.
- **Un paso manual nuevo:** añadir `NT SERVICE\WPShield` a Lectores del registro de eventos.
- **La vista Ataques del escritorio** gana rangos de 7 y 30 días desde el almacén, y sigue leyendo el
  registro de seguridad directamente cuando el servicio no está instalado.

## Alternativas consideradas

- **Más archivos JSON Lines.** El gateway ya los escribe y seguirán. Pero cada pregunta ("visto por
  primera vez", "volvió", "orígenes principales en 30 días") volvería a leer y a agregar todos los
  archivos, y un servidor MCP necesitaría de todos modos un motor de consultas.
- **El SQL Server, MySQL o PostgreSQL que ya hay en el servidor.** Pertenecen a las aplicaciones
  alojadas. La evidencia de una herramienta de seguridad no debe depender de, ni poder leerse a través
  de, las bases de datos que un atacante intenta alcanzar.
- **LiteDB u otro almacén de documentos embebido.** Funcionaría, pero SQLite es el formato que
  cualquier herramienta abre, y eso importa cuando hay que revisar la evidencia a mano en un incidente.
- **El escritorio como escritor.** Más sencillo, y solo registra mientras hay una ventana abierta.

## Enmienda (2026-11-24): ajustes y evidencia de cualquier tipo

El mantenedor pidió que el almacén guarde más que inicios de sesión fallidos, incluida configuración,
y que pueda crecer sin cambiar el esquema cada vez. Dos tablas lo hacen bajo las mismas reglas:

- **`events`**: evidencia de cualquier tipo que no tenga tabla propia (una petición HTTP que el gateway
  rechazó, un inicio de sesión de SQL Server o de FTP). Cada fila tiene un tipo, un origen, una hora,
  una dirección opcional, un asunto limpio y un pequeño detalle JSON (como máximo 4 KB, con los textos
  limpios y acotados), y una clave opcional que convierte una segunda copia en una operación nula. Los
  tipos son nombres en minúsculas; un tipo nuevo no necesita migración. Una fuente solo recibe tabla
  propia cuando una consulta la necesita, como pasó con los inicios de sesión fallidos.
- **`settings`** y **`settings_history`**: valores en JSON, pero **solo las claves que el código
  declara** en su catálogo de ajustes, cada una con su tipo, sus límites y cuándo surte efecto (en el
  próximo uso o en el próximo arranque; nunca "ya" sin decirlo). Las claves desconocidas se rechazan,
  para que una errata nunca se convierta en un ajuste que no hace nada en silencio. Cada cambio guarda
  el valor anterior y el nuevo, quién lo hizo y por qué. Los primeros ajustes son la retención (días de
  detalle, días de resúmenes, días de eventos, tamaño máximo), el rango con que abre la vista de
  ataques, etiquetas para direcciones conocidas y si una respuesta MCP puede incluir intentos sueltos.

Reglas que añade:

- **Los ajustes los escribe una herramienta de operador elevada o el servicio, nunca un lector.** El
  escritorio y un servidor MCP los leen. Una herramienta MCP que cambie un ajuste es una acción y queda
  bajo la sección 6.
- **Una etiqueta describe; nunca permite ni bloquea.** La lista de permitidos y los umbrales de
  bloqueo solo pasan a ser ajustes mediante el ADR propio del motor de decisión, con su validación.
- **Los ajustes que solo se aplican al arrancar lo dicen** cuando se cambian, la misma regla de
  configuración que `AGENTS.md` ya fija para los archivos.

## Cuándo revisar esta decisión

- Si un lector necesita acceso sin elevación, crear un grupo local dedicado en lugar de ampliar los
  permisos de la carpeta.
- Si se quiere acceso MCP remoto, es un ADR nuevo: autenticación, transporte y qué puede contener una
  respuesta cuando sale del servidor por la red.

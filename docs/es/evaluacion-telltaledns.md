# TelltaleDNS: ideas que conviene evaluar para WPShield

Estado: investigación revisada el 2026-11-14; primera entrega de evidencia implementada el 2026-11-17,
según se indica abajo. Los demás puntos son propuestas. Esta nota no aprueba integrar el proyecto de
origen ni afirma que WPShield esté listo para producción.

## Evidencia y límites

Se inspeccionó la revisión de origen `1928cea655b3c71d27857528135ee6d768274158`, cuyo commit es del
2026-11-14T19:37:16Z. Se leyeron documentación y archivos seleccionados de código y pruebas en Rust;
**no se ejecutaron** el software, las mediciones de rendimiento, el flujo de publicación ni las
pruebas del proyecto. La inspección del código demuestra que existen mecanismos y aserciones,
no que todo comportamiento anunciado funcione en un despliegue.
El [commit](https://github.com/paimonsoror/telltaledns/commit/1928cea655b3c71d27857528135ee6d768274158)
es la referencia reproducible de esta evaluación.

TelltaleDNS es un resolvedor y filtro DNS con políticas por dispositivo y observabilidad. WPShield
es un gateway HTTP para Windows/IIS con un filtro de red experimental separado. Lo transferible
es su diseño de explicaciones y operación, no su motor DNS ni su modelo de despliegue. La
[arquitectura](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/spec/02-architecture.md) del proyecto identifica Linux como plataforma principal y describe
un workspace Rust; [Cargo.toml](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/Cargo.toml) declara `Apache-2.0 OR MIT`.
Si en algún momento se copia código, deben revisarse las licencias de los archivos y dependencias
correspondientes y conservarse los avisos aplicables. Esta evaluación propone diseños independientes
en .NET, sin copiar implementaciones.

## Prioridades y criterios de aceptación

### 1. Evidencia de decisiones con versión — primero, M4 con consumidores de M3

**Primera entrega implementada (2026-11-17).** La [evidencia de solicitudes](evidencia-solicitudes.md)
añade un evento final versionado, versiones de compilación, un identificador de activación de la
configuración, completitud por etapa y resultado real. Los contratos portables de reglas permanecen
iguales: el gateway conoce el resultado del transporte. Quedan pendientes las explicaciones offline,
las instantáneas persistidas de configuración y una vista específica en la CLI.

**Mecanismo inspeccionado en el proyecto de origen.** [explain.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale-filter/src/explain.rs)
devuelve las reglas que coinciden, su precedencia, la regla ganadora, la versión de la instantánea
y la atribución a líneas del código fuente de las listas. También informa de fuentes ausentes y
huellas de contenido que han cambiado. Las
[pruebas asociadas](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale-filter/src/explain/tests.rs) comprueban la atribución a reglas y líneas y los
avisos sobre fuentes modificadas o ausentes. Esta explicación se genera fuera de la ruta de consultas
DNS; puede reservar memoria y leer las fuentes de reglas almacenadas.

**Propuesta para WPShield.** Ampliar el vocabulario existente de `RuleFinding`/`InspectionResult`
y JSON Lines con la versión del esquema de eventos, la versión del motor y del conjunto de reglas,
una revisión opaca de la configuración, el resultado operativo real, el motivo y el grado de
completitud de la inspección. Registrar la acción recomendada en Monitor por separado de si el
reenvío ocurrió realmente. Distinguir «sin inspeccionar», «inspección parcial», «sin hallazgos» y
«backend no disponible». Conservar los identificadores estables de reglas y la envoltura existente
`timestamp`, `level`, `category`, `message`, `state`.

**Aceptación.** Los casos sintéticos de Monitor, Block, Disabled, multipart malformado, agotamiento
de capacidad, cancelación y fallo de reenvío producen registros distinguibles. Todos los componentes
usan el mismo cliente resuelto. No se añade ningún secreto ni nombre de archivo o ruta sin normalizar.
Una explicación no puede atribuir líneas a una revisión histórica si solo dispone de otra revisión
actual. Las explicaciones detalladas permanecen fuera de la ruta de solicitudes. Esto también ofrece
a Reader-1 una base explícita para abstenerse cuando la evidencia sea incompleta.

### 2. Vista previa acotada de políticas — segundo, M3/M4; M5 puede mostrarla

**Mecanismo inspeccionado en el proyecto de origen.** [simulate.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale/src/simulate.rs)
reproduce registros de consultas conservados contra políticas candidatas, con límites de filas y
tiempo y resultados explícitos de parcial, ocupado y no disponible. Reutiliza el evaluador de reglas
en servicio y construye por separado los datos candidatos. Las
[pruebas de simulación](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale/src/simulate/tests.rs) comprueban que la instantánea en servicio no cambia y
que se respetan los límites de filas. Esto es distinto de reproducir registros al arrancar para
reconstruir estadísticas.

**Propuesta para WPShield.** Empezar con una comparación fuera de línea entre umbrales y modos
actuales y candidatos, sobre datos sintéticos y registros respetuosos con la privacidad, utilizando
el mismo motor de puntuación y acciones. Informar por sitio de las solicitudes que pasarían a
rechazarse o permitirse, la cantidad de entradas inspeccionadas, elegibles y excluidas, los motivos
de ausencia de datos, las revisiones de reglas y configuración y la ventana temporal evaluada.

**Aceptación.** La vista previa no modifica políticas activas ni infraestructura y respeta límites
de CPU, tiempo y filas. Si faltan entradas, devuelve «no se puede evaluar», nunca impacto cero.
Una puntuación agregada registrada puede servir para comparar umbrales; no puede recrear una regla
de contenido modificada. WPShield no conserva cuerpos ni muestras deliberadamente, por lo que los
logs ordinarios no permiten reproducir el contenido histórico de las cargas. Para esos cambios se
usan datos sintéticos inofensivos; no se añade retención de cuerpos para hacer posible la vista previa.
Una vista previa es una estimación histórica, no un pronóstico ni una autorización para activar Block.

### 3. Métricas de pérdida de evidencia y límites explícitos de privacidad — tercero, M4

**Mecanismo inspeccionado en el proyecto de origen.** [ring.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale-telemetry/src/ring.rs)
emite un registro completo o lo descarta cuando el búfer circular acotado está lleno, e incrementa
un contador de descartes. [event.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale-telemetry/src/event.rs) transforma registros según niveles de privacidad.
[privacy.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale/src/privacy.rs) gestiona un hash de nombres con clave, pero también avisa y recurre a
un hash sin clave cuando aquella no está disponible. Esa alternativa es un motivo concreto para no
tratar las afirmaciones de privacidad del proyecto como una garantía que pueda copiarse sin cambios.

**Propuesta para WPShield.** Conservar el rechazo de arranque existente cuando no se pueden escribir
logs y su política de disponibilidad durante la ejecución. Ampliar la observabilidad de la cola de
registro acotada que ya existe y mantener acotada la telemetría adicional, con contadores de eventos
descartados, fallos de escritura e inspecciones omitidas y un estado claro de evidencia degradada.
Exportar metadatos explícitos de cobertura con los informes. Para exportaciones a la comunidad,
utilizar una lista estricta de campos permitidos e identificadores sintéticos; aplicar un hash a
valores de baja entropía no basta para anonimizarlos. Los modos de privacidad pueden eliminar
información, pero nunca permitir credenciales, cookies, tokens, consultas completas ni cuerpos.

**Aceptación.** Una cola o un disco lleno no detiene el reenvío ni reserva memoria sin límite;
la pérdida queda visible mediante un canal de estado o contadores que siga funcionando. Un analista
no puede confundir un log parcial con evidencia completa. Las pruebas de exportación verifican los
campos estructurados y los mensajes formados, el aislamiento por sitio, los caracteres de control y
escapes ANSI y los valores prohibidos. Un fallo de la clave no debe debilitar silenciosamente la
garantía de privacidad de una exportación.

### 4. Mantener el análisis independiente de la configuración en servicio — M4/M5

**Mecanismo inspeccionado en el proyecto de origen.** [pipeline.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale/src/pipeline.rs)
utiliza `ArcSwap` para el estado compartido en servicio;
[snapshot.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale-filter/src/snapshot.rs) contiene manifiestos con versión y huellas de contenido. La
[especificación de arquitectura](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/spec/02-architecture.md) describe la separación entre los planos de datos y control.
Las pruebas de simulación citadas comprueban específicamente que evaluar un candidato no modifica
el estado en servicio; esta revisión no demuestra la disponibilidad del sistema completo ante todos
los posibles fallos del controlador.

**Propuesta para WPShield.** Mantener los informes, las llamadas a Reader-1 y las vistas previas
fuera de la ruta de solicitudes HTTP. Utilizar para cada proceso una configuración efectiva inmutable
e identificada explícitamente, y registrar esa revisión con las decisiones. Conservar la semántica
actual de configuración aplicada únicamente al arrancar. La recarga en caliente necesitaría un diseño
separado, validación y pruebas de activación atómica; guardar desde un dashboard no debe aparentar que
el gateway en ejecución ya adoptó el cambio.

**Aceptación.** Un dashboard detenido, un servicio de análisis fallido, una cuota de análisis agotada
o un candidato malformado no puede retrasar solicitudes, cambiar el modo de un sitio ni sustituir la
configuración efectiva. Esta propuesta no introduce clústeres, conmutación automática ni una
alternativa de arranque que recupere la última configuración válida.

### 5. Interfaz de agentes de solo lectura sobre servicios compartidos — después, M5/M8

**Mecanismo inspeccionado en el proyecto de origen.** [mcp.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale-api/src/mcp.rs)
envuelve rutas REST usando las credenciales del llamador.
[plans.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale-api/src/plans.rs) conserva planes acotados y con caducidad, y vincula su aplicación a la
versión de configuración. La aprobación humana es configurable, no universal. La
[especificación de agentes](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/spec/13-agent-api-and-mcp.md) también describe ámbitos de autorización, límites de resultados
y un interruptor para deshabilitar agentes. Algunas herramientas modifican estado; «tiene MCP» no
significa que toda la interfaz sea de solo lectura.

**Propuesta para WPShield.** Solo después de diseñar la administración autenticada, considerar
herramientas locales de lectura con alcance limitado: explicar una decisión registrada, resumir una
ventana temporal acotada de un sitio, informar de la cobertura de evidencia, consultar la configuración
efectiva sin secretos y ejecutar una vista previa fuera de línea. Reutilizar los mismos servicios y
contratos que la CLI y el dashboard. Reader-1 no necesita inicialmente MCP ni acceso de escritura.

**Aceptación.** Se prueban la autorización explícita por sitio, los límites de paginación, tiempo y
coste, la cancelación y las respuestas de error seguras. Los datos de los logs son entradas no
confiables, nunca instrucciones. No se expone SQL arbitrario, shell, acceso al sistema de archivos,
modificación de configuración ni operaciones de bloqueo. Cualquier flujo de escritura futuro
requiere una propuesta separada y no puede ampliar la autoridad de WPShield sobre la infraestructura.

### 6. Corpus persistentes de fuzzing y evidencia de publicación — pruebas M3/M4, distribución M6

**Mecanismo inspeccionado en el proyecto de origen.** El
[flujo de fuzzing](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/.github/workflows/fuzz.yml) configura ejecuciones con tiempo limitado, recuperación de corpus y
conservación de artefactos de fallos. Sus objetivos incluyen analizadores DNS, análisis de listas y
segmentos de logs. El [flujo de publicación](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/.github/workflows/release.yml) ejecuta una verificación previa antes de crear
la etiqueta y delega compilación y publicación; demuestra automatización, no que los binarios
publicados actualmente sean reproducibles o estén firmados correctamente.

**Propuesta para WPShield.** Reutilizar esta disciplina de pruebas para la normalización de nombres
y rutas de Windows, la doble decodificación, los delimitadores multipart y la serialización segura
de eventos. Añadir semillas de fallos reproducibles y aserciones de propiedades junto con las pruebas
unitarias y de integración actuales. Para M6, evaluar el SBOM de cada artefacto, su procedencia y la
comparación de compilaciones repetidas por separado de la firma para Windows.

**Aceptación.** Las semillas fijas reproducen el resultado en CI; el fuzzing tiene límites de tiempo,
memoria y entrada, usa marcadores sintéticos inofensivos y no publica secretos ni cargas de ataque.
Las invariantes incluyen normalización idempotente, salida acotada, identificadores estables de
reglas, semántica de Monitor y ausencia de almacenamiento de cuerpos en disco. La distribución
conserva nombres que indiquen vista previa de investigación, checksums, condición de prerelease y
la política de no marcar versiones como latest hasta M7; no se introducen publicaciones NuGet,
instaladores ni imágenes de contenedor.

## Secuencia recomendada y exclusiones

Empezar por el contrato de evidencia de M4 y los estados de completitud; seguir con una vista previa
pequeña y acotada e informes que hagan visible la pérdida de evidencia. Esto aporta entradas útiles
para una evaluación separada de Reader-1. El acceso de agentes llega después de la administración
autenticada; la evidencia de publicación corresponde a M6. Son tareas propuestas, no nuevas casillas
completadas del roadmap ni un sustituto de la validación pendiente con IIS.

Para esta evaluación no se incorpora a WPShield el resolvedor de TelltaleDNS, su filtrado DNS,
runtime Rust, despliegue Kubernetes ni clústeres. Sus cifras de rendimiento no deben copiarse como
objetivos de WPShield sin una carga HTTP/IIS y una medición local de referencia. Tampoco se copia
ninguna política de publicación como latest.

Monitor sigue siendo el modo predeterminado. Los listeners M1/M2 permanecen limitados a loopback y
la activación en producción sigue sin aprobarse. Este plan no cambia IIS, DNS, certificados, ajustes
del firewall, servicios ni bindings públicos. El filtro de red conserva únicamente su comportamiento
autorizado por separado, limitado a la vida de sus handles; los resultados del análisis nunca se
conectan directamente a bloqueos.

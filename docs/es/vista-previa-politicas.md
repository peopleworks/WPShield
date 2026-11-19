# Vista previa offline de políticas

Implementado: `wpshield preview` compara recomendaciones de inspección registradas con una política
candidata Monitor o Block. Es la segunda entrega de la [evaluación de TelltaleDNS](evaluacion-telltaledns.md).
Los dos motores de inspección y la vista previa usan el mismo cálculo `InspectionPolicy`. No se
reenvían solicitudes ni se ejecutan reglas de contenido: se mantienen constantes las puntuaciones registradas.

WPShield sigue siendo una versión de investigación, no aprobada para tráfico de producción. Monitor
continúa como modo predeterminado; los listeners M1/M2 siguen en loopback. Preview no realiza operaciones
sobre IIS, servicios, DNS, certificados, firewall, puertos públicos, configuración del gateway ni Reader-1.

## Ejecutarlo

Use una copia local de un archivo JSON Lines del gateway que contenga [eventos finales de esquema 1](evidencia-solicitudes.md):

```powershell
wpshield preview --log-file .\synthetic-evidence.jsonl --site wordpress-one.example --mode Block --observe-threshold 30 --block-threshold 80
```

`--site` selecciona un `SiteId` exacto, distinguiendo mayúsculas; no resuelve nombres de host HTTP.
`--site` y `--log-file` son obligatorios. El modo candidato predeterminado es Monitor; los umbrales
son 30/80. Observe debe estar entre 0 y 100; block, entre 1 y 100 y ser igual o mayor que observe.
Disabled no se simula: volver a activar la inspección no recupera puntuaciones que nunca se registraron.
Se rechazan opciones desconocidas, repetidas, sin valor o inválidas. `wpshield preview --help` las enumera.

El comando abre únicamente el archivo indicado para lectura y escribe JSON agregado en stdout.
Nunca lee la configuración activa y no tiene una opción para aplicar cambios. Cada ejecución es
independiente del gateway y de otras vistas previas. No necesita elevación ni contacta con otro servicio.

## Leer el resultado

| Campo | Significado |
| --- | --- |
| `candidate`, `candidatePolicyId`, `previewEngineVersion` | Modo y umbrales candidatos, su identificador canónico `score-policy-v1/...` y metadatos de compilación del motor que calculó la vista previa. |
| `selectedRecords` | Eventos finales asignados al sitio solicitado, incluidos los excluidos. |
| `eligibleRecords`, `excludedRecords`, `exclusions` | Registros comparables y registros que no permiten comparar, con motivos explícitos. Elegibles más excluidos equivale a seleccionados. |
| `newlyRefused`, `newlyPermitted` | Registros elegibles que pasan a la recomendación Block o dejan de tenerla. Son decisiones de política, no transacciones completadas por la aplicación. |
| `changedRecommendations`, `unchangedRecommendations` | Cambios entre Allow, Observe y Block, incluidos cambios del umbral de observación que no causan rechazo. |
| `comparisons` | Los mismos recuentos agrupados por activación de configuración, modo y versiones originales del gateway, motor y reglas; no se mezclan silenciosamente activaciones distintas. |
| `windowStart`, `windowEnd` | Fechas mínima y máxima entre los registros elegibles, sin depender del orden de entrada. Es la ventana evaluada, no una prueba de que incluya todas sus solicitudes. |
| `linesRead`, `bytesRead`, `ignoredLines`, `invalidLines`, `otherSiteRecords`, `evidenceLossNotices` | Cobertura de entrada, líneas no clasificadas o dañadas, aislamiento por sitio y avisos observados de pérdida de logs. |
| `status`, `stopReason`, `limits` | Si se completó la comparación de la entrada seleccionada, qué la interrumpió y los límites del recorrido. |

Si ningún registro es elegible, los recuentos de impacto y la ventana evaluada son **null**, no impacto
cero. `status` puede ser `complete`, `partial`, `cannot_evaluate` o `unavailable`. Sus códigos de salida
son 0, 2, 3 y 1; los argumentos inválidos también devuelven 1. Una comparación parcial conserva los
recuentos únicamente del subconjunto elegible. `appliesChanges` y `provesLogCompleteness` siempre son false.

Las acciones originales proceden de los eventos finales, después de aplicar el modo y los umbrales
originales. Las candidatas se calculan por separado con las puntuaciones de ruta y archivos; nunca se
suman ambas puntuaciones. Solo se admite una inspección de archivos omitida cuando el motivo explícito
es `non_multipart` o `empty_body` y acción y puntuación son null. Esos cuerpos siguen fuera de la inspección.

Se excluyen inspecciones parciales u omitidas por otros motivos, modo Disabled, presupuestos de tasa
excedidos, fallos o cancelaciones del transporte, esquema desconocido, procedencia ausente, listas de
reglas truncadas y resultados incoherentes. También se excluye un rechazo por ruta anterior a inspeccionar
archivos: flexibilizar la política de ruta no revela qué habría contenido el cuerpo sin leer. La deduplicación
usa activación e ID de solicitud; las filas repetidas cuentan como excluidas. No se confía en claves JSON
duplicadas ni UTF-8/JSON malformado. Los avisos conocidos de pérdida hacen parcial la comparación.

## Límites y alcance

| Límite | Predeterminado | Techo |
| --- | --- | --- |
| `--max-lines` (todas las líneas, incluidas las ignoradas) | 10.000 | 100.000 |
| `--max-bytes` (bytes leídos) | 16 MiB | 64 MiB |
| `--timeout-seconds` | 10 | 60 |
| Una línea JSON | 32 KiB | 32 KiB |
| Grupos de procedencia | 64 | 64 |
| Profundidad JSON | 16 | 16 |

El lector usa buffers fijos, no conserva el archivo completo y limita el seguimiento de duplicados
mediante el techo de líneas. Se informa explícitamente al agotar líneas, bytes o tiempo, encontrar
una línea excesiva, truncarse la fuente o quedar incompleto el último registro. Un archivo sin salto
de línea final se considera potencialmente incompleto. La lectura se detiene en el tamaño observado
al abrir; no sigue bytes añadidos después. Los cambios de longitud detectados se informan, pero no
se detecta una reescritura del mismo tamaño. El plazo es cooperativo después de abrir la fuente;
no garantiza la latencia de apertura del sistema operativo. Use una copia para reproducibilidad.
No se genera una huella del archivo ni una prueba de autenticidad.

Solo se devuelven la comparación agregada y los campos de procedencia permitidos: no se copian IDs de
solicitud, direcciones de cliente, rutas, nombres de archivo, cabeceras, muestras ni texto de mensajes.
Los IDs de sitio y metadatos de compilación/activación siguen siendo datos operativos; el resultado
no es una exportación anonimizada para la comunidad.

`complete` significa que todos los registros seleccionados de la entrada recorrida fueron comparables,
no que los logs cubran todo el tráfico. Los demás eventos cuentan como ignorados y nunca se reconstruyen
como solicitudes; los logs exclusivamente antiguos no permiten evaluar. Filtros, archivos ausentes,
rotación, caídas del proceso y avisos de pérdida ausentes pueden dejar huecos invisibles. Estas
puntuaciones no permiten simular reglas de contenido modificadas ni límites nuevos de tasa, tamaño o
parser. Es una estimación histórica sobre las muestras registradas, no una predicción, certificado de
seguridad ni autorización para activar Block. No hay nada que revertir: preview no cambia nada.
En un gateway desplegado por separado, el bypass sigue siendo la regla de reescritura de IIS antes de detener el servicio.

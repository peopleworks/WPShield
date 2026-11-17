# Evidencia de solicitudes: trazabilidad y completitud de la inspección

Implementado: el gateway emite un evento final `request_completed` por cada solicitud que entra en
su endpoint de reenvío. Es la primera entrega de la [evaluación de TelltaleDNS](evaluacion-telltaledns.md),
implementada de forma independiente en .NET. WPShield sigue siendo una versión de investigación,
no aprobada para tráfico de producción. Monitor sigue siendo el modo predeterminado; los listeners
de M1/M2 permanecen restringidos a loopback.

## Hallazgo, decisión y resultado

Los hallazgos y resúmenes describen lo que una etapa encontró y recomendó. No demuestran que el
reenvío terminó correctamente. El evento final se emite en `finally`, después del reenvío o rechazo,
en la categoría `WPShield.Gateway.Evidence` con nivel Information. Conserva la envoltura JSON Lines
existente (`timestamp`, `level`, `category`, `message`, `state`). Los consumidores deben leer
`state.EventType=request_completed` y `state.SchemaVersion=1`, sin analizar el mensaje renderizado.

`RequestId` enlaza el evento final con los hallazgos y la cabecera de respuesta
`X-WPShield-Request-ID`. `SiteId` y `Mode` identifican la política del sitio resuelto; ambos son null
para un host desconocido. `Client` procede del mismo `ResolvedClient` que usa el reenviador, incluido
el tratamiento de proxies confiables. Vale `unknown` si no se resolvió ninguna dirección.

| Campo | Significado |
| --- | --- |
| `ConfigurationRevision` | Identificador aleatorio opaco generado tras validar la configuración al iniciar. Es estable durante esta activación y cambia en cada reinicio, aunque los ajustes sean iguales. También aparece en el evento de activación. **No** es una huella, una instantánea ni una prueba de que dos activaciones usaran ajustes distintos. |
| `GatewayVersion`, `EngineVersion`, `WindowsRulesVersion`, `WordPressRulesVersion` | Versiones informativas de los ensamblados cargados, incluida la revisión de código cuando la compilación la incorpora; `unknown` si falta. Identifican metadatos de compilación, no procedencia firmada ni una reconstrucción exacta de cambios sin commit. |
| `Disposition`, `Reason` | Resultado real del procesamiento y motivo estable, separados de las recomendaciones de inspección. |
| `ForwardingAttempted` | Indica si se llamó al reenviador. Un true no demuestra entrega; un prefijo puede haber llegado al backend antes del fallo. |
| `StatusCode` | Estado de respuesta del gateway al terminar, o null ante cancelación o fallo no controlado. Un estado en un intercambio fallido no demuestra que el cliente recibiera la respuesta completa. |
| `RateLimitRuleId` | ID del presupuesto de solicitudes excedido, o null. Monitor registra el exceso y continúa; Block rechaza. |

`Disposition` tiene uno de estos valores:

- `forwarded` / `exchange_completed`: el reenviador terminó sin error de transporte. Una respuesta
  HTTP 4xx o 5xx del backend puede tener este resultado; no significa que WordPress aceptara un archivo.
- `rejected`: el gateway rechazó antes de llamar al reenviador. `Reason` conserva el token de error
  existente, como `unknown_host`, `request_blocked`, `upload_blocked`, `multipart_not_inspectable`,
  `multipart_concurrent_limit_exceeded`, `rate_limited`, `request_timeout` o `request_too_large`.
- `forwarding_failed`: se intentó reenviar, pero hubo un fallo; por ejemplo `backend_unavailable`
  o `request_too_large` cuando un cuerpo en streaming supera el límite después de iniciar el envío.
- `cancelled` / `request_cancelled`: se observó la cancelación de la solicitud durante el procesamiento.
- `failed`: una excepción no controlada interrumpió el procesamiento; `Reason` vale `pipeline_failure`
  o `forwarding_exception`. El evento no incluye el texto de la excepción.

## Qué se inspeccionó

La inspección de ruta y la de archivos tienen `PathStatus` / `UploadStatus` independientes y sus
campos `Reason`, `Action`, `Score`, `RuleIds` y `RuleIdsTruncated` (cada uno con prefijo `Path` o
`Upload`). Los IDs están separados por comas, sin duplicados, ordenados y limitados a 16 por etapa.
El truncamiento es explícito. La puntuación de archivos sigue siendo el máximo entre evaluaciones,
nunca una suma entre archivos.

| Estado | Interpretación y motivos |
| --- | --- |
| `not_started` | El procesamiento no llegó a la etapa (`not_reached`), por ejemplo tras rechazar un host desconocido o una ruta. |
| `not_inspected` | Omisión explícita: `disabled`, `inspection_disabled`, `empty_body`, `non_multipart` o `capacity_exhausted`. La acción y la puntuación quedan en null. |
| `partial` | El trabajo comenzó, pero no terminó: `malformed`, `limit_exceeded`, `read_timeout`, `parse_timeout`, `request_too_large`, `request_cancelled` o `interrupted`. Se conservan las evaluaciones de archivos que sí terminaron. |
| `complete` | Terminó la etapa configurada: `rules_completed` para reglas de ruta y `sampled_scope` para archivos. Una puntuación de cero sin IDs significa que no hubo hallazgos **dentro de ese alcance**. |

`PathAction` y `UploadAction` proceden de los motores después de aplicar el modo y los umbrales.
Un hallazgo en Monitor puede indicar `Observe` y terminar como `forwarded`, `forwarding_failed` o
`cancelled`. Una acción null significa que no se obtuvo un resultado de evaluación. Un resultado
`Allow` en una etapa parcial solo cubre las evaluaciones terminadas; no aprueba el resto sin inspeccionar.

`FilesRead` es null hasta que retorna el parser; después cuenta las vistas de nombres devueltas.
`FilesInspected` cuenta las vistas evaluadas por las reglas. `filename` y `filename*` pueden generar
dos vistas de una parte física. `SampleBytesInspected` suma los tamaños de las muestras evaluadas
y puede contar dos veces una muestra compartida. `SampleLimitBytes` es el máximo configurado de
bytes iniciales por vista. No son los bytes totales de la solicitud ni cantidades de archivos físicos.
Los campos no se escanean. Los cuerpos no multipart, el interior de archivos comprimidos y el
contenido posterior a la muestra inicial quedan fuera de la inspección de archivos. Una inspección
completa no certifica la ausencia de malware ni una cobertura exhaustiva del contenido.

## Compatibilidad, privacidad y límites pendientes

Los prefijos de hallazgos y resúmenes existentes se conservan. Los resúmenes de archivos ahora usan
`Decision=forward|reject` en lugar de afirmar anticipadamente `Disposition=forwarded|blocked`.
Las advertencias de multipart incompleto usan `ForwardPermitted` en lugar de `Forwarded`; las de
capacidad usan `ForwardUninspected` en lugar de `ForwardedUninspected`. Para conocer el resultado
real se debe leer el evento final. `wpshield watch` mantiene su vista de hallazgos y resúmenes;
una vista específica del evento final y las métricas son trabajo futuro. Los contratos portables
`RuleFinding` e `InspectionResult` no cambian.

El evento nuevo no añade rutas, nombres de archivo, hosts, cabeceras, consultas, cuerpos ni muestras.
La dirección del cliente, el ID configurado del sitio y el ID de solicitud siguen siendo datos
operativos: esto no es una exportación anonimizada para la comunidad. Deben mantenerse los controles
de acceso y retención existentes. No se escribe contenido de solicitudes en disco ni se conserva
una instantánea histórica de configuración o contenido para reproducir la evaluación.

Se hace una llamada final de logging por invocación del endpoint de reenvío, incluidos rechazos
tempranos y excepciones. Quedan fuera de esa garantía los endpoints de salud y reservados, rechazos
del servidor HTTP anteriores al endpoint, caídas del proceso, filtros de logging, saturación de la
cola y fallos de almacenamiento. Mantenga Information habilitado para `WPShield.Gateway.Evidence`.
La ausencia de un evento significa **desconocido**, nunca reenvío correcto ni solicitud inspeccionada.
Siguen aplicándose los avisos existentes de pérdida de logs; esta entrega no incluye completitud
durable, nuevas métricas de pérdida ni explicación o reproducción offline.

No se necesitan cambios de despliegue ni infraestructura. Aplicar una compilación requiere reiniciar;
la configuración no se recarga en caliente. En un gateway desplegado, el bypass sigue siendo la regla
de reescritura de IIS: detener el servicio mientras esa regla apunta a WPShield deja el sitio caído.
Este trabajo no modifica IIS, DNS, certificados, firewall, servicios ni puertos públicos y no integra Reader-1.

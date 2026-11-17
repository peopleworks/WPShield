# Plan de evaluación e integración condicional de Reader-1

Estado: propuesta, 2026-11-14. No se han realizado llamadas API, cambios de cuenta, envíos de datos ni integración.
Base WPShield: `7ec142f4561a84754b363155db30e24a91617549`. [ROADMAP](../../ROADMAP.md) sigue siendo el plan autoritativo.

## Recomendación

Evaluar Reader-1 como analista opcional de documentación pública e informes sintéticos de incidentes,
fuera de la inspección HTTP y del bloqueo. Primero medir si aporta valor frente a leer JSON, calcular
de forma determinista y consultar las fuentes. Participar en Corpus Hub es una actividad separada:
no instala Reader-1 ni valida el modelo con datos de WPShield.

## Documentación verificada; comportamiento no probado independientemente

- Reader-1 está en vista previa y es distinto de Query-1 y del buscador local. El proveedor reconoce
  errores de evidencia, de operación y respuestas incorrectas con confianza alta.
  [Anuncio](https://xerj.org/blog/xerj-reader-1-waitlist).
- Las entradas documentadas son `POST /v1/answers` y `POST /v1/execute`. Execute repite un programa
  sin inferencia del modelo, pero sigue siendo una API alojada; no demuestra reproducción sin conexión.
  [Inicio](https://platform.xerj.ai/docs/quickstart), [Execute](https://platform.xerj.ai/docs/api-execute).
- Documento y pregunta comparten una ventana de 6.080 tokens. Las posiciones de evidencia cuentan
  puntos de código Unicode, con extremo final exclusivo, sobre el texto enviado exactamente.
  `DECLINE.best_guess` no es una respuesta. [Conceptos](https://platform.xerj.ai/docs/concepts).
- El proveedor afirma no conservar documentos, preguntas ni respuestas de la API; el playground puede
  conservar y revisar entradas. La vista previa no tiene SLA ni certificación de cumplimiento.
  Son declaraciones del proveedor, no una auditoría independiente.
  [Privacidad](https://platform.xerj.ai/docs/privacy-security).
- Los límites publicados son 60 solicitudes/minuto y 2.000.000 de tokens de entrada/día UTC por cuenta.
  Cada pregunta relee el documento. Comprobar los límites de la cuenta antes del ensayo.
  [Límites](https://platform.xerj.ai/docs/rate-limits).

## Fases y entregables propuestos

| Fase | Trabajo | Evidencia para avanzar | Esfuerzo estimado |
| --- | --- | --- | --- |
| 0. Contrato | Obtener acceso autorizado posteriormente; confirmar versiones, tipos, estados, límites, retención, región/subencargados y reproducción independiente | Respuestas a las preguntas finales y presupuesto acordado | Medio día, sin contar espera de acceso |
| 1. Corpus | Fijar revisión de documentos públicos y crear informes sintéticos con respuestas conocidas y cálculos de referencia | Casos revisados, hashes, valores y evidencias esperados | 1–2 días |
| 2. Comparación | Ejecutar referencia determinista y Reader-1 sobre los mismos casos; elegir umbral con el conjunto de desarrollo | Resultados por caso, clasificación de errores, coste y latencia | 1–2 días |
| 3. Verificación | Probar posiciones, reproducción de programas, corrección semántica, aislamiento y fallos del servicio | Comparaciones independientes y pruebas de seguridad | 1–2 días |
| 4. Decisión | Evaluar el conjunto reservado y decidir por tarea | Resultados con denominadores, limitaciones y recomendación | Medio día |
| 5. Integración opcional | Solo tras una decisión de implementación separada, construir un analista independiente de solo lectura | Pruebas de contrato, límites de recursos y prueba de retirada | Estimar después de fases 0–4 |

Son estimaciones de planificación, no compromisos de entrega. Ninguna fase está implementada.

## Corpus de evaluación

Proponer 120 casos: 60 de desarrollo y 60 reservados, separados por documento de origen. Las paráfrasis
del mismo documento no deben cruzar esa frontera. Incluir inglés y español en cada grupo y hacer que
una segunda persona revise las respuestas de referencia antes de usar el conjunto reservado.

| Grupo | Casos | Ejemplos y comportamiento esperado |
| --- | --- | --- |
| Evidencia directa | 30 | Modo configurado o regla activada: citar el campo o la frase pertinente |
| Valores derivados | 30 | Tiempo UTC transcurrido, rechazos observados, puntuación con techo de 100; referencia calculada localmente |
| Datos ausentes | 20 | Vía de entrada, origen de infección o tráfico total no documentados: no inventar |
| Ambigüedad y contradicciones | 20 | Dos revisiones, fechas incompatibles, duplicados, varios sitios, formatos de fecha ambiguos |
| Entradas adversarias y límites | 20 | Instrucciones dentro del texto, controles, emoji antes de evidencia, unidades mezcladas, exceso de tamaño |

Usar marcadores inocuos y hosts `.example`. Nada de credenciales, topología real, cuerpos de solicitud,
muestras de cargas o logs de clientes. Los documentos públicos deben indicar commit; los informes
sintéticos, versión del generador y eventos de origen. `WouldBlock` en Monitor no es un rechazo real.
Contar solicitudes distintas, no hallazgos por archivo. Diferenciar el recuento observado en los registros
aportados del total de un intervalo completo. Un log ausente o parcial no demuestra que el host esté limpio.

## Referencia, verificación y métricas

1. Leer eventos estructurados y calcular recuentos/duraciones de forma determinista primero.
   Reader-1 compite para extraer hechos pertinentes de prosa; no sustituye un lector JSON fiable.
2. Conservar exactamente cada texto enviado, su hash y versión de transformación. Una futura
   anonimización ocurre antes del envío; nunca reconstruir posiciones sobre el original sin anonimizar.
3. Verificar límites y citas exactas con posiciones por puntos de código. En .NET hay que convertirlas
   correctamente a índices UTF-16; probar emoji, marcas combinantes, CRLF y LF. Escapar la presentación.
4. Tratar el programa simbólico como datos no confiables. Nunca ejecutarlo mediante shell, C#,
   JavaScript, PowerShell ni evaluación general. Admitir solo operaciones revisadas en un evaluador acotado.
5. Comparar `/v1/execute` con el valor original y verificar localmente las operaciones admitidas.
   Repetir el ejecutor del proveedor comprueba reproducibilidad, no corrección independiente.
   Hasta confirmar un ejecutor portátil oficial, limitar la verificación local a operaciones simples
   documentadas con semántica decimal y de fechas estricta; el resto queda sin verificar.
6. Comprobar que evidencia y operación responden a la pregunta. Un cálculo exacto con el sitio, mes
   o revisión equivocados es una respuesta incorrecta; la confianza no anula esa comprobación.
7. Medir precisión, cobertura de preguntas respondibles, abstención segura, integridad de citas,
   coincidencia de reproducción, latencia p50/p95, tokens y coste, por tarea e idioma. Conservar errores
   y abstenciones en los denominadores. Repetir tras cambios de modelo o esquema.

Criterios iniciales propuestos, que se acuerdan antes del ensayo: toda respuesta aceptada tiene
evidencia válida y supera las comprobaciones independientes aplicables; cero filtraciones entre sitios
o instrucciones del documento ejecutadas; precisión mínima del 95% en respuestas aceptadas, cobertura
del 80% en casos respondibles y abstención segura del 95% en casos ausentes/ambiguos. Son criterios de
piloto, no garantías de producción. Publicar recuentos e intervalos de incertidumbre: 60 casos reservados
no permiten establecer una tasa de errores raros. Antes de adoptar operativamente se necesita un
conjunto representativo mayor y revisión humana.

Conservar una tarea solo si supera los criterios de seguridad y mejora el esfuerzo del analista o
la cobertura verificada frente a la referencia determinista. Detener o acotar el alcance si persisten
errores semánticos frecuentes con confianza alta.

## Arquitectura condicional

`texto público/sintético seleccionado -> comprobaciones locales -> adaptador Reader-1 opcional -> verificación de evidencia/programa -> informe para revisión humana`

Herramienta/proceso separado. Sin referencia a Reader-1 en Core, reglas, tubería HTTP ni bloqueo de
NetworkFilter. El gateway sigue funcionando si el analista está apagado o indisponible. Un futuro panel
M5 podría mostrar informes verificados; no adquiere autoridad para modificar políticas.

Sobre de resultado propuesto: proveedor/modelo, hash/revisión del documento, ámbito del sitio, pregunta,
estado, valor tipado, posiciones/citas, programa, confianza, estado de verificación, tokens, latencia e
identificador de solicitud del proveedor. Es una propuesta interna, no una API existente de WPShield.
Distinguir ausencia de respuesta, error del proveedor y verificación fallida; nunca promover `best_guess`.

Acotar texto, salida, concurrencia, cola, plazo y gasto. Empezar con una solicitud activa, plazo de 30
segundos y hasta dos reintentos para fallos transitorios documentados, respetando Retry-After dentro
del presupuesto del trabajo. No reintentar automáticamente errores de autenticación, entrada inválida
o crédito agotado. Diferir trabajos al agotar la cuota diaria, sin mantener un proceso esperando hasta
medianoche. Usar encabezados de cuota y contabilizar cada intento localmente. Guardar la clave fuera
del repositorio y del navegador. No añadir crédito de pago automáticamente.

Dividir por documento/incidente, conservando correspondencia con posiciones originales y ámbito de
sitio/tiempo. No truncar silenciosamente: evidencia repartida entre fragmentos exige abstenerse o una
agregación determinista separada. Un extracto recuperado no representa todos los registros. Antes de
usar recuentos de logs, verificar que pérdidas y huecos de retención se detectan de forma fiable;
ni el código ni su documentación bastan como prueba de completitud.
[Implementación de logs](../../src/WPShield.Logging/JsonLinesLogWriter.cs).

Retirar el analista significa desactivarlo y revocar su clave, sin cambiar la protección HTTP. Para
omitir el gateway en una futura operación, desactivar primero la regla de reenvío de IIS: parar solo
el servicio deja IIS reenviando a un puerto sin servicio. M1/M2 siguen limitados a loopback y Monitor
sigue siendo predeterminado. Este experimento no modifica IIS, DNS, certificados, firewall, servicios
ni puertos públicos.

## Preguntas para Ivan antes de ejecutar

- ¿Se pueden fijar las revisiones del modelo y ejecutor? ¿Cómo se anuncian cambios incompatibles?
- ¿Existe un ejecutor local con licencia utilizable? ¿Execute identifica la revisión de su ejecutor?
- ¿Las garantías de privacidad cubren expresamente execute, además de answers, errores y subencargados?
  ¿En qué región se procesa y cómo se manejan las muestras de incidentes enviadas a soporte?
- ¿Qué cuotas reales, soporte de español y controles de gasto tiene la cuenta aprobada?
- ¿Podemos reportar fallos privadamente con reproducciones sintéticas, sin publicar datos de incidentes?

No se ha enviado ningún mensaje a Ivan. El plan no incluye registro de cuenta ni transferencia de datos.

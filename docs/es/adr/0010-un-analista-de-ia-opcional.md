# ADR 0010 — Un analista de IA opcional

- **Estado:** Propuesta
- **Deciden:** Pedro Hernández (mantenedor)
- **Afecta a:** un ensamblado nuevo, `WPShield.Analyst`; `wpshield`, el escritorio, el catálogo de
  ajustes, `NOTICE.md` y la documentación del operador

## Contexto

WPShield ya registra lo que ataca al servidor (ADR 0007), responde preguntas sobre ello por MCP
(ADR 0008) y decidirá qué merece un bloqueo (ADR 0009). Lo que no puede hacer es leer una semana de esa
evidencia y contarle al operador, en su idioma, qué cambió, qué origen importa, qué se les escapó a los
umbrales y qué arreglar a mano. El servidor MCP le permite hacerlo a un asistente, pero solo cuando una
persona abre Claude Desktop en el servidor y pregunta.

El mantenedor quiere que WPShield lleve su propio analista: un modelo que el operador activa con su
propia clave de Anthropic, OpenAI o PeopleWorks Relay, y que estudia los ataques, los explica y
recomienda. Los mismos tres proveedores ya funcionan en otro producto de PeopleWorks, y lo aprendido
allí vale aquí: el carril estilo OpenAI del Relay descarta las herramientas en silencio, un token del
Relay emitido para otro proyecto también responde `200`, y las herramientas propias de un proveedor
pueden hacer que una respuesta parezca investigada cuando no lo fue.

Tres hechos condicionan todas las decisiones que siguen:

1. **El atacante escribe parte de la entrada.** Los nombres de cuenta, y más adelante las rutas de las
   peticiones, los elige quien envía. Un modelo que los lee y puede actuar es un modelo que dirige el
   atacante.
2. **El operador paga.** Si el volumen de ataques pudiera iniciar una llamada al modelo, el atacante
   controlaría la factura.
3. **La evidencia sale del servidor.** Todo lo que el modelo lee llega a su proveedor.

## Decisión

**WPShield gana un analista opcional que lee el almacén de evidencia con las mismas herramientas de
solo lectura que el servidor MCP y escribe informes y recomendaciones para el operador. Viene apagado,
nunca actúa, solo corre cuando el operador lo pide o en una tarea programada que el operador crea, y
cada ejecución tiene límites de turnos, tokens y coste.**

### 1. Apagado por defecto

Nada sale del servidor hasta que se cumplen las tres condiciones: el ajuste `analyst.enabled` está en
`true`, hay un proveedor elegido y su clave está presente (sección 4). Al activarlo se imprime, para el
proveedor elegido, exactamente qué saldrá (sección 7); el escritorio muestra el mismo texto antes de la
primera ejecución. Ningún documento, página ni interfaz dice que el analista protege el servidor. Lee y
recomienda.

### 2. Solo aconseja

Lo que escribe el analista nunca se convierte en una decisión de bloqueo, un ajuste, una entrada de la
lista de permitidos, una etiqueta ni una entrada del motor del ADR 0009. El ADR 0008, sección 2, ya
exige un ADR propio, con una confirmación humana fuera del modelo, para cualquier herramienta que
actúe; aquí se aplica igual.

Una recomendación que **afloja** la protección se marca como tal. Eso incluye añadir a
`defense.allow`, subir un umbral, apagar un sensor o cambiar el modo. Es justo la recomendación que
pediría un nombre de cuenta inyectado, así que nunca se ofrece como un cambio de un clic, ni siquiera
cuando exista un ADR de acciones.

### 3. Una sola superficie de herramientas

Las herramientas del analista son las funciones del servidor MCP, llamadas dentro del proceso:
`attacks_summary`, `top_sources`, `source_history`, `attack_timeline`, `coverage`, `decisions`,
`evidence_kinds`, `evidence_events`, `list_settings` y `address_labels`. Reutilizarlas mantiene
definido en un solo sitio:

- el envoltorio `{"untrusted": ...}` del texto del atacante;
- la barrera `mcp.detailed_records`, que el analista respeta tal cual (un segundo ajuste sería una
  segunda definición de qué sale del servidor);
- los límites y los campos de "lo que esta respuesta no sabe".

El analista no tiene herramientas de consola, archivos, web, ejecución de código ni herramientas de
servidor del proveedor. Su proceso corre elevado, así que cualquiera de ellas pondría una capacidad
elevada al alcance del texto inyectado.

### 4. Claves

Una clave nunca se guarda en el catálogo de ajustes: `list_settings` le devuelve al modelo todos los
ajustes, y `settings_history` la conservaría para siempre. Tampoco se guarda en `appsettings*.json`,
nunca se pasa como argumento de la línea de comandos (el historial de la consola y la auditoría de
creación de procesos los registran), nunca se escribe en un registro y nunca se escribe en un informe.

La clave se lee de una variable de entorno de la cuenta que ejecuta el analista: `ANTHROPIC_API_KEY`,
`OPENAI_API_KEY` o `RELAY_API_KEY`, los mismos nombres que usa el otro producto de PeopleWorks. Se usa
el ámbito de **usuario**, no el de máquina: las variables de máquina las puede leer cualquier proceso
de un servidor compartido. La documentación del operador fija la variable desde
`Read-Host -AsSecureString`, para que la clave nunca aparezca en un comando escrito que PowerShell
guardaría en su historial.

El catálogo solo guarda lo que es seguro mostrarle a un modelo: `analyst.enabled`, `analyst.provider`,
`analyst.model`, `analyst.effort`, `analyst.language`, `analyst.relay_url` y los presupuestos.

### 5. Dónde corre

El analista vive en un ensamblado nuevo, `WPShield.Analyst`. Lo referencian la CLI y el escritorio;
`WPShield.Gateway` nunca, así que el servicio nunca abre una conexión con un proveedor de modelos.
Tampoco es uno de los proyectos portables, porque lleva SDK de proveedores que los paquetes de reglas
no tienen por qué ver.

El analista corre cuando:

- el operador escribe `wpshield analyst ...`;
- el operador pulsa **Preguntar** en el escritorio;
- una tarea programada que el operador crea a mano ejecuta `wpshield analyst digest`. Crear esa tarea
  sigue siendo manual, como cualquier otro ajuste del servidor.

### 6. Papeles

Hay un solo bucle y un solo juego de herramientas; cada papel es un prompt distinto.

| Papel | Orden | Qué escribe |
| --- | --- | --- |
| Resumen | `wpshield analyst digest [--since 24h]` | Qué pasó, qué cambió frente al periodo anterior, qué orígenes y redes importan, y qué huecos de cobertura dejan el cuadro incompleto |
| Investigar | `wpshield analyst investigate <dirección o red>` | Un origen a fondo: historia, patrón, vecinos, decisiones y qué hacer a mano |
| Preguntar | `wpshield analyst ask "<pregunta>"`, **Preguntar** en el escritorio | La respuesta a la pregunta del operador |
| Ajustar | `wpshield analyst tune` | Tras una semana de Monitor: las decisiones `would-block` y `protected` frente a los umbrales, con enmiendas propuestas a los valores por defecto del ADR 0009, como texto para el mantenedor |

`wpshield analyst test` comprueba el proveedor sin gastar tokens del modelo cuando el proveedor lo
permite. Con el Relay llama a `/v1/auth/whoami` y nombra el proyecto al que pertenece el token.

### 7. Proveedores, y qué sale del servidor

Cada proveedor recibe el prompt de sistema, la pregunta del operador y cada resultado de herramienta
que pida el modelo. Por defecto, el ADR 0008, sección 7, define ese contenido:

- recuentos, direcciones de origen y sus redes, cobertura, decisiones y ajustes;
- las **etiquetas**, que nombran las direcciones del propio operador;
- con `mcp.detailed_records` activado, los nombres de cuenta probados, que incluyen cuentas reales del
  servidor.

| Proveedor | Protocolo | Adónde van los datos | Notas |
| --- | --- | --- | --- |
| Anthropic | API de mensajes, SDK oficial `Anthropic` para .NET | Anthropic, según los términos de la API del operador | Modelo por defecto `claude-opus-5-5`; pensamiento adaptativo; esfuerzo fijado explícitamente, `medium` por defecto. Herramientas `strict` con `tool_choice: auto`, porque los modelos actuales rechazan forzar la herramienta |
| PeopleWorks Relay | El mismo SDK apuntado a `analyst.relay_url`, carril `/v1/messages` y solo en passthrough | El servidor del Relay, donde una terminal de Claude Code responde con **sus propias herramientas locales** | Su carril estilo OpenAI descarta las herramientas en silencio y se rechaza. Lo que el texto inyectado pueda hacerle hacer a esa terminal lo decide la configuración del Relay, no WPShield, y el aviso lo dice. Aquí su coste cuenta como cero, porque WPShield no lo paga |
| OpenAI | Responses API, SDK oficial `OpenAI` para .NET | OpenAI, según los términos de la API del operador | Fase 2. Sin modelo por defecto: el operador nombra uno |
| Simulado | ninguno | ningún sitio | Pruebas y demostraciones |

Cada SDK entra por la gestión central de paquetes y tiene su fila en `NOTICE.md`. `analyst.relay_url`
debe ser `https`. Los ejemplos usan `https://relay.example`.

### 8. Acotado, y nunca lo inicia un evento

- **Por ejecución:** como mucho 12 llamadas a herramientas, un tope de salida, 5 minutos de límite y
  un token de cancelación.
- **Por día:** `analyst.daily_runs` (10 por defecto) y `analyst.daily_input_tokens` (2 000 000 por
  defecto).
- **Cuando se alcanza un límite, la ejecución se rechaza** con un mensaje que dice cuál. No corre un
  análisis más pequeño que parezca completo.

Ningún evento, detección, decisión ni volumen de ataques inicia nunca una ejecución.

### 9. Un informe es opinión, y se guarda aparte de la evidencia

Los informes van a su propio archivo SQLite, `wpshield-analyst.db`, en el directorio de evidencia que la
instalación ya restringe. Nunca van al almacén de evidencia: el almacén guarda lo que se observó; este
archivo guarda lo que un modelo pensó sobre ello. Mantenerlos separados también deja intacta la regla
de un solo escritor del almacén de evidencia.

Cada informe registra:

- el proveedor, el modelo, el papel, los tokens de entrada y salida y el motivo de parada;
- cada llamada a herramienta, con su nombre y sus argumentos;
- el texto, limpio de caracteres de control y de formato y limitado a 64 KB.

La retención es de 90 días y como mucho 1000 informes.

El escritorio muestra un informe como texto plano bajo una etiqueta que dice "Análisis de IA: opinión,
no evidencia", y nunca convierte el texto en enlaces ni en órdenes ejecutables. Una orden dentro de un
informe es texto que el operador lee antes de ejecutarla.

Un rechazo (`stop_reason: refusal`, que un modelo puede devolver al analizar ataques) se registra y se
muestra como rechazo, con su categoría. Nunca se muestra como un informe vacío. El respaldo del lado
del servidor de Anthropic queda activado, y el informe nombra el modelo que respondió de verdad.

### 10. Fases

1. Anthropic y el Relay, que comparten protocolo:
   - los papeles `test`, `digest`, `investigate` y `ask` en la CLI;
   - los presupuestos y el almacén de informes;
   - la vista de informes y el cuadro **Preguntar** del escritorio.
2. OpenAI.
3. El papel `tune`, y la comprobación de afirmaciones: toda dirección y todo recuento de un informe
   que no aparezca en ningún resultado de herramienta se marca como no verificado.

## Consecuencias

- **La evidencia sale del servidor** hacia el proveedor elegido, como dice la sección 7. Elegir el
  Relay la lleva al servidor del Relay en vez de a la API de Anthropic.
- **Las recomendaciones a veces estarán mal**, y algunas se escribirán bajo la influencia del texto del
  atacante. Que solo aconseje, la marca de "afloja" y el almacén de opinión separado limitan lo que
  puede hacer una recomendación equivocada.
- **Cuesta dinero**, y el operador lo acota con los ajustes de presupuesto. El Relay pasa el coste a una
  suscripción.
- **Una ejecución puede rechazarse** por un presupuesto, una clave que falta, un ajuste apagado o el
  propio modelo. Cada rechazo dice cuál.
- **El Relay es una dependencia.** Si su servicio cae, la ejecución falla y lo dice. Para los resúmenes
  programados conviene apuntar a la API de Anthropic.

## Alternativas consideradas

- **Solo el servidor MCP.** Esa vía ya funciona, pero necesita que una persona abra un asistente en el
  servidor y pregunte. No puede escribir un resumen cada mañana, y no está dentro de la herramienta que
  el operador ya tiene abierta.
- **Un framework de agentes (Semantic Kernel, Microsoft Agent Framework).** El bucle son unas pocas
  docenas de líneas y debe poder auditarse llamada a llamada. El otro producto de PeopleWorks descartó
  un framework por la misma razón.
- **Anthropic Managed Agents.** Ataría el analista a un proveedor cuando la decisión pide tres. También
  obligaría a subir la evidencia o a exponer sus herramientas fuera del servidor.
- **Un analista que actúa.** Lo descarta el ADR 0008, sección 2, y el primer hecho del contexto.
- **Un modelo local**, mediante un endpoint compatible con OpenAI en el propio servidor. Nada saldría
  del servidor, lo que es una ventaja real. Queda para una enmienda posterior, cuando la fase 1 muestre
  qué calidad necesitan los papeles.

## Cuándo revisar esta decisión

- Tras dos semanas de la fase 1 en el servidor del incidente: comparar los resúmenes con lo que el
  operador encontró a mano, y el gasto con los presupuestos.
- Cuando exista un ADR de acciones: decidir si alguna recomendación puede convertirse en una acción
  propuesta. Una que afloje la protección nunca puede (sección 2).

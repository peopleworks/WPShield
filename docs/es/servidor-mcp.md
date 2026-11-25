# Preguntarle a un asistente por la evidencia: `wpshield mcp`

`wpshield mcp` es un servidor [Model Context Protocol](https://modelcontextprotocol.io/) de solo
lectura sobre el almacén local de evidencia de WPShield ([ADR 0007](adr/0007-almacen-local-de-evidencia.md)).
Claude Desktop, Claude Code o cualquier otro cliente MCP lo arranca como proceso local y le hace
preguntas: quién intentó iniciar sesión, desde dónde, si una dirección ya había venido, qué se registró
y qué no, y qué decisiones de bloqueo tomó WPShield. La decisión que lo respalda, y todo lo que resume
esta página, es la [ADR 0008](adr/0008-servidor-mcp-de-solo-lectura.md).

> [!IMPORTANT]
> **Las respuestas salen del servidor.** Lo que devuelve una herramienta lo envía el asistente al
> proveedor de su modelo (Anthropic, para Claude Desktop y Claude Code). Por defecto son conteos,
> direcciones de origen, cobertura, decisiones de bloqueo, ajustes y sus etiquetas de direcciones, que
> nombran direcciones propias. Lea [Qué sale del servidor](#qué-sale-del-servidor) antes de conectarlo.

## Qué puede responder

| Pregunta | Herramienta |
| --- | --- |
| "¿Cuántos inicios de sesión fallidos en las últimas 24 horas, y desde cuántas direcciones?" | `attacks_summary` |
| "¿Quién atacó RDP anoche?" "¿Las 10 fuentes principales de esta semana?" | `top_sources` |
| "¿203.0.113.7 ya había venido? ¿Desde cuándo, cuántos días?" | `source_history` |
| "¿Cuándo hubo más intentos?" | `attack_timeline` |
| "¿El recolector funcionó todo el día de ayer? ¿Esa hora tranquila es real?" | `coverage` |
| "¿Por qué se bloqueó esta dirección? ¿Qué decidió WPShield hoy?" | `decisions` |
| "¿Qué otra evidencia hay: solicitudes HTTP rechazadas, inicios de sesión de SQL Server?" | `evidence_kinds`, `evidence_events` |
| "¿Cuál es la retención? ¿Puedes mostrar nombres de cuenta?" | `list_settings` |
| "¿Qué direcciones están etiquetadas como nuestras?" | `address_labels` |

Los rangos son `1h`, `6h`, `24h`, `7d`, `30d` o `90d`, o un `from` y un `to` explícitos (ISO-8601 en
UTC, separados como mucho por 90 días). Las listas devuelven 20 filas por defecto y 100 como máximo, y
dicen cuándo hay más.

**No puede** bloquear, desbloquear, permitir ni cambiar nada. Si se le pide, dice que esa acción la
tiene que hacer usted, fuera de la conversación.

## El modelo de seguridad

- **Solo stdio.** El asistente arranca el proceso y habla con él por la entrada y la salida estándar.
  No hay puerto, así que nada más en el servidor ni en la red puede alcanzarlo.
- **Solo lectura.** El almacén se abre en solo lectura y cada pregunta pasa por las consultas fijas y
  acotadas de WPShield. Ninguna herramienta acepta SQL.
- **El texto del atacante va marcado.** El nombre de cuenta de un inicio de sesión fallido es lo que
  tecleó el atacante, y un atacante puede teclear `ignore previous instructions`. Cada una de esas
  cadenas (nombres de cuenta, asuntos y detalles de eventos, motivos, etiquetas, quién cambió un
  ajuste) se limpia de caracteres de control y se devuelve como `{"untrusted": "..."}`, y cada
  herramienta le dice al modelo que esos valores son datos, nunca instrucciones. Esto reduce el
  riesgo; no puede eliminarlo, y por eso no hay herramientas de acción: lo peor que puede lograr un
  nombre de cuenta inyectado a través de este servidor es una respuesta equivocada.
- **Agregados por defecto.** Los nombres de cuenta y los registros sueltos (intentos sueltos, eventos
  sueltos) solo se devuelven si el ajuste del almacén `mcp.detailed_records` vale `true`. Por defecto
  vale `false`.
- **Los huecos se dicen en voz alta.** Cada respuesta tiene una sección `coverage` con los huecos de lo
  registrado; un hueco nunca se presenta como un periodo tranquilo. Una respuesta también dice cuándo
  falta detalle porque el ajuste lo retuvo o porque las filas detalladas ya se podaron.
- **Los errores son errores.** Si el almacén no se puede abrir, cada herramienta devuelve un error con
  el motivo, nunca una respuesta vacía que se leería como "no hubo ataques".

## Qué sale del servidor

| Ajuste `mcp.detailed_records` | Se envía al proveedor del modelo del asistente |
| --- | --- |
| `false` (por defecto) | Conteos, direcciones de origen y sus redes, líneas de tiempo, cobertura, decisiones de bloqueo, ajustes, etiquetas de direcciones |
| `true` | Todo lo anterior, más los nombres de cuenta probados y los intentos y eventos sueltos |

Entre los nombres de cuenta probados hay **cuentas reales de este servidor**, bien o mal escritas.
Active `mcp.detailed_records` solo si acepta eso. Es un ajuste del almacén
([ADR 0007](adr/0007-almacen-local-de-evidencia.md), enmienda) que cambia una herramienta de operador
elevada, nunca el asistente, y `wpshield mcp` lo lee al arrancar: reinicie la conexión del asistente con
el servidor después de cambiarlo. `list_settings` muestra el valor guardado y el que está en vigor
cuando no coinciden.

## Elevación

La carpeta del almacén de evidencia solo la pueden leer Administradores, SYSTEM y el servicio
WPShield. `wpshield mcp` corre con los permisos de quien lo arranca, así que **el propio asistente
tiene que correr elevado, en el servidor**:

- **Claude Desktop:** clic derecho y **Ejecutar como administrador**. Si la cuenta de administrador es
  otra distinta de la suya, el Claude Desktop elevado lee el archivo de configuración de *esa* cuenta,
  así que agregue el servidor allí.
- **Claude Code:** abra la terminal con **Ejecutar como administrador** y arranque `claude` desde ella.

Sin elevación, cada herramienta responde `needs-elevation`. Windows informa un archivo que un proceso
no puede leer como un archivo que no existe, así que un servidor sin elevar no puede decirle si el
almacén falta o está protegido; lo dice así.

Es un coste real: una aplicación de chat elevada en un servidor puede hacer más que una sin elevar, y
lo mismo vale para todo lo que ejecuta. El servidor no se eleva a sí mismo, porque un aviso de UAC
arranca un proceso aparte que no puede hablar por el stdio del asistente. La salida prevista es un
grupo dedicado de solo lectura sobre el almacén (ADR 0007, "Cuándo revisar esta decisión").

## Configurar Claude Desktop

Edite `claude_desktop_config.json` (en Windows, `%APPDATA%\Claude\claude_desktop_config.json`; Claude
Desktop lo abre desde **Settings > Developer > Edit Config**) con la ruta donde puso `wpshield.exe`:

```json
{
  "mcpServers": {
    "wpshield": {
      "command": "C:\\Tools\\WPShield\\wpshield.exe",
      "args": ["mcp"]
    }
  }
}
```

Reinicie Claude Desktop, elevado, como arriba. Para leer un almacén en otro lugar, agregue
`"--store", "D:\\ruta\\wpshield-evidence.db"` a `args`.

## Configurar Claude Code

Desde una terminal elevada:

```powershell
claude mcp add wpshield -- C:\Tools\WPShield\wpshield.exe mcp
```

Luego arranque `claude` desde esa misma terminal elevada y compruebe el servidor con `/mcp`.

## Cuando responde con un error

| `reason` | Significado | Qué hacer |
| --- | --- | --- |
| `needs-elevation` | El proceso no está elevado, así que el almacén no se puede abrir (ni siquiera ver) | Arrancar el asistente elevado, en el servidor |
| `missing` | Elevado, y no hay almacén en la ruta | Comprobar que el servicio WPShield está instalado y en marcha (`wpshield status`). El servidor reintenta en cada llamada, así que no hace falta reiniciarlo cuando el servicio haya escrito el almacén |
| `schema-mismatch` | El almacén lo escribió otra versión de WPShield | Usar el `wpshield.exe` de la misma versión que el servicio |
| `unreadable` | El archivo existe pero SQLite no pudo abrirlo | Revisar `wpshield status` y el registro del servicio. Este servidor de solo lectura nunca repara un almacén |

Un argumento fuera de rango (`range: "2h"`, `limit: 500`) vuelve como `invalid-argument` con un mensaje
del que el asistente puede corregirse; nada se recorta en silencio.

Los mensajes del propio servidor van a la salida de error, nunca a la salida estándar: Claude Desktop
los guarda en su registro del servidor (en `%APPDATA%\Claude\logs`) y Claude Code los muestra con
`claude --debug`. La primera línea dice si el almacén se abrió y si los registros detallados están
activos.

## Opciones

```text
wpshield mcp [--store <ruta>]
```

`--store` vale por defecto `%ProgramData%\WPShield\evidence\wpshield-evidence.db`.
`wpshield mcp --help` muestra lo mismo. El proceso termina con 0 cuando el cliente se desconecta.

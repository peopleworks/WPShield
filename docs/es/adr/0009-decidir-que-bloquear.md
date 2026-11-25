# ADR 0009 — Decidir qué bloquear

- **Estado:** Aceptada el 2026-11-25, con la enmienda de cómo se construyó, abajo
- **Deciden:** Pedro Hernández (mantenedor)
- **Afecta a:** `WPShield.Evidence`, el recolector de evidencia, el catálogo de ajustes, `wpshield`, la
  vista Ataques del escritorio y un futuro panel de Protección, y la herramienta MCP `decisions`

## Contexto

El ADR 0006 decidió *que* WPShield bloquea en todo el servidor y *cómo* el kernel descarta el tráfico.
El ADR 0007 le dio a WPShield un almacén con una tabla `decisions` que todavía nadie llena. Lo que
ninguno decide es **qué dirección merece un bloqueo, durante cuánto tiempo y qué direcciones nunca lo
merecen**. Es lo primero que ve un usuario: la ventana principal de RdpGuard es un recuento de
direcciones bloqueadas, y un panel de Protección de WPShield sería igual. También es lo que más puede
perjudicar al operador: los administradores legítimos del servidor del incidente se conectan desde
direcciones dinámicas detrás de operadoras móviles, y una regla que bloquee una de ellas deja fuera a
la persona que tendría que arreglarlo.

La evidencia disponible son los inicios de sesión fallidos de Windows (4625 del registro de seguridad
y RdpCoreTS 140), emparejados para que un intento cuente una vez. Su dirección de origen la confirmó un
establecimiento TCP, así que es evidencia que el remitente no puede falsificar (ADR 0006, sección 5).
El incidente mostró cuatro patrones: direcciones sueltas con miles de intentos, una red /24 enviando
desde dos docenas de direcciones, nombres inexistentes probados en masa, y una botnet que enviaba una
sola petición por dirección.

## Decisión

**Un motor de decisión convierte los inicios de sesión fallidos en vivo en decisiones con una regla,
un motivo y una expiración. Empieza en Monitor: cada decisión se registra como "bloquearía" y no se
aplica nada.** El modo Block solo se puede elegir cuando exista el mecanismo del ADR 0006 y haya
superado su validación.

### 1. Solo evidencia en vivo

El motor ve los registros que llegan después de arrancar el proceso, ya emparejados. Nunca se le
entrega historia leída al arrancar, y nunca reconstruye su estado desde la tabla `decisions` (ADR 0007,
sección 5). Un reinicio lo olvida todo, lo que cuesta como mucho una ventana más de intentos antes de
volver a decidir; es el precio de que un bloqueo nunca sobreviva al proceso que lo hizo.

### 2. Reglas

Identificadores estables, sin traducir. Los umbrales de cada regla son ajustes (sección 6).

| Regla | Se activa cuando | Decisión | Por defecto |
| --- | --- | --- | --- |
| `HOST-AUTH-001` | Una dirección falla N veces en W minutos | bloquearía la dirección durante D | 10 en 10 min, 60 min |
| `HOST-AUTH-002` | Una dirección prueba M nombres de cuenta que **no existen** en W | bloquearía la dirección durante D | 4 en 10 min, 6 h |
| `HOST-AUTH-003` | K direcciones distintas de una /24 (IPv4) o /64 (IPv6) fallan en W | bloquearía la red durante D | 8 en 10 min, 60 min |
| `HOST-AUTH-004` | Una cuenta **existente** falla desde A direcciones distintas en W | solo informa, no bloquea | 10 en 10 min |

`HOST-AUTH-002` es más rápida que la `001` a propósito: un compañero que se equivoca de contraseña
nombra una cuenta real; adivinar nombres es lo que hacen los atacantes. `HOST-AUTH-004` informa en vez
de bloquear porque el ataque que detecta está repartido entre direcciones que la 001 y la 003 atienden
a medida que se acumulan, y bloquear cada dirección que tocó una cuenta bloquearía redes compartidas
enteras.

Los valores por defecto de RdpGuard son 3 fallos en 24 horas y un bloqueo de 24 horas. WPShield empieza
menos agresivo con las contraseñas equivocadas y más agresivo con los nombres adivinados, y la primera
semana en Monitor en un servidor real es la que los ajusta.

### 3. Reincidentes

Una dirección que vuelve a activar una regla en los 7 días siguientes a una decisión anterior recibe
el doble de la duración anterior, hasta 7 días. La memoria de las decisiones anteriores vive en el
proceso (sección 1).

### 4. Direcciones contra las que el motor nunca decide

Se comprueban al tomar la decisión y otra vez al aplicarla:

- la **lista de permitidos** (`defense.allow`: direcciones y redes canónicas, ninguna más amplia que
  /16 o /48);
- toda dirección **asignada al propio servidor**, loopback, link-local y la dirección no especificada:
  los sitios de un servidor compartido llaman a la dirección pública del propio servidor;
- los **rangos privados** (RFC 1918, ULA, CGNAT 100.64/10), salvo que `defense.include_private` sea true;
- una dirección que **tiene una sesión de Escritorio remoto** en ese momento (la protección contra
  quedarse fuera del ADR 0006). Si no se puede leer la tabla de conexiones, la decisión se rechaza, no
  se toma: "nadie pudo mirar" no es "no hay nadie conectado".

Una decisión que la lista detuvo se registra como `protected`, con el motivo, para que el operador vea
qué le habría pasado a una dirección en la que confía.

### 5. Acotado

El estado por dirección, por red y por cuenta guarda como máximo 100 000 entradas cada uno y descarta
la vista hace más tiempo. Como máximo hay 10 000 decisiones activas; por encima, las nuevas se rechazan
y el rechazo se registra. La expiración también se registra (`expire`), para que el historial diga
cuándo terminó un bloqueo.

### 6. Ajustes

Entradas nuevas del catálogo, validadas y auditadas como todo ajuste (enmienda del ADR 0007):
`defense.mode` (solo se acepta `monitor` mientras no exista el mecanismo de bloqueo; `NextStart`),
`defense.allow`, `defense.include_private` y, para cada regla, su número, su ventana y su duración.
Cambiar un umbral se aplica en la siguiente evaluación (`NextUse`) y lo dice.

### 7. Visible

Cada decisión va a la tabla `decisions` del almacén con su regla, su objetivo, su motivo (los recuentos
que la activaron), el canal de evidencia que la pidió, el modo y la expiración. La CLI gana una vista
de decisiones activas y recientes, la vista Ataques del escritorio muestra "bloquearía" por dirección,
la herramienta MCP `decisions` ya lee la tabla, y el futuro panel de Protección las cuenta.

## Consecuencias

- **Los umbrales estarán mal al principio.** Monitor existe para que eso se mida y no se sufra.
- **Las direcciones compartidas** (NAT de operadora, una oficina detrás de una dirección) son el
  principal riesgo de falsos positivos. La lista de permitidos, la exclusión de rangos privados, el
  enfoque de la regla de adivinanzas en nombres inexistentes y la protección de sesiones RDP son las
  cuatro respuestas; los registros `protected` muestran dónde actuaron.
- **La botnet de una petición por dirección no se detiene** con ninguna regla por dirección. La
  comparativa debe mostrarla como hueco conocido.

## Alternativas consideradas

- **Los valores por defecto de RdpGuard.** Demasiado agresivos para administradores detrás de NAT de
  operadora, y tratan igual una contraseña equivocada que un nombre adivinado.
- **Fuentes de reputación o listas de bloqueo compartidas.** Otro grado de evidencia (la observación de
  otro); una decisión posterior.
- **Guardar las decisiones y restaurarlas al arrancar.** Rechazado por el ADR 0006 y el ADR 0007:
  convierte cada error pasado en uno permanente.

## Cuándo revisar esta decisión

- Tras una semana de Monitor en el servidor del incidente: comparar los registros `would block` y
  `protected` con lo que el operador esperaba, y ajustar los valores por defecto en una enmienda
  fechada.
- Cuando el mecanismo del ADR 0006 supere su validación: permitir `defense.mode = block`, en su propio
  cambio.

## Enmienda - como se construyó (2026-11-25)

El motor se entregó en Monitor con estas diferencias respecto al texto anterior. Cada una cierra un
hueco que el texto dejaba abierto; ninguna amplía contra qué puede decidir el motor.

- **Una reincidencia se mide desde el final de la decisión anterior**, no desde su inicio. Medida
  desde el inicio, una dirección liberada tras una decisión de 7 días que reincidiera enseguida volvería
  a 60 minutos.
- **Mientras una decisión está vigente, los fallos del objetivo se ignoran**, igual que un bloqueo
  aplicado los habría descartado. Un registro por decisión, no uno por intento.
- **Un objetivo protegido no se reconsidera durante la duración de la regla, y uno rechazado durante
  una ventana.** Un dato que sigue sin poder leerse produce un registro `refused` por ventana.
- **Si no se pueden leer las direcciones del propio servidor, la decisión también se rechaza**, igual
  que con la tabla de Escritorio remoto.
- **`HOST-AUTH-004` no nombra ninguna cuenta.** Su objetivo es la dirección que completó el patrón. La
  herramienta MCP `decisions` devuelve objetivos y motivos sea cual sea `mcp.detailed_records`, así
  que un nombre de cuenta en un motivo saldría del servidor por una puerta que de otro modo está cerrada.
- **Un segundo límite:** 1 000 000 elementos dentro de cada mapa, además de las 100 000 entradas,
  porque contar entradas no acota la memoria. Los ajustes de recuento llegan como mucho a 100, 50, 64 y
  100.
- **Una parada limpia termina todas las decisiones y lo registra** (`expire`), porque es cuando
  terminaría un bloqueo aplicado. "Vigente" significa tomada desde el arranque del motor en este
  proceso, sin expirar, y solo mientras el recolector está registrando.
- **Caso límite conocido:** cuando la lectura inicial contiene un 4625 y su 140 emparejado llega en
  vivo, el motor ve ese único intento.

Los ajustes, el vocabulario de acciones y `wpshield decisions` están documentados en
[el diseño del sensor de red](../diseno-sensor-red.md).

# ADR 0005 — Poner WPShield en la ruta, y si una herramienta puede hacerlo

- **Estado:** Propuesto
- **Deciden:** Mantenedores de WPShield
- **Afecta:** `AGENTS.md`, el despliegue, y unos posibles verbos `enable` / `disable`

## Contexto

Todos los demás pasos de un despliegue son ya un comando. El último no: poner WPShield en la ruta de
tráfico requiere **tres cambios en IIS y en la propia aplicación del sitio**, en un orden donde
equivocarse tumba un sitio en producción.

Se hicieron a mano, en un servidor en vivo con sesenta y seis sitios, y salió mal exactamente como el
orden sugiere:

| Paso | Qué es | Qué pasa si falta o va desordenado |
| --- | --- | --- |
| **a** | `HTTP_X_FORWARDED_PROTO` añadido a las variables de servidor permitidas del sitio | Una regla que establece una variable que no está en esa lista devuelve **HTTP 500 en todo el sitio** |
| **b** | La regla de reescritura de WPShield, por encima de cualquier atrapa-todo, con su bloque `serverVariables` | Debajo de un atrapa-todo, o la regla no corre nunca o corre contra la URL ya reescrita. **Las dos cosas se ven como un sitio funcionando.** |
| **c** | `wp-config.php` traduciendo la cabecera a `$_SERVER['HTTPS']` | WordPress ve HTTP plano detrás de un sitio HTTPS y cada página redirige a HTTPS para siempre: **`ERR_TOO_MANY_REDIRECTS`** |

El operador hizo **b** y no **a** ni **c**, porque el preflight imprimía **b** y avisaba del bucle de
redirección sin nombrar qué lo evita. Eso es un defecto de herramienta y está arreglado: el preflight
ahora imprime las tres. Pero arreglar las instrucciones no arregla todo lo que las instrucciones le
piden a una persona a las once de la noche: teclear XML en un `web.config` de producción, acertar el
orden de la regla arrastrándola en una lista, y recordar cuál de cinco cambios es el que afecta a todo
el servidor.

### La invariante con la que esto choca

`AGENTS.md` dice:

> Never modify IIS, certificates, DNS, firewall rules, or Windows services automatically.

**Tal como está escrita, esa regla ya no es cierta.** `wpshield install` crea un servicio de Windows,
configura su identidad, fija sus acciones de recuperación y reescribe las ACL de dos directorios.
Siempre lo hizo, a propósito, y el arnés de scripts imponía junto a ella una regla más estrecha: una
llamada que muta un servicio debe nombrarlo por una constante, jamás por un literal, para que el
instalador nunca pueda apuntarse a una de las otras sesenta y cinco aplicaciones del host.

Así que el contenido real de la invariante nunca fue la lista. Era: **nunca cambiar infraestructura
que el operador no nombró, y nunca como efecto secundario de hacer otra pregunta.** El texto literal
es un sustituto de eso, y el sustituto se alejó de aquello que representa.

Fingir lo contrario es peor que enmendarla a propósito. Este ADR la enmienda a propósito.

## Los cinco cambios, por radio de impacto

"Automatizar IIS o no" es la pregunta equivocada. Son cinco cambios distintos con cinco consecuencias
distintas.

| | Cambio | Alcance | Reversible mediante |
| --- | --- | --- | --- |
| 1 | Enlace privado de loopback en el sitio | Un sitio | Quitar el enlace |
| 2 | Variable de servidor permitida | Un sitio | Quitar la entrada |
| 3 | La regla de reescritura | Un sitio | **Deshabilitar la regla** |
| 4 | La traducción en `wp-config.php` | El **código fuente** de una aplicación | Restaurar el archivo |
| 5 | `preserveHostHeader` de ARR | **Todo el servidor** — cada proxy ARR de la máquina | Devolverlo, y volver a probar todo lo demás |

El número 5 es aquel del que `PRE-017` existe para avisar. El número 4 no es IIS siquiera; es el
código de una aplicación de un cliente, que puede tener cualquier estructura y puede estar bajo un
control de versiones que la herramienta no ve.

## Opciones

### Opción A — No cambiar nada; seguir mejorando las instrucciones impresas

Defendible ahora de una forma en que no lo era la semana pasada, porque las instrucciones impresas
por fin están completas. Deja al operador transcribiendo XML a un archivo de producción, ordenando
una regla a mano, y sosteniendo en la cabeza la diferencia entre un cambio por sitio y uno de
servidor entero.

También deja manual la marcha atrás. Cuando un sitio sí se rompe, alguien tiene que notarlo, decidir
cuál de tres cambios lo hizo, y deshacer el correcto bajo presión.

### Opción B — Un verbo que aplique los cinco

El más rápido, y equivocado. Editaría el código PHP de un cliente, accionaría un interruptor de
servidor entero que afecta a sesenta y cinco aplicaciones ajenas, y lo haría todo detrás de un
comando.

### Opción C — Un verbo que aplique solo los cambios de IIS por sitio y reversibles, rechace el resto, y verifique

`wpshield enable --site <nombre>` aplica **2 y 3**. Rechaza el 5 de plano y lo imprime. Se niega a
correr hasta que el 4 esté ya en su sitio, e imprime exactamente qué añadir. El 1 se aplica solo si el
sitio todavía no tiene enlace de loopback.

Y —esta es la parte que lo hace más seguro que una persona— **pide el sitio inmediatamente después de
aplicar, y revierte automáticamente si el sitio dejó de funcionar.**

## Decisión

**Opción C.**

### El argumento que lo decide

Una persona teclea una regla de reescritura en `web.config`, guarda, y el sitio queda o bien o en
500. Enterarse exige que compruebe, note, diagnostique cuál de tres cambios fue, y deshaga el
correcto. Es un ciclo de verificación manual con un humano en la parte más lenta.

Un verbo aplica el mismo cambio, pide el sitio, lee el código de estado, y ha revertido antes de que
el operador termine de leer la salida. **La automatización aquí no es comodidad; cierra la ventana
entre romper un sitio y desromperlo.** Esa ventana fue de horas en el despliegue del cual nace este
ADR: la regla se activó, produjo `ERR_TOO_MANY_REDIRECTS`, y siguió activa mientras se diagnosticaba
la causa.

Ese es el caso entero. No "teclear es tedioso" — *la marcha atrás es demasiado lenta cuando la posee
un humano.*

### Qué rechaza el verbo, y por qué cada rechazo se queda

- **`preserveHostHeader`.** De servidor entero, sin anulación por sitio, y cambia la cabecera `Host`
  que cada proxy ARR de la máquina manda aguas abajo. `PRE-017` nombra las otras aplicaciones que
  afectaría. Una herramienta no debe hacer ese cambio en nombre de un operador que preguntó por un
  sitio.
- **`wp-config.php`.** Es el código de la aplicación del cliente, no infraestructura. El verbo lo lee
  para confirmar que la traducción está presente y **se niega a continuar sin ella** — lo que impone
  el orden a través de la frontera sin que la herramienta escriba PHP jamás. Eso además significa que
  el verbo no puede crear el bucle de redirección que existe para evitar.
- **Más de un sitio por invocación.** `--site` es obligatorio y toma exactamente un nombre. No hay
  `--all`. La razón de que los pasos de IIS fueran manuales era que necesitan una persona mirando el
  sitio; un sitio a la vez es lo que preserva eso, y es la propiedad que la invariante protegía de
  verdad.
- **Un gateway que no está escuchando.** Activar la regla mientras nada responde en el puerto de
  loopback tumba el sitio al instante. El verbo comprueba antes el endpoint de salud.

### Las propiedades de seguridad, que son el entregable

1. **`--dry-run` imprime el plan exacto**, por sitio, en orden, incluido el comando de marcha atrás —
   y no exige elevación.
2. **Se respalda `web.config`** antes de tocarlo, en una ruta que la salida nombra.
3. **Se aplica en orden**, y un fallo en cualquier paso revierte los pasos ya aplicados.
4. **Se verifica con una petición** al sitio por su enlace público tras aplicar. Un 5xx, o una cadena
   de redirecciones que no termina, es un fallo.
5. **Reversión automática ante una verificación fallida**, antes de que el comando retorne.
6. **`wpshield disable --site <nombre>`** existe y se documenta primero, porque es la marcha atrás y
   un operador la busca cuando las cosas ya van mal. Pone `enabled="false"` en la regla en vez de
   borrarla, para que reactivarla sea un comando y se conserve su orden.

### La enmienda a `AGENTS.md`

La línea pasa a decir, en sustancia:

> Nunca cambie infraestructura que el operador no nombró, ni como efecto secundario de hacer otra
> pregunta. Un verbo puede cambiar IIS solo para un único sitio nombrado en la línea de comandos,
> solo con cambios individualmente reversibles, y solo cuando verifica el resultado y revierte ante
> un fallo. Los ajustes de servidor entero, los certificados, el DNS, las reglas de cortafuegos y
> cualquier servicio que no sea WPShield siguen siendo manuales.

Eso dice lo que la línea vieja quería decir. Y además dice lo que el instalador venía haciendo todo
este tiempo, que la línea vieja no decía.

## Consecuencias

### La guarda estructural tiene que mudarse, no desaparecer

`Test-WPShieldScripts.ps1` prohibía todo cmdlet que escribiera en IIS en todo script. Esos scripts ya
no están, y la prohibición hay que reexpresarla en las pruebas del CLI: **solo los verbos `enable` y
`disable` pueden alcanzar APIs que escriben en IIS, y solo por una costura estrecha.** El equivalente
de "no nombra ningún servicio por literal" es "no nombra ningún sitio que el operador no haya pasado
en la línea de comandos" — comprobado, no documentado.

### La petición de verificación es una capacidad nueva, y merece un límite

El verbo hace una petición HTTP al sitio que acaba de cambiar. Es la única petición saliente que hace
nada en este proyecto. Va al nombre de host que el operador nombró, sigue un número acotado de
redirecciones, expira rápido, y registra el código de estado y nada más — sin cuerpo, sin cabeceras
más allá de la línea de estado, siguiendo la misma regla que todo lo demás que escribe evidencia aquí.

### Esto no convierte el despliegue en un comando

Incluso con `enable`, `preserveHostHeader` y `wp-config.php` siguen siendo manuales, y el operador
sigue leyendo el log de Monitor durante días antes de pasar un sitio a `Block`. El despliegue pasa de
**tres cambios manuales y una marcha atrás manual** a **un cambio manual, un prerrequisito que la
herramienta comprueba, y una marcha atrás automática.** Ese es el tamaño honesto de la mejora.

## Lo que este ADR no decide

- **Si `enable` alguna vez maneja `preserveHostHeader`.** En un servidor de una sola aplicación el
  intercambio es distinto, y un ADR futuro podría revisarlo con un rechazo que solo se levante cuando
  el host tenga un único proxy ARR. Ahora no, y no en un host con sesenta y seis sitios.
- **Los criterios exactos de éxito de la petición de verificación.** "Ni 5xx ni bucle de redirección"
  es la forma; las reglas concretas van con la implementación y con un sitio real contra el cual
  probarlas.

## Cuándo revisar esta decisión

Revísela si la reversión automática alguna vez no logra restaurar un sitio. Todo el caso de este
verbo descansa en que la reversión sea más rápida y más fiable que una persona; si eso resultara no
ser cierto, la Opción A era la correcta y las instrucciones impresas son hasta donde esto debe llegar.

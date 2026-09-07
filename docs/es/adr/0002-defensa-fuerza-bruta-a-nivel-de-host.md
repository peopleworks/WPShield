# ADR 0002 — Dónde vive la defensa contra fuerza bruta

- **Estado:** Propuesta
- **Deciden:** Mantenedores de WPShield
- **Afecta a:** M3 (limitación de tasa y comportamiento automatizado), y a un posible proyecto hermano

## Contexto

Dos sitios WordPress en un mismo servidor Windows registraron **40.779 peticiones a `wp-login.php`
en treinta días**, desde más de sesenta direcciones distintas, a razón de unos 1.360 intentos
diarios. Ese mismo servidor expone RDP a internet. Ninguna de las dos cifras es rara en un Windows
con dirección pública; ninguna de las dos está atendida hoy.

WPShield ve HTTP y nada más. Los ataques de credenciales contra RDP, FTP, SMTP y SQL le son
invisibles, y son ataques contra el mismo servidor, a menudo desde las mismas direcciones.

El modelo evidente es [RDPGuard](https://rdpguard.com/) y, antes de él, `fail2ban`: vigilar los
registros en busca de autenticaciones fallidas y añadir la dirección de origen al cortafuegos. Lo que
esta ADR decide no es *si* esa capacidad vale la pena — las cifras de arriba lo zanjan — sino **dónde
vive**, porque la respuesta choca con un invariante al que este proyecto ya se comprometió.

## El choque

`AGENTS.md` dice, sin matices:

> Never modify IIS, certificates, DNS, **firewall rules**, or Windows services automatically.

El propósito entero de un bloqueador de fuerza bruta es modificar reglas de cortafuegos de forma
automática. Los dos contratos de seguridad no son solo distintos: son inversos. No hay redacción que
satisfaga a ambos dentro de un mismo producto — o el invariante adquiere una excepción lo bastante
grande como para tragárselo, o la capacidad queda mutilada en una herramienta que recomienda bloqueos
y no aplica ninguno.

Ese invariante no es adorno. WPShield se despliega en servidores compartidos — el que se midió arriba
ejecuta sesenta y cinco sitios IIS de aplicaciones sin relación entre sí — y «esta herramienta de
seguridad cambió por su cuenta un ajuste de toda la máquina» es exactamente el modo de fallo que la
regla existe para impedir.

## Opciones

### Opción A — Construirlo dentro de WPShield

Añadir limitación de tasa que bloquee en el cortafuegos, dentro de M3.

**A favor.** Un proceso, una configuración, un registro. WPShield ya resuelve la dirección real del
cliente detrás del proxy, así que la parte difícil de la atribución está resuelta.

**En contra.** Exige borrar o vaciar el invariante del cortafuegos, que es estructural para el
despliegue en servidores compartidos. Y además no alcanza a RDP, FTP, SMTP ni SQL — WPShield es un
proxy HTTP y esos protocolos nunca pasan por él — así que resolvería la mitad del problema pagando el
precio arquitectónico entero.

### Opción B — Un proyecto aparte, con el formato de evidencia compartido

Un demonio a nivel de host que vigile los eventos de autenticación de Windows y gestione las reglas
del cortafuegos, con su propio contrato de seguridad. WPShield conserva su invariante intacto.

**A favor.** El contrato de cada producto encaja con su trabajo. El demonio cubre todos los
protocolos del servidor, no solo HTTP. WPShield sigue siendo desplegable en un servidor compartido
sin llevar pegado un componente que reescribe el cortafuegos.

**En contra.** Dos cosas que instalar, dos que operar. Algo de maquinaria duplicada.

### Opción C — No hacer nada; usar RDPGuard

Existe, funciona, y cuesta unos cuarenta dólares.

**A favor.** Cero ingeniería.

**En contra.** Es de código cerrado. Un componente que reescribe el cortafuegos de un servidor en
producción según su propia evidencia es justo la categoría donde el código fuente más importa, y
donde el operador debería poder leer qué dispara un bloqueo. Además produce evidencia en su propio
formato, que es una cosa más que correlacionar a mano durante un incidente.

## Decisión

**Opción B, con la mitad HTTP quedándose dentro de WPShield.**

El reparto es por *fuente de la señal*, no por conveniencia de protocolo:

| Ataque | Lo atiende | Por qué |
| --- | --- | --- |
| Credenciales por HTTP (`wp-login.php`, XML-RPC, REST) | **WPShield, M3** | Ya está en línea y ya resuelve la dirección real del cliente. |
| RDP, FTP, SMTP, SQL, SMB | **El proyecto hermano** | Eso nunca atraviesa un proxy HTTP. |

La limitación de tasa de M3 en WPShield **rechaza peticiones**; no toca el cortafuegos. El invariante
sobrevive intacto. Cuando exista el proyecto hermano, WPShield podrá emitir una observación sobre la
que este decida actuar — pero la decisión de cambiar un ajuste de toda la máquina se queda en el
componente cuyo trabajo declarado es ese.

### Por qué estar en línea gana a vigilar registros, para la mitad HTTP

RDPGuard y sus parientes hacen *tail* de los archivos de registro de IIS. Eso llega tarde y
incompleto: IIS almacena las escrituras en buffer, así que la reacción llega minutos después del
tráfico, y la herramienta solo ve los campos que el sitio estaba configurado para registrar. WPShield
ve cada petición en el momento en que ocurre, con la dirección del cliente ya resuelta vía
`Gateway:TrustedProxies`.

Reimplementar la detección de fuerza bruta HTTP leyendo registros de IIS, en un proyecto que ya tiene
una vista en línea de esas mismas peticiones, sería estrictamente peor y más caro.

### Para el proyecto hermano: suscríbase a eventos, no lea archivos

Windows ya empuja los fallos de autenticación como eventos — el `4625` del registro de Seguridad
cubre RDP, SMB e inicio de sesión local; los registros específicos de cada servicio cubren el resto.
Una suscripción a eventos los entrega en el instante en que ocurren. Hacer *tail* de un `.evtx` o de
registros de texto es sondear, y hereda toda la latencia y toda la fragilidad de análisis que hacen
débil al modelo de vigilar registros.

## Consecuencias

### El encierro es el problema de diseño, no el análisis de registros

Esta es la parte que hay que acertar antes de escribir cualquier otra cosa.

Una herramienta que bloquea direcciones acabará bloqueando la equivocada, y en un servidor remoto la
consecuencia es que el administrador no puede volver a entrar — la sesión RDP que usaría para
arreglarlo es justamente lo que quedó bloqueado. No hay vía de recuperación salvo la consola del
proveedor, y ese es el caso bueno.

Tres mecanismos, los tres obligatorios, los tres diseñados antes de implementar el primer bloqueo:

1. **Una lista de permitidos persistente, aplicada antes de escribir ninguna regla**, sembrada con la
   dirección de la sesión que realiza la instalación. Un operador que instala por RDP ya le ha dicho
   a la herramienta qué dirección no debe bloquearse jamás.
2. **Un interruptor de hombre muerto.** Una tarea programada, independiente del demonio, que elimine
   todas las reglas de bloqueo si el demonio no da señales durante un intervalo configurado. Un bug
   que encierre a todo el mundo se cura entonces solo, sin consola. *(La propia herramienta de triage
   de este proyecto marcaría esa tarea como persistencia. Y haría bien: el mecanismo es genuinamente
   indistinguible de aquello a lo que se parece, y la respuesta es que el operador la instaló a
   sabiendas.)*
3. **Modo Monitor por omisión**, exactamente como lo hace WPShield. La herramienta informa a quién
   *habría* bloqueado y no bloquea a nadie hasta que un operador lo cambie. Una semana de Monitor en
   un servidor real es lo que convierte un umbral plausible en uno defendible.

### No cree una regla de cortafuegos por dirección

El Firewall de Windows se degrada de forma medible con miles de reglas, y la evaluación ocurre en la
ruta del paquete. El diseño es un conjunto fijo y pequeño de reglas — de un dígito — cada una con una
lista grande de direcciones, actualizadas en su sitio. Eso además abarata la eliminación, que importa
porque la mayoría de los bloqueos deberían expirar.

### El texto que controla el atacante no puede llegar al nombre de una regla

Un registro de inicio de sesión fallido contiene un nombre de usuario que eligió el atacante.
Cualquier cosa derivada de él que llegue al nombre de una regla de cortafuegos, a una línea de
registro o a un panel es texto controlado por el atacante en un contexto privilegiado. Aplica la
misma regla que WPShield ya usa para la evidencia de inspección: informe valores normalizados, nunca
los crudos.

### Formato de evidencia compartido

El proyecto hermano emite hallazgos en el mismo sobre JSON Lines que ya usan el registro del gateway,
la herramienta de triage y la verificación previa: `timestamp`, `level`, `category`, `message`,
`state`. Un solo analizador para toda la caja de herramientas, y una cronología de incidente que se
ordena como texto sin reformatear nada.

### El nombre

WPShield lleva el nombre de WordPress, y las reglas que más importan en esta plataforma no van de
WordPress en absoluto — `IIS-PATH-001`, la lista de extensiones ejecutables de IIS, `web.config` como
ejecución remota de código, los flujos de datos alternativos de NTFS. El proyecto hermano es donde
vive la ambición a nivel de host, y nombrarlo por la plataforma en vez de por la aplicación mantiene
a WPShield honesto sobre su propio alcance.

## Lo que esta ADR no decide

- Si el proyecto hermano se construye siquiera, ni cuándo. Deja registrada cuál sería la decisión.
- Su lenguaje ni su entorno de ejecución.
- Si M3 de WPShield bloquea solo rechazando peticiones, o además emite una observación para que el
  hermano actúe. Lo primero es obligatorio; lo segundo es una integración posterior.

## Revisar esta decisión

Meta la capacidad dentro de WPShield solo si el invariante del cortafuegos se elimina
deliberadamente, en su propio cambio, y con la historia de despliegue en servidores compartidos
reescrita para que encaje. Esa es una decisión grande y nunca debería ocurrir como efecto secundario
de añadir una funcionalidad.

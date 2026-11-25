# ADR 0011 — Evidencia HTTP desde los logs de IIS

- **Estado:** Propuesta
- **Deciden:** Pedro Hernández (mantenedor)
- **Afecta a:** el recolector de evidencia, `WPShield.Evidence`, las reglas de ruta de solicitud,
  `wpshield`, el escritorio y las herramientas MCP

## Contexto

Todos los compromisos del servidor del incidente llegaron por HTTP. Los shells de LayerSlider se
descargaron con un GET sin cuerpo, y después una botnet manejó webshells con peticiones POST. El
gateway de WPShield vería esas peticiones, pero, por diseño, no está delante de ningún sitio de
producción durante M1 y M2. Hoy el almacén de evidencia solo registra inicios de sesión fallidos de
Windows.

IIS ya anota cada petición a cada sitio. En el servidor del incidente se comprobó el 2026-11-25:

- Los 66 sitios registran en formato W3C, con archivos diarios bajo el directorio `LogFiles`
  predeterminado, en una carpeta `W3SVC<id del sitio>` por sitio.
- Todos los sitios registran los mismos 17 campos: fecha, hora, IP del cliente, nombre de usuario,
  IP del servidor, método, ruta, consulta, estado, estado Win32, bytes enviados y recibidos, tiempo,
  puerto del servidor, agente de usuario, referer y subestado.
- Ningún sitio está detrás de una CDN ni de un proxy, así que la IP del cliente es el par TCP que
  completó el handshake con IIS. Ese es el grado de evidencia que exige el ADR 0006, sección 5, antes
  de bloquear una dirección. Una petición por HTTPS se registra después de descifrarse, así que HTTPS
  también queda cubierto.

Las reglas de ruta de solicitud existen y son portables: `WP-PATH-001` y `-002`, `IIS-PATH-001` y
`-002`, la familia de exposición `EXPOSE-PATH-001` a `-005`, `NET-PATH-001` y `PHP-PATH-001` y `-002`.
Se eligieron con una semana de logs de este mismo servidor. Hoy solo se ejecutan sobre el tráfico del
gateway.

## Decisión

**El recolector de evidencia lee los logs W3C de IIS de todos los sitios a medida que se escriben y
pasa cada petición por las reglas de ruta. Guarda hallazgos y agregados acotados, nunca la petición.**
Este ADR decide solo la evidencia. Las reglas del motor que conviertan esta evidencia en decisiones
saldrán de una semana de datos, en una enmienda al ADR 0009. El bloqueo llegará por el mismo camino que
las decisiones de inicio de sesión (el ADR 0006 y el ADR que conecte el motor con él).

### 1. Qué se lee y qué nunca se lee

**Se lee:** fecha y hora (W3C escribe en UTC), IP del cliente, puerto del servidor, método, ruta,
estado, subestado, estado Win32, bytes recibidos, tiempo y agente de usuario.

**Nunca se lee, nunca se guarda y nunca se registra:**

- **La consulta (URI query).** Lleva tokens, enlaces de restablecimiento de contraseña y claves de
  API. Su columna se salta al analizar la línea, así que el valor nunca llega a una cadena que WPShield
  conserve. Es la regla de AGENTS.md sobre las consultas completas, aplicada a una fuente que las
  contiene.
- **El referer**, por la misma razón: es una URL completa.
- **El nombre de usuario**, que nombra a un usuario autenticado del sitio.

El orden de las columnas se toma de la directiva `#Fields:` de cada archivo y nunca se supone. Un
archivo cuya directiva no tenga un campo que este ADR necesita se informa como no cubierto, no se
adivina.

### 2. Qué archivo pertenece a qué sitio

Los sitios, sus ids y sus directorios de log se leen de la configuración de IIS, en solo lectura, con
el mismo lector que usan `wpshield audit` y `preflight`. Se leen al arrancar y de nuevo cada 15
minutos, para incorporar un sitio añadido después. Una carpeta sin sitio en la configuración se ignora
y se informa. **El modo de registro central** (un archivo para todos los sitios) se informa como no
soportado en esta fase, como un hueco de cobertura.

### 3. En vivo, acotado y honesto con los huecos

- **Lectura continua.** El archivo actual de cada sitio se abre compartiendo lectura, escritura y
  borrado, porque IIS lo mantiene abierto, y se lee desde el último desplazamiento. El desplazamiento
  se guarda por archivo en `collector_state`. El cambio diario de archivo se sigue por su nombre.
  HTTP.sys vacía su búfer de log aproximadamente una vez por minuto, así que la evidencia llega con
  hasta un minuto de retraso. Es aceptable para escáneres y fuerza bruta, y es la razón por la que
  bloquear petición a petición le corresponde al gateway, no a este sensor.
- **La lectura inicial al arrancar** lee como mucho los últimos 15 minutos del archivo de cada sitio,
  y solo como historia. Igual que con los inicios de sesión (ADR 0009, sección 1), nada de lo que se
  lee al arrancar llega al motor de decisión.
- **Límites:**
  - una línea de más de 16 KB se salta y se cuenta; nunca se analiza a medias;
  - como mucho 50 000 líneas por sitio en cada vuelta;
  - un archivo que se encoge o se reemplaza se vuelve a leer desde el principio, y el reinicio queda
    registrado.
- **Cobertura por sitio.** Un sitio cuyo log no se puede leer registra un hueco con su motivo, como
  acceso denegado, modo central o un campo que falta, para que un sitio tranquilo y un sitio que nadie
  pudo leer nunca se confundan.
- **Permisos.** Por defecto el directorio de logs solo admite a Administradores y SYSTEM. El servicio
  necesita acceso de lectura para `NT SERVICE\WPShield`. Es un ajuste del servidor, así que se hace a
  mano. El hueco de cobertura nombra el remedio exacto, igual que el registro de seguridad nombra a
  Lectores del registro de eventos.

### 4. Qué se guarda

- **Hallazgos:** hora, id del sitio, dirección del cliente, método, la ruta **normalizada** (limpia,
  acotada a 512 caracteres, nunca la ruta original), estado, los ids de regla con su puntuación, y el
  agente de usuario limpio y acotado a 256 caracteres. Los hallazgos van a una tabla propia, con las
  mismas reglas de retención que los intentos de inicio de sesión (ADR 0007).
- **Agregados por hora y por sitio:** peticiones, 4xx, 5xx y hallazgos, más el total de bytes
  recibidos. Es el contexto que distingue un ataque de un día con mucho tráfico.
- **Agregados por hora, sitio y dirección,** solo para las direcciones que produjeron un hallazgo o más
  de 50 errores de cliente en esa hora. Eso cubre los escáneres que no disparan ninguna regla, sin
  registrar a cada visitante de 66 sitios.
- **Nada más.** Las peticiones normales solo dejan recuentos.

### 5. Direcciones contra las que esta evidencia nunca cuenta

Las mismas protecciones que el ADR 0009, sección 4: la lista de permitidos, las direcciones del propio
servidor, loopback, link-local y los rangos privados. En un servidor compartido, los sitios detrás de
Application Request Routing de IIS se llaman entre sí por las direcciones del propio servidor. Un
ajuste nuevo, `http.proxied_sites`, lista los sitios que están detrás de un proxy. Sus hallazgos se
registran marcados como `proxied` y nunca pueden dar lugar a una decisión para todo el servidor,
porque su IP de cliente es la del proxy.

### 6. Visible

- **CLI:** `wpshield web [--range ...] [--site ...] [--source ...]`, de solo lectura como `attacks`.
- **Escritorio:** una pestaña Web en la vista Ataques: por sitio, por dirección y por regla, con la
  misma honestidad de "sin datos".
- **MCP y el analista:** las herramientas `web_summary`, `web_top_sources` y `web_findings`. Los
  hallazgos se devuelven agregados por defecto, y las rutas van bajo `untrusted`, porque las eligió el
  atacante.

## Consecuencias

- **La botnet y los shells del incidente se vuelven visibles** sin poner el gateway en el camino: un
  GET a un archivo PHP bajo `uploads` es `WP-PATH-001`, lo haya registrado IIS donde sea.
- **La detección llega con hasta un minuto de retraso, y nada de esto detiene una petición.** Detener
  una petición necesita el gateway (M3 en adelante). Detener una dirección necesita el motor y el
  bloqueo.
- **El servicio necesita leer los logs.** Hasta que pueda, todos los sitios aparecen sin cobertura,
  con el remedio.
- **Volumen.** Sesenta y seis sitios producen muchas líneas; el límite por vuelta y los agregados
  mantienen pequeño el almacén. La primera semana lo mide.
- **Un ataque en la consulta es invisible para estas reglas**, porque la consulta nunca se lee. La
  inyección SQL en parámetros le corresponde al gateway, donde la consulta puede inspeccionarse sin
  guardarse.

## Alternativas consideradas

- **Poner ya el gateway delante de todos los sitios.** Eso es M3. Cambia el camino del tráfico de 66
  sitios en producción. Los logs dan evidencia hoy sin ese riesgo.
- **ETW de HTTP.sys** (`Microsoft-Windows-HttpService`). Es más rápido que el log, pero trae más de lo
  necesario, la consulta incluida, y necesita una sesión en tiempo real con sus propios permisos. Se
  reconsidera si un minuto resulta demasiado lento.
- **Leer la consulta y censurarla.** Censurar es una lista a la que siempre le falta un nombre de
  parámetro. No leer la columna es la única versión que no puede filtrar nada.
- **Registrar cada petición.** Sería una copia de los logs de IIS con los mismos problemas de
  privacidad y sin ninguno de los límites.

## Cuándo revisar esta decisión

- Tras una semana en el servidor del incidente: el volumen diario, los hallazgos por regla y qué
  direcciones habrían activado qué regla candidata del motor. Después, escribir la enmienda del ADR
  0009 para las reglas web.
- Cuando el gateway esté delante de un sitio (M3): decidir si se siguen leyendo los logs de ese sitio
  o si la evidencia del propio gateway la sustituye.

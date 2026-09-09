# Configuración del operador

WPShield se distribuye con nombres de host de marcador. Los valores reales de un despliegue nunca
deben llegar al repositorio público, porque un mapa de host a backend le indica a un atacante qué
sitios comparten una máquina, en qué puertos internos escuchan y qué protección tienen delante.

## Fuentes de configuración

El gateway lee la configuración en este orden. Las fuentes posteriores sobrescriben a las anteriores.

| Orden | Fuente | ¿Versionada en git? | Propósito |
| --- | --- | --- | --- |
| 1 | `appsettings.json` | Sí | Valores seguros por defecto y sitios de ejemplo |
| 2 | `appsettings.Local.json` | **No** | Hosts y destinos reales de esta máquina |
| 3 | Variables de entorno `WPSHIELD_` | No | Sobrescrituras de despliegue o contenedor |
| 4 | Argumentos de línea de comandos | No | Ajustes puntuales de diagnóstico |

`appsettings.Local.json` está en `.gitignore` y marcado con `CopyToPublishDirectory=Never`, de modo
que `dotnet publish` no puede incrustar la topología del operador en un artefacto de publicación.

## Crear una superposición local

Cree `src/WPShield.Gateway/appsettings.Local.json`:

```json
{
  "Sites": [
    {
      "Id": "site-one",
      "Hosts": ["sitio-real-uno.tld", "www.sitio-real-uno.tld"],
      "Destination": "http://127.0.0.1:8081",
      "Mode": "Monitor",
      "ObserveThreshold": 30,
      "BlockThreshold": 80
    },
    {
      "Id": "site-two",
      "Hosts": ["sitio-real-dos.tld", "www.sitio-real-dos.tld"],
      "Destination": "http://127.0.0.1:8082",
      "Mode": "Monitor",
      "ObserveThreshold": 30,
      "BlockThreshold": 80
    }
  ]
}
```

> [!WARNING]
> **`Destination` es el enlace privado de loopback, nunca el puerto público.** Según la
> [ADR 0001](adr/0001-ruta-de-trafico-en-produccion.md), IIS conserva el 80 y el 443, y WPShield
> reenvía a un *segundo* enlace del mismo sitio que usted añade para esto — `127.0.0.1:8081`.
> Escribir ahí `http://127.0.0.1:443` es el error intuitivo, porque 443 es el puerto que un operador
> asocia con el sitio, y manda HTTP en claro contra un puerto que espera TLS.
>
> Ese valor pasa todas las demás reglas: es loopback, y no es el puerto del listener. El gateway
> ahora **se niega a arrancar** con un destino en el 80 o el 443, porque de lo contrario arranca, se
> declara sano, y falla solo cuando llega una petición real — que en esta ruta de tráfico significa
> fallar en el sitio en producción.
>
> El `http://` sin cifrar es correcto para ese salto. Nunca sale de la máquina; el TLS termina en el
> enlace público de IIS.

> [!WARNING]
> **Los arreglos JSON se combinan elemento por elemento, no se reemplazan.** Esto aplica también al
> arreglo anidado `Hosts`, no solo a `Sites`. Si `appsettings.json` declara dos sitios de ejemplo con
> dos hosts cada uno y su superposición declara un sitio con un host, las entradas sobrantes quedan
> activas y enrutables — incluido `www.wordpress-one.example` dentro de un sitio que usted creía
> haber sobrescrito por completo. Declare **cada sitio y cada host** de forma explícita.

### El gateway se niega a arrancar con una superposición parcial

Como ese error es silencioso y peligroso, el validador de arranque falla cerrado cuando aparecen
nombres de host reales junto a los marcadores de documentación (RFC 2606) que vienen en
`appsettings.json`:

```text
Unhandled exception. System.InvalidOperationException: Configuration mixes real hostnames with the
documentation placeholders shipped in appsettings.json: site-one:www.wordpress-one.example. JSON
configuration merges arrays element by element, so a local overlay that declares fewer sites, or
fewer hosts inside a site, leaves the surplus example entries active and routable. Declare every
site and every host explicitly in appsettings.Local.json.
```

El mensaje nombra las entradas sobrantes exactas. Una configuración compuesta únicamente por
marcadores es la configuración de demostración intacta y arranca con normalidad, de modo que un clon
recién descargado sigue funcionando.

### Confirme la tabla de sitios resuelta

El gateway además imprime lo que realmente resolvió en cada arranque:

```text
info: WPShield.Gateway.Configuration
      Gateway configuration resolved 2 site(s).
info: WPShield.Gateway.Configuration
      Configured site. SiteId=site-one Hosts=sitio-real-uno.tld, www.sitio-real-uno.tld Destination=http://127.0.0.1:8081/ Mode=Monitor
```

Lea ese bloque en cada arranque. Si aparece un host `*.example`, su superposición está incompleta.

## Forma con variables de entorno

Use `__` como separador de sección:

```powershell
$env:WPSHIELD_Sites__0__Id = "site-one"
$env:WPSHIELD_Sites__0__Hosts__0 = "sitio-real-uno.tld"
$env:WPSHIELD_Sites__0__Destination = "http://127.0.0.1:8081"
$env:WPSHIELD_Sites__0__Mode = "Monitor"
```

Aplica la misma advertencia sobre la combinación por índice.

## Proxies de confianza

`Gateway:TrustedProxies` enumera las direcciones de par cuyas cabeceras `X-Forwarded-For` y
`X-Forwarded-Proto` WPShield va a creer. **Está vacío por defecto**, y una lista vacía significa que
toda cabecera de reenvío entrante se descarta y cada solicitud se atribuye a la dirección que se
conectó.

```json
{
  "Gateway": {
    "TrustedProxies": ["127.0.0.1", "::1"]
  }
}
```

### Cuándo hace falta

Solo cuando otra cosa termina la conexión del cliente. En el laboratorio de loopback el gateway es el
único salto y el valor por defecto vacío es el correcto. Bajo la ruta de tráfico elegida en el
[ADR 0001](adr/0001-ruta-de-trafico-en-produccion.md) — IIS conserva los puertos 80 y 443 y reescribe
hacia el gateway por loopback — toda solicitud llega desde un proxy local, y dejarlo vacío tiene dos
consecuencias, una de ellas nada sutil:

- **Todo visitante queda registrado como `127.0.0.1`.** La evidencia nombra al proxy en lugar del
  atacante.
- **WordPress concluye que lo alcanzaron por HTTP.** IIS termina el TLS y le habla al gateway en HTTP
  plano, así que sin un `X-Forwarded-Proto` respetado WordPress genera URLs canónicas, redirecciones
  y destinos de inicio de sesión con `http://` detrás de un sitio HTTPS. Eso es un bucle de
  redirección, no una degradación.

### Qué concede la confianza y qué no

La confianza se le concede a una **dirección de par**, nunca a una cabecera, y desbloquea exactamente
dos cabeceras.

| Cabecera | Par no confiable | Par de confianza |
| --- | --- | --- |
| `X-Forwarded-For` | Se descarta y se reemplaza por la dirección del par | Se respeta y se reemplaza por el cliente resuelto |
| `X-Forwarded-Proto` | Se descarta y se reemplaza por el esquema de la conexión | Se respeta si es exactamente `http` o `https` |
| `X-Forwarded-Host` | Se reemplaza por el host del sitio resuelto | Se reemplaza por el host del sitio resuelto |
| `Forwarded` y toda otra variante `X-Forwarded-*` | Se descarta | **Se descarta** |
| `X-Real-IP`, `CF-Connecting-IP`, `True-Client-IP` y el resto de la familia de IP de cliente | Se descarta | **Se descarta** |
| `X-Original-URL`, `X-Rewrite-URL` | Se descarta | **Se descarta** |
| `X-WPShield-Request-ID` | Se descarta | **Se descarta** |

Las últimas cuatro filas son el punto. Una cabecera de sobrescritura de ruta no se vuelve legítima
porque la haya presentado un proxy, y `X-WPShield-Request-ID` debe seguir siendo imposible de
falsificar desde cualquier par: la condición de prevención de bucles de la regla de reescritura de
IIS depende de que un cliente no pueda establecerla.

### Solo direcciones exactas

Un rango CIDR se **rechaza, no es que falte implementarlo**:

```text
Unhandled exception. System.InvalidOperationException: Gateway:TrustedProxies:0 ('127.0.0.0/8') is a
CIDR range. Gateway:TrustedProxies accepts exact IP addresses only.
```

Estas entradas deciden qué cabeceras pasan a ser autoritativas. Un rango escrito un bit demasiado
amplio le concede esa autoridad a hosts que usted nunca quiso incluir, y bajo esta ruta de tráfico el
único par de confianza es un proxy local, así que un rango no aporta nada. Los nombres de host se
rechazan por otra razón: la comparación es contra la dirección de par de una conexión viva, que es un
número, y en la ruta de la solicitud no se hace ninguna resolución de nombres.

### Gana la entrada más a la derecha

WPShield lee la entrada **más a la derecha** de la cadena `X-Forwarded-For` y no salta las entradas
que resultan ser direcciones de proxies de confianza.

Un proxy anexa la dirección que efectivamente vio, así que la entrada más a la derecha es la única
que escribió el salto de confianza; todo lo que está a su izquierda es lo que el cliente decidió
enviar. La alternativa convencional, recorrer de derecha a izquierda saltando las entradas de
confianza, es la suplantación clásica: un cliente envía `X-Forwarded-For: 8.8.8.8, 127.0.0.1`, la
lógica de salto pasa por encima de la entrada que parece de confianza, y el atacante fijó su propia
dirección. WPShield resuelve esa solicitud como `127.0.0.1`.

Esto supone exactamente un salto de proxy, que es lo que especifica el ADR 0001. Si una cabecera
falta, está malformada o es demasiado larga, WPShield vuelve a la dirección del par en lugar de
adivinar: equivocarse de forma visible, porque un operador que ve llegar todas las solicitudes desde
el proxy investiga, mientras que uno que ve una dirección verosímil elegida por el atacante no.

> [!IMPORTANT]
> Haga que la regla de reescritura **establezca** la cabecera en lugar de confiar en que el proxy la
> anexe. Un `<set name="HTTP_X_FORWARDED_FOR" value="{REMOTE_ADDR}" />` explícito reemplaza lo que
> haya enviado el cliente, de modo que la cabecera lleva exactamente una entrada y es la que IIS midió.
> Esto se valida en el laboratorio M1.3 antes de cualquier uso en producción.

### Confírmelo en el arranque

El gateway informa en qué postura está, junto a la tabla de sitios resuelta:

```text
info: WPShield.Gateway.Configuration
      Trusted proxies configured. X-Forwarded-For and X-Forwarded-Proto are honored from these peers only. TrustedProxies=127.0.0.1, ::1
```

```text
info: WPShield.Gateway.Configuration
      No trusted proxies configured. Every inbound forwarding header is stripped and each request is attributed to the address that connected.
```

Se imprimen ambos estados porque ambos son incorrectos en algún escenario, y el comportamiento por sí
solo no le dirá en cuál está hasta que el tráfico ya esté fluyendo. Una entrada que no sea de loopback
se informa como Warning: el gateway solo acepta conexiones de loopback, así que esa entrada nunca
podría coincidir.

## Limitación de tasa

`Gateway:RateLimit` acota cuántas veces un cliente puede llegar a las rutas que usted nombre. Está
**apagada en código y encendida en la configuración publicada**, y es **dirigida, no global** — el
operador lista las rutas.

```json
{
  "Gateway": {
    "RateLimit": {
      "Enabled": true,
      "Rules": [
        {
          "Id": "wordpress-login",
          "Paths": [ "/wp-login.php", "/xmlrpc.php" ],
          "PermitLimit": 10,
          "WindowSeconds": 300
        }
      ]
    }
  }
}
```

### Por qué dirigida y no global

Una sola vista de página de WordPress son decenas de peticiones — hojas de estilo, scripts, fuentes,
imágenes. Un presupuesto aplicado a todas o se pone tan alto que no detiene nada, o estrangula a los
lectores.

El tráfico para el cual existe esto no se parece a eso. Dos sitios en un mismo host registraron
**40.779 peticiones a `wp-login.php` en treinta días**, desde más de sesenta direcciones, y todas
fueron al mismo puñado de rutas. El [ADR 0002](adr/0002-defensa-fuerza-bruta-a-nivel-de-host.md)
decidió que la mitad HTTP de la defensa contra fuerza bruta se queda dentro de WPShield; esta es esa
mitad.

### Obedece el modo del sitio, como todo lo demás

| `Mode` del sitio | Qué pasa cuando un cliente agota su presupuesto |
| --- | --- |
| `Disabled` | Nada. Ni se consulta el limitador. |
| `Monitor` | Una línea de log en Information con `Action=Observe`, y **la petición se reenvía**. |
| `Block` | HTTP **429** con `Retry-After`, una línea en Warning con `Action=Block`. |

Un limitador que rechazara tráfico en Monitor sería el único componente aquí donde Monitor no es
Monitor, así que se comprueba a través del pipeline real en vez de darse por sentado.

### Particionado por el cliente resuelto, no por el par que conecta

Los presupuestos se indexan por sitio, luego regla, luego la dirección de cliente que resolvió
`Gateway:TrustedProxies`. **Esa última parte carga peso.** Bajo esta ruta de tráfico toda petición
llega desde un proxy local, así que un limitador indexado por el par que conecta metería a todo
internet en un solo cubo: el visitante número once del día quedaría rechazado y una fuerza bruta se
vería igual que una tarde ocupada. Configure `TrustedProxies` antes de confiar en un límite de tasa.

### Qué vigilar

- **Las rutas se comparan enteras**, sin distinguir mayúsculas, contra la ruta decodificada. Un
  WordPress instalado bajo `/blog` necesita `/blog/wp-login.php`. Coincidir con más de lo que usted
  escribió es como un limitador empieza a rechazar tráfico que nadie le pidió mirar.
- **`Rules` es un arreglo, así que una superposición lo fusiona elemento por elemento** — la misma
  trampa que trae `Sites`. Declare todas las reglas que quiera, no solo la que está cambiando.
- **Una oficina detrás de una sola dirección NAT comparte presupuesto.** Diez intentos cada cinco
  minutos es generoso para una persona y brutal para un script, pero contrástelo con cómo entran sus
  propios usuarios antes de poner un sitio en `Block`.
- El arranque imprime cada regla cargada, e imprime `Rate limiting is off` cuando no hay ninguna. Se
  reportan los dos estados porque el comportamiento por sí solo no le dice en cuál está.

## Límites de inspección

`Gateway:Multipart` contiene los límites de la pasada de inspección de cargas. A diferencia de
`Sites`, es un **objeto** JSON, así que la fusión de arreglos elemento a elemento descrita arriba no
le aplica: una superposición que fija un valor deja el resto en sus valores de fábrica, que es lo que
espera un operador que edita una sola línea.

```json
{
  "Gateway": {
    "Multipart": {
      "ReadTimeoutSeconds": 120
    }
  }
}
```

Cada ajuste, su valor predeterminado y su tope están documentados en
[inspección multipart acotada](m2-inspeccion-multipart.md). Conviene saber dos cosas antes de
tocarlos:

- **Un valor fuera de rango impide el arranque**, no se acota en silencio. A un operador que pide
  `"MaximumFileCount": 100000` y recibe 100 sin aviso no se le ha dicho nada, y la configuración
  nunca debe aparentar que hace algo que no hace.
- **`Gateway:Multipart:Enabled: false` devuelve el gateway a ser un proxy inverso con un límite de
  tamaño.** No se almacena ningún cuerpo, no se toma ninguna muestra y ninguna regla de carga corre
  sobre tráfico real. Es una vía de escape para incidentes, no una perilla de ajuste, y el gateway
  registra una advertencia en cada arranque mientras está apagada.

El gateway imprime los límites que realmente aplicará junto a la tabla de sitios resuelta:

```text
info: WPShield.Gateway.Configuration
      Multipart upload inspection enabled. MaximumRequestBytes=6291456 MaximumFileCount=20 MaximumFieldCount=200 MaximumPartHeaderBytes=16384 SampleBytes=4096 ReadTimeoutSeconds=30
```

## Archivos de log

En modo Monitor el log es lo único que WPShield produce. Reenvía todas las solicitudes de cualquier
forma, así que un gateway sin dónde escribir está observando tráfico y no se lo está contando a
nadie — y bajo un servicio de Windows no hay consola a la cual recurrir.

```json
{
  "Logging": {
    "File": {
      "Enabled": true,
      "Directory": "C:\\ProgramData\\WPShield\\logs",
      "FileNamePrefix": "wpshield",
      "MaximumFileBytes": 33554432,
      "RetainedFileCount": 14,
      "MaximumQueuedEntries": 10000
    }
  }
}
```

Un objeto JSON por línea, UTF-8, sin indentación:

```json
{"timestamp":"2026-09-06T04:12:31.4180000+00:00","level":"Information","category":"WPShield.Gateway.Request","message":"Request forwarding. RequestId=8f3a… SiteId=site-one Client=203.0.113.5 Method=GET Path=/wp-admin/","state":{"RequestId":"8f3a…","SiteId":"site-one","Client":"203.0.113.5","Method":"GET","Path":"/wp-admin/"}}
```

Están presentes tanto el mensaje ya compuesto como los campos estructurados, de modo que el archivo
lo puede leer una persona que lo sigue durante un despliegue y lo puede parsear lo que sea que lo
agregue después. La plantilla del mensaje no se escribe: duplicaría el tamaño de cada línea y el
mensaje compuesto ya dice lo mismo.

`Directory` es absoluto en la configuración que se publica, y así debe quedarse. Una ruta relativa se
sigue aceptando y se resuelve contra la **raíz de contenido**, que para un servicio de Windows es el
directorio de instalación y no `C:\Windows\System32`. El filtrado por nivel usa el mecanismo estándar
de proveedores, así que `Logging:File:LogLevel:Default` funciona igual que para la consola.

> [!WARNING]
> **Un directorio de registros relativo sigue a donde se haya descomprimido el build, y los dos
> destinos son incorrectos.** Descomprimido bajo una raíz web, deja la bitácora de evidencia — y
> `appsettings.Local.json`, que nombra todos los hosts que usted protege — dentro del árbol que IIS
> reparte; `.json` está en el mapa MIME predeterminado de IIS, así que ese archivo se puede descargar
> por HTTP. Descomprimido en el directorio de instalación, se resuelve a un directorio que
> `wpshield install` deja deliberadamente de solo lectura para la cuenta de servicio, de modo que
> toda escritura falla.
>
> Las dos cosas pasaron en el mismo servidor la misma semana. Ahora el gateway se niega a arrancar
> cuando no puede escribir en el directorio resuelto, e `wpshield install` escribe la ruta que
> endureció en esta opción en vez de suponer que el gateway la va a adivinar.

### El arranque se niega antes que correr sin evidencia

Si el directorio resuelto no se puede crear, o no se puede escribir un archivo dentro, el gateway no
arranca. Reporta el directorio, la causa subyacente y qué hacer al respecto.

Es una asimetría deliberada frente al comportamiento en marcha, que nunca rechaza tráfico: un disco
que se llena a las tres de la mañana es una condición que llega mientras WPShield es lo único que
está delante de un sitio, y descartar líneas de log es la respuesta menos mala. Un directorio sobre el
cual la cuenta de servicio nunca recibió permiso de escritura es distinto en naturaleza. Es un error
de despliegue, es cierto antes de que llegue la primera solicitud, y nada de él se ve desde afuera del
proceso — el gateway arrancaría, se reportaría sano, aplicaría todas las reglas y no registraría
ninguna.

Un log de seguridad vacío se ve exactamente igual que una noche tranquila. Negarse a arrancar es la
única manera de que ese error se note alguna vez.

### Rotación y retención

Un archivo se cierra y se abre uno nuevo cuando alcanza `MaximumFileBytes` o cuando cambia la fecha
UTC. Los nombres son `wpshield-20260906.jsonl` y luego `wpshield-20260906_0001.jsonl` para el segundo
archivo del mismo día.

> [!NOTE]
> El separador del ordinal es `_` y no `-` a propósito. La retención ordena los archivos por nombre, y
> `-` ordena *antes* que `.`, así que `wpshield-20260906-1.jsonl` se compararía como más antiguo que
> el `wpshield-20260906.jsonl` al que en realidad sucede — y la retención habría borrado los archivos
> más nuevos de un día con mucho tráfico conservando los más viejos.

Se conservan `RetainedFileCount` archivos y el resto se borra al abrir uno nuevo. Un archivo que no
se puede borrar, porque un visor de logs lo tiene abierto, se omite en lugar de reintentarse: la
retención es tarea doméstica y nunca debe convertirse en el motivo por el que el log deja de
escribirse.

### Qué pasa cuando la cola se llena

Las entradas se componen en el hilo que llama y se entregan a una cola acotada que drena un único
escritor. Cuando esa cola se llena, la entrada se **descarta**, no se pone a esperar:

```json
{"timestamp":"…","level":"Warning","category":"WPShield.Gateway.Logging","message":"Log entries were dropped because the write queue was full. The gap is in this file, not in what the gateway did.","state":{"DroppedEntries":42}}
```

Bloquear la ruta de la solicitud en E/S de disco dejaría que un disco lento o lleno se convierta en
una caída del servicio, y una cola sin cota dejaría que se convierta en un fallo por falta de
memoria. Descartar es la única de las tres opciones que el log puede admitir después — y lo admite,
en cuanto baja la presión.

### Los permisos del archivo no los pone el gateway

WPShield crea el directorio pero no lo restringe. Los logs llevan nombres de host reales, rutas
reales y direcciones de cliente reales, así que el ACL del directorio es parte de la instalación y no
de la configuración. Hasta que exista el procedimiento de instalación, restrínjalo usted:

```powershell
icacls "C:\ProgramData\WPShield\logs" /inheritance:r `
  /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "<cuenta del servicio>:(OI)(CI)M"
```

### Ejecución como servicio de Windows

El gateway detecta por sí mismo al administrador de control de servicios; no hace falta ningún
interruptor. Bajo un servicio fija su raíz de contenido al directorio de instalación, instala el
ciclo de vida que responde a las peticiones de parada y apagado, y agrega el Registro de eventos de
Windows como segundo destino — de modo que un gateway que no arranca dice por qué en algún lugar
donde un operador lo va a encontrar.

## La configuración no se recarga en caliente

Las opciones del gateway y de los sitios se validan una sola vez al arrancar y se capturan durante
toda la vida del proceso. Editar `appsettings.json` con el gateway en ejecución **no tiene efecto** y
no genera ninguna advertencia. Reinicie el gateway para aplicar un cambio y lea la tabla de sitios
resuelta para confirmarlo.

Es una decisión deliberada. Una configuración de seguridad aplicada a medias es más peligrosa que
una que exige un reinicio.

## Lo que nunca debe commitearse

- Nombres de host reales y sus destinos de backend.
- Asignación de puertos internos de IIS.
- Números de compilación exactos del sistema operativo o de IIS.
- El inventario de plugins de una instalación concreta.
- Registros de producción, incluso redactados, sin revisión previa.

Mantenga las notas de planificación específicas del operador en `DEVELOPMENT_PLAN.local.md`, que
también está ignorado por git.

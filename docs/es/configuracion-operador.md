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

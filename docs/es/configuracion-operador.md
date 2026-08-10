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

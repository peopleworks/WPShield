# M2.1: Controles limitados de solicitud

M2.1 agrega controles absolutos sobre el cuerpo de las solicitudes. Son la base sobre la que se
construye la pasada de inspección multipart: el límite de solicitud es lo que acota el búfer descrito
en [inspección multipart acotada](m2-inspeccion-multipart.md), de modo que nada allí puede superar lo
que se configura aquí. El gateway permanece limitado a loopback y `Monitor` continúa siendo el modo
predeterminado.

## Valores predeterminados

| Configuración | Predeterminado | Rango permitido |
| --- | ---: | ---: |
| `Gateway:MaximumRequestBytes` | 6 MiB (`6291456`) | 1 byte a 64 MiB |
| Límite de transporte | 64 MiB | Fijo |
| Timeout de actividad del proxy | 100 segundos | 1 a 300 segundos |

El límite de solicitud de 6 MiB deja espacio para la envoltura del upload legítimo planificado de 5 MiB. El límite fijo de 64 MiB impide eliminar la protección mediante configuración.

## Comportamiento

- Una solicitud de un sitio conocido con `Content-Length` mayor que el límite se rechaza antes de contactar su backend.
- Las solicitudes sin longitud declarada, incluyendo cuerpos chunked, se cuentan mientras YARP las lee y reenvía.
- Cuando un cuerpo en streaming supera el límite, se detiene el reenvío y se devuelve HTTP 413 de forma segura si los headers de respuesta no han comenzado.
- El límite aplica en los modos `Monitor`, `Block` y `Disabled` porque es un control absoluto de recursos.
- Los hosts desconocidos continúan fallando cerrados con HTTP 421 antes de reenviar sus cuerpos.
- Las respuestas y logs contienen solamente request ID, site ID, tamaños y límites. No contienen cuerpos, query strings completas, autorización, cookies, nonces ni tokens.
- WPShield nunca escribe un cuerpo de solicitud en disco, y nunca retiene un cuerpo mayor que el límite configurado. Un cuerpo `multipart/form-data` se retiene en memoria mientras dura la pasada de inspección, porque el modo Block tiene que decidir antes de reenviar; toda otra solicitud pasa en streaming directo y nunca se retiene. Véase [inspección multipart acotada](m2-inspeccion-multipart.md).

La respuesta HTTP 413 es:

```json
{
  "error": "request_too_large",
  "requestId": "correlation-id"
}
```

Como toda respuesta que WPShield genera, ahora lleva `X-WPShield-Request-ID`, `X-Content-Type-Options: nosniff` y `Cache-Control: no-store`. Hasta este hito no llevaba ninguna de las tres: `HttpResponse.Clear()` borra las cabeceras además del código de estado, así que los escritores de 413 y 502 borraban las cabeceras de correlación y nosniff que había puesto el primer middleware.

## Limitación del streaming

Para un cuerpo sin longitud declarada, el gateway no conoce el tamaño final antes de leerlo, así que el límite se aplica a medida que se lee.

- **En la vía con búfer** — una solicitud `multipart/form-data` que se está inspeccionando — el cuerpo se vacía en el búfer acotado antes de contactar siquiera con el backend. Si supera el límite, no se ha reenviado nada y el 413 es completo.
- **En la vía de streaming** — toda otra solicitud — un prefijo limitado, nunca mayor que el límite configurado, podría llegar al backend asignado antes de detectar el exceso.

Mantener de todos modos límites equivalentes en IIS y PHP. Son el control que sigue aplicando cuando se omite o se apaga WPShield.

## Configuración

```json
{
  "Gateway": {
    "Urls": ["http://127.0.0.1:10000"],
    "ActivityTimeoutSeconds": 100,
    "MaximumRequestBytes": 6291456,
    "Multipart": {
      "Enabled": true,
      "MaximumFileCount": 20,
      "MaximumFieldCount": 200,
      "MaximumPartHeaderBytes": 16384,
      "SampleBytes": 4096,
      "ReadTimeoutSeconds": 30
    }
  }
}
```

`MaximumRequestBytes` es el tope contra el que se miden todos los límites multipart, y por eso ambos viven en una sección que el operador lee junta. Cada ajuste de `Gateway:Multipart` está documentado en [inspección multipart acotada](m2-inspeccion-multipart.md).

Los límites inválidos impiden el inicio. No aumentar el límite para evadir solicitudes malformadas; usar el valor mínimo compatible con el tráfico legítimo documentado.

## Reversión

Restaurar el valor anterior de `MaximumRequestBytes` y reiniciar el gateway de laboratorio. No modificar bindings públicos de IIS, DNS, certificados, firewall ni servicios de Windows.

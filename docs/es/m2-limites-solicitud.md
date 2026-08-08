# M2.1: Controles limitados de solicitud

M2.1 agrega controles absolutos sobre el cuerpo de las solicitudes antes de introducir el parser multipart. El gateway permanece limitado a loopback y `Monitor` continúa siendo el modo predeterminado.

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
- WPShield no guarda cuerpos completos en memoria ni escribe cuerpos en disco.

La respuesta HTTP 413 es:

```json
{
  "error": "request_too_large",
  "requestId": "correlation-id"
}
```

## Limitación del streaming

Para un cuerpo sin longitud declarada, el gateway no conoce el tamaño final antes de leerlo. Un prefijo limitado, nunca mayor que el límite configurado, podría llegar al backend asignado antes de detectar el exceso. Mantener límites equivalentes en IIS y PHP. La inspección multipart previa al reenvío y los límites específicos de uploads continúan pendientes en M2.

## Configuración

```json
{
  "Gateway": {
    "Urls": ["http://127.0.0.1:10000"],
    "ActivityTimeoutSeconds": 100,
    "MaximumRequestBytes": 6291456
  }
}
```

Los límites inválidos impiden el inicio. No aumentar el límite para evadir solicitudes malformadas; usar el valor mínimo compatible con el tráfico legítimo documentado.

## Reversión

Restaurar el valor anterior de `MaximumRequestBytes` y reiniciar el gateway de laboratorio. No modificar bindings públicos de IIS, DNS, certificados, firewall ni servicios de Windows.

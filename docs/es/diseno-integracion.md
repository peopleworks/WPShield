# WPShield.Integration — Diseño (Español)

WPShield.Integration es un **proyecto de puente opcional, de adhesión voluntaria**, que
conecta los hallazgos de `WPShield.SecurityMonitor` con `WPShield.NetworkFilter.BlockListRule`,
de modo que las IPs detectadas por reglas de seguridad (fuerza bruta de RDP, fallos de
inicio de sesión, etc.) se bloqueen a nivel de paquete mediante
`WPShield.NetworkFilter.NetworkFilterEngine` antes de que lleguen a IIS.

## Por qué existe

`WPShield.NetworkFilter` inspecciona encabezados TCP/UDP pero no puede ver si una conexión
RDP tuvo éxito o falló — eso ocurre dentro de la sesión de autenticación, después del
handshake TCP. `WPShield.SecurityMonitor` lee el registro de eventos de Seguridad de Windows
y ve los resultados de autenticación, pero no puede bloquear paquetes directamente.

`WPShield.Integration` cierra el bucle: los hallazgos de seguridad con `Action == Block`
(por ejemplo, `WP-SEC-001` fuerza bruta de RDP) agregan la IP de origen ofensiva a la lista
de bloqueo dinámica usada por `WPShield.NetworkFilter`, por lo que la IP del atacante se
descarta a nivel de paquete en el siguiente intento de conexión.

## Posición en la arquitectura

```
Registro de eventos de Seguridad (falla 4625 RDP)
        │
        ▼
WPShield.SecurityMonitor (WP-SEC-001 detecta fuerza bruta)
        │
        ▼
WPShield.Integration → NetworkFilterBlockListSink
        │
        ▼
WPShield.NetworkFilter.BlockListRule (lista de bloqueo dinámica)
        │
        ▼
WPShield.NetworkFilter.NetworkFilterEngine (descarta paquetes)
```

## Componentes

| Componente | Responsabilidad |
|------------|-----------------|
| `NetworkFilterBlockListSink` | Implementa `ISecurityEventSink`. Recibe hallazgos de seguridad; si `Action == Block`, extrae `source_ip` de la evidencia y lo agrega a la `BlockListRule`. |
| `SecurityToNetworkFilterBridge` | Clase de conveniencia que conecta `SecurityEventMonitor`, `NetworkFilterEngine` y `BlockListRule` en un solo objeto. |

## Ejemplo de uso

```csharp
using WPShield.Integration;
using WPShield.SecurityMonitor;
using WPShield.NetworkFilter;

// Construir el puente con configuraciones predeterminadas.
using var bridge = new SecurityToNetworkFilterBridge();

// Escanear el registro de Seguridad según tu propio calendario (por ejemplo, cada 30 segundos).
using var cts = new CancellationTokenSource();
while (!cts.Token.IsCancellationRequested)
{
    int processed = bridge.ScanSecurityLogOnce();
    await Task.Delay(TimeSpan.FromSeconds(30), cts.Token);
}

// bridge.BlockListRule se comparte con bridge.NetworkFilterEngine,
// por lo que las IPs bloqueadas se aplican inmediatamente al filtro de paquetes.
```

### Cableado manual (sin el puente)

Si prefieres conectar los componentes tú mismo:

```csharp
var blockListRule = new BlockListRule(new List<string>());
var sink = new NetworkFilterBlockListSink(blockListRule);

var monitor = SecurityEventBuilder.Build(
    new SecurityEventConfiguration { PublishingEnabled = true },
    sink: sink);

var filterEngine = NetworkFilterBuilder.Build(new NetworkFilterConfiguration
{
    BlockList = new List<string>() // poblada por el sink
});
```

## Requisitos de seguridad

- **Solo adhesión voluntaria.** El proyecto de integración no es referenciado por el núcleo del gateway ni por los proyectos de reglas. Los operadores deben agregarlo explícitamente a su despliegue.
- **Sin cambios silenciosos.** El sink solo agrega IPs que produjeron un hallazgo de `Block`. Nunca elimina IPs a menos que el operador llame a `RemoveIp` o `UpdateBlockList` en la `BlockListRule`.
- **Seguro para subprocesos.** Tanto `NetworkFilterBlockListSink` como `BlockListRule` usan bloqueos para que el sink pueda publicar desde cualquier subproceso sin bloquear el camino de los paquetes por más tiempo que una copia de diccionario.
- **Seguro para la privacidad.** El sink solo almacena direcciones IP de origen e IDs de regla — nunca contraseñas, tokens de sesión ni cargas completas de eventos.

## Fuera del alcance

- Bloqueo en tiempo real. `SecurityEventMonitor.ScanOnce()` es de sondeo; el puente no se suscribe a flujos de eventos en vivo.
- Expiración de IPs. Las IPs bloqueadas permanecen en la lista hasta que el operador las elimine. Considera combinar con la limitación de velocidad y bloques temporales de M3 cuando ese hito llegue.

## Pasos siguientes

1. Confirmar que `src/WPShield.Integration/` tiene como destino `net10.0-windows` y referencia tanto a `WPShield.SecurityMonitor` como a `WPShield.NetworkFilter`.
2. Agregar pruebas unitarias para `NetworkFilterBlockListSink` y `SecurityToNetworkFilterBridge`.
3. Escribir `docs/en/integration-design.md` como espejo de este documento.

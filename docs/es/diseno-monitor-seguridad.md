# WPShield.SecurityMonitor — Diseño (Español)

WPShield.SecurityMonitor es un **componente en modo usuario, exclusivo de Windows**, que lee
el registro de eventos de Seguridad de Windows y detecta ataques de autenticación como fuerza
bruta de Escritorio Remoto (RDP) y fallos repetidos de inicio de sesión. Publica hallazgos en
un receptor que puede alimentar la lista de bloqueo dinámica de `WPShield.NetworkFilter`,
cerrando la brecha entre el filtrado a nivel de paquetes y los fallos de autenticación que los
paquetes por sí solos no pueden revelar.

## Por qué existe

Un host de producción con WordPress sobre Windows Server fue observado recibiendo ataques
sostenidos tanto en puertos web (80/443) como en Escritorio Remoto (TCP 3389).
`WPShield.NetworkFilter` puede bloquear paquetes por IP de origen y tasa, pero no puede ver si
una conexión RDP tuvo éxito o falló — eso ocurre dentro de la sesión de autenticación, después
del handshake TCP.

`WPShield.SecurityMonitor` lee el Event ID `4625` (inicio de sesión fallido) y `4624` (inicio
de sesión exitoso) del registro de Seguridad, identifica el Tipo de Inicio de Sesión `10`
(RemoteInteractive = RDP) y genera hallazgos cuando una IP de origen supera un umbral
configurable de fallos. Esos hallazgos pueden publicarse a una lista de bloqueo que
`NetworkFilter` consume, de modo que la IP del atacante se descarta a nivel de paquete antes de
que pueda intentar otro inicio de sesión.

## Posición en la arquitectura

| Capa | Componente | Qué ve | ¿Bloquea? |
|---|---|---|---|
| 1 | Firewall de Windows | Reglas estáticas de IP | Sí |
| 2 | `WPShield.NetworkFilter` | Encabezados TCP/UDP de paquetes | Sí |
| 3 | **`WPShield.SecurityMonitor`** | **Registro de Seguridad (resultados de autenticación)** | **Indirectamente** |
| 4 | `WPShield.Gateway` | Cuerpos de solicitud HTTP | Sí (cargas) |
| 5 | IIS + WordPress | Capa de aplicación | No |

El monitor no bloquea tráfico directamente. Emite hallazgos (puntuación, acción, evidencia) a
un `ISecurityEventSink`. Una implementación del operador decide qué hacer: escribir en el log
JSON Lines, publicar IPs en la lista de bloqueo dinámica de `NetworkFilter`, alertar, etc.

## Responsabilidades

1. **Leer el registro de eventos de Seguridad de Windows** (solo lectura; nunca modifica, borra
   ni archiva).
2. **Filtrar por Event IDs configurados** (predeterminado: 4624 éxito, 4625 fallo).
3. **Evaluar reglas** contra IP de origen, nombre de usuario, tipo de inicio de sesión, proceso
   y marca de tiempo.
4. **Aplicar conteo de fallos en ventana deslizante** por IP de origen.
5. **Publicar hallazgos** en un `ISecurityEventSink` configurado.
6. **Requerir privilegios de Administrador**; se niega a iniciarse sin ellos.

## Lo que NO hace

- No modifica el registro de Seguridad de Windows (solo lectura).
- No bloquea paquetes directamente (alimenta hallazgos a un receptor).
- No instala ni configura nada silenciosamente.
- No reemplaza el firewall de Windows, Microsoft Defender ni un IDS/IPS.

## Configuración (`appsettings.SecurityMonitor.json` o variables `WPSHIELD_SECURITYMONITOR_*`)

```json
{
  "SecurityMonitor": {
    "Enabled": false,
    "LogName": "Security",
    "EventIds": [ 4624, 4625 ],
    "RemoteLogonTypes": [ "10" ],
    "MaxFailedLogonsPerWindow": 5,
    "WindowMinutes": 5,
    "AllowList": [ "127.0.0.1", "10.0.0.5" ],
    "PublishingEnabled": true
  }
}
```

- `Enabled` predeterminado `false`. El monitor no lee nada hasta que se habilite explícitamente.
- `LogName` es el nombre del registro de eventos de Windows. Predeterminado: `"Security"`.
- `EventIds` es la lista de IDs de evento a inspeccionar. Predeterminado: `[4624, 4625]`.
- `RemoteLogonTypes` identifica inicios de sesión RDP (Tipo de Inicio de Sesión `10` = RemoteInteractive).
- `MaxFailedLogonsPerWindow` es el umbral antes de generar un hallazgo. Predeterminado: `5`.
- `WindowMinutes` es la ventana deslizante para conteo de fallos. Predeterminado: `5`.
- `AllowList` contiene IPs de origen que nunca se marcan ni publican.
- `PublishingEnabled` controla si los hallazgos se envían al receptor. Predeterminado: `true`.

## Reglas

| RuleId | Señal | Puntuación | Acción en umbral |
|---|---|---|---|
| `WP-SEC-001` | Fuerza bruta RDP: ≥ N fallos de Tipo de Inicio de Sesión 10 desde una IP por ventana | 40 / 80 / 100 | Observe / Block / Block |
| `WP-SEC-002` | Cualquier inicio de sesión fallido (4625): ≥ N fallos desde una IP por ventana | 30 / 70 / 100 | Observe / Block / Block |

Las puntuaciones siguen la misma escala 0–100 que las reglas de carga HTTP y las reglas de paquetes de red.

## Contratos (C#)

```csharp
namespace WPShield.Abstractions;

public sealed record SecurityInspectionContext
{
    public required int EventId { get; init; }
    public required string SourceIp { get; init; }
    public required string UserName { get; init; }
    public required string LogonType { get; init; }
    public required string ProcessName { get; init; }
    public required string ComputerName { get; init; }
    public required DateTimeOffset TimeCreated { get; init; }
    public required string Message { get; init; }
}

public sealed record SecurityInspectionResult
{
    public required string RuleId { get; init; }
    public required int Score { get; init; } // 0-100
    public required NetworkInspectionAction Action { get; init; }
    public required string MessageKey { get; init; }
    public required IReadOnlyDictionary<string, object> Evidence { get; init; }
}

public interface ISecurityInspectionRule
{
    string RuleId { get; }
    SecurityInspectionResult Inspect(
        SecurityInspectionContext context,
        CancellationToken cancellationToken = default);
}

public interface ISecurityEventSink
{
    void Publish(SecurityInspectionResult finding, SecurityInspectionContext context);
}
```

```csharp
namespace WPShield.SecurityMonitor;

public sealed record SecurityEventConfiguration
{
    public string LogName { get; init; } = "Security";
    public IReadOnlyList<int> EventIds { get; init; } = new[] { 4624, 4625 };
    public IReadOnlyList<string> RemoteLogonTypes { get; init; } = new[] { "10" };
    public int MaxFailedLogonsPerWindow { get; init; } = 5;
    public int WindowMinutes { get; init; } = 5;
    public IReadOnlyList<string> AllowList { get; init; } = [];
    public bool PublishingEnabled { get; init; } = true;
}

public static class SecurityEventBuilder
{
    public static SecurityEventMonitor Build(
        SecurityEventConfiguration? configuration = null,
        IEnumerable<ISecurityInspectionRule>? extraRules = null,
        ISecurityEventSink? sink = null);
}
```

## Ejemplo de uso

```csharp
using WPShield.SecurityMonitor;
using WPShield.SecurityMonitor.Rules;

var config = new SecurityEventConfiguration
{
    MaxFailedLogonsPerWindow = 5,
    WindowMinutes = 5,
    AllowList = new[] { "127.0.0.1" }
};

var sink = new MyBlockListSink(); // implementa ISecurityEventSink
var monitor = SecurityEventBuilder.Build(config, sink: sink);

// Escanear periódicamente (por ejemplo, cada 30 segundos)
using var cts = new CancellationTokenSource();
while (!cts.Token.IsCancellationRequested)
{
    int processed = monitor.ScanOnce();
    await Task.Delay(TimeSpan.FromSeconds(30), cts.Token);
}
```

## Requisitos de seguridad

- **Solo lectura.** El monitor abre el registro de Seguridad solo para lectura. Nunca lo
  modifica, borra, archiva ni exporta.
- **Se requiere elevación.** Leer el registro de Seguridad requiere privilegios de
  Administrador. La falta de elevación es un bloqueador de inicio, no un modo degradado.
- **Sin instalación silenciosa.** El operador ejecuta el monitor explícitamente; nunca
  instala servicios ni cambia ACLs automáticamente.
- **Evidencia segura para la privacidad.** Los hallazgos contienen IDs de regla, puntuaciones,
  IPs, nombres de usuario y tipos de inicio de sesión — nunca contraseñas, tokens de sesión ni
  cargas completas de eventos.

## Integración con los hitos (milestones)

| Hito | Relación |
|---|---|
| M2.7 Filtro de red | Los hallazgos de SecurityMonitor alimentan la lista de bloqueo dinámica de `WPShield.NetworkFilter`. |
| M3 Limitación de velocidad | `WP-SEC-001` y `WP-SEC-002` son la mitad de autenticación de la limitación de velocidad; M3 agrega la mitad HTTP. |
| M4 Observabilidad | Los hallazgos de SecurityMonitor usan el mismo sobre JSON Lines que el gateway. |
| M6 Servicio de Windows | `SecurityEventMonitor` puede ejecutarse como parte del servicio de Windows de WPShield bajo `NT SERVICE\WPShield`. |

## Fuera del alcance

- Bloqueo en tiempo real (el monitor es de sondeo vía `ScanOnce`; no se suscribe a flujos de eventos en vivo).
- Leer otros registros de eventos (Sistema, Aplicación) — solo Seguridad.
- Descifrar o inspeccionar el contenido de sesiones RDP.

## Pasos siguientes

1. Confirmar que `src/WPShield.SecurityMonitor/` tiene como destino `net10.0-windows` y referencia solo a `WPShield.Abstractions`.
2. Agregar pruebas unitarias para `RdpBruteForceRule` y `FailedLogonRule`.
3. Agregar una implementación de ejemplo de `ISecurityEventSink` que publique en `WPShield.NetworkFilter.BlockListRule`.
4. Escribir `docs/en/security-monitor-design.md` como espejo de este documento.

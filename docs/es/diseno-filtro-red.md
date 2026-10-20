# WPShield.NetworkFilter — Diseño (Español)

WPShield.NetworkFilter es un **filtro de paquetes en modo usuario, exclusivo de Windows**, que
inspecciona tráfico TCP/UDP entrante antes de que llegue a IIS y WordPress. Está construido sobre
**WinDivert**, por lo que un controlador del sistema firmado maneja la captura y la reinyección de
paquetes, mientras que **todas las decisiones de filtrado se toman en este proceso**. Nunca se
ejecuta en kernel, nunca adquiere un spinlock de kernel, y aplica un presupuesto de tiempo
estricto por paquete para que una regla lenta nunca pueda paralizar la pila de red.

## Por qué existe

Un servidor de producción con WordPress sobre Windows Server se observó fallando repetidamente con
**`0x00000133` — DPC_WATCHDOG_VIOLATION**. Un volcado de memoria del kernel (`MEMORY.DMP`) analizado
con WinDbg/kd mostró que el controlador `mwac.sys` (Malwarebytes Web Access Control) quedó bloqueado
esperando un spinlock en pila mientras inspeccionaba conexiones entrantes en contexto DPC, consumiendo
501 ciclos de reloj contra un límite de 500 del watchdog. El servidor se reinició por la fuerza cuatro
veces en octubre de 2026.

WPShield.NetworkFilter es la respuesta del proyecto a ese modo de fallo: protección en capa de red
bajo el control del proyecto, con tiempos de espera ajustables, puntuación de reglas acotada y una
garantía estructural de que nunca puede convertirse en aquello que pretende defender.

## Posición en el camino del tráfico

| Capa | Componente | Posición | Privilegios | ¿Bloquea tráfico? |
|---|---|---|---|---|
| 1 | Firewall de Windows | Reglas estáticas de IP | Sistema | Sí |
| 2 | **WPShield.NetworkFilter** | **TCP/UDP entrante, modo usuario vía WinDivert** | **Administrador (solo controlador WinDivert)** | **Sí** |
| 3 | WPShield.Gateway | Proxy inverso HTTP, solo loopback | Usuario normal | Sí (cargas) |
| 4 | IIS Request Filtering | Filtrado basado en URL | Sistema | Sí |
| 5 | WordPress | Capa de aplicación | Grupo de aplicaciones | No |

El filtro se sitúa **entre la pila de red e IIS**. Los paquetes bloqueados se descartan antes de
llegar a IIS, por lo que nunca consumen hilos del grupo de aplicaciones, nunca llegan a PHP y nunca
alcanzan a WordPress.

## Responsabilidades

1. **Capturar paquetes TCP/UDP entrantes** a través de WinDivert con filtros configurados por el
   operador (predeterminado: `tcp.Inbound`).
2. **Evaluar reglas acotadas** contra IP origen/destino, puertos, protocolo, tamaño del paquete y
   una muestra acotada del payload inicial (primeros 64 bytes).
3. **Descartar paquetes que coincidan con una regla de bloqueo**; reinyectar todos los demás para
   que continúen hacia IIS.
4. **Aplicar un presupuesto de tiempo estricto por paquete** (predeterminado: 5 ms). Si una regla
   tarda más, el paquete se reinyecta sin inspeccionar. El filtro nunca paraliza el camino de red.
5. **Emitir eventos en el sobre de log del gateway** (`timestamp`, `level`, `category`,
   `message`, `state`) para que los hallazgos de red se correlacionen con los hallazgos del gateway
   bajo los mismos nombres de campo.
6. **Falla cerrado en configuración inválida**, pero **falla abierto en tiempo de inspección**: una
   regla lenta nunca bloquea tráfico, solo registra una advertencia de presupuesto.

## Lo que NO hace

- No se ejecuta en kernel ni adquiere spinlocks de kernel.
- No modifica enlaces de IIS, reglas de URL Rewrite, ARR, grupos de aplicaciones ni ninguna
  configuración de IIS.
- No instala WinDivert silenciosamente; el operador lo instala explícitamente.
- No captura cuerpos completos de paquetes. Solo una muestra acotada del inicio se expone a las
  reglas.
- No descifra cargas TLS (solo los encabezados TCP/UDP son visibles).
- No reemplaza el firewall de Windows, Microsoft Defender ni un WAF. Los complementa.

## Configuración (`appsettings.NetworkFilter.json` o variables `WPSHIELD_NETWORKFILTER_*`)

```json
{
  "NetworkFilter": {
    "Enabled": false,
    "Filter": "tcp.Inbound",
    "MaxInspectionTimeMilliseconds": 5,
    "MaxConnectionsPerMinute": 60,
    "MaxDistinctPortsPerMinute": 20,
    "BlockList": [ "45.227.254.34", "94.154.43.74" ]
  }
}
```

- `Enabled` predeterminado `false`. El filtro no captura nada hasta que se habilite explícitamente.
- `Filter` es una cadena de filtro WinDivert. Predeterminado: `"tcp.Inbound"`.
- `MaxInspectionTimeMilliseconds` es el presupuesto por paquete. Predeterminado: `5`. Una regla
  que lo exceda hace que el paquete se reinyecte y se registre una advertencia de presupuesto.
- `MaxConnectionsPerMinute` alimenta `WP-NET-002` (limitación de velocidad). Predeterminado: `60`.
- `MaxDistinctPortsPerMinute` alimenta `WP-NET-003` (detección de escaneo de puertos).
  Predeterminado: `20`.
- `BlockList` alimenta `WP-NET-001` (lista de bloqueo estática). Predeterminado: vacío.

## Reglas

| RuleId | Señal | Puntuación | Acción en umbral |
|---|---|---|---|
| `WP-NET-001` | IP origen en lista de bloqueo dinámica | 100 | Block |
| `WP-NET-002` | > N conexiones de una IP por minuto | 40 / 70 / 100 | Observe / Observe / Block |
| `WP-NET-003` | > N puertos destino distintos de una IP por minuto | 60 / 80 / 100 | Observe / Block / Block |

Las puntuaciones siguen la misma escala 0–100 que las reglas de carga HTTP, y se aplican las mismas
semánticas Monitor/Block por sitio.

## Contratos (C#)

```csharp
namespace WPShield.Abstractions;

public enum NetworkInspectionAction
{
    Allow = 0,
    Observe = 1,
    Block = 2
}

public sealed record NetworkInspectionContext
{
    public required string SourceIp { get; init; }
    public required string DestinationIp { get; init; }
    public required int SourcePort { get; init; }
    public required int DestinationPort { get; init; }
    public required string Protocol { get; init; } // "TCP" o "UDP"
    public required DateTimeOffset Timestamp { get; init; }
    public int PacketSize { get; init; }
    public ReadOnlyMemory<byte> PayloadSample { get; init; } = default;
}

public sealed record NetworkInspectionResult
{
    public required string RuleId { get; init; }
    public required int Score { get; init; } // 0-100
    public required NetworkInspectionAction Action { get; init; }
    public required string MessageKey { get; init; }
    public required IReadOnlyDictionary<string, object> Evidence { get; init; }
}

public interface INetworkInspectionRule
{
    string RuleId { get; }
    NetworkInspectionResult Inspect(
        NetworkInspectionContext context,
        CancellationToken cancellationToken = default);
}
```

```csharp
namespace WPShield.NetworkFilter;

public sealed record NetworkFilterConfiguration
{
    public string Filter { get; init; } = "tcp.Inbound";
    public TimeSpan MaxInspectionTime { get; init; } = TimeSpan.FromMilliseconds(5);
    public int MaxConnectionsPerMinute { get; init; } = 60;
    public int MaxDistinctPortsPerMinute { get; init; } = 20;
    public IReadOnlyList<string> BlockList { get; init; } = [];
}

public static class NetworkFilterBuilder
{
    public static NetworkFilterEngine Build(NetworkFilterConfiguration? configuration = null);
}
```

## Flujo de captura

```
El operador habilita NetworkFilter
        │
        ▼
Validar configuración (WinDivert presente, filtro parseable, presupuesto > 0)
        │
        ▼
Abrir controlador WinDivert con filtro "tcp.Inbound" (modo usuario)
        │
        ▼
Para cada paquete interceptado:
  ├─ Analizar encabezados IPv4 + TCP/UDP (sin punteros, muestra acotada)
  ├─ Iniciar cronómetro
  ├─ Evaluar RateLimitRule (WP-NET-002)
  ├─ Evaluar BlockListRule (WP-NET-001)
  ├─ Evaluar PortScanRule (WP-NET-003)
  ├─ Si alguna regla devuelve Block → descartar paquete
  ├─ Detener cronómetro
  ├─ Si transcurrido > MaxInspectionTime → registrar advertencia de presupuesto, reinyectar
  └─ De lo contrario → reinyectar paquete vía WinDivertSend
        │
        ▼
Emitir eventos JSON Lines al sobre de log del gateway
Rotar archivo de salida al alcanzar el límite de tamaño
```

## Requisitos de seguridad

- **WinDivert es una dependencia externa.** El proyecto hace P/Invoke a `WinDivert.dll` pero nunca la descarga ni la instala. El operador instala el runtime de WinDivert explícitamente.
- **Solo modo usuario.** Toda la evaluación de reglas se ejecuta en este proceso. WPShield no escribe código de kernel.
- **Sin spinlocks en el camino de los paquetes.** Los bloqueos en proceso protegen el estado de limitación de velocidad solo; nunca se mantienen mientras se recibe o reinyecta un paquete.
- **El presupuesto de inspección es estructural.** 5 ms por paquete por defecto. Una regla lenta se trata como una violación de presupuesto, no como una decisión de bloqueo.
- **Sin captura predeterminada.** `Enabled: false` significa que no se observa ni descarta ningún paquete.
- **Evidencia segura para la privacidad.** Los registros contienen IDs de regla, puntuaciones, IPs, puertos y acción — nunca cargas completas de paquetes, credenciales ni cookies.

## Integración con los hitos (milestones)

| Hito | Relación |
|---|---|
| M2.6 Herramienta de triage | Los eventos de NetworkFilter usan el mismo sobre JSON Lines que los informes de triage, por lo que la correlación forense es un solo analizador. |
| M3 Limitación de velocidad | `WP-NET-002` y `WP-NET-003` son la mitad en capa de red de la limitación de velocidad; M3 agrega la mitad HTTP (controles de ráfaga por IP en el gateway). |
| M4 Observabilidad | Los hallazgos de NetworkFilter alimentan la corriente de eventos estructurados; los patrones de rotación/retención se alinean con el gateway. |
| M6 Servicio de Windows | `NetworkFilterEngine` puede ejecutarse como parte del servicio de Windows de WPShield bajo `NT SERVICE\WPShield`. |
| M7 Activación controlada | Si WPShield se coloca frente a IIS vía ARR, NetworkFilter descarta tráfico de ataque antes de que llegue a la regla de reescritura. |

## Fuera del alcance de este diseño

- Filtrado de tráfico saliente (el filtro predeterminado es `tcp.Inbound`).
- Fragmentación ICMP u otros protocolos IP.
- Inspección profunda de paquetes más allá de la muestra inicial de 64 bytes.
- Integración con interna de WordPress (base de datos, `wp_options`, etc.).

## Pasos siguientes

1. Confirmar que `src/WPShield.NetworkFilter/` tiene como destino `net10.0-windows` y referencia solo a `WPShield.Abstractions`.
2. Documentar la instalación de WinDivert como un paso explícito del operador (nunca silenciosa).
3. Agregar pruebas unitarias para `RateLimitRule`, `BlockListRule` y `PortScanRule`.
4. Agregar prueba de integración con un servidor TCP sintético local y captura WinDivert (requiere WinDivert en la pierna de CI).
5. Escribir `docs/en/network-filter-design.md` como espejo de este documento.

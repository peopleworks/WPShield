# WPShield.NetworkSensor — Diseño (Español)

WPShield.NetworkSensor es un **componente separado, opcional y exclusivo de Windows** que captura
metadatos de red en los puertos que el operador nombre (por ejemplo `80` y `443`) para que el
operador pueda ver qué tráfico llega al host. **No es** el gateway HTTP, **no está** en el camino
de las solicitudes y **nunca** modifica IIS.

## Por qué debe ser separado

| Preocupación | WPShield.Gateway (M1/M2) | WPShield.NetworkSensor (propuesto) |
|---|---|---|
| Posición | Proxy inverso inline, solo loopback | Captura pasiva, proceso separado |
| Privilegios | Usuario normal, listener en loopback | Administrador, controlador Npcap |
| ¿Modifica IIS? | No | No |
| ¿Ve cuerpos de solicitud? | Solo muestras acotadas de multipart | Nunca |
| ¿Ve cadenas de consulta? | Nunca las registra | Nunca las registra |
| Exposición predeterminada | Loopback `127.0.0.1:10000` | Ninguna hasta que el operador lo habilite |

Mezclar un controlador de captura de paquetes dentro del gateway HTTP rompería la invariante de
loopback-only, requeriría privilegios de kernel dentro del camino de solicitud y tentaría a
inspeccionar cuerpos completos — todo prohibido por AGENTS.md y THREAT_MODEL.md.

## Responsabilidades

1. **Capturar solo metadatos.** IP origen/destino, puerto origen/destino, método HTTP, ruta de
   solicitud (cadena de consulta eliminada), código de estado de respuesta, tamaño del cuerpo,
   marca de tiempo y nombre de interfaz de red.
2. **Filtrar solo por puertos nombrados por el operador.** Un filtro BPF restringe la captura a
   los puertos listados en la configuración (predeterminado: ninguno — el sensor no captura nada
   hasta que se configure).
3. **Nunca capturar cuerpos completos, credenciales, cookies, encabezados de autorización,
   nonces, tokens ni cadenas de consulta completas.** Esto es estructural, no un umbral que se
   pueda bajar después.
4. **Emitir eventos en el sobre de log del gateway** (`timestamp`, `level`, `category`,
   `message`, `state`) para que un reporte forense y un log del gateway se correlacionen con los
   mismos nombres de campo.
5. **Falla cerrado.** Si falta Npcap, no hay elevación o la configuración es inválida, el sensor
   se niega a iniciar y escribe un mensaje de bloqueo claro.

## Lo que NO hace

- No vincula puertos 80/443 ni cambia los enlaces de IIS.
- No modifica reglas de URL Rewrite, ARR, grupos de aplicaciones ni ninguna configuración de IIS.
- No instala Npcap silenciosamente; el operador lo instala explícitamente.
- No ejecuta en modo promiscuo a menos que el operador lo elija explícitamente.
- No inspecciona, bufferiza ni almacena cuerpos de solicitud/respuesta.
- No bloquea tráfico. Solo observa e informa.
- No reemplaza los logs de IIS, Microsoft Defender ni un WAF.

## Configuración (`appsettings.NetworkSensor.json` o variables `WPSHIELD_NETWORKSENSOR_*`)

```json
{
  "NetworkSensor": {
    "Enabled": false,
    "Interfaces": [ "Ethernet", "vEthernet (WSL)" ],
    "Ports": [ 80, 443 ],
    "PromiscuousMode": false,
    "MaxEventsPerSecond": 1000,
    "OutputPath": "C:\\WPShield\\Logs\\network.ndjson",
    "Rotation": {
      "MaxFileSizeBytes": 104857600,
      "RetentionDays": 30
    }
  }
}
```

- `Enabled` predeterminado `false`. El sensor no captura nada hasta que se habilite explícitamente.
- `Interfaces`, cuando está presente, limita la captura a esos nombres de adaptador. Cuando está
  vacío, se usan todos los adaptadores que coincidan con el filtro de puertos.
- `Ports` es obligatorio cuando está habilitado. Lista vacía = no captura nada.
- `PromiscuousMode` predeterminado `false`. `true` es una elección explícita del operador,
  registrada como evento de nivel blocker.
- `MaxEventsPerSecond` limita la tasa de emisión para que el sensor no se convierta en un
  amplificador de ruido.
- `OutputPath` es un archivo que el sensor escribe; es la única escritura que hace el componente.

## Modelo de evento (JSON Lines, sobre del gateway)

Cada línea emitida es un objeto JSON:

```json
{
  "timestamp": "2026-10-20T14:32:07.1234567Z",
  "level": "Information",
  "category": "WPShield.NetworkSensor",
  "message": "Solicitud HTTP observada",
  "state": "observed",
  "requestId": "ns-1a2b3c4d-...",
  "interface": "Ethernet",
  "srcIp": "192.0.2.10",
  "dstIp": "192.0.2.1",
  "srcPort": 51422,
  "dstPort": 443,
  "method": "POST",
  "path": "/wp-admin/admin-ajax.php",
  "statusCode": 200,
  "bodySizeBytes": 12450,
  "tls": true
}
```

Solo campos seguros para la privacidad. `path` es la ruta de solicitud **sin** la cadena de
consulta. Nunca aparecen `Authorization`, `Cookie`, `Set-Cookie`, contenido del cuerpo ni cadena
de consulta completa.

## Contratos (C#)

Estos contratos viven en `WPShield.NetworkSensor` y hacen referencia solo a
`WPShield.Abstractions` para tipos compartidos cuando proceda.

```csharp
namespace WPShield.NetworkSensor;

public sealed class NetworkSensorConfiguration
{
    public bool Enabled { get; init; }
    public IReadOnlyList<string> Interfaces { get; init; } = [];
    public IReadOnlyList<int> Ports { get; init; } = [];
    public bool PromiscuousMode { get; init; }
    public int MaxEventsPerSecond { get; init; } = 1000;
    public string OutputPath { get; init; } = string.Empty;
    public RotationConfiguration Rotation { get; init; } = new();
}

public sealed class RotationConfiguration
{
    public long MaxFileSizeBytes { get; init; } = 100_000_000;
    public int RetentionDays { get; init; } = 30;
}

public sealed record NetworkEvent
{
    public required DateTimeOffset Timestamp { get; init; }
    public required string Level { get; init; }
    public required string Category { get; init; }
    public required string Message { get; init; }
    public required string State { get; init; }
    public required string RequestId { get; init; }
    public required string InterfaceName { get; init; }
    public required string SourceIp { get; init; }
    public required string DestinationIp { get; init; }
    public required int SourcePort { get; init; }
    public required int DestinationPort { get; init; }
    public required string HttpMethod { get; init; }
    public required string Path { get; init; } // cadena de consulta eliminada
    public required int StatusCode { get; init; }
    public required long BodySizeBytes { get; init; }
    public required bool Tls { get; init; }
}

public interface INetworkSensor : IAsyncDisposable
{
    Task StartAsync(CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
    bool IsRunning { get; }
}

public interface INetworkEventSink
{
    Task WriteAsync(NetworkEvent @event, CancellationToken cancellationToken);
}
```

## Flujo de captura

```
El operador habilita NetworkSensor
        │
        ▼
Validar configuración (puertos no vacíos, Npcap presente, elevación)
        │
        ▼
Construir filtro BPF: "tcp port 80 or tcp port 443"
        │
        ▼
Abrir captura en vivo en interfaces seleccionadas (sin modo promiscuo por defecto)
        │
        ▼
Para cada paquete:
  ├─ Analizar Ethernet/IP/TCP
  ├─ Si el puerto destino no está en la lista configurada → omitir
  ├─ Intento de análisis HTTP ligero (método, ruta, estado, tamaño)
  ├─ Eliminar cadena de consulta de la ruta
  ├─ Emitir NetworkEvent al receptor (JSON Lines)
  └─ Aplicar cubeta de tokens MaxEventsPerSecond
        │
        ▼
Rotar archivo de salida al alcanzar el límite de tamaño; purgar archivos más antiguos que RetentionDays
```

## Requisitos de seguridad

- **Npcap es una dependencia externa.** El sensor la referencia pero nunca la descarga ni la instala.
- **Se requiere elevación.** El proceso debe ejecutarse como Administrador. Falta de elevación es un bloqueador de inicio, no un modo degradado.
- **Sin cambios de cuenta de servicio privilegiados.** El sensor no crea servicios de Windows, no cambia ACLs ni modifica IIS.
- **Los eventos son escrituras de solo añadido.** La rotación reemplaza archivos pero nunca edita contenido existente.
- **Sin captura predeterminada.** `Enabled: false` y `Ports` vacío significa que no se observa ningún paquete.

## Integración con los hitos (milestones)

| Hito | Relación |
|---|---|
| M4 Observabilidad | Los eventos de NetworkSensor alimentan la misma corriente de eventos estructurados; los patrones de rotación/retención se alinean. |
| M5 Dashboard | Vista de solo loopback en el dashboard de eventos de NetworkSensor; autenticación de Windows antes de cualquier uso remoto. |
| M7 Activación controlada | Si WPShield se coloca eventualmente frente a IIS vía ARR (M7), el gateway ya ve tráfico HTTP; NetworkSensor es visibilidad complementaria en capa de red, no redundante. |

## Fuera del alcance de este diseño

- Inyección o bloqueo de paquetes.
- Descifrado de cargas TLS (solo metadatos del handshake: `tls: true`).
- Firmas de prevención de intrusiones.
- Integración con interna de WordPress (base de datos, `wp_options`, etc.).

## Pasos siguientes

1. Agregar `src/WPShield.NetworkSensor/` con destino `net10.0-windows`.
2. Agregar SharpPcap + PacketDotNet a `Directory.Packages.props`.
3. Implementar enlace y validación de configuración.
4. Implementar construcción de filtro BPF y bucle de captura en vivo.
5. Implementar receptor de eventos JSON Lines con rotación.
6. Agregar pruebas unitarias para validación de configuración, eliminación de cadena de consulta y serialización de eventos.
7. Agregar prueba de integración con un servidor HTTP sintético local y captura en loopback (requiere Npcap en la pierna de CI).
8. Escribir `docs/en/network-sensor-design.md` como espejo de este documento.
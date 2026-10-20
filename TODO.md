# TODO — Próxima sesión

Estado actual: rama `main`, commit `1641f3b`, push a `origin/main` completado.
Build: 0 warnings, 0 errores. Tests: 1,370 pasando, 0 fallos.

---

## 🔴 Inmediato (este fin de semana)

### 1. Ejecutar pruebas M1.3 contra IIS real (tú tienes IIS)

El usuario mencionó que tiene IIS en su máquina. Las pruebas en
`tests/WPShield.Gateway.Tests/IISValidationTests.cs` están escritas pero **saltan
si no detectan IIS escuchando en 127.0.0.1:8081 o :8082**.

**Qué hacer:**
1. Configurar dos sitios WordPress en IIS en loopback puertos 8081 y 8082.
2. Ejecutar:
   ```powershell
   dotnet test tests/WPShield.Gateway.Tests/WPShield.Gateway.Tests.csproj --configuration Release --filter "FullyQualifiedName~IISValidationTests"
   ```
3. Verificar que ninguna falle. Si falla alguna, revisar `docs/en/m1-iis-validation.md`
   o `docs/es/validacion-iis-m1.md` para el checklist manual de 16 ítems.

### 2. Probar `wpshield network-monitor` con Npcap

El comando está implementado (`src/WPShield.Cli/NetworkMonitorCommand.cs`) pero **no
se ha probado en máquina real** porque requiere Npcap y elevación de Administrador.

**Qué hacer:**
1. Instalar Npcap en la máquina con IIS (https://npcap.com/#download).
2. Abrir PowerShell como Administrador.
3. Ejecutar:
   ```powershell
   dotnet run --project src/WPShield.Cli -- network-monitor --ports 80,443 --output C:\Temp\wpshield-network.ndjson
   ```
4. Generar tráfico (curl al localhost) y verificar que aparecen líneas JSON en el
   output sin cuerpos, credenciales ni query strings.
5. Detener con Ctrl+C.

---

## 🟡 Esta semana (M3 / M4 pendientes)

### 3. Rate limiting de solicitudes HTTP (M3)

Ya existe `src/WPShield.Gateway/RequestRateLimiter.cs` con presupuesto fijo por
cliente/sitio/ruta. Lo que falta:
- Pruebas de integración que verifiquen HTTP 429 en Block mode y Observe en Monitor.
- Documentación de `Gateway:RateLimit` en inglés y español.

### 4. Observabilidad automatizada (M4)

Se agregaron 3 pruebas de redacción (`LogRedactionTests.cs`). Falta:
- Más casos: `Authorization` en uploads, `Cookie` en multipart, `Set-Cookie` en respuestas del backend.
- Métricas por sitio (requests, actions, rule matches, duration).
- Structured JSON Lines con rotation y retention ya existe en `WPShield.Logging`.

### 5. Revisar que `Directory.Packages.props` no rompa Linux CI

Se agregaron `SharpPcap 4.1.0` y `PacketDotNet 1.4.9-pre53` pero **solo
`WPShield.NetworkSensor` los referencia**. Verificar que la pierna de Linux CI
sigue buildando y testeando exactamente los 4 proyectos portables
(`Abstractions`, `Core`, `Rules.Windows`, `Rules.WordPress`).

---

## 🟢 Próximos meses (roadmap)

| Hito | Qué falta | Prioridad |
|---|---|---|
| M1.3 | Validación real contra IIS (ver ítem 1 arriba) | Alta |
| M3 | Rate limiting por IP/sitio, políticas login/XML-RPC/uploads | Media |
| M4 | Métricas, eventos estructurados, tests de redacción completos | Media |
| M5 | Dashboard multilingüe, solo loopback inicialmente | Baja |
| M6 | Releases firmados, checksums, versión 1.0.0 | Baja |
| M7 | Activación controlada (una prueba, un sitio real, ambos en Monitor) | Baja |
| M8 | Community rule packages, branch protection, private vulnerability reporting | Baja |

---

## 📋 Checklist antes de cada commit (de AGENTS.md)

```powershell
dotnet restore WPShield.slnx
dotnet build WPShield.slnx --configuration Release --no-restore
dotnet test WPShield.slnx --configuration Release --no-build
dotnet format WPShield.slnx --verify-no-changes
git diff --check
```

No commitear ni pushear hasta que todo esté verde.

---

## Notas de arquitectura (no modificar sin leer AGENTS.md)

- `WPShield.NetworkSensor` es **separado** del gateway: nunca referencia a
  `WPShield.Gateway`, `Core`, `Abstractions` ni las reglas desde el gateway en
  dirección inversa.
- El sensor requiere Npcap y elevación de Administrador. Nunca se instala
  silenciosamente.
- `Monitor` es el modo por defecto. `Block` requiere configuración explícita
  por sitio.
- Nunca escribir cuerpos de request a disco. El buffer es `ArrayPool<byte>` y
  no referencia ninguna API de archivo.
- Los 4 proyectos portables deben seguir buildando y testeando en Linux CI.

---

**Última actualización:** Tue Oct 20 2026 — Después del commit `1641f3b` (Items 1–4 completados, push a origin/main).
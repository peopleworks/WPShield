# Despliegue

Cómo WPShield llega a un servidor Windows y se pone delante de un sitio en producción, y cómo
quitarlo. Tres scripts y cuatro pasos manuales en IIS.

> **WPShield es una vista previa de investigación y no está aprobado para tráfico de producción.**
> Todo lo de abajo supone un sitio que se puede permitir romper, en modo `Monitor`, con una marcha
> atrás que ya ensayó.

## La forma del asunto

| Paso | Quién lo hace | Por qué |
| --- | --- | --- |
| `Publish-WPShield.ps1` | máquina de compilación | Compilación autocontenida `win-x64`, archivada con checksum. |
| `Invoke-WPShieldTriage.ps1` | servidor | ¿Este servidor ya está comprometido? Un gateway delante de un webshell existente protege la entrada, no lo que ya está dentro. |
| `wpshield preflight` | servidor | ¿Puede funcionar aquí la ruta de tráfico? Despeje todo bloqueante. |
| `Install-WPShield.ps1` | servidor | Directorios, ACLs, servicio, identidad de mínimo privilegio. |
| **IIS: enlace privado** | **a mano** | El puerto al que WPShield reenvía de vuelta. |
| **IIS: `preserveHostHeader`** | **a mano** | Es de servidor entero. Vea la advertencia. |
| **IIS: la regla de reescritura** | **a mano** | El interruptor que pone a WPShield en la ruta. |
| **IIS: verificar y observar** | **a mano** | Modo Monitor, leyendo el registro, antes de bloquear nada. |
| `Uninstall-WPShield.ps1` | servidor | Revierte la instalación. **No** es una marcha atrás por sí solo. |

Los pasos de IIS son manuales a propósito. Son los cambios que tumban un sitio en producción,
necesitan una persona mirando el sitio mientras ocurren, y en un servidor compartido afectan a
aplicaciones que no tienen nada que ver con WPShield. `AGENTS.md` lo convierte en invariante: nada de
este repositorio modifica IIS, certificados, DNS, reglas de cortafuegos ni servicios de Windows de
forma automática, y `Test-WPShieldScripts.ps1` rompe la compilación si aparece un cmdlet que escriba
en IIS dentro de cualquier script.

## 1. Compilar

```powershell
.\scripts\Publish-WPShield.ps1
```

Produce `artifacts\wpshield-<versión>-win-x64-RESEARCH-PREVIEW-NOT-FOR-PRODUCTION\`, lo mismo como
`.zip`, y un `.sha256` al lado. Verifique el checksum después de copiar — un archivo que llega dañado
no es una hipótesis.

**Autocontenida, a propósito.** Una compilación dependiente del framework es más pequeña y funciona
donde esté instalado el runtime correspondiente. Esta publica autocontenida de todos modos, porque el
servidor para el que WPShield está escrito es compartido: una máquina con decenas de aplicaciones
ajenas, donde el parche que otra persona aplique al runtime compartido no debería poder detener el
gateway de seguridad.

**Sin recorte.** El recorte reduciría bastante el tamaño y también eliminaría en silencio tipos que el
enlace de configuración y la inyección de dependencias resuelven por reflexión. Un gateway que no
arranca a las 3 de la mañana porque un recortador quitó un enlazador es peor que un directorio grande.

La publicación se niega a producir un artefacto que contenga `appsettings.Local.json`, y borra la
salida si lo encuentra. Ese archivo lleva nombres de host y topología reales y nunca debe entrar en un
paquete de despliegue.

## 2. Triage primero

Si hay alguna duda sobre el servidor, corra [la herramienta de triage](herramienta-de-triage.md) antes
que nada. Poner un gateway delante de un sitio ya comprometido protege la vía de entrada — no hace
nada con los shells que ya están en disco, y no expulsa a un intruso que se movió fuera de la raíz web.

## 3. Verificación previa

```powershell
wpshield preflight --output preflight.jsonl
```

Solo lectura. Despeje todo bloqueante antes de continuar, y repita hasta que no quede ninguno. Vea
[verificación previa](verificacion-previa.md) para qué significa cada comprobación. Termina imprimiendo
el `appsettings.Local.json` a usar, rellenado con los sitios que encontró.

## 4. Instalar

Primero en seco. `-WhatIf` imprime cada paso sin hacer ninguno, y no exige elevación:

```powershell
.\scripts\Install-WPShield.ps1 -Path C:\staging\wpshield -WhatIf
```

Después, elevado:

```powershell
.\scripts\Install-WPShield.ps1 -Path C:\staging\wpshield -ConfigurationPath C:\staging\appsettings.Local.json
```

Lo que hace:

- **Se niega a correr si `-InstallPath` o `-LogPath` está dentro de un directorio que IIS sirve**, antes
  de haber creado, copiado o registrado nada. `-AllowWebRootPaths` lo permite con advertencia.
- Crea `C:\Program Files\WPShield` y `C:\ProgramData\WPShield\logs`.
- Copia la compilación, y la configuración del operador si le pasa una.
- **Escribe la ruta de registros en `Logging:File:Directory` del `appsettings.json` instalado.** Crear
  y endurecer un directorio del cual nunca se le habló al gateway no endurece nada; sólo reporta que
  sí.
- Registra un servicio llamado `WPShield`, y jamás ningún otro.
- Le da la **cuenta virtual `NT SERVICE\WPShield`** — sin contraseña que guardar en ningún sitio, sin
  cuenta que administrar, y con una identidad por servicio que sí se puede nombrar en una ACL.
- Reemplaza los permisos de ambos directorios por tres entradas: SYSTEM y el grupo local de
  administradores con control total, y la cuenta del servicio con **lectura y ejecución** en los
  binarios y **modificación** en los registros. La herencia se desactiva y las entradas heredadas se
  descartan en vez de copiarse, porque copiarlas conserva exactamente el acceso amplio que esto quita.
- Configura el servicio para reiniciarse tras una caída: 5s, 15s, 60s.

Los principales se conceden por SID conocido, no por nombre. `BUILTIN\Administrators` es
`BUILTIN\Administradores` en un Windows en español, y un script que concede por nombre allí no concede
nada, en silencio.

El servicio **no se inicia** salvo que pase `-Start`. Un gateway sin configuración de sitios no
resuelve ningún host, y arrancarlo antes de que la configuración esté en su sitio no demuestra nada.

### Por qué importan los permisos del directorio de registros

`C:\ProgramData` concede lectura a `BUILTIN\Users` por omisión. Un registro de WPShield lleva rutas de
peticiones, aciertos de reglas y direcciones de cliente, así que en un servidor con aplicaciones de
otras personas ese valor por omisión lo haría legible por toda cuenta de la máquina. `PRE-016` reporta
esa condición; la instalación no puede ser lo que la crea.

### Por qué el instalador escribe la ruta además de endurecerla

Durante una versión, esos dos pasos no coincidían. El instalador creaba `C:\ProgramData\WPShield\logs`,
quitaba la herencia, le daba **modificación** a la cuenta de servicio e imprimía `Logs to:
C:\ProgramData\WPShield\logs`. Nunca se lo dijo al gateway. El gateway leía `Logging:File:Directory`,
que se publicaba como el relativo `logs`, lo resolvía contra su raíz de contenido e intentaba escribir
junto a sus propios binarios — el directorio que este mismo instalador deja deliberadamente en
**lectura y ejecución** para esa cuenta. Toda escritura fallaba. El fallo se anunciaba por la salida de
error estándar, para la cual un servicio de Windows no tiene consola.

Una instalación hecha según el manual producía cero evidencia y no decía nada al respecto. Al operador
se le había dicho, en pantalla, que el registro estaba en un directorio endurecido.

Cambiaron dos cosas. El instalador escribe la ruta que endureció en la configuración que el gateway
lee, y el gateway **se niega a arrancar** cuando no puede escribir ahí. `Test-WPShieldScripts.ps1`
ahora comprueba que el valor por omisión de `-LogPath` y el `Logging:File:Directory` publicado nombren
el mismo directorio, y ejercita la edición contra una copia real del archivo publicado.

## 5. Confirmar que escucha, antes de tocar IIS

```powershell
Start-Service WPShield
Invoke-WebRequest http://127.0.0.1:10000/_wpshield/health/ready -UseBasicParsing
```

Si eso no responde, deténgase aquí. Nada en IIS ha cambiado todavía, así que nada está roto todavía.

## 6. Los pasos de IIS, a mano

**a. Añada un enlace privado de loopback** a cada sitio, en el puerto de destino de su configuración —
`127.0.0.1:8081`, `127.0.0.1:8082`. Es a donde WPShield reenvía.

**b. Active `preserveHostHeader`.**

```powershell
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
  -Filter 'system.webServer/proxy' -Name 'preserveHostHeader' -Value $true
```

> **Esto es de servidor entero.** `system.webServer/proxy` vive en `applicationHost.config` y **no
> tiene anulación por sitio**, así que esto cambia la cabecera `Host` que *todo* proxy de ARR de la
> máquina envía aguas abajo, no solo los que usa WPShield. `PRE-017` lista los otros proxies por
> nombre. Pruebe cada uno inmediatamente después del cambio, no al día siguiente. Revertir es la misma
> línea con `$false`.

**c. Añada la regla de reescritura** a cada sitio:

```xml
<rule name="WPShield" stopProcessing="true">
  <match url=".*" />
  <conditions>
    <add input="{HTTP_X_WPSHIELD_REQUEST_ID}" pattern="^$" />
  </conditions>
  <action type="Rewrite" url="http://127.0.0.1:10000/{R:0}" />
</rule>
```

**Póngala primero.** Una regla con `stopProcessing="true"` y coincidencia `.*` se traga toda petición
antes de que se evalúe cualquier regla posterior, y **la regla de enlaces permanentes de WordPress
tiene exactamente esa forma**. Ponga la de WPShield por debajo y no se ejecuta nunca — y el fallo es
silencioso: el sitio funciona perfectamente y no se inspecciona nada. `PRE-018` reporta qué sitios
tienen una.

La condición es la guarda de bucle. WPShield estampa `X-WPShield-Request-ID` en todo lo que reenvía,
así que la petición de vuelta no vuelve a coincidir; y **elimina cualquier copia entrante**, así que un
visitante no puede añadir la cabecera él mismo y saltarse la inspección. Las dos mitades son
estructurales — quite la eliminación y la guarda de bucle se convierte en un bypass de autenticación.

## 7. Obsérvelo en modo Monitor

`Monitor` es el valor por omisión y debería quedarse así todo el tiempo que haga falta para creerle al
registro. WPShield reenvía todo y anota qué habría rechazado. Lea `C:\ProgramData\WPShield\logs`, busque
cualquier cosa que se habría bloqueado y no debería, y solo entonces considere `Block` — un sitio a la
vez.

## Marcha atrás

**Esta es la parte que hay que leer antes de necesitarla.**

Una vez que la regla de reescritura está activa, **detener el servicio no esquiva WPShield: tumba el
sitio.** IIS sigue reenviando cada petición a un puerto de loopback sin nada detrás, y todo visitante
recibe un error.

**El bypass es la regla de reescritura.** Desactívela y el tráfico vuelve a ir directo al sitio, esté
como esté el servicio. Ese es el control al que hay que recurrir, y el que hay que ensayar.

| Situación | Haga esto |
| --- | --- |
| WPShield bloquea algo que no debería | Ponga el sitio en `Monitor` y reinicie el servicio. |
| El gateway se porta mal y necesita el sitio ya | **Desactive la regla de reescritura.** |
| Algo más se rompió tras `preserveHostHeader` | Póngalo de vuelta en `$false`, y luego investigue. |
| Quitar WPShield definitivamente | Desactive las reglas, confirme que los sitios sirven, y entonces `Uninstall-WPShield.ps1`. |

## Desinstalar

```powershell
.\scripts\Uninstall-WPShield.ps1 -WhatIf
.\scripts\Uninstall-WPShield.ps1 -RemoveFiles
```

**Se niega a ejecutarse** mientras vea una regla de reescritura de WPShield habilitada, y se niega
igualmente cuando no puede leer la configuración de IIS en absoluto — porque «nadie pudo mirar» no es
«no hay nada», y en una desinstalación esa diferencia decide si el sitio se queda en pie. `-Force`
anula, para cuando ya confirmó que la regla está desactivada o el sitio ya está caído.

Los registros **se conservan** por omisión. Son la memoria de lo que el gateway vio, y una
desinstalación durante un incidente es el peor momento para borrar evidencia. Pase `-RemoveLogs` cuando
lo diga en serio.

La cuenta virtual desaparece con el servicio; no queda ninguna cuenta atrás. Los enlaces y las reglas
que añadió a mano en IIS siguen ahí — quítelos usted si el gateway no va a volver.

## Qué queda abierto

`ROADMAP.md` M6 lleva el resto: releases firmadas y notas de versión bilingües. La instalación no está
firmada, y por eso se entrega con un checksum en su lugar.

## Véase también

- [Verificación previa](verificacion-previa.md) — despeje todo bloqueante antes de instalar.
- [Herramienta de triage](herramienta-de-triage.md) — ¿este servidor ya está comprometido?
- [ADR 0001 — ruta de tráfico en producción](adr/0001-ruta-de-trafico-en-produccion.md) — por qué la ruta es así.
- [Configuración del operador](configuracion-operador.md)

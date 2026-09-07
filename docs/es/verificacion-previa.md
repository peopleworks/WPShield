# Verificación previa

`scripts/Invoke-WPShieldPreflight.ps1` comprueba si un servidor Windows con IIS está listo para poner
WPShield delante de sus sitios en producción, e informa de cada bloqueante. **No cambia nada**: ni un
ajuste de IIS, ni un enlace, ni una regla de reescritura, ni un servicio, ni una ACL, ni una regla de
cortafuegos.

Ejecútela antes de instalar nada. Vuelva a ejecutarla después de arreglar lo que nombre.

```powershell
.\scripts\Invoke-WPShieldPreflight.ps1
.\scripts\Invoke-WPShieldPreflight.ps1 -SiteName 'example-one','example-two' -OutputPath .\preflight.jsonl
```

> **Ejecutarlo desde `cmd.exe`.** Un `.ps1` no es ejecutable desde el símbolo del sistema: escribir su
> nombre allí lo abre en un editor o reporta un comando no reconocido, según la asociación de
> archivos. Hay que llamar al intérprete de forma explícita, desde un símbolo **elevado**:
>
> ```
> powershell -NoProfile -ExecutionPolicy Bypass -File C:\temp\Invoke-WPShieldPreflight.ps1 -OutputPath C:\temp\preflight.jsonl
> ```

Ejecútela elevada. Sin elevación, la configuración de IIS, los puertos a la escucha y los permisos de
los directorios son parcialmente ilegibles, y la respuesta sale mal **en la dirección optimista** —
que es la peor dirección para una verificación de preparación. El script reporta su propia falta de
elevación como bloqueante justamente por eso.

## Por qué existe

La ruta de tráfico de la [ADR 0001](adr/0001-ruta-de-trafico-en-produccion.md) es: IIS conserva los
puertos 80 y 443, URL Rewrite y ARR envían cada petición a WPShield en un puerto de loopback, y
WPShield la reenvía a un enlace privado de loopback del mismo sitio.

Esa ruta tiene varias formas de fallar, y comparten una propiedad desagradable: **fallan en el sitio
en producción, en el momento de activar la regla de reescritura, con un error que no dice qué está
mal.**

- **El interruptor de proxy de ARR a nivel de servidor viene apagado.** Con él apagado, una regla que
  apunta a `http://127.0.0.1:10000` no hace proxy: devuelve **404 en cada petición**, y nada en el
  registro explica por qué.
- **ARR no preserva la cabecera `Host` del cliente por omisión.** WPShield resuelve el sitio a partir
  de esa cabecera y cierra con **HTTP 421** cuando no coincide con ningún sitio configurado. Con esto
  apagado, el sitio entero responde 421 en cuanto la regla entra en vigor.
- **La regla manda todo a WPShield, y WPShield lo manda de vuelta a IIS.** Si la petición de vuelta
  vuelve a coincidir con la regla, entra en bucle.
- **Puede que otra cosa ya tenga el puerto.** En un servidor con decenas de aplicaciones, eso no es
  hipotético.

Cada una de esas es un arreglo de cinco minutos y unos veinte minutos muy malos si se descubre en
producción.

## Qué comprueba

| ID | Qué responde |
| --- | --- |
| `PRE-001` | ¿Está elevada la sesión? Bloqueante si no, porque todo lo de abajo respondería optimistamente. |
| `PRE-002` | Versiones de Windows y de PowerShell. |
| `PRE-003` | ¿Hay runtime de ASP.NET Core 10, o hace falta la compilación autocontenida? |
| `PRE-004` | ¿Está IIS instalado, corre `W3SVC`, se lee su configuración? |
| `PRE-005` | ¿Está instalado URL Rewrite? Sin él no hay forma de entrar. |
| `PRE-006` | ¿Está instalado ARR? URL Rewrite reescribe una URL pero no puede reenviar la petición a otro proceso. |
| `PRE-007` | **¿Está habilitado el proxy de ARR a nivel de servidor?** La trampa del 404 silencioso. |
| `PRE-008` | **¿Preserva ARR la cabecera `Host` del cliente?** La trampa del 421 en todo el sitio. |
| `PRE-009` | ¿Está libre el puerto de loopback del gateway? |
| `PRE-010` | ¿Están libres los puertos privados candidatos, o ya son un enlace de IIS? |
| `PRE-011` | ¿Quién tiene los puertos 80 y 443? WPShield nunca ocupa un puerto público. |
| `PRE-012` | Inventario de sitios: enlaces, ruta física, estado, si parece WordPress. |
| `PRE-013` | Reglas de reescritura existentes, contra las que hay que ordenar la de WPShield. |
| `PRE-014` | ¿Ya existe un servicio WPShield? Entonces esto es una actualización, no una instalación. |
| `PRE-015` | El directorio de instalación y sus permisos. |
| `PRE-016` | El directorio de registros: **¿pueden leerlo cuentas sin privilegios?** |
| `PRE-017` | **Qué otras aplicaciones ya pasan por ARR** — el radio de impacto del arreglo de `PRE-008`. |
| `PRE-018` | Reglas atrapa-todo que detienen el procesamiento, antes de las cuales debe ir la de WPShield. |
| `PRE-019` | **¿Alguna parte de WPShield quedaría dentro de un directorio que IIS sirve?** |

`PRE-016` es bloqueante y no advertencia. `C:\ProgramData` es el sitio convencional para un directorio
de registros y su ACL por omisión concede lectura a `BUILTIN\Users` — así que un registro de WPShield
con rutas de peticiones, aciertos de reglas y direcciones de cliente sería legible por toda cuenta de
un servidor que ejecuta aplicaciones de otras personas.

Cada estado es `Pass`, `Warn`, `Blocker` o `Info`, y **todo bloqueante lleva un remedio**. Una
verificación que informa de un problema sin decir qué hacer con él ha movido el problema, no lo ha
resuelto.

## `PRE-017` — el arreglo de `PRE-008` es de servidor entero

`preserveHostHeader` vive en `applicationHost.config`, bajo `system.webServer/proxy`, que es una
**sección de nivel de servidor sin anulación por sitio**. Así que el remedio de `PRE-008` cambia la
cabecera `Host` que *todo* proxy de ARR de la máquina envía aguas abajo, no solo los que usará
WPShield.

En un servidor con una aplicación eso es un intercambio razonable. En uno con sesenta, algunas de
ellas proxies inversos hacia otros procesos, es un cambio que hay que hacer a conciencia y verificar
de inmediato. `PRE-017` encuentra esos otros proxies buscando reglas cuya acción sea un `Rewrite` a
una URL absoluta `http://` o `https://`, y los nombra **antes** de accionar el interruptor, no después
de que algo deje de funcionar.

La mayoría de las aplicaciones tras un proxy inverso quieren el `Host` original y mejoran al
recibirlo. Algunas están configuradas asumiendo que no lo reciben. En cualquier caso no es un cambio
que afecte solo a WPShield, y el operador debe saber qué aplicaciones volver a probar.

## `PRE-018` — el orden frente a una regla atrapa-todo

Una regla con `stopProcessing="true"` y coincidencia `.*` se traga toda petición antes de que se
evalúe cualquier regla posterior. **La regla de enlaces permanentes de WordPress tiene exactamente esa
forma**, así que en un sitio WordPress la regla de WPShield tiene que ir *primero* o no se ejecuta
nunca — y el modo de fallo es silencioso: todo sigue funcionando, y no se inspecciona nada.

## `PRE-019` — WPShield no es una aplicación de IIS

WPShield es un proceso aparte que escucha en un puerto de loopback al que IIS le reenvía. Nada de él
va debajo de una raíz web, y `PRE-019` no deja que eso pase en silencio. Compara la ruta de
instalación, la ruta de registros y —si ya hay un servicio WPShield registrado— el directorio desde
el cual ese servicio realmente corre, contra `%SystemDrive%\inetpub` y la ruta física de **todos** los
sitios de IIS, incluidos los que `-SiteName` filtró. Un sitio por el que nadie preguntó sirve su
directorio con la misma eficacia.

Instalado bajo un directorio servido, tres cosas salen mal a la vez:

- **`appsettings.Local.json` se puede descargar por HTTP.** `.json` está en el mapa MIME
  predeterminado de IIS, y ese archivo nombra todos los hosts que este gateway protege y el puerto
  privado detrás de cada uno.
- **La bitácora de evidencia queda en el árbol que IIS reparte.** Hoy `.jsonl` no está en el mapa
  MIME, así que no se sirve. Eso es una tabla de extensiones, no una frontera de seguridad, y está a
  una entrada de `mimeMap` de cambiar.
- **Un webshell en cualquier sitio vecino lo lee todo** sin necesidad de una sola petición HTTP, y
  aprende exactamente qué puede y qué no puede ver el escudo.

Esta comprobación existe porque pasó. WPShield se descomprimió en `C:\inetpub\wwwroot\WPShield` en el
servidor para el cual se construyó este proyecto, y escribió su log ahí durante un día antes de que
alguien leyera la primera línea. `Install-WPShield.ps1` ahora rechaza esa disposición de plano;
`-AllowWebRootPaths` lo permite con advertencia.

## La ausencia de hallazgos no es un hallazgo

Cuando IIS no se puede leer, el script emite `PRE-012` como bloqueante diciéndolo, en vez de imprimir
una lista de sitios vacía. En una verificación de preparación, *"no hay sitios"* y *"nadie pudo
mirar"* nunca deben verse igual: la primera invita a seguir y la segunda no.

## Qué imprime al final

Dos cosas que de otro modo se escriben a mano, que es de donde salen las erratas que causan un 421.

**El `appsettings.Local.json` a usar**, rellenado con los sitios que encontró — nombres de host,
puertos privados de destino, y `Mode: Monitor`, porque WPShield debería observar un sitio real antes
de rechazar nada en él. El archivo se **imprime, nunca se escribe**: pertenece a ese servidor, está en
`.gitignore`, y un script de solo lectura debe seguir siendo de solo lectura.

`TrustedProxies` queda en `127.0.0.1`, que es la dirección del par que presenta ARR. Si un sitio usa
HTTPS, el script dice por qué eso importa: sin ello se descarta `X-Forwarded-Proto`, WordPress ve HTTP
plano detrás de un sitio HTTPS y empieza a emitir URLs `http://`. Eso es un bucle de redirección, no
una degradación sutil.

**La regla de reescritura**, con su guarda de bucle incluida:

```xml
<rule name="WPShield" stopProcessing="true">
  <match url=".*" />
  <conditions>
    <add input="{HTTP_X_WPSHIELD_REQUEST_ID}" pattern="^$" />
  </conditions>
  <action type="Rewrite" url="http://127.0.0.1:10000/{R:0}" />
</rule>
```

La condición es la guarda de bucle, y **sus dos mitades son estructurales.** WPShield estampa
`X-WPShield-Request-ID` en todo lo que reenvía, así que la petición que vuelve del gateway no vuelve a
coincidir con la regla. Y WPShield *elimina* cualquier copia entrante de esa cabecera, así que un
visitante no puede añadirla y saltarse la inspección entera. Quite la eliminación y la guarda de bucle
se convierte en un bypass de autenticación.

## El informe

Con `-OutputPath`, los hallazgos se escriben como JSON Lines en el **mismo sobre que usan el registro
del gateway y la herramienta de triage** — `timestamp`, `level`, `category`, `message`, `state` — de
modo que los tres se leen con un solo analizador. `Blocker` corresponde a `Error`, `Warn` a `Warning`,
el resto a `Information`.

Como en el informe de triage, toda cadena se escapa al ASCII imprimible, para que nada recuperado del
servidor pueda llevar un carácter de control o una secuencia de escape hasta quien lo lea.

## Qué no hace

- **No instala nada ni arregla nada.** A propósito. En un servidor que ejecuta aplicaciones de otras
  personas, cambiar un ajuste de IIS no debería ser un efecto secundario de hacer una pregunta.
- **No demuestra que la ruta funcione.** Demuestra que se cumplen las precondiciones. Confirmar que la
  regla no puede entrar en bucle, que `Host` sobrevive al salto de ARR y que `X-Forwarded-Proto` llega
  a WordPress requiere enviar tráfico — eso es `scripts/Test-WPShieldIisLab.ps1` y la lista de
  verificación de M1.3.
- **No juzga la seguridad del sitio.** Eso es
  [`Invoke-WPShieldTriage.ps1`](herramienta-de-triage.md), y en un servidor sobre el que tenga alguna
  duda, es el primero que hay que correr: poner un gateway delante de un sitio ya comprometido protege
  la vía de entrada, no los shells que ya están dentro.

## Véase también

- [ADR 0001 — ruta de tráfico en producción](adr/0001-ruta-de-trafico-en-produccion.md)
- [Herramienta de triage](herramienta-de-triage.md)
- [Configuración del operador](configuracion-operador.md)

# Verificar accesos web de IIS

Usa una copia estable de un registro W3C de un único servidor IIS. El lector funciona sin conexión
y solo necesita acceso de lectura al archivo. Indica el valor exacto de la columna `s-sitename`
generada por el servidor. Según la configuración de IIS puede ser un número, una etiqueta de
instancia o el nombre del sitio.

```powershell
wpshield iis-login --log-file .\example.log --site W3SVC7 --json
```

Cada observación incluye el número de línea, la hora UTC, el estado HTTP, el subestado IIS y el
estado Win32. El informe indica el SHA-256 y el tamaño del prefijo leído para volver a localizar
esas líneas en la misma copia. La salida omite usuarios, direcciones IP, rutas, cadenas de consulta
y cabeceras. El comando conserva la configuración de IIS, auditoría y firewall.

| Evidencia registrada | Observación |
| --- | --- |
| HTTP 401.1 y Win32 1326 (fallo de inicio de sesión) | `login-rejected`. Ambos valores deben constar en la misma línea del sitio. |
| 401.2 anónimo con Win32 5 o 401.1 anónimo con Win32 2148074254 | `challenge-compatible`. Esa línea por sí sola deja el resultado desconocido. |
| HTTP 2xx, subestado y Win32 cero, y usuario autenticado en `cs-username` | `authenticated-request`. Una sesión puede atender varias solicitudes después del acceso. |
| La línea anterior es compatible con un desafío y esta solicitud autenticada cumple los criterios siguientes | `challenge-followed-by-success`, con referencia a ambas líneas. |
| Otros 401 | `unknown`. |

Para asociar dos líneas deben ser consecutivas, pertenecer al sitio elegido bajo el mismo esquema
y usar HTTP/1.1, las mismas IP y puertos en ambos extremos, método y ruta, con horas UTC ordenadas
a diez segundos de distancia como máximo. La etiqueta describe la secuencia observada. Un proxy
compartido, la reutilización de conexiones o consultas distintas pueden impedir identificar al
usuario o el inicio de sesión original. La columna opcional `c-port` debe proceder de la variable
de servidor `REMOTE_PORT` en un campo personalizado de confianza. Usa registros existentes cuyo
origen conozcas. Si faltan campos, cambia un extremo, hay una línea intermedia o se usa HTTP/2,
se muestran las observaciones por separado.

Las filas de otros sitios quedan excluidas. Las que carecen de sitio se cuentan en
`UnattributedRows`. Muchos registros por sitio omiten `s-sitename`. La atribución queda entonces
como desconocida, aunque la carpeta, la cabecera Host o el puerto sugieran un sitio. El lector
respeta cada declaración `#Fields:` y espera filas UTF-8 o ASCII terminadas en salto de línea.
[Configuración de registros IIS](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/site/logfile) · [Campos W3C](https://learn.microsoft.com/en-us/windows/win32/http/w3c-logging) · [Intercambio de autenticación IIS](https://learn.microsoft.com/en-us/troubleshoot/iis/401-error-preauthentication-header) · [Error 1326](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1300-1699-)

Los límites son 4 MiB de entrada, 16 KiB por línea, 64 campos, 256 observaciones y cinco segundos
de lectura y análisis. La salida 0 indica evidencia disponible; 1, argumentos inválidos o archivo
ilegible; 2, cobertura parcial por límites, filas malformadas o sin sitio; y 3, lectura completa
sin evidencia elegible. En un servidor de laboratorio, contrasta ambas líneas con un acceso IIS
autorizado. Hay pruebas sintéticas. Quedan pendientes la validación en IIS real y el contraste
con los eventos de Seguridad de Windows.

## Referencia de una línea

```powershell
wpshield iis-login --log-file .\ejemplo.log --site W3SVC7 --json | Set-Content -Encoding UTF8 .\iis.json
wpshield audit-reference --snapshot .\iis.json --source iis --line 3
```

Elija el número físico `Line` de una observación del informe guardado. La salida contiene el
SHA-256 y la longitud en bytes del prefijo, la línea elegida y la del desafío previo si el lector
vinculó ambas observaciones. Para verificarlo, calcule la huella de esa cantidad de bytes al
comienzo de la copia W3C original y consulte las líneas indicadas. Un prefijo distinto identifica
otros datos. La exportación copia la referencia que figura en el informe.
[Límites de selección y códigos de salida](diseno-sensor-red.md#referencia-de-auditoría-seleccionada)

# M1: Gateway HTTP multisitio de laboratorio

Esta versión escucha únicamente en `127.0.0.1:10000`. No debe exponerse todavía a Internet ni reemplazar los bindings públicos de IIS.

## Topología prevista

- WPShield Gateway: `127.0.0.1:10000`
- IIS / peopleworks.com.do: `127.0.0.1:8081`
- IIS / peopleworksgpt.com: `127.0.0.1:8082`
- Upload legítimo declarado: 5 MB (se aplicará en M2)

## Preparar IIS sin interrumpir producción

Conservar los bindings actuales de 80 y 443. Agregar temporalmente un binding HTTP local distinto a cada sitio. El binding local debe probarse antes de iniciar WPShield.

No cambiar certificados, HTTPS público, DNS, firewall ni servicios de Windows en M1.

## Validación de inicio M1.1

WPShield rechaza el inicio cuando:

- no existe ningún sitio configurado;
- un host está asignado más de una vez, incluso si cambia solamente mayúsculas y minúsculas;
- un listener no usa HTTP o HTTPS sobre una dirección IP de loopback;
- un destino no utiliza una URI absoluta HTTP o HTTPS;
- un destino está fuera de loopback durante M1; o
- un destino utiliza un puerto listener de WPShield y podría crear un bucle de proxy.

Estos fallos son errores de configuración. Se debe corregir la configuración, no debilitar la validación.

## Ejecutar

```powershell
dotnet run --project src/WPShield.Gateway
```

## Comprobar salud

```powershell
curl.exe http://127.0.0.1:10000/_wpshield/health/live
curl.exe http://127.0.0.1:10000/_wpshield/health/ready
```

El espacio completo `/_wpshield/health/` se procesa localmente y nunca se reenvía. El acceso remoto a salud permanece deshabilitado de forma predeterminada.

## Probar cada sitio

```powershell
curl.exe -I -H "Host: peopleworks.com.do" http://127.0.0.1:10000/
curl.exe -I -H "Host: peopleworksgpt.com" http://127.0.0.1:10000/
```

Un host no configurado debe producir HTTP 421:

```powershell
curl.exe -i -H "Host: invalid.example" http://127.0.0.1:10000/
```

Un backend no disponible produce una respuesta JSON HTTP 502 consistente:

```json
{
  "error": "backend_unavailable",
  "requestId": "correlation-id"
}
```

La respuesta al cliente nunca incluye el destino, detalles de excepciones, credenciales, cookies, cuerpo de la solicitud ni query string. Los logs de solicitudes del gateway contienen únicamente metadatos seguros como request ID, site ID, método y ruta. El logging informativo de solicitudes de ASP.NET Core y YARP está deshabilitado para prevenir la exposición de query strings.

## Pruebas de integración sintéticas M1.2

Las pruebas automatizadas ejecutan dos backends Kestrel locales y seguros llamados `site-one` y `site-two`. No utilizan IIS, WordPress, hostnames de producción ni datos de producción. El gateway y ambos backends escuchan en loopback usando puertos asignados dinámicamente por el sistema operativo.

La suite de integración verifica:

- cada hostname configurado llega únicamente a su backend asignado;
- los hosts desconocidos reciben HTTP 421 y no llegan a ningún backend;
- los valores falsificados de `X-Forwarded-For`, `X-Forwarded-Proto` y `X-Forwarded-Host` son reemplazados;
- un `X-WPShield-Request-ID` generado por el gateway llega al backend;
- el método HTTP, la ruta y el query string se reenvían correctamente;
- los backends no disponibles o con timeout producen una respuesta HTTP 502 segura; y
- el espacio de salud permanece local y no llega a ningún backend.

Las pruebas automatizadas comprueban que sus puertos no sean 80, 443, 8081, 8082 ni 10000. El timeout configurable de actividad del proxy está limitado entre 1 y 300 segundos; el valor predeterminado del laboratorio continúa siendo 100 segundos.

## Validación local con IIS M1.3

M1.3 es un procedimiento de laboratorio controlado por un operador, no un despliegue automatizado. WPShield no crea ni modifica bindings de IIS. Antes de validar, un administrador debe agregar y comprobar estos bindings temporales de loopback sin cambiar los puertos públicos 80 y 443:

- `peopleworks.com.do` en `127.0.0.1:8081`
- `peopleworksgpt.com` en `127.0.0.1:8082`

Ejecutar el gateway únicamente después de que ambos destinos respondan directamente. El script de prueba de solo lectura se detiene si un destino o el gateway no está disponible y nunca imprime cuerpos de respuesta, cookies ni datos de autorización:

```powershell
.\scripts\Test-WPShieldIisLab.ps1 `
  -SiteOneStaticPath "/wp-includes/css/dashicons.min.css" `
  -SiteTwoStaticPath "/wp-includes/css/dashicons.min.css" `
  -GatewayLogPath "C:\ruta\al\log-capturado-del-gateway.log"
```

El script comprueba las páginas principales directa y vía gateway, `/wp-admin/`, login, REST, cron, AJAX, redirecciones, HEAD, un recurso estático conocido, un 404 sintético, salud local, rechazo de hosts desconocidos, marcadores de privacidad y listeners sin cambios en los puertos 80 y 443. Las rutas estáticas deben identificar archivos públicos que existan en cada instalación. La ruta del log debe corresponder a la salida capturada durante la misma ejecución.

### Lista manual autenticada

Usar una cuenta administrativa dedicada al laboratorio y una ventana privada del navegador. No copiar credenciales, cookies, nonces, códigos OAuth ni logs de producción en issues o informes.

| Prueba | Resultado esperado |
| --- | --- |
| Login y logout de WordPress | La autenticación funciona por el puerto 10000; no aparece un bucle ni un puerto interno |
| Navegación en `/wp-admin/` | Dashboard, CSS, JavaScript, imágenes y redirecciones cargan normalmente |
| Upload multimedia | Un archivo benigno menor de 5 MB se carga y puede abrirse; M1 no lo inspecciona ni bloquea |
| API REST | Las rutas autenticadas y públicas usadas por el sitio funcionan igual que directamente por IIS |
| Cron y AJAX | Las tareas programadas y operaciones de `admin-ajax.php` terminan sin errores del gateway |
| Elementor | El editor abre, carga recursos, muestra preview y guarda un borrador inocuo sin publicarlo |
| Google Site Kit | El dashboard abre, conserva la conexión existente y los valores OAuth no aparecen en logs |
| 404 y redirecciones canónicas | Los códigos y URLs públicas coinciden con el comportamiento directo de IIS |
| Revisión de privacidad | Los logs no contienen credenciales, Authorization, Cookie, Set-Cookie, nonces, OAuth, cuerpos ni query strings completas |

Registrar solamente pass/fail, códigos HTTP, duración, request IDs y observaciones saneadas. M1.3 termina únicamente cuando ambos sitios pasan las pruebas automáticas, la lista manual y la revisión de privacidad.

## Reversión

Detener WPShield basta para desactivar este laboratorio. Como los bindings públicos de IIS permanecen intactos, los visitantes continúan entrando directamente por 80/443.

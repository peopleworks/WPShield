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

## Reversión

Detener WPShield basta para desactivar este laboratorio. Como los bindings públicos de IIS permanecen intactos, los visitantes continúan entrando directamente por 80/443.

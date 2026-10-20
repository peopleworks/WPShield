# M1.3 — Validación con IIS local

Este documento describe el procedimiento para validar WPShield contra una instalación real de IIS
en loopback, sin tocar los enlaces públicos en los puertos 80 y 443. Es trabajo de M1.3 y un
prerrequisito para la activación controlada de M7.

## Topología

El laboratorio usa dos sitios de WordPress en IIS, cada uno vinculado a un puerto loopback:

| Sitio | Host | Enlace IIS | Destino de WPShield |
|---|---|---|---|
| wordpress-one | wordpress-one.example | 127.0.0.1:8081 | http://127.0.0.1:8081/ |
| wordpress-two | wordpress-two.example | 127.0.0.1:8082 | http://127.0.0.1:8082/ |

El gateway escucha en `127.0.0.1:10000`. Los enlaces públicos en 80 y 443 nunca se cambian
durante esta validación.

```
Cliente de prueba local
        │
        ▼
WPShield Gateway
127.0.0.1:10000
        │
        ├── wordpress-one.example
        │         ▼
        │   IIS 127.0.0.1:8081
        │
        └── wordpress-two.example
                  ▼
              IIS 127.0.0.1:8082
```

## Requisitos previos

1. Windows Server con IIS 10 instalado.
2. Dos sitios de WordPress configurados en IIS, vinculados a los puertos loopback 8081 y 8082.
3. Elementor y Google Site Kit instalados en al menos un sitio (objetivos de compatibilidad).
4. El binario del gateway construido desde el commit actual:
   ```powershell
   dotnet build WPShield.slnx --configuration Release
   ```
5. Los valores reales solo en `appsettings.Local.json` — nunca confirmado, nunca publicado.

## Lista de validación

Ejecute cada elemento y registre el resultado. Cualquier falla detiene el despliegue para ese
sitio hasta que se corrija.

### 1. El gateway inicia y resuelve los sitios

Inicie el gateway y confirme que imprime la tabla de sitios resueltos:

```powershell
dotnet run --project src/WPShield.Gateway
```

Salida esperada:

```text
info: WPShield.Gateway.Configuration[0]
      Gateway configuration resolved 2 site(s).
info: WPShield.Gateway.Configuration[0]
      Configured site. SiteId=wordpress-one Hosts=wordpress-one.example Destination=http://127.0.0.1:8081/ Mode=Monitor
info: WPShield.Gateway.Configuration[0]
      Configured site. SiteId=wordpress-two Hosts=wordpress-two.example Destination=http://127.0.0.1:8082/ Mode=Monitor
```

### 2. Hosts desconocidos fallan cerrado con 421

```powershell
curl.exe -i -H "Host: unknown.example" http://127.0.0.1:10000/
```

Debe retornar `421 Misdirected Request` con `{"error":"unknown_host","requestId":"…"}` y no
debe alcanzar ningún backend de IIS.

### 3. Página principal

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/
```

Debe retornar `200 OK` desde el sitio IIS uno, no desde el sitio dos.

### 4. Administración y login

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/wp-admin/
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/wp-login.php
```

Deben alcanzar el sitio uno. No envíe credenciales — solo verifique que la ruta llegue al backend.

### 5. Recursos estáticos

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/wp-content/themes/example/style.css
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/wp-content/plugins/elementor/assets/js/frontend.min.js
```

CSS, JS, imágenes y otros recursos estáticos deben enrutarse al sitio correcto y retornar
`200` o `304`.

### 6. API REST

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/wp-json/wp/v2/posts
```

Debe alcanzar el endpoint de REST de WordPress del sitio uno.

### 7. Cron de WordPress

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/wp-cron.php
```

Debe alcanzar el sitio uno y retornar `200`.

### 8. AJAX administrativo

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/wp-admin/admin-ajax.php?action=heartbeat
```

Debe alcanzar el sitio uno. `admin-ajax.php` recibe tráfico legítimo de Elementor y otros
plugins, por lo que ninguna regla de ruta debe rechazarlo.

### 9. Redirecciones y HEAD

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/
curl.exe -X HEAD -H "Host: wordpress-one.example" http://127.0.0.1:10000/
```

HEAD debe retornar el mismo estado que GET sin cuerpo.

### 10. Respuestas 404

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/this-path-does-not-exist
```

Debe retornar `404` desde el WordPress del sitio uno, no un error generado por WPShield.

### 11. Cargas

Publique un archivo sintético inofensivo a `wp-admin/async-upload.php` y confirme que llega al
sitio uno:

```powershell
curl.exe -F "async-upload=@test-image.jpg" -H "Host: wordpress-one.example" http://127.0.0.1:10000/wp-admin/async-upload.php
```

En modo Monitor la carga se reenvía y se registra; en modo Block un hallazgo por encima del
umbral se rechaza con `403`.

### 12. Compatibilidad con Elementor

Cargue una página editada con Elementor a través del gateway:

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/elementor-test-page/
```

Debe retornar `200` con los recursos de Elementor cargados desde el sitio uno.

### 13. Compatibilidad con Google Site Kit

Cargue una página con Google Site Kit a través del gateway:

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/site-kit-page/
```

Debe retornar `200`. Site Kit realiza llamadas a REST y admin-AJAX; todas deben enrutarse al
sitio correcto.

### 14. Enlaces públicos sin cambios

Confirme que los enlaces públicos de IIS en los puertos 80 y 443 no se tocaron:

```powershell
Import-Module WebAdministration
Get-WebBinding | Select-Object protocol, bindingInformation
```

Los puertos 80 y 443 deben seguir apuntando a los sitios IIS originales, no a WPShield.

### 15. Sin secretos en los logs

Revise el archivo de log del gateway durante la duración de esta validación. Confirme que no
aparece ninguno de los siguientes:

- Encabezados `Authorization`, `Cookie`, `Set-Cookie`
- Nonces de WordPress
- Claves API, tokens, contraseñas
- Cadenas de consulta completas
- Cuerpos de solicitud completos ni contenido de cargas

Los logs deben registrar solo: ID de solicitud, ID de sitio, método, ruta (sin cadena de
consulta), código de estado, IDs de regla y puntuaciones.

### 16. Rollback

Detenga el proceso del gateway. El tráfico a IIS en 8081/8082 se reanuda directamente, tal como
estaba antes de iniciar WPShield. Como los enlaces IIS 80/443 nunca se cambiaron, el tráfico
público nunca se vio afectado.

## Criterios de salida

Los 16 elementos pasan y el log del gateway no contiene secretos. El operador ha leído la tabla de
sitios resueltos línea por línea y ha confirmado que coincide con el enrutamiento previsto.

## Automatización

El conjunto de pruebas en `tests/WPShield.Gateway.Tests/IISValidationTests.cs` automatiza los
elementos 2–10 y 15 contra una instalación local de IIS. Salta automáticamente cuando IIS no
está disponible, por lo que es seguro ejecutarlo en cualquier máquina — incluida la pierna de CI
de Linux — sin fallar.
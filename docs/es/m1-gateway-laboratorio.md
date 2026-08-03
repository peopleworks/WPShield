# M1: Gateway HTTP multisitio de laboratorio

Esta versión escucha únicamente en `127.0.0.1:10000`. No debe exponerse todavía a Internet ni reemplazar los bindings públicos de IIS.

## Topología prevista

- WPShield Gateway: `127.0.0.1:10000`
- IIS / peopleworks.com.do: `127.0.0.1:8081`
- IIS / peopleworksgpt.com: `127.0.0.1:8082`
- Upload legítimo declarado: 5 MB (se aplicará en M2)

## Preparar IIS sin interrumpir producción

Conservar los bindings actuales de 80 y 443. Agregar temporalmente un binding HTTP local distinto a cada sitio. El binding local debe probarse antes de iniciar WPShield.

No cambiar certificados, HTTPS público, DNS ni firewall en M1.

## Ejecutar

```powershell
dotnet run --project src/WPShield.Gateway
```

## Comprobar salud

```powershell
curl.exe http://127.0.0.1:10000/_wpshield/health/live
curl.exe http://127.0.0.1:10000/_wpshield/health/ready
```

## Probar cada sitio

```powershell
curl.exe -I -H "Host: peopleworks.com.do" http://127.0.0.1:10000/
curl.exe -I -H "Host: peopleworksgpt.com" http://127.0.0.1:10000/
```

Un host no configurado debe producir HTTP 421:

```powershell
curl.exe -i -H "Host: invalid.example" http://127.0.0.1:10000/
```

## Reversión

Detener WPShield basta para desactivar este laboratorio. Como los bindings públicos de IIS permanecen intactos, los visitantes continúan entrando directamente por 80/443.

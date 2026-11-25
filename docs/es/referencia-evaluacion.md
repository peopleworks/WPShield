# Referencia de evaluación

[English](../en/evaluation-reference.md) · [Índice de documentación](../README.md)

## Comparación con otras opciones

La tabla compara el diseño, sin medir tasas de detección. WPShield carece de un benchmark frente a estos productos.

| | WPShield | Plugins de WordPress (Wordfence, Sucuri, …) | ModSecurity y OWASP CRS | Cloudflare / Azure Front Door WAF |
| --- | --- | --- | --- | --- |
| Dónde se ejecuta | Proxy inverso en Windows, antes de IIS y PHP | PHP dentro de WordPress, o antes mediante prepend en algunos casos | Módulo del servidor web, antes de la aplicación | Antes de que el tráfico llegue a tu red |
| Producción | Vista previa de investigación en loopback | Sí | Sí | Sí |
| Normalización de nombres en Windows y NTFS | Todas las reglas ven el nombre normalizado | Ausente del modelo documentado, orientado a Linux y Apache | Reglas orientadas a Linux | Sin acceso al sistema de archivos |
| Handlers IIS y cargas `web.config` | `IIS-CONFIG-001`, `IIS-UPLOAD-001` | Sin documentar | Fuera de CRS | No aplicable |
| Actualizaciones de reglas | Por PR en el repositorio | Alimentación continua de inteligencia de amenazas | Releases de CRS y fuentes de proveedores | Gestionadas por el proveedor |
| Mitigación DDoS volumétrica | Fuera de alcance | Limitada | Fuera de alcance | Sí |
| Escaneo de archivos en disco | Fuera de alcance | Sí | No | No |
| ID estable y evidencia por hallazgo | ID, puntuación, clave y evidencia | Varía | Sí, con su propio ajuste de reglas | IDs del proveedor y detalle limitado |
| Coste | Gratis, MIT | Nivel gratuito y fuente de pago | Gratis y de código abierto | Pago por encima del nivel gratuito |

Las otras opciones llevan años en producción. Wordfence y sus pares ofrecen inteligencia de amenazas, escaneo de archivos y protección de acceso con una base amplia de instalaciones. ModSecurity y OWASP CRS cubren inyección, traversal, anomalías de protocolo y más. Su módulo IIS ha recibido poco mantenimiento y las reglas asumen alojamiento en Linux. Cloudflare y Azure Front Door absorben tráfico volumétrico, terminan TLS y filtran bots antes de llegar al servidor.

WPShield inspecciona la solicitud en Windows con conocimiento de cómo se escribe un nombre de archivo y de los casos ejecutables de IIS como `web.config` y `.aspx`. Para protección en producción están las alternativas de la tabla.

IIS Request Filtering ya está disponible en IIS y filtra la URL, extensiones, segmentos ocultos, verbos y longitud de consulta. La inspección del cuerpo multipart por WPShield complementa ese filtro.

## Trabajo reciente de seguridad

Este resumen precede al primer release. Consulta el [registro de cambios](../../CHANGELOG.md) para el trabajo posterior y el razonamiento de cada corrección.

- **Cuatro variantes del nombre que eludían `WP-UPLOAD-001`.** `shell.php.`, `shell.php `, `shell.php::$DATA` y `photo.php.jpg` llegaban como scripts ejecutables en Windows y pasaban la comprobación previa. Ahora se normaliza con criterios de Windows.
- **`IIS-CONFIG-001`** detecta la carga de `web.config`, que puede habilitar ejecución de código en IIS sin subir un script.
- **`IIS-UPLOAD-001`** cubre las extensiones que IIS ejecuta como la identidad del pool.
- **Retirada del conjunto completo de cabeceras de reenvío no confiables.** Incluye variantes `X-Forwarded-*`, `Forwarded`, cabeceras de dirección de cliente y las de sustitución de ruta `X-Original-URL` y `X-Rewrite-URL`.
- **Cuerpos acotados.** Rechazo temprano cuando `Content-Length` excede el límite y durante la lectura cuando se desconoce la longitud.
- **Topología de producción retirada del repositorio público.** Ahora el arranque rechaza hostnames reales mezclados con los de ejemplo, señal de una superposición parcial.

## Proyectos relacionados

Las herramientas de PeopleWorks comparten plataforma y estilo. Cada una tiene su propio flujo de trabajo.

| Proyecto | Para qué sirve |
| --- | --- |
| [SQLDiff](https://github.com/peopleworks/SqlSchemaDiff) | Compara esquemas SQL Server y escribe un script que ajusta el destino al origen sin perder sus filas. |
| [SyncJob](https://github.com/peopleworks/syncjob) | Sincroniza los datos SQL Server con cargas completas o incrementales mediante CLI o servicio Windows, con auditoría por ejecución. |
| [XAF Logic Explainer](https://github.com/peopleworks/XAFLogicExplainer) | Lee una aplicación DevExpress XAF con Roslyn y explica sus entidades, controladores, acciones, reglas, navegación y ajustes del Model Editor a un asistente de programación. |
| WPShield | Inspecciona solicitudes HTTP antes de IIS, PHP y WordPress en Windows Server. |

Los cuatro usan .NET y licencia MIT, priorizan Windows y proceden de PeopleWorks. Para combinar WPShield con defensas del servidor, consulta Microsoft Defender e IIS Request Filtering.

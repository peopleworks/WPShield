# Evaluación de la protección del servidor frente a RdpGuard

El objetivo es superar a RdpGuard en la protección de los servicios que usa el operador. Esta es
la línea de base documental del 22 de noviembre de 2026. RdpGuard anuncia detección de fallos
repetidos, bloqueo automático de IP con umbral y duración configurables, listas de excepciones,
Geo-IP e IP Cloud. Las mediciones comparativas siguen pendientes. Comparar la detección local
en condiciones equivalentes y medir por separado el efecto de las fuentes de reputación.
[RdpGuard](https://rdpguard.com/) · [Guía del fabricante](https://rdpguard.com/help.aspx)

## Cobertura y orden de trabajo

La primera entrega de WPShield es el monitor pasivo de flujos en un adaptador. La opción
`--rdp-port` de esta rama añade evidencia de inicios de sesión interactivos remotos de Windows.
El gateway ya inspecciona rutas y cargas HTTP compatibles y aplica límites por sitio. El monitor
de seguridad registra hallazgos. La biblioteca de integración tiene una lista de bloqueo en
memoria. El comando independiente aplica mediante WFP las entradas del operador. Las pruebas de
prevención se realizan solo en una [VM desechable](validacion-filtro-red-vm.md).
[Monitor de red](diseno-sensor-red.md) · [Roadmap M2.8](../../ROADMAP.md#m28--security-event-log-monitoring)

| Servicio | Qué documenta RdpGuard | Qué debe demostrar WPShield |
| --- | --- | --- |
| Escritorio Remoto | Fallos de autenticación RDP. [Guía](https://rdpguard.com/rdp-protection-settings.aspx) | Validar `--rdp-port` con eventos reales de tipo 10 y una sesión autorizada. Medir aparte los fallos de NLA que quedan fuera de esa vista. |
| Microsoft SQL Server | Fallos de inicio de sesión 18456. [Guía](https://rdpguard.com/mssql-server-protection.aspx) | El lector de Aplicación identifica éxitos y fallos por instancia. Las pruebas sintéticas verifican el aislamiento de proveedores. Falta contrastar un registro conocido en Windows Server y medir omisiones. [Evidencia SQL](diseno-sensor-red.md#evidencia-de-inicios-de-sesión-de-sql-server) |
| IIS Web Login | Fallos de Basic, Digest y NTLM. [Guía](https://rdpguard.com/iis-web-login-protection.aspx) | El lector W3C verifica secuencias compatibles con negociación, rechazos 401.1 con Win32 1326 y atribución desconocida. Falta validación real y contraste con el registro Seguridad. [Evidencia IIS](evidencia-accesos-iis.md) |
| HTTP | Patrones de solicitudes en registros de acceso. [Guía](https://rdpguard.com/http-vulnerability-scan-protection.aspx) | Evaluar por separado los hallazgos HTTP en rutas WordPress y el análisis de registros web. |
| FTP | Intentos de acceso FTP fallidos. [Guía](https://rdpguard.com/ftp-bruteforce-protection.aspx) | Elegir un servidor y una fuente de auditoría. Verificar el rechazo y el reintento legítimo, también bajo FTPS cuando exista registro del servidor. |
| IMAP | Fallos al acceder al buzón. [Guía](https://rdpguard.com/imap-bruteforce-protection.aspx) | Atribuir el fallo a IMAP en un registro de autenticación del servidor de correo. |
| POP3 | Fallos de autenticación POP3. [Guía](https://rdpguard.com/pop3-bruteforce-protection.aspx) | Distinguir un fallo de acceso de una desconexión normal del cliente. |
| SMTP | Fallos de autenticación del cliente SMTP. [Guía](https://rdpguard.com/stop-smtp-bruteforce.aspx) | Separar un fallo de autenticación del rechazo de un destinatario o de una entrega. |
| MySQL | Intentos de autenticación rechazados. [Guía](https://rdpguard.com/mysql-brute-force-protection.aspx) | Verificar qué campos registra la instancia y detectar un rechazo sin publicar nombres de cuenta ni consultas. |
| ASP.NET Forms | Eventos de validación de solicitudes de ASP.NET Web Forms clásico. [Guía](https://rdpguard.com/asp-net-web-forms-protection.aspx) | Evaluar validación de solicitudes y autenticación de formularios como resultados distintos. Cada uno requiere su propia evidencia de aplicación. |
| RD Web Access | Indicios de IIS y de auditoría de Windows. [Guía](https://rdpguard.com/rdweb-access-protection.aspx) | Atribuir el resultado al portal RD Web y distinguirlo de un inicio de sesión de escritorio remoto. |
| VoIP/SIP | Fallos SIP con cobertura condicionada por transporte y cifrado. [Guía](https://rdpguard.com/voip-sip-brute-force-protection.aspx) | Usar evidencia de la centralita y reconocer un desafío normal seguido de éxito. |
| SSH | Fallos de OpenSSH para Windows. [Guía](https://rdpguard.com/openssh-brute-force-protection.aspx) | Normalizar eventos del proveedor OpenSSH y probar métodos de acceso por clave y contraseña. |
| Microsoft VPN (RRAS) | Eventos RemoteAccess 20271 e IPsec 4652. [Guía](https://rdpguard.com/ms-vpn-rras-brute-force-protection.aspx) | Confirmar proveedor, tipo de VPN y origen identificable. Un error de negociación requiere interpretación propia. |

La secuencia propuesta comienza con RDP, Microsoft SQL Server e IIS Web Login. El primer lector
de SQL Server cubre el evento 18456 en Aplicación. Queda por evaluar qué evidencia adicional
aportan los grupos de auditoría de inicio de sesión de SQL Server. Para IIS se partirá de
registros separados por sitio y del mecanismo de autenticación habilitado. Se anotarán los campos
disponibles en la versión probada antes de decidir qué se puede correlacionar.
[Auditoría de SQL Server](https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-action-groups-and-actions) · [Configuración de registros de IIS](https://learn.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/configure-logging-in-iis)

## Cómo decidir si WPShield lo supera

1. Fijar antes del ensayo el servicio, las versiones, el proveedor, la política de auditoría, los
   umbrales y la duración de la observación. Comparar instalaciones aisladas equivalentes. Documentar
   la configuración predeterminada de cada producto y, aparte, las pruebas con umbrales comunes.
2. Etiquetar los resultados esperados por una fuente independiente. Empezar con registros sintéticos
   de éxito, rechazo, reintento legítimo, IP compartida, datos incompletos o duplicados y rotación
   de registros. Separar las pruebas offline de las pruebas con tráfico autorizado en Windows Server.
3. Publicar por servicio y versión los aciertos, las omisiones, los falsos positivos y las
   atribuciones erróneas, con numerador y denominador. Informar `unknown`, pérdidas de captura y
   disponibilidad de auditoría por separado. Medir latencia mediana y p95, CPU y memoria bajo la misma carga.
4. Registrar por separado **observación**, **detección** y **prevención verificada**. Para acreditar
   prevención, comprobar el efecto con un cliente de prueba independiente, la continuidad del acceso
   legítimo, la caducidad, el desbloqueo y la recuperación administrativa. La prueba inicial usa
   Monitor. El ensayo de bloqueo requiere un entorno desechable y un mecanismo de recuperación verificado.
5. Publicar una ventaja únicamente para el servicio, métrica y configuración medidos. Una mejora
   exige repeticiones comparables, evidencia revisable y resultados sobre disponibilidad y falsos
   positivos. Conservar salidas agregadas y referencias de registro, sin cuentas, credenciales ni
   contenido de sesiones. Las capacidades pendientes y los resultados inconcluyentes quedan visibles.
   Elegir la métrica principal antes de cada ensayo. Por ejemplo, lograr menos bloqueos indebidos
   con igual cobertura de detección, o reducir la latencia p95 manteniendo detección y falsos bloqueos.
   Un resultado que deja al administrador legítimo sin acceso falla la prueba de recuperación.

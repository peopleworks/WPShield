# Auditoría

`wpshield audit` lee cómo está montado un servidor IIS e informa de la configuración que permite que un
sitio comprometido se apodere del resto. **No cambia nada**: ni un pool, ni un permiso, ni una
asignación de controlador, ni un binding, ni un servicio, ni una regla de firewall.

```powershell
wpshield audit
wpshield audit --output auditoria.jsonl
```

Ejecútelo elevado. Sin elevación, las identidades de los pools, las asignaciones de controladores y los
permisos de las carpetas son en parte ilegibles, y la respuesta sale **optimista**. Por eso informa de
su propia falta de elevación como `AUDIT-001`, un hallazgo crítico, y marca la ejecución completa como
incompleta en lugar de imprimir un informe limpio.

## Por qué existe

Un web shell en un sitio es un incidente. Varias configuraciones de un servidor IIS compartido
pueden comprometer todo el servidor, y ningún escaneo de los propios sitios informa de
ninguna de ellas:

1. **Pools de aplicación que corren como administrador.** Un comando enviado al shell se ejecuta como
   administrador del servidor, no como una identidad web restringida.
2. **Carpetas de sitio escribibles por todas las cuentas.** Toda identidad de pool es miembro de
   `Users` e `IIS_IUSRS` mientras corre, así que un shell en un sitio puede escribir en todos los demás.
3. **PHP asignado a sitios que no lo necesitan.** Una asignación de PHP heredada del servidor o
   configurada a nivel de sitio puede permitir que IIS ejecute archivos PHP en un sitio que no usa PHP.
4. **Un sitio que responde a cualquier nombre de host y sirve la carpeta que contiene a todos los
   demás**: el `Default Web Site` de serie en `*:80` sobre `C:\inetpub\wwwroot`, que se quedó ahí cuando
   se añadieron los sitios reales debajo. Detener un sitio comprometido no saca sus archivos de
   internet: siguen accesibles por la dirección del servidor a través del sitio atrapa-todo.
5. **Una raíz web que se solapa con una carpeta FTP.** Una cuenta FTP podría escribir archivos que IIS sirva
   o ejecute con la identidad del pool de aplicaciones del sitio web.

Ninguna de estas es un problema de WordPress, y ninguna se ve desde fuera. Juntas son la diferencia
entre un sitio comprometido y un servidor comprometido.

## Qué comprueba

| ID | Severidad | Qué significa |
| --- | --- | --- |
| `AUDIT-001` | Crítico cuando no pudo mirar | Se ejecuta elevado y la configuración de IIS es legible. Si falla cualquiera de las dos, la ejecución se marca incompleta y sale con `1`: "nadie pudo mirar" nunca debe leerse como "no hay nada". |
| `AUDIT-002` | Crítico | Pools que se ejecutan como `LocalSystem` o con una cuenta que pertenece directamente al grupo local de Administradores, identificado por SID. El informe enumera los sitios que sirve cada pool. Revisa a mano las cuentas que no se pudieron resolver. **Cambia la contraseña al final.** Los pools que aún usan la cuenta fallarán en su próximo inicio y sus sitios devolverán HTTP 503. Cada migración a `ApplicationPoolIdentity` elimina una copia almacenada de la contraseña. |
| `AUDIT-003` | Advertencia | Pools que comparten `NetworkService` o `LocalService`. Corren con una sola identidad, así que ningún permiso de carpeta puede impedir que uno de esos sitios toque los archivos de otro. |
| `AUDIT-004` | Advertencia | Comprueba los controladores efectivos en la raíz de cada sitio HTTP/HTTPS, exista o no una asignación de PHP en el servidor. Enumera los sitios WordPress que deben conservar PHP, los demás sitios que lo ejecutan y aquellos cuya configuración de controladores no pudo leerse. Enumera los sitios sin enlaces HTTP/HTTPS en una línea aparte y los excluye del recuento de PHP. Advierte cuando un sitio sin WordPress ejecuta PHP o si no se pudo leer la configuración. En los demás casos, una asignación a nivel de servidor es informativa y una asignación solo a nivel de sitio pasa la comprobación. |
| `AUDIT-005` | Crítico | Carpetas de sitio en las que `Everyone`, `Users`, `Authenticated Users` o `IIS_IUSRS` pueden escribir, comprobado por SID. Cuentan las entradas que solo se heredan, porque dan escritura sobre todo lo que hay debajo de la carpeta, que es donde cae un archivo dejado por un atacante. Una carpeta cuyos permisos no se pueden leer es una advertencia, nunca un aprobado. |
| `AUDIT-006.<sitio>` | Crítico si está iniciado | Un sitio con un binding HTTP o HTTPS sin nombre de host, cuya carpeta contiene las carpetas de otros sitios. Detenido es una advertencia: hoy no se llega a nada a través de él, y en cuanto arranque se llega a todo. |
| `AUDIT-007` | Advertencia | La raíz configurada de un sitio HTTP/HTTPS y una raíz o un directorio virtual FTP comparten ruta o una carpeta contiene a la otra. Esto incluye un solo sitio con bindings FTP y HTTP/HTTPS. Separa las carpetas o comprueba a mano que el aislamiento de usuarios FTP impide a todas las cuentas FTP acceder a la carpeta que sirve IIS. También advierte si faltan rutas necesarias para la comprobación. Pasa si las carpetas no se solapan y es informativo si IIS no tiene enlaces FTP. |

## Nunca repara

Cada remedio que imprime es un cambio que se hace **a mano**, un pool o un sitio cada vez, con una
persona mirando el sitio mientras ocurre. Los tests lo comprueban.

La razón es la misma que la de la [ADR 0005](adr/0005-poner-wpshield-en-la-ruta.md) y la verificación
previa: en un servidor con aplicaciones de otras personas, cambiar la identidad de un pool o reemplazar
los permisos de una carpeta puede tumbar un sitio, y una herramienta de postura que "arreglara" el
servidor como efecto secundario de una consulta haría exactamente eso.

Su única escritura es en el propio WPShield. Tras cada corrida completa registra un resumen (ID de
hallazgo, severidades y recuentos, nunca nombres de sitios, pools ni cuentas) como una foto de postura en
el almacén de evidencias de WPShield ([ADR 0013](adr/0013-datos-del-host-y-centro-de-mando.md)), para que
`wpshield host posture` muestre cómo avanza "grupos como administrador: N de M". No es un cambio en el
servidor, y la última línea del informe dice si el resumen se registró. Una corrida que no pudo mirar
(sin elevación, IIS ilegible) nunca se registra, para que no reemplace una lectura real. `--store` indica
el almacén.

## Nunca lee una contraseña

Un pool que corre con una cuenta con nombre guarda la contraseña de esa cuenta en la configuración de
IIS, y cualquier administrador puede recuperarla en texto claro. La auditoría lee el nombre de la
cuenta y nunca la contraseña: sus datos no tienen un campo para ella, el lector nunca toca ese
atributo, y un test revisa su código fuente buscando cualquier lectura, por propiedad o por nombre de
atributo.

## Códigos de salida

| Código | Significado |
| --- | --- |
| `0` | Ningún hallazgo crítico. |
| `1` | No pudo mirar (sin elevación, IIS ilegible) o un argumento era incorrecto. |
| `2` | Al menos un hallazgo crítico. |

## El informe

`--output` escribe JSON Lines con el mismo sobre que usan el log del gateway, la verificación previa y
la herramienta de triage (`timestamp`, `level`, `category`, `message`, `state`), con `category` igual a
`WPShield.Audit`. Todos los elementos de todas las listas van en él; la salida de terminal corta cada
lista a los 25 elementos y dice cuántos quedan.

El informe lleva nombres reales de sitios, rutas de carpetas y nombres de cuentas. Lo cubre la regla
`*.jsonl` del `.gitignore` del repositorio; manténgalo fuera de cualquier sitio público.

## Hasta dónde se ha probado

Las comprobaciones se prueban con instantáneas sintéticas de IIS. Una ejecución con elevación en un
servidor IIS real sirvió de base para los cambios del informe sobre contraseñas, PHP y FTP. La
comprobación de FTP compara las rutas configuradas. El operador comprueba el acceso efectivo y el
aislamiento de los usuarios FTP.

## Qué no comprueba todavía

Dicho ahora en lugar de descubierto después:

- **Firmas.** Si todos los módulos globales de IIS, y binarios como `sethc.exe` y `utilman.exe`, están
  firmados válidamente por Microsoft. La mayoría de los binarios de Windows están firmados por
  catálogo, y .NET no tiene una API para verificarlo, así que necesita su propia pieza de interop
  hecha con cuidado.
- **El host más allá de IIS.** Suscripciones de eventos WMI, registros de eventos borrados, el tamaño
  del registro de seguridad, reglas de firewall abiertas a cualquier dirección y el historial de
  Microsoft Defender. La [herramienta de triage](herramienta-de-triage.md) cubre parte de esto hoy.
- **Los puertos a la escucha y los inicios de sesión por Escritorio Remoto.** Ambos tienen ya su
  propia herramienta, fuera de la auditoría, y la auditoría no lee ninguna de las dos:
  - `wpshield network-monitor --listeners --owners` lista los sockets TCP en escucha y los sockets
    UDP asociados, cada uno con el identificador de proceso que Windows informó para él, y el
    monitor de escritorio muestra el mismo inventario
    ([inventario de puertos locales](diseno-sensor-red.md#inventario-de-puertos-locales),
    [monitor de escritorio](diseno-sensor-red.md#monitor-de-escritorio)). Ninguno compara un puerto
    con el firewall, así que un puerto a la escucha con una regla abierta a cualquier dirección
    sigue sin aparecer en ninguna parte.
  - `wpshield network-monitor --flows --rdp-port <puerto>` asocia cada flujo entrante de Escritorio
    Remoto observado con el resultado del inicio de sesión en Windows y su número de registro de
    Seguridad
    ([evidencia de inicios de sesión por Escritorio Remoto](diseno-sensor-red.md#evidencia-de-inicios-de-sesión-por-escritorio-remoto)).
    Lee el último minuto del registro Seguridad mientras captura, así que muestra los inicios de
    sesión que ve ocurrir; ninguna de las dos herramientas guarda un historial por dirección de
    origen.
- **El comportamiento en los logs de IIS.** Un script que responde a peticiones POST con un tamaño de
  respuesta distinto cada vez es la firma de un web shell en uso, y la forma más fiable de encontrar
  uno que ninguna firma de antivirus ha detectado.
- **La pertenencia anidada a grupos.** Una cuenta que es administradora solo a través de un grupo de
  dominio anidado dentro del grupo local de Administradores se lee como no miembro.
- **Las entradas de denegación se tratan de forma gruesa.** Una denegación para un grupo amplio lo
  quita de la lista de escritores sin comparar las dos máscaras. El error va hacia informar de menos,
  nunca hacia inventar un escritor.

Estas son las comprobaciones que añadirá el panel de postura del host de la consola prevista, con las
mismas condiciones de solo lectura.

## Véase también

- [Verificación previa](verificacion-previa.md): si este servidor está listo para WPShield. La
  auditoría hace otra pregunta: si este servidor es seguro para alojar sitios.
- [Herramienta de triage](herramienta-de-triage.md): qué hay ya en un servidor que puede estar
  comprometido.

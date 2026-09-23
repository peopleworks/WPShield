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

Un web shell en un sitio es un incidente. Cuatro configuraciones habituales de un servidor IIS
compartido lo convierten en un servidor comprometido, y ningún escaneo de los propios sitios informa de
ninguna de ellas:

1. **Pools de aplicación que corren como administrador.** Un comando enviado al shell se ejecuta como
   administrador del servidor, no como una identidad web restringida.
2. **Carpetas de sitio escribibles por todas las cuentas.** Toda identidad de pool es miembro de
   `Users` e `IIS_IUSRS` mientras corre, así que un shell en un sitio puede escribir en todos los demás.
3. **PHP asignado para todo el servidor.** Un archivo `.php` escrito en la carpeta de un sitio .NET se
   ejecuta allí, así que el shell se extiende a sitios que nunca ejecutaron PHP.
4. **Un sitio que responde a cualquier nombre de host y sirve la carpeta que contiene a todos los
   demás**: el `Default Web Site` de serie en `*:80` sobre `C:\inetpub\wwwroot`, que se quedó ahí cuando
   se añadieron los sitios reales debajo. Detener un sitio comprometido no saca sus archivos de
   internet: siguen accesibles por la dirección del servidor a través del sitio atrapa-todo.

Ninguna de estas es un problema de WordPress, y ninguna se ve desde fuera. Juntas son la diferencia
entre un sitio comprometido y un servidor comprometido.

## Qué comprueba

| ID | Severidad | Qué significa |
| --- | --- | --- |
| `AUDIT-001` | Crítico cuando no pudo mirar | Se ejecuta elevado y la configuración de IIS es legible. Si falla cualquiera de las dos, la ejecución se marca incompleta y sale con `1`: "nadie pudo mirar" nunca debe leerse como "no hay nada". |
| `AUDIT-002` | Crítico | Pools que corren como `LocalSystem` o como una cuenta que es miembro directo del grupo local de Administradores, localizado por el SID del grupo para que funcione en un Windows en español. Cada uno aparece con los sitios que sirve. Una cuenta que no se puede resolver es una advertencia para revisar a mano, nunca un aprobado. |
| `AUDIT-003` | Advertencia | Pools que comparten `NetworkService` o `LocalService`. Corren con una sola identidad, así que ningún permiso de carpeta puede impedir que uno de esos sitios toque los archivos de otro. |
| `AUDIT-004` | Advertencia | PHP asignado a nivel de servidor, con los sitios que ejecutan PHP sin contener WordPress. Si solo lo ejecutan sitios WordPress, se informa como información. |
| `AUDIT-005` | Crítico | Carpetas de sitio en las que `Everyone`, `Users`, `Authenticated Users` o `IIS_IUSRS` pueden escribir, comprobado por SID. Cuentan las entradas que solo se heredan, porque dan escritura sobre todo lo que hay debajo de la carpeta, que es donde cae un archivo dejado por un atacante. Una carpeta cuyos permisos no se pueden leer es una advertencia, nunca un aprobado. |
| `AUDIT-006.<sitio>` | Crítico si está iniciado | Un sitio con un binding HTTP o HTTPS sin nombre de host, cuya carpeta contiene las carpetas de otros sitios. Detenido es una advertencia: hoy no se llega a nada a través de él, y en cuanto arranque se llega a todo. |

## Nunca repara

Cada remedio que imprime es un cambio que se hace **a mano**, un pool o un sitio cada vez, con una
persona mirando el sitio mientras ocurre. Los tests lo comprueban.

La razón es la misma que la de la [ADR 0005](adr/0005-poner-wpshield-en-la-ruta.md) y la verificación
previa: en un servidor con aplicaciones de otras personas, cambiar la identidad de un pool o reemplazar
los permisos de una carpeta puede tumbar un sitio, y una herramienta de postura que "arreglara" el
servidor como efecto secundario de una consulta haría exactamente eso.

## Nunca lee una contraseña

Un pool que corre con una cuenta con nombre guarda la contraseña de esa cuenta en la configuración de
IIS, y cualquier administrador puede recuperarla en texto claro. La auditoría lee el nombre de la
cuenta y nunca la contraseña: sus datos no tienen un campo para ella, y un test revisa su código fuente
buscando cualquier lectura de ese atributo.

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

## Qué no comprueba todavía

Dicho ahora en lugar de descubierto después:

- **Firmas.** Si todos los módulos globales de IIS, y binarios como `sethc.exe` y `utilman.exe`, están
  firmados válidamente por Microsoft. La mayoría de los binarios de Windows están firmados por
  catálogo, y .NET no tiene una API para verificarlo, así que necesita su propia pieza de interop
  hecha con cuidado.
- **El host más allá de IIS.** Inicios de sesión de Escritorio Remoto por dirección de origen,
  suscripciones de eventos WMI, registros de eventos borrados, el tamaño del registro de seguridad,
  puertos a la escucha con una regla de firewall abierta a cualquier dirección, y el historial de
  Microsoft Defender. La [herramienta de triage](herramienta-de-triage.md) cubre parte de esto hoy.
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

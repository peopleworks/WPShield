# Validar el bloqueo WFP en una VM desechable

Usa una VM nueva de Windows Server en un conmutador virtual privado. Prepara una consola de
hipervisor, una instantánea, un cliente de administración permitido y otro cliente para las pruebas.
Usa direcciones de laboratorio y mantén en loopback los listeners de la puerta de enlace durante
M1/M2. Realiza este procedimiento solo en la VM desechable, nunca en el servidor de producción.
Registra el commit, la compilación de Windows, las direcciones de laboratorio, los tiempos, los
resultados y el GUID de subcapa `93a54814-5f1d-44f3-b2ba-f4df18dfe12f`.

1. **Arbitraje con el firewall.** Ejecuta `wpshield network-filter --check` en una consola de
   administrador elevada. Abre un listener TCP temporal y permite manualmente su puerto en el
   Firewall de Windows. Comprueba una conexión nueva desde el cliente de prueba. Ejecuta
   `wpshield network-filter --mode Block --allow 203.0.113.20 --block 198.51.100.44` con las direcciones
   de los clientes de laboratorio. Repite la conexión y confirma el rechazo. Guarda la salida de
   `netsh wfp show filters file=wfp-filters.xml` y localiza la subcapa y el filtro de WPShield. Repite
   con una regla autenticada que permita **Invalidar reglas de bloqueo** (*Override block rules*) y
   un cliente que cumpla sus requisitos de autenticación. Anota si prevalece sobre WPShield. Retira
   las reglas temporales al terminar.
2. **Terminación forzada.** Abre rápidamente conexiones nuevas y mide cada una desde el cliente
   bloqueado. En la consola de la VM, ejecuta `taskkill /F /PID <pid-de-wpshield>` contra el proceso
   de bloqueo. Mide hasta la primera conexión exitosa desde la terminación del proceso y exige que
   transcurra menos de un segundo. Ejecuta `netsh wfp show filters file=wfp-after-kill.xml` y comprueba
   que desaparecieron todos los filtros de WPShield.
3. **RDP.** Abre una sesión RDP desde el cliente de administración incluido en `--allow`. Bloquea
   al otro cliente y verifica que RDP sigue respondiendo. Omite la IP administrativa del argumento
   y confirma que Block se niega a arrancar mientras siga activa esa conexión.
4. **10.000 filtros.** Ejecuta el [programa de carga](../en/network-filter-vm-validation.md#load-harness)
   en una consola elevada. Utiliza sus direcciones sintéticas solo en esta VM aislada. Registra el
   tiempo de arranque, la memoria privada del proceso de Base Filtering Engine (consulta el PID con
   `sc.exe queryex BFE`) y la latencia de conexiones nuevas de un cliente ajeno al rango. Mide antes,
   durante y después, y registra el número de muestras, la mediana y el percentil 95. Confirma que
   hay 10.000 filtros de WPShield en WFP. Detén el programa y verifica que se retiraron.
5. **Protección de endpoint.** Repite los puntos 1–3 con el filtrado de red del producto de terceros
   habilitado. Prueba una conexión inocua denegada por la política del producto antes y después de
   añadir el filtro de WPShield. Verifica que su bloqueo sigue activo y revisa el registro del
   sistema para detectar caídas o inestabilidad. Anota el producto y su versión.
6. **Identidad.** Registra el resultado en la consola elevada y repite la prueba con la cuenta virtual
   de WPShield mediante la receta de abajo. Si hay una denegación, registra la operación y el código
   de estado. Mantén el proceso independiente de administrador hasta que otro ADR autorice conectar
   el motor de decisión o cambiar los permisos WFP. Esta receta no concede permisos WFP.

La consola del Firewall de Windows y `Get-NetFirewallRule` muestran las reglas creadas manualmente
en la VM. Consulta los filtros dinámicos de WPShield con `netsh wfp show filters`.

## Probar la identidad del servicio WPShield

Usa una VM desechable sin un servicio llamado `WPShield`. Coloca la CLI publicada y sus archivos de
ejecución en `C:\WfpLab\cli`, con lectura y ejecución para la cuenta virtual. En un **Símbolo del
sistema** elevado, crea manualmente una instancia de diagnóstico de inicio a petición. El
administrador de servicios de Windows inicia el ejecutable con la cuenta virtual del mismo nombre.
Concede escritura a la cuenta virtual solo en la carpeta de resultados.

```bat
mkdir C:\WfpLab\results
sc.exe create WPShield binPath= "C:\WfpLab\cli\wpshield.exe network-filter --check --service-check-output C:\WfpLab\results\wfp-check.txt" start= demand obj= "NT SERVICE\WPShield"
icacls C:\WfpLab\cli /grant "NT SERVICE\WPShield:(OI)(CI)RX"
icacls C:\WfpLab\results /grant "NT SERVICE\WPShield:(OI)(CI)M"
sc.exe qc WPShield
sc.exe start WPShield
type C:\WfpLab\results\wfp-check.txt
sc.exe stop WPShield
sc.exe delete WPShield
```

El archivo debe identificar a `NT SERVICE\WPShield`. El servicio de diagnóstico espera a que lo
detengas con `sc.exe stop` tras escribir el resultado. PsExec `-i -s` usa `LocalSystem` y no sirve para
comprobar los permisos de la cuenta virtual. Restaura la instantánea de la VM al terminar.

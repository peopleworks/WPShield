# Filtro de red

`wpshield network-filter` simula o aplica bloqueos por IP remota en todo el servidor. Usa esta
versión preliminar de investigación en una VM desechable de Windows Server. Durante M1 y M2, la
puerta de enlace permanece en loopback.

## Comprobar y simular

Ejecuta la comprobación con la identidad de Windows que añadirá los filtros. El comando muestra la
identidad, la operación que Windows denegó si procede y el código de salida 0 si pasa o 1 si falla.

```powershell
wpshield network-filter --check
wpshield network-filter --allow 203.0.113.20 --block 198.51.100.44
```

La comprobación abre una sesión WFP dinámica y añade, enumera y elimina un filtro RFC 5737. Una
consola de administrador elevada normalmente tiene acceso. El [guion de validación en VM](validacion-filtro-red-vm.md)
también muestra cómo comprobar la identidad real `NT SERVICE\WPShield` mediante el administrador de
servicios de Windows. Monitor es el modo predeterminado y registra los bloqueos del operador antes
de salir. No abre ninguna sesión WFP.

## Bloquear en el laboratorio

```powershell
wpshield network-filter --mode Block --allow 203.0.113.20 --block 198.51.100.44,2001:db8::44 --output wfp-events.jsonl
netsh wfp show filters file=wfp-filters.xml
```

Usa en `--allow` la IP real del cliente RDP de tu VM. Block comprueba el puerto RDP configurado y las
conexiones establecidas a ese puerto, rechaza solapamientos entre las listas y realiza la autoprueba
antes de instalar los filtros del operador. Cada filtro tiene una condición de IP remota IPv4 o IPv6
en la subcapa ALE de recepción/aceptación de WPShield. El bloqueo afecta a todo el servidor. Los
filtros dinámicos se consultan con `netsh wfp show filters`. La consola del Firewall de Windows y
`Get-NetFirewallRule` no los muestran.

Detén el proceso activo antes de iniciar otro Block o ejecutar `--check`. La subcapa dinámica
tiene un solo propietario por servidor.

Ctrl+C cierra la sesión dinámica. La terminación del proceso y el reinicio también eliminan sus
objetos WFP. Si el proceso se cuelga, pueden seguir activos hasta que se termine el proceso. Para
omitir la puerta de enlace de IIS se deshabilita su regla de reescritura.

## Límites y evidencia

- La lista de permitidos admite hasta 1.000 entradas. Los bloqueos del operador admiten direcciones
  individuales y prefijos CIDR de /16 o mayores en IPv4 y /48 o mayores en IPv6. Se rechazan
  direcciones reservadas para tráfico local.
- El conjunto admite 1.000 entradas por omisión y hasta 10.000. Los bloqueos del operador duran hasta
  que se cierra la sesión. Un hallazgo de registro admitido puede añadir un bloqueo temporal o
  prolongar su duración. `--block-ttl-minutes` tiene un valor predeterminado de 60 y admite de 1 a
  10.080. Las expiraciones se revisan cada cinco segundos.
- Las actualizaciones nativas se ejecutan en transacciones WFP. Si una falla, se cierra la sesión
  y se registra el error. Así se levantan también los bloqueos cuyo borrado por expiración haya fallado.
- Los eventos usan el formato JSON Lines de la puerta de enlace. El bloqueo y su expiración llevan
  `WP-NET-001` y `requested_by`. La evidencia registra la dirección normalizada y los campos fijos
  pertinentes.
- El adaptador del registro de Seguridad acepta eventos 4625 de tipos 3 y 10. Es una integración
  de biblioteca. El comando independiente aplica las entradas del operador. La conexión con el motor
  de decisión del ADR 0009 requiere su propio ADR. [Diseño de integración](diseno-integracion.md)

Consulta el [ADR 0006](adr/0006-bloqueo-en-capa-de-red.md) para ver la decisión y los criterios de aceptación.

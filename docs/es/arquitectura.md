# Arquitectura

WPShield se diseña como un sistema por capas:

1. **Abstractions** define contratos estables.
2. **Core** identifica sitios y evalúa reglas.
3. **Paquetes de reglas** contienen detecciones específicas de cada plataforma.
4. **Gateway/proxy** inspecciona una cantidad limitada de datos antes de enviar la solicitud a IIS. Desde M2 esto es real y no una intención: un cuerpo `multipart/form-data` se almacena en memoria dentro del límite de solicitud —nunca en disco—, se reduce a un nombre acotado y una muestra inicial acotada por archivo, lo evalúan todas las reglas y luego se reenvía o se rechaza. Véase [inspección multipart acotada](m2-inspeccion-multipart.md) para saber qué queda cubierto y qué no.
5. **Interfaz de administración** mostrará configuración y evidencia operativa sin exponer secretos.

Una instancia de WPShield puede proteger varios sitios WordPress alojados en IIS. El valor HTTP `Host` selecciona una configuración y un destino explícitos. Un host desconocido se rechaza con HTTP 421 antes de contactar a ningún backend; no existe un sitio predeterminado al que recurrir.

El modo inicial es `Monitor`. Aunque una detección supere el umbral de bloqueo, se registra como `Observe` hasta que el operador active explícitamente `Block` para ese sitio.

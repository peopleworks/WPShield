# Arquitectura

WPShield se diseña como un sistema por capas:

1. **Abstractions** define contratos estables.
2. **Core** identifica sitios y evalúa reglas.
3. **Paquetes de reglas** contienen detecciones específicas de cada plataforma.
4. **Gateway/proxy** inspeccionará una cantidad limitada de datos antes de enviar la solicitud a IIS.
5. **Interfaz de administración** mostrará configuración y evidencia operativa sin exponer secretos.

Una instancia de WPShield podrá proteger varios sitios WordPress alojados en IIS. El valor HTTP `Host` seleccionará una configuración y un destino explícitos. El gateway futuro deberá rechazar hosts desconocidos, no enviarlos a un sitio predeterminado.

El modo inicial es `Monitor`. Aunque una detección supere el umbral de bloqueo, se registra como `Observe` hasta que el operador active explícitamente `Block` para ese sitio.

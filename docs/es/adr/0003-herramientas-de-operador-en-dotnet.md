# ADR 0003 — Las herramientas de operador pasan a una CLI de .NET

- **Estado:** Aceptado
- **Deciden:** Mantenedores de WPShield
- **Afecta:** todos los scripts de `scripts/` salvo el de triage, y la forma de toda futura
  funcionalidad de cara al operador

## Contexto

WPShield es un proyecto .NET cuya superficie de operador es PowerShell. Medido el día en que se
escribió esto:

| | Líneas |
| --- | --- |
| C# bajo `src/` | 9.831 |
| PowerShell bajo `scripts/` | **5.561** |

**El treinta y seis por ciento del proyecto es PowerShell**, y 1.264 de esas líneas son
`Test-WPShieldScripts.ps1` — un arnés de pruebas hecho a mano que existe para dar lo que `dotnet
test` da gratis: comprobación de parseo, de codificación, una guarda estructural contra escrituras, y
una comparación de que los scripts no se han desviado del código que replican.

Fue una primera decisión razonable. Un Windows Server trae PowerShell 5.1 y nada más garantizado, un
incidente no espera a una compilación, y un solo archivo ASCII se puede copiar a un servidor por
cualquier vía, incluida una ventana de chat. Todas esas razones eran reales.

Lo que cambió el equilibrio fueron tres días ejecutando los scripts contra un servidor en vivo con
sesenta y seis sitios.

## Lo que costó de verdad

De diez defectos encontrados en esos tres días, **tres no pueden existir en C#**:

| Defecto | Por qué C# lo impide |
| --- | --- |
| `@('config', $name, 'obj=', $account, 'password=', '')` — Windows PowerShell 5.1 **descarta** el argumento vacío, así que `sc.exe` rechazó la línea de comandos y la instalación reventó en el paso 4 de 6, dejando el gateway como `LocalSystem` con los directorios sin restringir | `ProcessStartInfo.ArgumentList` es una colección tipada; un elemento vacío es un argumento vacío |
| `-replace '\\', '\\\\'` emitía **cuatro** barras, porque una cadena de reemplazo de .NET no trata la barra invertida como escape. La configuración impresa no se podía pegar | Una cadena es una cadena |
| El `$LASTEXITCODE` de una llamada nativa se escapó del arnés, que imprimió `All 71 checks passed` y con eso mismo falló el build | El código de salida es el que usted retorna |

Comparten una propiedad, y es la que importa: **ninguna prueba vio ninguno, porque no hay
compilador.** Los tres los encontró un operador en un servidor de producción.

### El argumento que lo zanja

`Test-WPShieldScripts.ps1` documenta así su propia cuarta sección:

> El triage reporta si WPShield rechazaría una petición a cada artefacto que encuentra. Lo responde
> desde **sus propias copias** de las listas de extensiones y directorios del gateway, porque tiene
> que correr en un servidor sin runtime de .NET y sin una compilación de WPShield. **Las copias
> derivan.** Una copia desviada no falla ruidosamente — reporta en silencio una cobertura que el
> gateway no tiene, que es peor que no reportar nada.

Existe una categoría entera de pruebas para vigilar la deriva de una copia. En C# no hay copia: la
herramienta referencia `WPShield.Rules.WordPress` y la categoría entera desaparece.

### La parte que no es sobre defectos

Un operador que corre esto a las once de la noche tiene que saberse siete nombres de archivo y los
parámetros de cada uno. No hay un `--help` que enumere lo que la herramienta puede hacer. Para un
producto .NET esa es la puerta de entrada equivocada, y es la razón de que este ADR exista: la
petición vino del operador, no de los mantenedores.

## Opciones

### Opción A — Dejarlo en PowerShell y seguir endureciendo el arnés

El arnés ya corre bajo PowerShell 7 y bajo Windows PowerShell 5.1 en CI, y ejercita la gramática real
de `sc.exe`. Eso cierra los tres defectos de arriba y nada más. Todo script futuro vuelve a empezar
sin seguridad de tipos, la comprobación de deriva se queda, y la puerta de entrada sigue midiendo
siete nombres de archivo.

### Opción B — Mover todo, incluido el triage

Elimina 5.561 líneas de PowerShell y con ellas la comprobación de deriva. También elimina la
propiedad para la cual se construyó el triage: la tarde en que se encontró el compromiso, se pegó en
una ventana de RDP sobre un servidor que no tenía WPShield instalado y en el que no se confiaba lo
suficiente como para instalarlo. Un binario es una propuesta de confianza distinta en una máquina de
la que ya se sospecha.

### Opción C — Mover todo salvo el triage

`install`, `uninstall`, `preflight`, `publish` y el paso de IIS que todavía no existe pasan a ser
verbos de un único `wpshield.exe`. `Invoke-WPShieldTriage.ps1` se queda tal cual: un archivo ASCII,
sin dependencias, copiable por cualquier vía.

## Decisión

**Opción C.**

La línea divisoria es **cuándo corre la herramienta**, no qué hace:

| | Corre cuando | Forma |
| --- | --- | --- |
| `triage` | Antes de instalar nada, sobre un host que puede estar comprometido, con urgencia | **PowerShell**, sin cambios |
| `preflight` | Antes de instalar, deliberadamente | `wpshield.exe` |
| `install`, `uninstall` | Elevado, cambiando la máquina | `wpshield.exe`, dentro del artefacto que instala |
| `publish` | En una máquina de compilación con el SDK | `wpshield.exe` |
| `enable` (el paso de IIS) | Contra tráfico en vivo | `wpshield.exe`, y nace aquí |

### `System.CommandLine`, y ya es estable

`System.CommandLine 2.0.12` es un paquete de primera parte publicado, no el preview de siempre.
Aporta `--help`, opciones tipadas y validadas, subcomandos y códigos de salida — justo lo que este
proyecto ha venido escribiendo a mano en cada script.

### Un ensamblado aparte, y eso es forzado, no elegido

La CLI no puede vivir en `WPShield.Gateway`. `MultipartInspectionReaderTests.GatewayAssembly_ReferencesNoTypeThatCanWriteToDisk`
escanea las referencias de tipo de ese ensamblado buscando `File`, `FileStream`, `Directory` y
`StreamWriter`, y un instalador copia archivos para ganarse la vida. Ponerla ahí obligaría a relajar
la garantía de libertad de disco, y **una garantía relajada una vez es una garantía que se erosiona**
— el mismo razonamiento que ya puso a `WPShield.Logging` en su propio ensamblado.

Entonces: `src/WPShield.Cli`, produciendo `wpshield.exe`.

## Consecuencias

### Todo lo que aprendieron los scripts tiene que sobrevivir a la mudanza

Los scripts no son largos por casualidad; son largos porque cada uno carga con un defecto que ya
ocurrió. Nada de eso puede perderse en la traducción, y esta es la lista contra la que se comprueba
la migración:

- El instalador **se niega** a instalar dentro de un directorio que IIS sirve, antes de crear, copiar
  o registrar nada.
- **Escribe** en la configuración que el gateway lee la ruta de registros que endureció, porque
  endurecer un directorio en el que nadie escribe no endurece nada.
- Nombra el servicio por una constante, jamás por un literal, para que nunca pueda apuntarse a otro
  servicio en un host con sesenta y seis aplicaciones.
- No cambia **nada** de IIS como efecto secundario.
- Las notas finales no deben indicarle al operador que haga lo que la herramienta acaba de hacer.
- El `preflight` reporta ambos estados de todo lo que comprueba, porque la ausencia de un hallazgo no
  es un hallazgo.
- Todo verbo destructivo admite una pasada en seco, y esa pasada no requiere elevación.

### `--dry-run`, no `-WhatIf`

`SupportsShouldProcess` es un idioma de PowerShell. El comportamiento que da — previsualizar sin
cambiar — no lo es, y es obligatorio en todo verbo que cambie la máquina. Se escribe `--dry-run`.

### El artefacto lleva dos aplicaciones autocontenidas

`wpshield.exe` y `WPShield.Gateway.exe` se publican en un mismo directorio. Sus archivos de runtime
son idénticos, así que el directorio guarda una sola copia de cada uno y el archivo comprimido no se
duplica. Eso lo comprueba el verbo de publicación, no se da por sentado.

### CI sigue corriendo la suite de PowerShell

Hasta que desaparezca el último script, `Test-WPShieldScripts.ps1` sigue corriendo bajo PowerShell 7
y bajo Windows PowerShell 5.1. Cuando solo quede el triage, la mayor parte del arnés se va con los
scripts que vigilaba — y la comprobación de deriva se va la primera, porque la herramienta que
vigila será la única que todavía la necesite.

## Lo que este ADR no decide

- **Si el triage acaba mudándose también.** Una vez que WPShield está instalado en un host, el
  runtime de .NET ya está ahí y `wpshield triage` funcionaría. El caso de arranque en frío es un
  servidor donde WPShield aún no está instalado — un cliente nuevo, o un incidente. Mantener dos
  implementaciones reintroduciría exactamente la deriva que este ADR elimina, así que si el triage se
  muda alguna vez, el de PowerShell se borra en vez de conservarse al lado.
- **Si el paso de IIS se automatiza siquiera.** `AGENTS.md` dice que nunca se modifique IIS
  automáticamente. El verbo `enable` es donde esa restricción se revisa, en su propia decisión, y
  este ADR solo dice dónde viviría tal verbo.

## Cuándo revisar esta decisión

Revísela si la CLI alguna vez necesita correr donde PowerShell puede y ella no — un host sin forma de
recibir un binario, o un entorno donde un ejecutable sin firmar se rechaza y un script no. Esa es la
única condición bajo la cual la Opción C fue la división equivocada.

# CyberWatch Intel

Agregador inicial de fuentes públicas de ciberseguridad, vulnerabilidades e incidentes. Diseñado para publicarse en GitHub Pages y evolucionar hacia una plataforma de Cyber Threat Intelligence (CTI).

## Qué incluye

- Fuentes RSS/Atom configurables en `config/sources.json`.
- Catálogo CISA Known Exploited Vulnerabilities (KEV).
- Consulta de CVE recientes mediante la API de NVD.
- Normalización básica de URLs y títulos.
- Deduplicación conservadora por URL y título exacto normalizado.
- Panel web interactivo (`index.html`) con búsqueda, filtros, categorías, regiones y estado de fuentes.
- Wallboard automático (`wallboard.html`) para pantallas de sala de monitoreo: sin scroll, indicadores, alertas prioritarias persistentes, rotación de publicaciones y reloj.
- Actualización automática con GitHub Actions.
- Datos públicos guardados en `data/incidents.json`.

## Requisitos para ejecutar localmente

- Python 3.11 o posterior recomendado.
- Conexión a Internet.

```bash
python -m venv .venv
```

Activar el entorno:

**macOS / Linux**
```bash
source .venv/bin/activate
```

**Windows PowerShell**
```powershell
.venv\Scripts\Activate.ps1
```

Instalar dependencias y ejecutar:

```bash
pip install -r requirements.txt
python scripts/collect.py
```

Después, abre `index.html` para el panel interactivo o `wallboard.html` para la pantalla de monitoreo. Para evitar limitaciones del navegador al cargar JSON local, es mejor usar un servidor local sencillo:

```bash
python -m http.server 8000
```

Luego visita `http://localhost:8000` para el panel interactivo o `http://localhost:8000/wallboard.html` para el wallboard.

## Publicar en GitHub Pages

1. Crea un repositorio público llamado `cyberwatch-intel`.
2. Sube todos los archivos y carpetas de este proyecto conservando su estructura.
3. En GitHub, abre **Settings → Pages**.
4. En **Build and deployment**, elige **Deploy from a branch**.
5. Selecciona la rama `main` y la carpeta `/(root)`, luego guarda.
6. En **Settings → Actions → General**, confirma que el flujo de trabajo tenga permisos de lectura y escritura para el contenido del repositorio si la organización permite modificar esa opción.
7. Abre **Actions**, selecciona **Actualizar inteligencia pública** y ejecuta **Run workflow** para probar la primera recopilación.
8. Revisa los registros de ejecución y el archivo `data/incidents.json`.
9. Cuando Pages termine de publicar, usa la URL que aparece en **Settings → Pages**.
10. Para el panel interactivo, abre `https://TU-USUARIO.github.io/cyberwatch-intel/`. Para la pantalla de sala, abre `https://TU-USUARIO.github.io/cyberwatch-intel/wallboard.html`. Sustituye `TU-USUARIO` por tu usuario de GitHub.
11. En el equipo conectado a la pantalla, usa el navegador en pantalla completa. El botón ⛶ del wallboard activa pantalla completa; en algunos navegadores puede requerir una interacción inicial.

## Wallboard para sala de monitoreo

`wallboard.html` está diseñado para permanecer visible en una pantalla sin que una persona tenga que desplazarse por la página. Muestra indicadores generales, hasta tres alertas de prioridad alta, una publicación destacada que rota automáticamente cada 18 segundos, actividad reciente, hora local de Santiago y estado de las fuentes. Revisa si hay datos nuevos cada 60 segundos.

Las alertas se priorizan a partir de los campos disponibles (CISA KEV, severidad y CVSS). Esto es una regla orientativa, no una evaluación completa del riesgo ni una confirmación de que un sistema concreto esté comprometido. La ausencia de alertas visibles no significa ausencia de amenazas. Los enlaces abren las fuentes originales en otra pestaña.

El wallboard utiliza el mismo `data/incidents.json` que el panel interactivo. No requiere una base de datos ni servicios pagados adicionales. Si el navegador o la pantalla se reinician, configura el equipo para volver a abrir la URL del wallboard.

## API de NVD

La API pública de NVD puede utilizarse sin una clave, pero sus límites de solicitudes son menores. Si necesitas una clave, solicítala en el portal oficial de NVD y guárdala en:

**Settings → Secrets and variables → Actions → New repository secret**

- Nombre: `NVD_API_KEY`
- Valor: la clave que te entregue NVD

No guardes claves en el código, JSON, HTML ni en un repositorio público.

## Añadir fuentes

Edita `config/sources.json` y agrega un objeto a `rss_sources` con:

- `name`: nombre visible de la fuente.
- `url`: URL RSS/Atom.
- `category`: categoría.
- `region`: región.
- `sector`: sectores de interés.

Comprueba primero que el canal RSS esté disponible y respeta los términos de uso, límites de acceso y atribución del proveedor. No todas las páginas ofrecen RSS y algunas fuentes pueden fallar temporalmente.

## Qué significa la deduplicación en esta versión

Se agrupan publicaciones que tienen la misma URL normalizada o el mismo título normalizado. No se fusionan automáticamente títulos solo parecidos, porque podrían referirse a incidentes diferentes.

Las fichas CVE de NVD y CISA KEV pueden coexistir como registros relacionados. La siguiente fase puede incorporar una vista unificada por CVE, relaciones entre incidentes y agrupación semántica revisable.

## Arquitectura preparada para evolucionar

La separación entre componentes permite añadir más adelante:

- Un modelo de datos de incidentes separado de artículos fuente.
- Agrupación de incidentes por entidades, fecha, CVE y similitud.
- Relaciones con MITRE ATT&CK cuando las fuentes las documenten.
- Resúmenes con citas y enlaces a fuentes.
- Historial de cambios y alertas.
- Un backend o base de datos si los límites de archivos JSON dejan de ser suficientes.

## Limitaciones y buenas prácticas

- La recopilación es de información pública; no accede a inteligencia clasificada.
- El resultado no sustituye la verificación humana ni la respuesta a incidentes.
- Las afirmaciones de atribución pueden ser preliminares o disputadas.
- Los canales RSS, las APIs y las políticas pueden cambiar.
- GitHub Actions no garantiza que cada ejecución programada ocurra exactamente a la hora prevista.
- Los repositorios y sitios públicos son visibles por otras personas; nunca publiques credenciales, datos sensibles ni información interna.
- Los resúmenes del RSS pueden contener HTML; el panel los muestra como texto para reducir riesgos de inyección.
- La información pertenece a sus respectivas fuentes. Conserva la atribución y consulta las condiciones de reutilización.

## Fuentes configuradas inicialmente

- CISA Cybersecurity Advisories
- Cisco Talos
- Unit 42
- BleepingComputer
- NCSC UK
- CERT-EU
- NIST Cybersecurity Insights
- SANS Internet Storm Center
- CISA KEV
- NVD CVE API

Verifica disponibilidad y condiciones de uso antes de confiar en la continuidad de cualquier fuente.

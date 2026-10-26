# CyberWatch Intel

Agregador inicial de fuentes públicas de ciberseguridad, vulnerabilidades e incidentes. Diseñado para publicarse en GitHub Pages y evolucionar hacia una plataforma de Cyber Threat Intelligence (CTI).

## Qué incluye

- Fuentes RSS/Atom configurables en `config/sources.json`.
- Catálogo CISA Known Exploited Vulnerabilities (KEV).
- Consulta de CVE recientes mediante la API de NVD.
- Normalización básica de URLs y títulos.
- Deduplicación conservadora por URL y título exacto normalizado.
- Panel web interactivo (`index.html`) con búsqueda, filtros por tipo, categoría, región, fuente, prioridad estimada y antigüedad; incluye salud detallada de fuentes.
- Wallboard automático (`wallboard.html`) para pantallas de sala de monitoreo: sin scroll, indicadores, alertas prioritarias persistentes, rotación de publicaciones y reloj.
- Actualización automática con GitHub Actions.
- Indicadores de última revisión, estado por fuente, latencia, código HTTP y última publicación disponible.
- Puntaje heurístico de prioridad con motivos visibles; no representa probabilidad de ataque ni sustituye un análisis de riesgo.
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

Las alertas se priorizan con una heurística explicable que considera CISA KEV, severidad/CVSS y términos que pueden indicar explotación, ransomware, APT, zero-day o infraestructura crítica. El puntaje es orientativo, no representa probabilidad de ataque ni una evaluación completa del riesgo, y no confirma que un sistema concreto esté comprometido. La ausencia de alertas visibles no significa ausencia de amenazas. Los enlaces abren las fuentes originales en otra pestaña.

La tipografía del wallboard usa tamaños adaptables y un ajuste automático que reduce gradualmente el texto de los titulares y resúmenes cuando no cabe en el espacio disponible, manteniendo límites mínimos para proteger la legibilidad. El wallboard utiliza el mismo `data/incidents.json` que el panel interactivo. No requiere una base de datos ni servicios pagados adicionales. Si el navegador o la pantalla se reinician, configura el equipo para volver a abrir la URL del wallboard.

### Fuentes de ciberdefensa y tecnología incorporadas

La configuración incluye fuentes públicas de CISA, Cisco Talos, Unit 42, BleepingComputer, NCSC UK, CERT-EU, NIST, SANS ISC, C4ISRNET (Cyber y Space), EMAD, Zona Militar, Breaking Defense, The War Zone, CyberScoop, Google Cloud Threat Intelligence/Mandiant y SentinelLabs. También se agregaron canales RSS/Atom revisados para Cisco PSIRT y Security Blog, Check Point Research, Microsoft Security Blog, Google Project Zero, AWS Security Blog y Security Bulletins, Oracle Security, OpenAI News, NVIDIA Developer Blog — Cybersecurity y Meta Engineering/News Security.

Se omitieron los enlaces propuestos que devolvieron errores, redirigieron a páginas HTML en lugar de un feed, o ya estaban representados por una fuente existente. La verificación hecha desde el navegador confirma que varios endpoints responden con tipos de contenido RSS/Atom/XML; la comprobación final de que entreguen entradas válidas ocurre en el recopilador de GitHub Actions. Un feed puede cambiar o fallar temporalmente, por lo que el estado se registra en cada ejecución.

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

Comprueba primero que el canal RSS esté disponible y respeta los términos de uso, límites de acceso y atribución del proveedor. No todas las páginas ofrecen RSS y algunas fuentes pueden fallar temporalmente. El recopilador conserva la fecha de recolección de los registros sin cambios y evita reescribir `data/incidents.json` cuando no hay cambios sustantivos. Publica una marca de revisión cada dos horas para detectar datos potencialmente obsoletos sin generar commits cada 30 minutos.

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


### Fuentes de defensa y threat intelligence (versión v3)

Se añadieron feeds RSS de Breaking Defense, The War Zone (TWZ), CyberScoop, Google Cloud Threat Intelligence (Mandiant) y SentinelLabs. Las URL se contrastaron con respuestas RSS accesibles o directorios recientes de feeds; aun así, la disponibilidad puede cambiar y se valida nuevamente en cada ejecución del recopilador.

Se retiraron de `config/sources.json` las fuentes que reportaron errores: NATO CCDCOE, USCYBERCOM NetDefense, Defense One — Cyber y Cyber Defense Magazine.

El feed específico de informes del NCSC UK (`report-rss-feed.xml`) no se agregó porque aparece como inactivo; se conserva el feed general del NCSC que ya existía. La URL `https://cert.europa.eu/rss` no se agregó porque no se pudo confirmar su respuesta; se conserva la fuente CERT-EU que ya estaba configurada (`publications/security-advisories-rss`), sin duplicarla.

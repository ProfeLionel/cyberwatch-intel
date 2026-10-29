# Cambios de CyberWatch Intel

## v4.6 — Threatmap conectado a fuentes públicas
- El Threatmap deja el generador visual de demostración y consulta Cloudflare Radar, DShield/SANS ISC, ThreatFox y URLhaus.
- Se incorporan arcos agregados país-país de Cloudflare Layer 7, sin presentarlos como sesiones individuales.
- Se añaden marcadores para IP públicas observadas/IOC que obtengan geolocalización aproximada.
- Se incorpora IPWho.is con caché de 30 días y un máximo de 12 IP nuevas consultadas por ejecución.
- Nuevo recopilador independiente `scripts/collect_threatmap.py` y workflow horario `update-threatmap.yml`.
- Nuevo snapshot `data/threatmap.json`; no se alteran `data/incidents.json` ni `data/history.json`.
- Rediseño de `threatmap.html` con mapa central, capas y filtros, estadísticas, ranking regional, eventos recientes y estado/atribución de fuentes.
- Si una fuente falla, se conserva la última captura válida y se informa el estado.
- Se documentan límites, atribución y metodología de cada fuente.
- El panel Top regiones permite alternar entre IP únicas geolocalizadas, IOC de malware y URL de URLhaus, respetando el filtro regional.
- Los paneles de capas muestran la fecha de actualización de cada fuente; las rutas usan SVG para permitir su animación.


## v4.5 — Ajuste de distribución vertical del Threatmap
- Se redujeron espacios vacíos y se acercaron mapa y paneles al encabezado.
- Se mantuvo la altura de los indicadores superiores ajustada a su contenido.

## v4.4 — Ajuste de cuadros superiores
- Los indicadores pueden ocupar el ancho disponible con altura autoajustada al texto.

## v4.3 — CARTO Voyager
- Se incorporó el mapa base CARTO Voyager y se ajustó el encabezado de indicadores.

## v4.2 — Wallboard de mapa global (modo de demostración)
- Añadido `threatmap.html` con mapa mundial, clasificación por tipo, filtros y enlaces entre vistas.
- Esta etapa inicial utilizaba rutas visuales de demostración, sustituidas en v4.6 por datos públicos agregados y observados.

## v4.1 — Rotación de revisiones y actividad reciente
- Alertas prioritarias con recomendaciones de revisión y rotación.
- Actividad reciente con desplazamiento suave y pausa accesible.
- Se retiraron los feeds AWS Security Blog, AWS Security Bulletins y Oracle Security Blog, y se añadió Oracle Security Alerts.

## v4.0 — Mejoras de fuentes, prioridades e historial
- Incorporación de canales RSS/Atom adicionales.
- Filtros por fuente, prioridad y antigüedad.
- Indicador de frescura de datos, salud por fuente y prioridad heurística explicable.
- Historial diario de hasta 90 días para tendencias.
- Mejoras del wallboard y reducción de timeout HTTP del recopilador.

# CyberWatch Intel

Agregador de inteligencia pública de ciberseguridad, vulnerabilidades e incidentes. Diseñado para GitHub Pages y GitHub Actions.

## Qué incluye

- Fuentes RSS/Atom configurables en `config/sources.json`.
- Catálogo CISA Known Exploited Vulnerabilities (KEV) y CVE recientes mediante NVD.
- Deduplicación conservadora por URL normalizada y título exacto normalizado.
- Dashboard interactivo (`index.html`) con búsqueda, filtros, salud de fuentes e indicadores.
- Wallboard SOC (`wallboard.html`) con alertas prioritarias rotativas y actividad reciente con desplazamiento suave.
- Threatmap conectado (`threatmap.html`) con datos públicos de Cloudflare Radar, DShield, ThreatFox y URLhaus.
- Recopilación horaria independiente para el Threatmap mediante GitHub Actions.

## Threatmap global conectado — v4.6

El Threatmap separa las fuentes por tipo de evidencia para evitar presentar indicadores o estadísticas como ataques individuales confirmados:

| Capa | Fuente | Representación |
|---|---|---|
| Ataques geográficos L7 | Cloudflare Radar | Arcos entre países basados en pares y porcentajes agregados de ataques de capa 7 mitigados durante el periodo de consulta. |
| Actividad observada | DShield / SANS ISC | Marcadores de IP públicas incluidas en el feed Top 10 de sensores DShield. No es una lista confirmada de atacantes. |
| IOC de malware | ThreatFox | Indicadores recientes. Solo se dibujan IP públicas cuando se geolocalizan; hashes y dominios permanecen en el panel. |
| URL de malware | URLhaus | URL recientes de distribución de malware. Solo se dibujan hosts que sean IP públicas y puedan geolocalizarse. |
| Geolocalización | IPWho.is | País, región y coordenadas aproximadas de la IP. No identifica a una persona ni demuestra dónde está una víctima. |

Los arcos Cloudflare expresan relaciones agregadas país-país (no sesiones individuales ni números absolutos). Los marcadores DShield/ThreatFox/URLhaus son capas distintas y no se conectan artificialmente entre sí. La interfaz informa fuente, estado y última actualización.

### Secretos necesarios para el Threatmap

En GitHub, abre **Settings → Secrets and variables → Actions** y crea estos secretos si aún no existen:

- `CLOUDFLARE_RADAR_TOKEN`: token de Cloudflare con permiso de lectura de Radar.
- `ABUSECH_AUTH_KEY`: Auth-Key comunitaria de abuse.ch para ThreatFox y URLhaus.

Las claves se leen desde el workflow y no se guardan en HTML ni en JSON. DShield e IPWho.is no requieren un token para los usos incorporados aquí.

### Actualización y límites

- Workflow: `.github/workflows/update-threatmap.yml`.
- Programación: una vez por hora (minuto 23 UTC) y ejecución manual disponible.
- DShield: feed estático `top10.txt`, consultado como máximo una vez por hora.
- ThreatFox: IOC de los últimos 1 día; se conserva el recuento total y una muestra de hasta 250 indicadores para la vista.
- URLhaus: hasta 50 URL recientes por ejecución.
- IPWho.is: máximo de 12 consultas de IP nuevas por ejecución, caché de 30 días y máximo de 300 entradas para limitar consumo.
- Si una fuente falla, se conserva su última captura válida y el panel marca los datos como anteriores/error. GitHub Actions puede retrasar ejecuciones programadas.

Los datos se guardan en `data/threatmap.json`, separado de `data/incidents.json` y `data/history.json`. Esto evita alterar el dashboard y su histórico actual.

### Atribución y condiciones de uso

- Cloudflare Radar: mostrar atribución a Cloudflare Radar y respetar CC BY-NC 4.0. Esta integración está preparada para el uso personal, educativo y demostrativo no comercial declarado para el proyecto.
- DShield: atribuir a SANS Technology Institute, Internet Storm Center, `https://isc.sans.edu`. No revender los datos ni descargar feeds estáticos más de una vez por hora.
- ThreatFox y URLhaus: uso comunitario sujeto a fair use y condiciones de abuse.ch.
- IPWho.is: endpoint gratuito sin clave, con límite documentado de 1.000 solicitudes diarias por IP cliente.
- CARTO y OpenStreetMap: se conserva la atribución visible en el mapa.

Consulta `docs/THREATMAP-FUENTES-Y-DATOS.md` para metodología, condiciones, estructura y limitaciones.

## Publicar en GitHub Pages

1. Copia los archivos del paquete conservando sus rutas dentro de la raíz del repositorio.
2. No reemplaces `data/incidents.json` ni `data/history.json`.
3. Comprueba que los secretos `CLOUDFLARE_RADAR_TOKEN` y `ABUSECH_AUTH_KEY` existen en GitHub Actions.
4. En GitHub, abre **Actions → Actualizar datos del Threatmap → Run workflow** para la primera ejecución manual.
5. Revisa los registros y comprueba que se genere/actualice `data/threatmap.json`.
6. Cuando GitHub Pages publique el cambio, abre `https://TU-USUARIO.github.io/cyberwatch-intel/threatmap.html`.

El dashboard y wallboard SOC existentes continúan usando `data/incidents.json`; el nuevo Threatmap consume `data/threatmap.json`.

## Requisitos para ejecutar localmente

- Python 3.11 o posterior recomendado.
- Conexión a Internet.
- `requests` para el recopilador del Threatmap; el colector principal mantiene las dependencias de `requirements.txt`.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m http.server 8000
```

Para probar el Threatmap localmente, configura en el entorno `CLOUDFLARE_RADAR_TOKEN` y `ABUSECH_AUTH_KEY`, ejecuta `python scripts/collect_threatmap.py` y abre `http://localhost:8000/threatmap.html`.

## Wallboard SOC

`wallboard.html` presenta alertas prioritarias y actividad reciente utilizando los registros del recopilador principal. Su puntuación es heurística y orientativa; no representa probabilidad de ataque ni confirma que un sistema esté comprometido.

## Fuentes RSS y ciberseguridad

La configuración existente incluye fuentes públicas de CISA, Cisco Talos, Unit 42, BleepingComputer, NCSC UK, CERT-EU, NIST, SANS ISC, C4ISRNET, EMAD, Zona Militar, Breaking Defense, The War Zone, CyberScoop, Google Cloud Threat Intelligence/Mandiant, SentinelLabs, Cisco PSIRT, Check Point Research, Microsoft Security Blog, Google Project Zero, Oracle Security Alerts, OpenAI News, NVIDIA Developer Blog y Meta Engineering/News Security, entre otras. La disponibilidad de cada feed puede cambiar y se valida en cada ejecución.

## Deduplicación

Se agrupan publicaciones que tienen la misma URL normalizada o el mismo título normalizado. No se fusionan automáticamente títulos solo parecidos, porque podrían referirse a incidentes diferentes. Las fichas CVE de NVD y CISA KEV pueden coexistir como registros relacionados.

## Limitaciones y buenas prácticas

- La recopilación utiliza información pública y no accede a inteligencia clasificada.
- La geolocalización IP es aproximada; no identifica personas ni atribuye autoría.
- Los arcos Cloudflare son datos agregados y no prueban una conexión individual.
- Los feeds/API y sus políticas pueden cambiar; verifica condiciones de uso y atribución.
- El resultado no sustituye la verificación humana ni la respuesta a incidentes.
- Nunca publiques credenciales ni datos sensibles. Los repositorios públicos son visibles por terceros.
- GitHub Actions no garantiza que cada ejecución ocurra exactamente a la hora prevista.

## Referencias oficiales

- [Cloudflare Radar API](https://developers.cloudflare.com/radar/)
- [DShield feeds](https://www.dshield.org/feeds_doc.html)
- [ThreatFox Community API](https://threatfox.abuse.ch/api/)
- [URLhaus Community API](https://urlhaus.abuse.ch/api/)
- [IPWho.is API](https://ipwhois.io/documentation)

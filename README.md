# RADAR

Agregador local de inteligencia pública de ciberseguridad, vulnerabilidades e incidentes. Se puede abrir desde un servidor web local; GitHub no es necesario para ejecutarlo.

## Qué incluye

- Fuentes RSS/Atom configurables en `config/sources.json`.
- Catálogo CISA Known Exploited Vulnerabilities (KEV) y CVE recientes mediante NVD.
- Puntuación EPSS de FIRST para CVE cuando la API está disponible; se conserva y marca el último valor si falla la consulta.
- Deduplicación conservadora por URL normalizada y título exacto normalizado.
- Dashboard interactivo (`index.html`) con búsqueda, filtros, salud de fuentes e indicadores.
- Dashboard con carga progresiva por scroll infinito y sin controles de paginación.
- Wallboard SOC (`wallboard.html`) con alertas prioritarias rotativas, navegación manual por flechas y actividad reciente con desplazamiento suave.
- Favicon compartido por las tres pantallas principales.
- Threatmap conectado (`threatmap.html`) con datos públicos de Cloudflare Radar, DShield, ThreatFox y URLhaus.
- Recopiladores Python ejecutables manualmente desde el equipo local.

## Threatmap global conectado — v4.6

El Threatmap separa las fuentes por tipo de evidencia para evitar presentar indicadores o estadísticas como ataques individuales confirmados:

| Capa | Fuente | Representación |
|---|---|---|
| Pares geográficos L7 | Cloudflare Radar | Arcos entre centroides de países basados en pares y porcentajes agregados de ataques de capa 7 mitigados durante el periodo de consulta. La ubicación del país de destino se basa en la ubicación de facturación de la zona protegida; no identifica un servidor o víctima concretos. |
| Actividad observada | DShield / SANS ISC | Marcadores de IP públicas incluidas en el feed Top 10 de sensores DShield. No es una lista confirmada de atacantes. |
| IOC de malware | ThreatFox | Indicadores recientes. Solo se dibujan IP públicas cuando se geolocalizan; hashes y dominios permanecen en el panel. |
| URL de malware | URLhaus | URL recientes de distribución de malware. Solo se dibujan hosts que sean IP públicas y puedan geolocalizarse. |
| Geolocalización | IPWho.is | País, región y coordenadas aproximadas de la IP. No identifica a una persona ni demuestra dónde está una víctima. |

Los arcos Cloudflare expresan relaciones agregadas país-país (no sesiones individuales ni números absolutos). La ubicación representada usa centroides y la ubicación de destino de Cloudflare puede corresponder a facturación de la zona protegida, no a un servidor. Los marcadores DShield/ThreatFox/URLhaus son capas distintas y no se conectan artificialmente entre sí. La interfaz informa fuente, estado y última actualización. [Metodología de Cloudflare Radar](https://developers.cloudflare.com/radar/investigate/application-layer-attacks/).

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
- NVD pagina todas las respuestas disponibles del periodo configurado; si no puede completar la paginación informa el resultado parcial.
- El colector principal conserva el snapshot si fallan todas las fuentes. La vista identifica publicaciones retenidas de fuentes que fallaron.

Los datos se guardan en `data/threatmap.json`, separado de `data/incidents.json` y `data/history.json`. Esto evita alterar el dashboard y su histórico actual.

### Atribución y condiciones de uso

- Cloudflare Radar: mostrar atribución a Cloudflare Radar y respetar CC BY-NC 4.0. Esta integración está preparada para el uso personal, educativo y demostrativo no comercial declarado para el proyecto.
- DShield: atribuir a SANS Technology Institute, Internet Storm Center, `https://isc.sans.edu`. No revender los datos ni descargar feeds estáticos más de una vez por hora.
- ThreatFox y URLhaus: uso comunitario sujeto a fair use y condiciones de abuse.ch.
- IPWho.is: endpoint gratuito sin clave, con límite documentado de 1.000 solicitudes diarias por IP cliente.
- Dependabot revisa semanalmente las dependencias Python y GitHub Actions; las actualizaciones deben revisarse antes de integrarse.
- CARTO y OpenStreetMap: se conserva la atribución visible en el mapa.
- El identificador de mapa CARTO incluido en el HTML es público por diseño; restringe su uso al dominio del sitio y configura límites en el proveedor si el plan lo permite.

La metodología, condiciones, estructura y limitaciones de cada fuente se resumen en esta sección y en el aviso visible del mapa.

## Ejecutar RADAR en un servidor web local

- Python 3.11 o posterior recomendado.
- Conexión a Internet.
- Para consultar feeds con los recopiladores, instala las dependencias de `requirements.txt`.
- El servidor web usa solo la biblioteca estándar de Python.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 run_local.py
```

Abre las direcciones que imprime el servidor: dashboard en `http://127.0.0.1:8000/`, Wallboard SOC en `/wallboard.html` y Threatmap en `/threatmap.html`. Mantén la terminal abierta mientras lo usas y presiona `Ctrl+C` para detener el servidor. Si el puerto está ocupado, usa `python run_local.py --port 8080`.

El sitio lee sus capturas locales desde `data/incidents.json`, `data/history.json` y `data/threatmap.json`. Para actualizar datos, en otra terminal activa el mismo entorno virtual y ejecuta el recopilador correspondiente:

```bash
python3 scripts/collect.py
python3 scripts/collect_threatmap.py
```

Los recopiladores consultan fuentes externas y guardan resultados en `data/`. El Threatmap puede usar `CLOUDFLARE_RADAR_TOKEN` y `ABUSECH_AUTH_KEY` definidas como variables de entorno locales; nunca pegues sus valores en archivos del proyecto. Si no configuras esas claves, se mantienen los datos existentes y las fuentes que las requieren se mostrarán sin actualización. La ejecución local no necesita GitHub Pages ni GitHub Actions.

Los workflows de `.github/workflows/` se conservan en el repositorio para su uso independiente, pero no se ejecutan al iniciar RADAR localmente.

## Wallboard SOC

`wallboard.html` presenta alertas prioritarias y actividad reciente utilizando los registros del recopilador principal. Su puntuación es heurística y orientativa; no representa probabilidad de ataque ni confirma que un sistema esté comprometido. La rotación se puede pausar o avanzar manualmente y respeta la preferencia del navegador por movimiento reducido.

## Fuentes RSS y ciberseguridad

La configuración existente incluye fuentes públicas de CISA, Cisco Talos, Unit 42, BleepingComputer, The Hacker News, NCSC UK, CERT-EU, NIST, SANS ISC, C4ISRNET, EMAD, Zona Militar, Breaking Defense, The War Zone, CyberScoop, Google Cloud Threat Intelligence/Mandiant, SentinelLabs, Cisco PSIRT, Check Point Research, Microsoft Security Blog, Google Project Zero, Oracle Security Alerts, OpenAI News, NVIDIA Developer Blog y Meta Engineering/News Security, entre otras. La disponibilidad de cada feed puede cambiar y se valida en cada ejecución.

CVE.org no publica actualmente un RSS oficial para los registros CVE. El colector ya consulta el API oficial de NVD, que mantiene sincronización con la CVE List; [NVD indica](https://nvd.nist.gov/general/FAQ-Sections/CVE-FAQs) que las actualizaciones del CVE List se reflejan en su sitio y API dentro de 24 horas. La [página histórica de feeds de CVE](https://www.cve.org/Resources/Media/Archives/OldWebsite/cve/data_feeds.html) dirige a NVD y la [propuesta de crear un RSS propio de CVE](https://github.com/CVEProject/Ideas/issues/7) sigue pendiente.

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
- [FIRST EPSS API y metodología](https://www.first.org/epss/)
- [DShield feeds](https://www.dshield.org/feeds_doc.html)
- [ThreatFox Community API](https://threatfox.abuse.ch/api/)
- [URLhaus Community API](https://urlhaus.abuse.ch/api/)
- [IPWho.is API](https://ipwhois.io/documentation)

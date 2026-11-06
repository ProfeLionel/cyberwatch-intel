# AGENTS.md — instrucciones para agentes de código

## Proyecto
RADAR: dashboard de inteligencia, wallboard SOC y Threatmap público alojado en GitHub Pages y automatizado con GitHub Actions.
Lee `CODEX_HANDOFF.md` para contexto funcional, técnico, fuentes, validaciones y decisiones históricas.

## Reglas obligatorias

1. Responde en español salvo que el usuario solicite otro idioma.
2. El usuario ha indicado que las consultas son solo consultas: **no diseñar ni programar hasta que lo pida explícitamente**. Si solicita una evaluación, explicación o recomendación, no modifiques archivos.
3. Antes de cualquier cambio, inspecciona el estado real del repositorio, rama, commits, archivos y workflows. No asumas que un ZIP o patch anterior fue instalado.
4. No sobrescribas ni elimines `data/incidents.json`, `data/history.json` ni snapshots de producción sin autorización explícita y una copia de seguridad acordada.
5. Mantén el recopilador principal y el recopilador Threatmap separados salvo que el usuario solicite expresamente una refactorización.
6. Nunca hardcodees ni imprimas secretos. Usa `CLOUDFLARE_RADAR_TOKEN` y `ABUSECH_AUTH_KEY` desde GitHub Actions Secrets. No incluyas valores secretos en commits, logs, documentación ni HTML.
7. No hagas push, commits, releases, despliegues ni cambios remotos sin autorización explícita.
8. Verifica documentación oficial y condiciones de uso actuales antes de cambiar integraciones o endpoints.
9. Respeta licencias, atribuciones, límites de consulta y reglas de distribución. Cloudflare Radar está documentado bajo CC BY-NC 4.0 en el uso aquí considerado; el propósito del usuario es personal/educativo/demostrativo no comercial.
10. No presentes como «ataques en tiempo real» datos que son estadísticas agregadas, IOC, escaneos de sensores o indicadores históricos. Etiqueta claramente la naturaleza, fuente y fecha de cada dato.
11. No dibujes arcos origen-destino si una fuente no entrega ambos extremos. La geolocalización IP es aproximada y no identifica personas, atacantes ni víctimas.
12. No elimines artículos por similitud semántica sin un diseño que conserve fuentes y contexto. Agrupa incidentes y preserva evidencia/trazabilidad.
13. Si una fuente falla, conserva la última captura válida cuando proceda e informa claramente que los datos están desactualizados.
14. Evita cambios visuales no solicitados en dashboard y wallboard al trabajar en Threatmap.
15. Ejecuta validaciones de Python, JavaScript, JSON, workflow y ZIP pertinentes; informa exactamente qué se pudo y qué no se pudo verificar.

## Datos y arquitectura conocidos

- `data/incidents.json`: datos del recopilador principal; preservar.
- `data/history.json`: snapshots diarios del dashboard; preservar.
- `data/threatmap.json`: snapshot de las fuentes geográficas/IOC del mapa.
- `scripts/collect.py`: colector principal RSS/CISA/NVD.
- `scripts/collect_threatmap.py`: colector separado para Cloudflare, DShield, ThreatFox, URLhaus y GeoIP (si v4.6 está instalado).
- `.github/workflows/update-intelligence.yml`: workflow del colector principal.
- `.github/workflows/update-threatmap.yml`: workflow horario del Threatmap (v4.6), cron `23 * * * *` UTC y ejecución manual.
- `index.html`: dashboard.
- `wallboard.html`: Wallboard SOC.
- `threatmap.html`: mapa.

## Semántica de las fuentes del Threatmap

- Cloudflare Radar: pares geográficos agregados de ataques Layer 7 mitigados; no son sesiones individuales ni una visión completa de Internet.
- DShield: IP observadas por sensores; no es lista confirmada de atacantes ni aporta siempre destino.
- ThreatFox: IOC relacionados con malware; un IOC no demuestra ataque en curso.
- URLhaus: URL de distribución de malware; `online` no implica víctima o ataque activo.
- IPWho.is: geolocalización aproximada de IP pública, sin atribución de identidad.

## Futuras tareas aún no implementadas

- Pantalla «Chile» basada en API MISP del CSIRT Nacional: `https://apimisp.csirt.gob.cl/docs`. Usuario aún no ha obtenido token ni confirmado permisos de redistribución. No integrar hasta validar acceso, autenticación, scopes, TLP y autorización para dashboard público.
- Traducción de publicaciones al español: idea en evaluación; conservar siempre original y CVE/hash/IP/URL sin traducir.
- Mejor deduplicación/correlación semántica: agrupar incidentes relacionados sin eliminar publicaciones complementarias.

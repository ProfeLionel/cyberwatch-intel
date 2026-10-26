# Cambios de CyberWatch Intel — versión mejorada

- Incorporación de 13 canales RSS/Atom adicionales verificados por respuesta con tipo de contenido RSS/Atom/XML.
- Exclusión de URLs propuestas que devolvieron 404/403/410/502, redirigieron a páginas HTML o duplicaban feeds existentes.
- Filtros del panel interactivo por fuente, prioridad estimada y antigüedad, además de los filtros previos.
- Indicador de frescura de datos y lista detallada de salud por fuente.
- Priorización heurística explicable basada en CISA KEV, CVSS/severidad y señales textuales; no equivale a probabilidad de ataque.
- Historial diario de hasta 90 días para tendencias de publicaciones, KEV, CVE y alertas prioritarias.
- Wallboard con tipografía base más grande, ajuste automático de texto y advertencia de datos potencialmente desactualizados.
- Marca de revisión cada dos horas para reducir commits de mantenimiento.
- Timeout HTTP reducido a 15 segundos para que el recopilador pueda procesar un mayor número de fuentes dentro del tiempo límite de GitHub Actions.

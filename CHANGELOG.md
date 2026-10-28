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

## v4.1 — Rotación de revisiones y actividad reciente

- Alertas prioritarias: muestran hasta tres recomendaciones de revisión por página y rotan cada 18 segundos cuando existen más de tres alertas de prioridad alta. El contador indica el tramo visible.
- Cada alerta incluye una sugerencia inicial de revisión según señales como CISA KEV, severidad, CVSS o CVE. Es orientación heurística, no un diagnóstico de exposición.
- Actividad reciente: presenta hasta 15 publicaciones y se desplaza automáticamente a 8 px/s; el movimiento se pausa al pasar el puntero o dar foco al panel y se desactiva cuando el sistema solicita movimiento reducido.
- Fuentes: se retiraron AWS Security Blog, AWS Security Bulletins y Oracle Security Blog. Se añadió Oracle Security Alerts con el feed proporcionado por el mantenedor. La URL respondió como XML al comprobarla desde el navegador y figura como activa en un directorio de feeds consultado; la validación real de entradas se confirma en el siguiente ciclo de GitHub Actions.

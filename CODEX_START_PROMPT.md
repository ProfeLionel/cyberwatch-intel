# Prompt inicial para Codex

Copia el texto siguiente en Codex después de abrir el repositorio `ProfeLionel/cyberwatch-intel` (o el clon local correspondiente):

---

Vas a continuar el proyecto **RADAR**. Antes de actuar, lee completos los archivos `AGENTS.md` y `CODEX_HANDOFF.md`.

Tu primera tarea es exclusivamente de inspección y diagnóstico. **No edites archivos, no crees archivos, no ejecutes commits, no hagas push, no alteres GitHub Actions, no publiques despliegues y no cambies secretos.**

1. Inspecciona la rama actual, los últimos commits y el árbol completo del repositorio.
2. Determina si la integración Threatmap v4.6 está instalada comparando estos archivos y sus contenidos:
   - `threatmap.html`
   - `scripts/collect_threatmap.py`
   - `.github/workflows/update-threatmap.yml`
   - `data/threatmap.json`
   - `docs/THREATMAP-FUENTES-Y-DATOS.md`
   - `INSTRUCCIONES-INSTALACION.md`
3. Comprueba si existen sin leer sus valores los nombres de los secretos `CLOUDFLARE_RADAR_TOKEN` y `ABUSECH_AUTH_KEY`, si tu integración/entorno permite consultar únicamente su presencia. Nunca imprimas valores.
4. Identifica cualquier diferencia entre el estado real del repositorio y el contexto documentado. Señala especialmente si el patch v4.6 parece pendiente, parcial o ya instalado.
5. Comprueba si `data/incidents.json` y `data/history.json` existen y advierte que deben preservarse.
6. Revisa los workflows y apunta posibles riesgos de concurrencia o permisos, pero no los cambies.
7. Devuelve un informe en español con: estado actual, archivos presentes, diferencias, riesgos, próximos pasos recomendados y pruebas que habría que realizar.

No implementes ninguna mejora en esta primera fase. Espera una instrucción explícita del usuario antes de modificar el proyecto.

---

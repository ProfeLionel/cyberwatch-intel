# Paquete de traspaso RADAR para Codex

Este paquete contiene documentación de contexto, no el código fuente del proyecto ni una copia del repositorio.

## Archivos

- `CODEX_HANDOFF.md`: resumen amplio del historial de decisiones, arquitectura, estado de v4.6, fuentes, pruebas, licencias, seguridad y próximos pasos.
- `AGENTS.md`: instrucciones persistentes que Codex debe seguir al trabajar dentro del repositorio.
- `CODEX_START_PROMPT.md`: prompt inicial para que Codex inspeccione el proyecto sin modificarlo.

## Cómo usarlo

1. Descarga y descomprime este paquete.
2. Abre Codex y conecta/abre el repositorio `ProfeLionel/cyberwatch-intel` o un clon local actualizado.
3. Copia `CODEX_HANDOFF.md`, `AGENTS.md` y `CODEX_START_PROMPT.md` a la raíz del repositorio. Si ya existe un `AGENTS.md`, revisa y combina sus reglas en lugar de reemplazarlo sin leerlo.
4. Inicia Codex con el contenido de `CODEX_START_PROMPT.md`.
5. La primera tarea será solo un diagnóstico de lectura. No autorices cambios hasta revisar el informe.

## Importante

ChatGPT no puede transferir literalmente el historial completo de conversación a Codex. Este paquete transfiere el contexto de trabajo y las decisiones técnicas relevantes. Codex debe verificar la situación actual del repositorio, porque la versión v4.6 se preparó como un patch y puede que todavía no esté instalada en GitHub.

Nunca pegues API keys o tokens en estos archivos. El usuario confirmó que los nombres de secretos configurados son `CLOUDFLARE_RADAR_TOKEN` y `ABUSECH_AUTH_KEY`, pero sus valores no se han copiado aquí.

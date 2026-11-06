# RADAR — traspaso de contexto para Codex

- **Fecha de preparación:** 29 de octubre de 2026
- **Repositorio:** https://github.com/ProfeLionel/cyberwatch-intel
- **GitHub Pages:** https://profelionel.github.io/cyberwatch-intel/
- **Dashboard:** https://profelionel.github.io/cyberwatch-intel/
- **Wallboard SOC:** https://profelionel.github.io/cyberwatch-intel/wallboard.html
- **Threatmap:** https://profelionel.github.io/cyberwatch-intel/threatmap.html

> Este documento resume el contexto de trabajo y las decisiones técnicas que se han establecido en una conversación larga con ChatGPT. No es una exportación literal del historial de chat. Codex debe inspeccionar el estado real del repositorio antes de asumir que todos los paquetes o cambios mencionados aquí ya están publicados en GitHub.

---

## 1. Instrucción principal para Codex

El usuario quiere continuar el desarrollo de RADAR con Codex, transfiriendo el contexto acumulado. Al iniciar el trabajo:

1. Inspecciona primero el repositorio real, la rama activa, el árbol de archivos y los últimos commits.
2. Compara el estado real con esta nota y determina qué partes de la versión v4.6 ya están instaladas. La v4.6 fue preparada como paquete incremental, pero ChatGPT no publicó directamente esos cambios en GitHub.
3. No reemplaces archivos existentes ni borres datos históricos sin autorización expresa.
4. No modifiques ni programes nada cuando el usuario formule una consulta o pida una evaluación. El usuario ha indicado expresamente: **«No debes desarrollar nada a menos que te lo diga»**. Solo implementa cuando lo solicite explícitamente.
5. No hagas push, despliegues, cambios en GitHub Actions o cambios destructivos sin autorización explícita.
6. Nunca solicites, imprimas, registres ni incluyas en commits los valores de API keys, tokens o secretos. Usa GitHub Actions Secrets y variables de entorno.
7. Distingue siempre datos observados, estadísticas agregadas, indicadores de compromiso (IOC), inferencias y datos de demostración. No presentes un IOC como un ataque en curso ni inventes vínculos origen-destino.
8. Antes de implementar una API nueva, consulta su documentación oficial vigente, revisa autenticación, límites, licencias, atribución y permisos de redistribución.
9. Cuando termines una tarea, informa archivos modificados, pruebas ejecutadas, resultados, limitaciones y pasos manuales pendientes.

El usuario conversa en español y prefiere instrucciones claras, paso a paso, orientadas al repositorio GitHub existente. No necesita explicaciones innecesariamente complejas.

---

## 2. Objetivo del proyecto

**RADAR** es un agregador público de inteligencia de ciberseguridad, vulnerabilidades e incidentes, publicado mediante GitHub Pages y automatizado con GitHub Actions.

El proyecto tiene tres vistas principales:

- **Dashboard de inteligencia (`index.html`):** publicaciones de fuentes RSS/Atom, CVE/NVD, CISA KEV, filtros, estado de fuentes e información histórica.
- **Wallboard SOC (`wallboard.html`):** alertas prioritarias, recomendaciones de revisión y actividad reciente con desplazamiento automático.
- **Threatmap (`threatmap.html`):** mapa mundial con capas de inteligencia pública. La evolución prevista incluye una pantalla nacional de Chile basada en la API MISP del CSIRT, aún pendiente de autorización y validación.

El usuario definió el propósito como personal, educativo y demostrativo, sin fines comerciales. La cobertura del Threatmap debe ser mundial, con énfasis visual en Chile y Latinoamérica.

---

## 3. Historial funcional y decisiones de diseño

### Dashboard y recopilador principal

- Proyecto inicialmente construido con HTML estático, un recopilador Python y GitHub Actions.
- Estructura original conocida:

```text
cyberwatch-intel/
├── index.html
├── wallboard.html
├── README.md
├── requirements.txt
├── config/sources.json
├── scripts/collect.py
├── data/incidents.json
└── .github/workflows/update-intelligence.yml
```

- `scripts/collect.py` recopila fuentes RSS/Atom, CISA KEV y NVD.
- `data/incidents.json` contiene los incidentes/publicaciones recolectados. **No sobrescribirlo con una plantilla vacía ni eliminarlo.**
- La deduplicación principal es conservadora: URL normalizada y título normalizado con coincidencia exacta. No hace deduplicación semántica general de titulares parecidos.
- No eliminar automáticamente publicaciones con un mismo CVE: pueden aportar análisis, mitigaciones o información complementaria. Es preferible agruparlas por incidente/CVE y conservar la procedencia y los enlaces originales.
- El histórico del dashboard usa `data/history.json`, con capturas diarias. El gráfico de tendencias refleja snapshots del inventario almacenado, no un conteo puro de ataques ni necesariamente publicaciones nuevas del día.
- La puntuación de prioridad del recopilador es heurística y orientativa; no representa probabilidad matemática de ataque ni confirma compromiso.

### Wallboard SOC

- El panel «Alertas Prioritarias» rota automáticamente páginas de alertas cuando hay más resultados que los mostrados.
- Incluye recomendaciones de revisión orientativas por alerta.
- «Actividad Reciente» utiliza desplazamiento suave y continuo, configurable para facilitar la lectura, y contempla pausa/foco y preferencias de movimiento reducido.
- Mantener advertencias de datos antiguos cuando la última ejecución sea demasiado antigua.

### Evolución del Threatmap

- **v4.2:** primera pantalla de mapa mundial, con rutas demostrativas. El modo DEMO estaba explícitamente etiquetado; esas rutas no representaban ataques reales.
- **v4.3:** uso de CARTO Voyager Raster como mapa base; clave de CARTO visible en el HTML por ser GitHub Pages.
- **v4.4:** cuadros/indicadores superiores a ancho completo, con altura ajustada al texto.
- **v4.5:** reducción de espacios verticales innecesarios para acercar el mapa y los paneles a los indicadores.
- **v4.6:** propuesta de conexión a fuentes reales: Cloudflare Radar, DShield, ThreatFox y URLhaus, con datos normalizados en un JSON separado.

La versión v4.6 se entregó como paquete incremental `cyberwatch-intel-v4.6-real-threatmap-patch.zip`. No asumir que ya está en la rama principal; comprobarlo en GitHub. El paquete incluyó:

```text
threatmap.html
scripts/collect_threatmap.py
.github/workflows/update-threatmap.yml
data/threatmap.json
README.md
CHANGELOG.md
docs/THREATMAP-FUENTES-Y-DATOS.md
INSTRUCCIONES-INSTALACION.md
```

La instrucción de instalación de v4.6 indica no reemplazar estos archivos existentes del proyecto:

- `data/incidents.json`
- `data/history.json`
- `scripts/collect.py`
- `config/sources.json`
- `index.html`
- `wallboard.html`

El recopilador del Threatmap fue separado del recopilador RSS principal para evitar interferencias.

---

## 4. Estado técnico conocido de Threatmap v4.6

### Archivos y responsabilidades

- `threatmap.html`: interfaz del mapa, panel de capas, filtros, estadísticas, ranking, últimos eventos y atribución de fuentes.
- `scripts/collect_threatmap.py`: recopilador específico para fuentes del mapa y enriquecimiento GeoIP.
- `.github/workflows/update-threatmap.yml`: automatización horaria y ejecución manual.
- `data/threatmap.json`: snapshot independiente de los datos del mapa.
- `docs/THREATMAP-FUENTES-Y-DATOS.md`: metodología, límites y atribuciones.

### Flujo del workflow

- Workflow: `Actualizar datos del Threatmap`.
- Disparadores: `workflow_dispatch` y `schedule`.
- Cron de v4.6: `23 * * * *` (una vez por hora, minuto 23 UTC; GitHub puede retrasar la ejecución).
- Python 3.12.
- Dependencia fijada: `requests==2.32.5`.
- Permiso `contents: write` para actualizar `data/threatmap.json`.
- El workflow usa commit de `github-actions[bot]` y rebase/reintentos para evitar perder actualizaciones concurrentes.

### Secretos ya configurados por el usuario en GitHub

El usuario confirmó que estos secretos ya existen en **Settings → Secrets and variables → Actions**:

- `CLOUDFLARE_RADAR_TOKEN`
- `ABUSECH_AUTH_KEY`

No se conocen ni deben solicitarse sus valores. Si se necesita validar su presencia, revisar solo nombres de secretos o ejecutar el workflow sin exponer contenido.

### Fuentes, consultas y significado correcto

#### Cloudflare Radar

- Endpoint utilizado por v4.6:
  `https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/attacks?limit=20&dateRange=1d&format=json`
- Autenticación: `Authorization: Bearer $CLOUDFLARE_RADAR_TOKEN`.
- La respuesta incluye pares de países y porcentajes/valores agregados de ataques de capa 7 mitigados observados por Cloudflare.
- En el mapa: arcos entre centroides aproximados de países a partir de los pares agregados.
- **No** son sesiones individuales, cantidades absolutas ni una visión completa de Internet. No atribuir autoría ni afirmar que un equipo de un país fue víctima.
- El usuario probó la API desde su Mac: `success=True`, `errors=[]`, 5 pares recibidos. `lastUpdated` observado: `2026-10-28T23:30:00Z`. Ejemplos de pares: United States → United States, Netherlands → United States, China → United States.
- Para uso no comercial declarado por el usuario, respetar atribución y licencia **CC BY-NC 4.0**. Si cambia el propósito a comercial, revisar la licencia antes de continuar.

#### DShield / SANS Internet Storm Center

- Feed utilizado: `https://feeds.dshield.org/feeds/top10.txt`.
- Sin API key para el feed público usado.
- El usuario probó el feed: HTTP 200, 15 líneas recibidas, con direcciones IP en el contenido.
- La implementación v4.6 conserva hasta 10 IP públicas y únicas.
- Es actividad reportada por sensores; no una lista confirmada de atacantes ni una relación origen-destino. No inventar destino geográfico.
- No descargar feeds estáticos más de una vez por hora y respetar atribución a SANS Technology Institute / Internet Storm Center. No revender los datos.

#### ThreatFox (abuse.ch)

- Endpoint: `https://threatfox-api.abuse.ch/api/v1/`.
- Método: POST.
- Header: `Auth-Key: $ABUSECH_AUTH_KEY`.
- Cuerpo: `query=get_iocs`, `days=1`.
- La prueba del usuario devolvió `query_status=ok`, 2.092 indicadores. Los ejemplos incluían `sha256_hash`, categoría `payload` y malware `Mirai`.
- v4.6 conserva una muestra de hasta 250 IOC en el JSON, junto con el recuento total devuelto.
- Solo IP públicas que puedan geolocalizarse podrían convertirse en marcadores; hashes y dominios permanecen en paneles/listados.
- Un IOC no demuestra que haya un ataque activo ni proporciona automáticamente país de origen y destino.
- Uso de API comunitaria sujeto a fair use/condiciones de abuse.ch.

#### URLhaus (abuse.ch)

- Endpoint correcto empleado en v4.6:
  `https://urlhaus-api.abuse.ch/v1/urls/recent/limit/50/`
- Método: GET.
- Header: `Auth-Key: $ABUSECH_AUTH_KEY`.
- Importante: la primera prueba falló con HTTP 405 porque se probó POST sobre `/v1/urls/recent/`. El método correcto verificado por el usuario es GET sobre la URL con `limit/5/` o `limit/50/`.
- La prueba correcta del usuario devolvió `query_status=ok`, cinco URLs; ejemplos con `url_status=online`, `threat=malware_download`.
- v4.6 recopila hasta 50 URL recientes.
- Solo geolocalizar hosts que sean IP públicas explícitas. No convertir nombres de dominio en coordenadas inventadas.
- `online` describe el estado que informa URLhaus; no prueba que haya víctimas ni ataques en curso.
- Uso comunitario sujeto a fair use/condiciones de abuse.ch.

#### Geolocalización IP: IPWho.is

- Endpoint: `https://ipwho.is/{ip}`.
- Uso sin clave en la implementación v4.6.
- El recopilador limita a 12 consultas de IP nuevas por ejecución, cachea resultados durante 30 días y limita la caché a 300 entradas.
- El usuario aceptó que la geolocalización es aproximada.
- Nunca identifica a una persona, atacante o víctima. Solo debe ubicarse IP pública global; excluir IP privadas/reservadas.

### Resultado de pruebas de API efectuadas por el usuario

Estas pruebas fueron realizadas desde el Mac del usuario, antes de la implementación. No equivalen a la validación de GitHub Actions:

| Fuente | Resultado de prueba | Estado |
|---|---|---|
| Cloudflare Radar | `success=True`, 5 pares | Acceso validado desde Mac |
| ThreatFox | `query_status=ok`, 2.092 IOC | Acceso validado desde Mac |
| URLhaus | `query_status=ok`, 5 URL | Acceso validado desde Mac; GET correcto |
| DShield | HTTP 200, 15 líneas | Feed accesible desde Mac |

La primera ejecución del workflow v4.6 en GitHub Actions seguía pendiente en el momento de esta nota. El entorno donde se creó el paquete no pudo hacer llamadas reales a Internet. Hubo validaciones locales y pruebas simuladas de los adaptadores.

### Estructura de `data/threatmap.json` en v4.6

Campos principales observados:

- `schema_version`
- `generated_at`, `last_checked_at`
- `notice`
- `cloudflare` (pares, metadatos y timestamps)
- `dshield` (IP observadas)
- `threatfox` (recuento, muestra de IOC)
- `urlhaus` (recuento, muestra de URL)
- `geo_cache`
- `source_status`
- `stats`
- `attribution`

La plantilla inicial v4.6 contiene fuentes pendientes de la primera ejecución; no confundir esos contadores de plantilla con datos recogidos en producción.

---

## 5. Diseño objetivo aprobado para la pantalla Threatmap

El usuario aprobó un concepto visual tipo SOC oscuro, con mapa mundial central, acentos de cian/azul, rojo, naranja y verde, y énfasis en Chile/Latinoamérica.

Distribución de la maqueta aprobada:

- Barra superior con marca RADAR, navegación, cobertura y última actualización.
- Navegación lateral con Threatmap, resumen, ataques, indicadores, fuentes y configuración.
- Mapa mundial como elemento principal.
- Panel lateral de capas con interruptores y estado/actualización por fuente.
- Panel de filtros por región, país y tipo de amenaza.
- Panel inferior de estadísticas globales.
- Ranking de regiones/países con pestañas IP, Malware y URLs.
- Lista de últimos eventos.
- Panel de fuentes y atribuciones.
- Nota de uso educativo: los datos proceden de fuentes públicas y no representan por sí solos ataques confirmados ni una visión completa de Internet.

La imagen fue una maqueta conceptual. No se debe afirmar que las métricas de la imagen son datos reales; los contadores de la imagen eran ilustrativos.

### Reglas semánticas de visualización

1. **Arcos Cloudflare:** estadísticas agregadas de país-origen a país-destino de ataques L7, dentro del periodo informado. No son flujos individuales en vivo.
2. **DShield:** IP reportadas por sensores. Puede mostrar país de la IP si se geolocaliza, pero no inventar destino.
3. **ThreatFox:** IOC de malware; solo una IP pública geolocalizable puede mostrarse en el mapa. Hashes/domains sin coordenadas van a los listados.
4. **URLhaus:** URL de distribución de malware; geolocalizar solo cuando el hostname de la URL es una IP pública, no un dominio genérico.
5. **GeoIP:** aproximado. No atribuye identidad, actor o víctima.
6. Mostrar fuente, hora de consulta, timestamp original del proveedor si está disponible, frescura y errores/stale status.
7. No sumar indicadores, IP, URL y pares Cloudflare como si fueran unidades homogéneas de «ataques».
8. Mantener capas separadas visualmente y permitir filtros sin cambiar el significado de los datos.

---

## 6. Pantalla futura «Chile» — API MISP del CSIRT Nacional

El usuario desea una pantalla especial para amenazas en Chile y preguntó si es posible usar:

- Documentación: https://apimisp.csirt.gob.cl/docs

La documentación se identificó como una API MISP con endpoint de autenticación `POST /token` y endpoints/áreas descritos para IOC, APT, TTP y malware. Se mencionaron las rutas siguientes como puntos a revisar en Swagger (no asumir sus esquemas hasta inspeccionar la versión real de la documentación):

- `/ioc/ip_amenazas`
- `/ioc/dominios`
- `/ioc/hashes`
- `/ioc/urls`
- `/ioc/archivos`
- `/ioc/correos_phishing`
- `/apt/info`
- `/apt/ttp`
- `/ttp/info`
- `/malware/info`

**Estado:** el usuario todavía no ha indicado que obtuvo un token ni credenciales del CSIRT. Solo pidió instrucciones para solicitarlos. La obtención y las condiciones de acceso están pendientes.

### Próximos pasos de la futura integración chilena

1. Obtener autorización/credenciales por el canal oficial del CSIRT.
2. Confirmar si se admite acceso para un proyecto educativo individual, los scopes/read-only permissions y la expiración/renovación del token.
3. Confirmar explícitamente qué datos pueden mostrarse en un dashboard público de GitHub Pages. Acceder a datos no equivale a tener derecho de redistribución.
4. Revisar reglas TLP, distribución MISP, restricciones por evento/atributo, licencias y atribución.
5. Consultar Swagger y probar endpoints de lectura de forma limitada; registrar campos reales y timestamps.
6. Solo entonces diseñar un adaptador y pantalla Chile; no asumir que cualquier IOC tiene relación geográfica con Chile.
7. La ubicación de una IP en Chile no prueba que el incidente afecte a una víctima chilena. Separar «IP geolocalizada en Chile», «IOC relacionado con Chile» e «incidente reportado en Chile».

El usuario preguntó cómo obtener el token; se le indicó contactar al CSIRT y solicitar acceso API MISP, permisos de lectura y autorización de difusión pública. No compartir tokens en chats ni HTML.

---

## 7. Traducción al español (idea futura, no implementada)

El usuario preguntó por traducir publicaciones de fuentes internacionales. Propuesta discutida:

- Integrar un motor de traducción en el proceso de recopilación, no en el HTML del navegador.
- Mantener el original y una versión traducida de título/resumen.
- Traducir solo registros nuevos para controlar costos.
- Conservar nombres de fabricantes, productos, CVE, CVSS, hashes, IP y URL sin alteraciones.
- Si la traducción falla, mostrar original.
- Evaluar Google Cloud Translation, DeepL API o LibreTranslate autoalojado.
- Guardar API keys como GitHub Secrets.

No se ha elegido proveedor ni se ha implementado la traducción.

---

## 8. Deduplicación y calidad de inteligencia

Estado conocido del recopilador principal:

- Duplicados por URL normalizada y título exacto normalizado: sí.
- Detección semántica de noticias similares: no está implementada de forma general.
- Mismo CVE en múltiples publicaciones: pueden mantenerse múltiples registros.

Recomendación debatida:

- Nivel 1: deduplicación exacta por URL/título.
- Nivel 2: correlación por identificadores técnicos (CVE, hash, IP, dominio, campaña, familia de malware), con reglas de contexto.
- Nivel 3: similitud semántica de título/resumen, preferentemente para agrupar y no borrar.
- Conservar artículos fuente distintos aunque se agrupen bajo un incidente común; una noticia puede agregar mitigación o análisis diferente.

No aplicar borrado automático agresivo que reduzca la trazabilidad.

---

## 9. Fuentes RSS que se han trabajado

A lo largo de las primeras versiones se amplió la configuración de RSS/Atom con fuentes de proveedores, CERTs y medios especializados. Entre las fuentes añadidas y verificadas como endpoints RSS/Atom/XML se mencionaron:

- Cisco Security Advisories / PSIRT
- Cisco Security Blog
- Check Point Research
- Microsoft Security Blog
- Google Project Zero
- AWS Security Blog y AWS Security Bulletins (después el usuario indicó retirar las fuentes AWS que no funcionaban)
- Oracle Security Blog (después retirado) y nuevo feed de Oracle Security Alerts:
  `https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml`
- OpenAI News
- NVIDIA Developer Blog — Cybersecurity
- C4ISRNET — Space
- Meta Engineering — Security
- Meta News — Security

Se evitaron feeds que respondían 404/403/410/502, se redirigían a HTML o no se podían validar como RSS/Atom. Cisco Talos y Google Cloud/Mandiant ya existían en el catálogo y no debían duplicarse.

**Importante:** verificar la configuración actual en `config/sources.json`; la lista anterior es contexto histórico, no garantía de que todas estén vigentes hoy.

---

## 10. Seguridad, privacidad y operación

- Repositorio público: todo HTML/JS/JSON publicado es visible para terceros.
- API keys y tokens solo en GitHub Actions Secrets y variables de entorno.
- Nunca imprimir secretos en logs o respuestas, ni guardarlos en JSON estático.
- CARTO: el token de teselas está embebido en el HTML de GitHub Pages y es público por diseño. Restringirlo por dominio en el panel de CARTO al dominio `profelionel.github.io` y supervisar consumo. No copiar su valor en documentos de contexto.
- No incluir datos personales, credenciales, datos internos de clientes o logs sensibles en `data/`.
- Si se integra telemetría propia (firewall, Suricata, Zeek, SIEM), definir anonimización, retención y permisos antes de publicar datos.
- Validar atribución y licencias de cada fuente. El propósito de uso debe permanecer dentro de los términos aplicables.
- Mantener un fallback de última captura válida si una API falla, pero etiquetar con claridad datos antiguos y su fecha de última actualización.
- Evitar presentar el proyecto como servicio de monitorización completo de Internet; es una agregación de fuentes públicas y observaciones limitadas.

---

## 11. Lista de próximos pasos (sin ejecutar hasta que el usuario lo solicite)

1. En Codex, inspeccionar el repositorio GitHub y comprobar si el paquete v4.6 está instalado.
2. Si no está instalado, mostrar el diferencial y solicitar autorización del usuario antes de aplicar el patch.
3. Ejecutar manualmente el workflow `Actualizar datos del Threatmap` después de confirmar que los dos secrets existen; verificar que `data/threatmap.json` se actualiza, sin exponer valores.
4. Verificar en vivo la página Threatmap, la carga de teselas CARTO y la consistencia de paneles.
5. Confirmar la política y atribución de las fuentes, especialmente Cloudflare CC BY-NC 4.0, DShield y abuse.ch.
6. Diseñar y validar acceso al CSIRT MISP para futura pantalla nacional; esperar autorización y condiciones de redistribución.
7. Evaluar traducción al español sin alterar identificadores técnicos.
8. Diseñar correlación/deduplicación de incidentes sin eliminar información complementaria.

No ejecutar todos estos pasos automáticamente. Deben hacerse en respuesta a instrucciones explícitas del usuario.

---

## 12. Prompt inicial sugerido para Codex

El archivo `CODEX_START_PROMPT.md` que acompaña este documento contiene un prompt listo para copiar. En resumen, debe pedir a Codex leer este documento y `AGENTS.md`, inspeccionar el repositorio, determinar qué partes de v4.6 están instaladas y entregar un diagnóstico del estado actual. La primera tarea es solo de lectura: no debe editar, hacer commits, modificar secretos ni ejecutar despliegues.

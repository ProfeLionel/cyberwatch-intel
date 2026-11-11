#!/usr/bin/env python3
"""Recopilador básico de fuentes públicas de ciberseguridad para RADAR.

- Lee RSS/Atom.
- Consulta el catálogo CISA KEV.
- Consulta CVE recientes desde NVD.
- Deduplica por URL normalizada y título normalizado.
- Guarda datos públicos en data/incidents.json.

No extrae contenido de páginas arbitrarias ni intenta eludir controles de acceso.
"""
from __future__ import annotations

import calendar
import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import feedparser
import requests

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "sources.json"
OUTPUT_PATH = ROOT / "data" / "incidents.json"
HISTORY_PATH = ROOT / "data" / "history.json"
USER_AGENT = "RADAR/1.0 (public-source aggregator)"
TIMEOUT = 15

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json, application/atom+xml, application/rss+xml, application/xml, text/xml, */*"})

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "mc_cid", "mc_eid"
}
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def clean_text(value: str | None) -> str:
    value = unescape(value or "")
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def normalize_url(url: str | None) -> str:
    if not url:
        return ""
    try:
        parts = urlsplit(url.strip())
        if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
            return ""
        scheme = parts.scheme.lower()
        netloc = parts.netloc.lower()
        path = re.sub(r"/+$", "", parts.path) or "/"
        query = [
            (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if k.lower() not in TRACKING_PARAMS
        ]
        query.sort()
        return urlunsplit((scheme, netloc, path, urlencode(query, doseq=True), ""))
    except Exception:
        return ""


def normalize_title(title: str) -> str:
    title = clean_text(title).lower()
    title = re.sub(r"\bcve\s*[-–]\s*(\d{4})\s*[-–]\s*(\d+)\b", r"cve-\1-\2", title)
    title = re.sub(r"[^a-z0-9áéíóúüñ]+", " ", title)
    return re.sub(r"\s+", " ", title).strip()


def parse_date(value: str | None) -> str | None:
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()
    except Exception:
        pass
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()
    except Exception:
        return None


def stable_id(*parts: str) -> str:
    raw = "|".join(p or "" for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def classify(text: str, base_category: str = "Ciberseguridad") -> list[str]:
    t = (text or "").lower()
    tags = []
    rules = {
        "vulnerabilidad": ["cve-", "vulnerability", "vulnerabilidad", "zero-day", "zero day", "patch", "parche"],
        "ransomware": ["ransomware", "extortion", "extorsión"],
        "malware": ["malware", "trojan", "trojan", "backdoor", "infostealer"],
        "phishing": ["phishing", "credential theft", "robo de credenciales"],
        "espionaje": ["espionage", "espionaje", "state-sponsored", "state sponsored", "nation-state"],
        "infraestructura_critica": ["critical infrastructure", "infraestructura crítica", "industrial control", "ics", "scada"],
        "defensa_militar": ["military", "militar", "armed forces", "fuerzas armadas", "defense", "defence", "defensa", "navy", "air force"],
        "sector_publico": ["government", "governmental", "gobierno", "ministerio", "public sector", "sector público", "agency"],
        "filtracion": ["data breach", "breach", "leak", "filtración", "filtrados", "exposed data"],
    }
    for tag, needles in rules.items():
        if any(n in t for n in needles):
            tags.append(tag)
    if not tags:
        tags.append("general")
    return tags


def get_cves(text: str) -> list[str]:
    return sorted({x.upper() for x in CVE_PATTERN.findall(text or "")})


def estimate_priority(text: str, kev: bool = False, severity: str | None = None,
                      cvss: float | int | None = None) -> tuple[int, str, list[str]]:
    """Puntaje heurístico transparente; no representa probabilidad de ataque."""
    reasons: list[str] = []
    score = 10
    sev = (severity or "").lower()
    try:
        cvss_num = float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        cvss_num = None
    if kev:
        score += 70
        reasons.append("incluida en CISA KEV")
    if sev == "critical" or (cvss_num is not None and cvss_num >= 9):
        score += 35
        reasons.append("severidad crítica/CVSS ≥ 9")
    elif sev == "high" or (cvss_num is not None and cvss_num >= 7):
        score += 22
        reasons.append("severidad alta/CVSS ≥ 7")
    t = (text or "").lower()
    keyword_rules = [
        ("explotación mencionada", ["actively exploited", "exploited in the wild", "explotación activa", "explotada activamente"] , 20),
        ("ransomware/campaña", ["ransomware", "campaign", "campaña", "mass exploitation"], 12),
        ("APT/espionaje", ["apt ", "apt-", "advanced persistent threat", "state-sponsored", "state sponsored", "nation-state", "cyber espionage", "ciberespionaje"], 12),
        ("infraestructura crítica", ["critical infrastructure", "infraestructura crítica", "industrial control", "ics/ot", "scada"], 10),
        ("zero-day", ["zero-day", "zero day", "zero-day vulnerability", "día cero"], 15),
    ]
    for reason, terms, points in keyword_rules:
        if any(term in t for term in terms):
            score += points
            reasons.append(reason)
    score = min(score, 100)
    label = "crítica" if score >= 85 else "alta" if score >= 65 else "media" if score >= 35 else "informativa"
    return score, label, reasons or ["clasificación inicial por defecto"]


def base_item(title: str, link: str, source: str, category: str, published: str | None,
              summary: str, region: str = "Global", item_type: str = "article",
              extra: dict | None = None) -> dict | None:
    url = normalize_url(link)
    title = clean_text(title)
    if not url or not title:
        return None
    combined = f"{title} {summary}"
    score, priority_label, priority_basis = estimate_priority(combined)
    item = {
        "id": stable_id(url),
        "title": title[:400],
        "url": url,
        "source": source,
        "category": category,
        "region": region,
        "published_at": published,
        "summary": clean_text(summary)[:1200],
        "type": item_type,
        "tags": classify(combined, category),
        "cves": get_cves(combined),
        "priority_score": score,
        "priority_label": priority_label,
        "priority_basis": priority_basis,
        "collected_at": now_iso()
    }
    if extra:
        item.update(extra)
    score, priority_label, priority_basis = estimate_priority(
        f"{item.get('title', '')} {item.get('summary', '')}",
        kev=bool(item.get("kev")), severity=item.get("severity"), cvss=item.get("cvss")
    )
    item["priority_score"] = score
    item["priority_label"] = priority_label
    item["priority_basis"] = priority_basis
    return item


def fetch_rss(source: dict) -> tuple[list[dict], dict]:
    name = source["name"]
    url = source["url"]
    started = time.monotonic()
    status = {"source": name, "url": url, "ok": False, "count": 0, "error": None, "checked_at": now_iso()}
    try:
        response = SESSION.get(url, timeout=TIMEOUT)
        status["http_status"] = response.status_code
        response.raise_for_status()
        parsed = feedparser.parse(response.content)
        if parsed.bozo and not parsed.entries:
            raise ValueError("La respuesta no parece un RSS/Atom válido.")
        items = []
        for entry in parsed.entries[:100]:
            title = entry.get("title", "")
            link = entry.get("link", "")
            summary = entry.get("summary", "") or entry.get("description", "")
            published = parse_date(entry.get("published") or entry.get("updated") or entry.get("created"))
            item = base_item(
                title=title,
                link=link,
                source=name,
                category=source.get("category", "Ciberseguridad"),
                published=published,
                summary=summary,
                region=source.get("region", "Global"),
                item_type="article",
                extra={"sectors": source.get("sector", ["publico", "privado"])}
            )
            if item:
                items.append(item)
        status.update({"ok": True, "count": len(items), "last_published_at": max((i.get("published_at") or "" for i in items), default=None) or None})
        status["duration_ms"] = round((time.monotonic() - started) * 1000)
        logging.info("%s: %s publicaciones", name, len(items))
        return items, status
    except Exception as exc:
        status["error"] = str(exc)[:300]
        status["duration_ms"] = round((time.monotonic() - started) * 1000)
        logging.warning("%s: %s", name, status["error"])
        return [], status


def fetch_cisa_kev(source: dict) -> tuple[list[dict], dict]:
    started = time.monotonic()
    status = {"source": source["name"], "url": source["url"], "ok": False, "count": 0, "error": None, "checked_at": now_iso()}
    try:
        response = SESSION.get(source["url"], timeout=TIMEOUT)
        status["http_status"] = response.status_code
        response.raise_for_status()
        payload = response.json()
        items = []
        for vuln in payload.get("vulnerabilities", []):
            cve = (vuln.get("cveID") or "").upper()
            if not cve:
                continue
            title = f"{cve}: {vuln.get('vulnerabilityName') or vuln.get('product') or 'Vulnerabilidad explotada'}"
            summary = " ".join(filter(None, [
                vuln.get("shortDescription", ""),
                f"Proveedor: {vuln.get('vendorProject', '')}.",
                f"Producto: {vuln.get('product', '')}.",
                f"Acción requerida: {vuln.get('requiredAction', '')}.",
                f"Fecha agregada al catálogo: {vuln.get('dateAdded', '')}.",
                f"Uso en campañas de ransomware: {vuln.get('knownRansomwareCampaignUse', 'desconocido')}."
            ]))
            item = base_item(
                title=title,
                link=f"https://nvd.nist.gov/vuln/detail/{cve}",
                source=source["name"],
                category="Vulnerabilidades explotadas (CISA KEV)",
                published=parse_date(vuln.get("dateAdded")),
                summary=summary,
                item_type="vulnerability",
                extra={
                    "cves": [cve],
                    "vendor": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                    "kev": True,
                    "date_added": vuln.get("dateAdded"),
                    "due_date": vuln.get("dueDate"),
                    "known_ransomware_campaign_use": vuln.get("knownRansomwareCampaignUse"),
                    "required_action": vuln.get("requiredAction")
                }
            )
            if item:
                items.append(item)
        status.update({"ok": True, "count": len(items)})
        status["duration_ms"] = round((time.monotonic() - started) * 1000)
        logging.info("%s: %s CVE en catálogo", source["name"], len(items))
        return items, status
    except Exception as exc:
        status["error"] = str(exc)[:300]
        status["duration_ms"] = round((time.monotonic() - started) * 1000)
        logging.warning("%s: %s", source["name"], status["error"])
        return [], status


def fetch_nvd(source: dict) -> tuple[list[dict], dict]:
    started = time.monotonic()
    status = {"source": source["name"], "url": source["url"], "ok": False, "count": 0, "error": None, "checked_at": now_iso()}
    try:
        days = int(source.get("lookback_days", 7))
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        page_size = min(max(int(source.get("results_per_page", 2000)), 1), 2000)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "resultsPerPage": page_size,
            "startIndex": 0
        }
        # NVD API dates are UTC; API key is optional but recommended for higher limits.
        api_key = os.getenv("NVD_API_KEY")
        headers = {"apiKey": api_key} if api_key else {}
        rows = []
        total_results = None
        while True:
            response = SESSION.get(source["url"], params=params, headers=headers, timeout=TIMEOUT)
            status["http_status"] = response.status_code
            response.raise_for_status()
            payload = response.json()
            page_rows = payload.get("vulnerabilities", [])
            rows.extend(page_rows)
            total_results = int(payload.get("totalResults", len(rows)))
            params["startIndex"] += len(page_rows)
            if not page_rows or params["startIndex"] >= total_results:
                break
            # NVD recomienda espaciar consultas; evita ráfagas en paginación.
            time.sleep(6 if not api_key else 0.7)
        items = []
        for row in rows:
            cve_obj = row.get("cve", {})
            cve = cve_obj.get("id", "")
            descriptions = cve_obj.get("descriptions", [])
            desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
            metrics = cve_obj.get("metrics", {})
            cvss = None
            severity = None
            for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                values = metrics.get(metric_name, [])
                if values:
                    data = values[0].get("cvssData", {})
                    cvss = data.get("baseScore")
                    severity = data.get("baseSeverity") or values[0].get("baseSeverity")
                    break
            published = parse_date(cve_obj.get("published"))
            url = f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else ""
            item = base_item(
                title=f"{cve}: {desc[:180]}" if cve else desc[:200],
                link=url,
                source=source["name"],
                category="Vulnerabilidades (NVD)",
                published=published,
                summary=desc,
                item_type="vulnerability",
                extra={
                    "cves": [cve] if cve else [],
                    "cvss": cvss,
                    "severity": severity,
                    "kev": False
                }
            )
            if item:
                items.append(item)
        status.update({"ok": True, "count": len(items), "total_results": total_results,
                       "partial": len(rows) < (total_results or 0)})
        if status["partial"]:
            status["error"] = f"Respuesta parcial: {len(rows)} de {total_results} CVE recuperadas."
        status["duration_ms"] = round((time.monotonic() - started) * 1000)
        logging.info("%s: %s CVE recientes", source["name"], len(items))
        return items, status
    except Exception as exc:
        status["error"] = str(exc)[:300]
        status["duration_ms"] = round((time.monotonic() - started) * 1000)
        logging.warning("%s: %s", source["name"], status["error"])
        return [], status


def fetch_cve_list_v5(source: dict) -> tuple[list[dict], dict]:
    """Recoge CVE publicados recientemente desde el delta más reciente de CVE List V5."""
    started = time.monotonic()
    status = {"source": source["name"], "url": source["url"], "ok": False,
              "count": 0, "error": None, "checked_at": now_iso()}
    try:
        response = SESSION.get(source["url"], timeout=TIMEOUT)
        status["http_status"] = response.status_code
        response.raise_for_status()
        batch = response.json()
        if not isinstance(batch, dict) or not isinstance(batch.get("new"), list) or not isinstance(batch.get("updated"), list):
            raise ValueError("La respuesta no coincide con el formato delta de CVE List V5.")

        records = {}
        for change in batch["new"] + batch["updated"]:
            if not isinstance(change, dict):
                continue
            cve_id = str(change.get("cveId", "")).upper()
            record_url = change.get("githubLink", "")
            parsed_record_url = urlsplit(record_url) if isinstance(record_url, str) else None
            if (CVE_PATTERN.fullmatch(cve_id) and parsed_record_url
                    and parsed_record_url.scheme == "https"
                    and parsed_record_url.netloc == "raw.githubusercontent.com"
                    and parsed_record_url.path.startswith("/CVEProject/cvelistV5/main/cves/")):
                records[cve_id] = record_url

        max_records = min(max(int(source.get("max_records", 100)), 1), 200)
        selected = list(records.items())[:max_records]
        lookback = max(int(source.get("lookback_days", 7)), 1)
        cutoff = datetime.now(timezone.utc) - timedelta(days=lookback)
        items = []
        skipped_outside_window = 0
        for cve_id, record_url in selected:
            record_response = SESSION.get(record_url, timeout=TIMEOUT)
            record_response.raise_for_status()
            record = record_response.json()
            metadata = record.get("cveMetadata", {})
            if metadata.get("state") != "PUBLISHED":
                continue
            containers = record.get("containers", {})
            cna = containers.get("cna", {})
            published_raw = metadata.get("datePublished") or metadata.get("dateReserved")
            published = parse_date(published_raw)
            if not published or datetime.fromisoformat(published.replace("Z", "+00:00")) < cutoff:
                skipped_outside_window += 1
                continue
            descriptions = cna.get("descriptions", [])
            description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
            description = description or next((d.get("value", "") for d in descriptions), "")
            title = cna.get("title") or f"{cve_id}: {description[:180]}"
            cvss = severity = None
            for metric in (cna.get("metrics") or []):
                if not isinstance(metric, dict):
                    continue
                cvss_data = next((metric[key] for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
                                  if isinstance(metric.get(key), dict)), None)
                if cvss_data:
                    cvss = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity")
                    break
            affected = cna.get("affected") or []
            vendors = sorted({str(entry.get("vendor")) for entry in affected
                              if isinstance(entry, dict) and entry.get("vendor")})
            products = sorted({str(entry.get("product")) for entry in affected
                               if isinstance(entry, dict) and entry.get("product")})
            item = base_item(
                title=title,
                link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                source=source["name"],
                category=source.get("category", "Vulnerabilidades (CVE Program)"),
                published=published,
                summary=description,
                item_type="vulnerability",
                extra={"cves": [cve_id], "cvss": cvss, "severity": severity,
                       "kev": False, "vendor": ", ".join(vendors) or None,
                       "product": ", ".join(products) or None,
                       "cve_record_url": f"https://www.cve.org/CVERecord?id={cve_id}"}
            )
            if item:
                items.append(item)
        status.update({"ok": True, "count": len(items), "batch_fetch_time": batch.get("fetchTime"),
                       "records_seen": len(records), "records_checked": len(selected),
                       "skipped_outside_lookback": skipped_outside_window,
                       "partial": len(records) > max_records})
        if status["partial"]:
            status["error"] = f"Lote limitado a {max_records} de {len(records)} registros CVE."
        status["duration_ms"] = round((time.monotonic() - started) * 1000)
        logging.info("%s: %s CVE recientes", source["name"], len(items))
        return items, status
    except Exception as exc:
        status["error"] = str(exc)[:300]
        status["duration_ms"] = round((time.monotonic() - started) * 1000)
        logging.warning("%s: %s", source["name"], status["error"])
        return [], status


def enrich_epss(items: list[dict], previous: dict | None = None) -> dict:
    """Añade probabilidad EPSS de FIRST sin mezclarla con CVSS o CISA KEV."""
    started = time.monotonic()
    status = {"source": "FIRST EPSS", "url": "https://api.first.org/data/v1/epss",
              "ok": False, "count": 0, "error": None, "checked_at": now_iso()}
    cves = sorted({str(cve).upper() for item in items for cve in item.get("cves", [])
                   if CVE_PATTERN.fullmatch(str(cve))})
    if not cves:
        status.update({"ok": True, "note": "No hay CVE para enriquecer."})
        return status
    previous_items = previous.get("items", []) if isinstance(previous, dict) else []
    if not isinstance(previous_items, list):
        previous_items = []
    old_scores: dict[str, dict] = {}
    old_cves: set[str] = set()
    for old_item in previous_items:
        if not isinstance(old_item, dict):
            continue
        item_cves = {str(cve).upper() for cve in old_item.get("cves", [])}
        old_cves.update(item_cves)
        score = {key: old_item[key] for key in ("epss", "epss_percentile", "epss_date")
                 if old_item.get(key) is not None}
        if score:
            for cve in item_cves:
                old_scores[cve] = score
    old_status = next((s for s in (previous.get("source_status", []) if isinstance(previous, dict) else [])
                       if isinstance(s, dict) and s.get("source") == "FIRST EPSS"), {})
    old_check = old_status.get("epss_checked_at") or old_status.get("checked_at") or old_status.get("last_success_at")
    try:
        old_check_dt = datetime.fromisoformat(str(old_check).replace("Z", "+00:00"))
        if old_check_dt.tzinfo is None:
            old_check_dt = old_check_dt.replace(tzinfo=timezone.utc)
        cache_fresh = bool(old_status.get("ok")) and datetime.now(timezone.utc) - old_check_dt.astimezone(timezone.utc) < timedelta(hours=20)
    except (TypeError, ValueError):
        cache_fresh = False
    if cache_fresh:
        for item in items:
            if item.get("epss") is None:
                found = next((old_scores[cve] for cve in item.get("cves", []) if cve in old_scores), None)
                if found:
                    item.update(found)
    requested_cves = [cve for cve in cves if not cache_fresh or cve not in old_cves]
    if not requested_cves:
        status.update({"ok": True, "count": sum(1 for cve in cves if cve in old_scores),
                       "cves_requested": 0, "note": "Se reutiliza la captura EPSS reciente.",
                       "epss_checked_at": old_check})
        if old_check:
            status["checked_at"] = old_check
        status["duration_ms"] = round((time.monotonic() - started) * 1000)
        return status
    scores: dict[str, dict] = {}
    try:
        # La API acepta listas CVE; cada lote mantiene la URL dentro de límites prácticos.
        batches = [requested_cves[i:i + 100] for i in range(0, len(requested_cves), 100)]
        for batch in batches:
            response = SESSION.get("https://api.first.org/data/v1/epss",
                                   params={"cve": ",".join(batch), "limit": len(batch)},
                                   timeout=TIMEOUT)
            response.raise_for_status()
            payload = response.json()
            if payload.get("status-code") != 200:
                raise ValueError("FIRST EPSS devolvió una respuesta no válida.")
            for row in payload.get("data", []):
                cve = str(row.get("cve", "")).upper()
                if cve in batch:
                    scores[cve] = {"epss": row.get("epss"),
                                   "epss_percentile": row.get("percentile"),
                                   "epss_date": row.get("date")}
        for item in items:
            found = next((scores[cve] for cve in item.get("cves", []) if cve in scores), None)
            if found:
                item.update(found)
                item.pop("epss_stale", None)
            else:
                old_value = next((old_scores[cve] for cve in item.get("cves", []) if cve in old_scores), None)
                if old_value:
                    item.update(old_value)
                    item["epss_stale"] = True
        status.update({"ok": True, "count": sum(1 for cve in cves if cve in scores or cve in old_scores), "cves_requested": len(requested_cves),
                       "error": None, "epss_checked_at": now_iso()})
    except Exception as exc:
        status["error"] = str(exc)[:240]
    status["duration_ms"] = round((time.monotonic() - started) * 1000)
    return status


def deduplicate(items: list[dict]) -> list[dict]:
    """Deduplicación conservadora: URL idéntica o título normalizado idéntico.

    Las coincidencias aproximadas no se fusionan automáticamente para evitar
    mezclar incidentes distintos. Se puede añadir una capa de agrupación futura.
    """
    by_url: dict[str, dict] = {}
    by_title: dict[str, dict] = {}
    for item in items:
        url = normalize_url(item.get("url"))
        title_key = normalize_title(item.get("title", ""))
        if not url or not title_key:
            continue
        if url in by_url:
            existing = by_url[url]
            sources = set(existing.get("related_sources", [existing.get("source", "")]))
            sources.add(item.get("source", ""))
            existing["related_sources"] = sorted(s for s in sources if s)
            if len(item.get("summary", "")) > len(existing.get("summary", "")):
                existing["summary"] = item["summary"]
            existing["cves"] = sorted(set(existing.get("cves", [])) | set(item.get("cves", [])))
            continue
        if title_key in by_title:
            existing = by_title[title_key]
            sources = set(existing.get("related_sources", [existing.get("source", "")]))
            sources.add(item.get("source", ""))
            existing["related_sources"] = sorted(s for s in sources if s)
            existing["cves"] = sorted(set(existing.get("cves", [])) | set(item.get("cves", [])))
            continue
        item["related_sources"] = [item.get("source", "")]
        by_url[url] = item
        by_title[title_key] = item

    result = list(by_url.values())
    result.sort(key=lambda x: x.get("published_at") or "", reverse=True)
    return result


def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def main() -> None:
    config = load_config()
    all_items: list[dict] = []
    statuses: list[dict] = []

    for source in config.get("rss_sources", []):
        items, status = fetch_rss(source)
        all_items.extend(items)
        statuses.append(status)
        time.sleep(0.3)

    for source in config.get("structured_sources", []):
        if source.get("type") == "cisa_kev":
            items, status = fetch_cisa_kev(source)
        elif source.get("type") == "nvd_recent":
            items, status = fetch_nvd(source)
        elif source.get("type") == "cve_list_v5_recent":
            items, status = fetch_cve_list_v5(source)
        else:
            continue
        all_items.extend(items)
        statuses.append(status)
        time.sleep(0.5)

    previous = None
    if OUTPUT_PATH.exists():
        try:
            previous = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            previous = None

    if not statuses or not any(s.get("ok") for s in statuses):
        raise RuntimeError("Todas las fuentes fallaron; se conserva el último snapshot publicado.")

    # Ante una falla parcial, conserva los registros previos atribuibles a esa fuente.
    previous_items = previous.get("items", []) if isinstance(previous, dict) else []
    failed_sources = {s.get("source") for s in statuses if not s.get("ok") or s.get("partial")}
    previous_status = {s.get("source"): s for s in (previous.get("source_status", [])
                       if isinstance(previous, dict) else []) if isinstance(s, dict)}
    for status in statuses:
        if status.get("source") in failed_sources:
            old_status = previous_status.get(status.get("source"), {})
            status["stale_data"] = bool(old_status.get("ok") or old_status.get("last_success_at"))
            status["last_success_at"] = old_status.get("last_success_at") or old_status.get("checked_at")
    preserved = []
    for old_item in previous_items:
        old_sources = set(old_item.get("related_sources", [])) | {old_item.get("source")}
        if old_sources & failed_sources:
            item = dict(old_item)
            item["stale_data"] = True
            preserved.append(item)
    all_items.extend(preserved)
    epss_status = enrich_epss(all_items, previous if isinstance(previous, dict) else None)
    if not epss_status.get("ok"):
        old_epss_by_cve = {}
        for old_item in previous_items:
            if not isinstance(old_item, dict):
                continue
            values = {key: old_item[key] for key in ("epss", "epss_percentile", "epss_date")
                      if old_item.get(key) is not None}
            if values:
                for cve in old_item.get("cves", []):
                    old_epss_by_cve[cve] = values
        for item in all_items:
            if item.get("epss") is None:
                old_values = next((old_epss_by_cve[cve] for cve in item.get("cves", [])
                                   if cve in old_epss_by_cve), None)
                if old_values:
                    item.update(old_values)
                    item["epss_stale"] = True
        old_epss_status = next((s for s in previous.get("source_status", [])
                                if isinstance(s, dict) and s.get("source") == "FIRST EPSS"), {}) \
            if isinstance(previous, dict) else {}
        epss_status["stale_data"] = bool(old_epss_by_cve)
        epss_status["last_success_at"] = old_epss_status.get("last_success_at") or old_epss_status.get("checked_at")
    statuses.append(epss_status)

    unique_items = deduplicate(all_items)
    run_time = now_iso()
    payload = {
        "generated_at": run_time,
        "last_checked_at": run_time,
        "items": unique_items,
        "source_status": statuses,
        "notice": (
            "Información recopilada de fuentes públicas. Verifica siempre el informe original. "
            "La presencia de una publicación no implica que todos sus datos estén confirmados."
        ),
        "stats": {
            "items_before_deduplication": len(all_items),
            "items_after_deduplication": len(unique_items),
            "items_published": len(unique_items),
            "items_stale_preserved": len(preserved),
            "sources_ok": sum(1 for s in statuses if s["ok"] and not s.get("partial")),
            "sources_total": len(statuses)
        }
    }
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Historial diario para observar tendencias sin registrar una fila por cada ejecución.
    try:
        history = json.loads(HISTORY_PATH.read_text(encoding="utf-8")) if HISTORY_PATH.exists() else []
        if not isinstance(history, list):
            history = []
    except (json.JSONDecodeError, OSError):
        history = []
    today = datetime.now(timezone.utc).date().isoformat()
    daily_snapshot = {
        "date": today,
        "items_total": len(unique_items),
        "kev_total": sum(1 for item in unique_items if item.get("kev")),
        "items_with_cve": sum(1 for item in unique_items if item.get("cves")),
        "priority_high": sum(1 for item in unique_items if item.get("priority_label") in {"crítica", "alta"}),
        "new_items": 0,
        "new_kev": 0,
        "sources_ok": sum(1 for status in statuses if status.get("ok")),
        "sources_total": len(statuses)
    }
    previous_by_id = {str(item.get("id") or item.get("url")): item for item in previous_items
                      if isinstance(item, dict)}
    new_items = sum(1 for item in unique_items if str(item.get("id") or item.get("url")) not in previous_by_id)
    new_kev = sum(1 for item in unique_items if item.get("kev") and
                  not previous_by_id.get(str(item.get("id") or item.get("url")), {}).get("kev"))
    old_today = next((entry for entry in history if entry.get("date") == today), {})
    daily_snapshot["new_items"] = int(old_today.get("new_items", 0)) + new_items
    daily_snapshot["new_kev"] = int(old_today.get("new_kev", 0)) + new_kev
    if history and history[-1].get("date") == today:
        history[-1] = daily_snapshot
    else:
        history.append(daily_snapshot)
    history = history[-90:]
    history_changed = not HISTORY_PATH.exists()
    if HISTORY_PATH.exists():
        try:
            history_changed = json.loads(HISTORY_PATH.read_text(encoding="utf-8")) != history
        except (json.JSONDecodeError, OSError):
            history_changed = True

    # Conserva collected_at en registros sin cambios y evita commits periódicos
    # cuando el contenido y el estado de las fuentes siguen siendo iguales.
    if isinstance(previous, dict):
        previous_by_id = {str(item.get("id") or item.get("url") or item.get("title")): item
                          for item in previous.get("items", []) if isinstance(item, dict)}
        for item in payload["items"]:
            key = str(item.get("id") or item.get("url") or item.get("title"))
            old_item = previous_by_id.get(key)
            if old_item:
                old_comparable = {k: v for k, v in old_item.items() if k != "collected_at"}
                new_comparable = {k: v for k, v in item.items() if k != "collected_at"}
                if old_comparable == new_comparable and old_item.get("collected_at"):
                    item["collected_at"] = old_item["collected_at"]

        # Si el estado de una fuente no cambió, conservar su sello de comprobación anterior.
        old_status = {s.get("source"): s for s in previous.get("source_status", []) if isinstance(s, dict)}
        status_volatile = {"checked_at", "duration_ms"}
        for status in payload["source_status"]:
            old = old_status.get(status.get("source"))
            if old:
                old_stable = {k: v for k, v in old.items() if k not in status_volatile}
                new_stable = {k: v for k, v in status.items() if k not in status_volatile}
                if old_stable == new_stable:
                    for key in status_volatile:
                        if key in old:
                            status[key] = old[key]

        def comparable(data: dict) -> dict:
            return {
                "items": [{k: v for k, v in item.items() if k != "collected_at"}
                          for item in data.get("items", [])],
                "source_status": [{k: v for k, v in status.items() if k not in status_volatile}
                                  for status in data.get("source_status", [])],
                "notice": data.get("notice", ""),
                "stats": data.get("stats", {})
            }

        same_content = comparable(previous) == comparable(payload)
        previous_check = previous.get("last_checked_at") or previous.get("generated_at")
        try:
            last_check_dt = datetime.fromisoformat(str(previous_check).replace("Z", "+00:00"))
            if last_check_dt.tzinfo is None:
                last_check_dt = last_check_dt.replace(tzinfo=timezone.utc)
            heartbeat_due = datetime.now(timezone.utc) - last_check_dt.astimezone(timezone.utc) >= timedelta(hours=2)
        except Exception:
            heartbeat_due = True

        if same_content and not heartbeat_due:
            if history_changed:
                HISTORY_PATH.write_text(json.dumps(history, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                logging.info("Actualizado historial diario; sin cambios en las publicaciones actuales.")
            else:
                logging.info("Sin cambios sustantivos; se conserva el archivo publicado. Próximo sello de revisión en el siguiente ciclo de 2 h.")
            return
        if same_content:
            # Un sello cada 2 horas permite advertir de datos obsoletos sin generar un commit cada 30 minutos.
            payload["generated_at"] = previous.get("generated_at") or run_time
            for status in payload["source_status"]:
                status["checked_at"] = run_time

    OUTPUT_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if history_changed:
        HISTORY_PATH.write_text(json.dumps(history, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    logging.info("Guardado %s con %s publicaciones únicas", OUTPUT_PATH, len(unique_items))


if __name__ == "__main__":
    main()

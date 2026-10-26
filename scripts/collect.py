#!/usr/bin/env python3
"""Recopilador básico de fuentes públicas de ciberseguridad para CyberWatch Intel.

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
USER_AGENT = "CyberWatchIntel/1.0 (public-source aggregator)"
TIMEOUT = 25

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


def base_item(title: str, link: str, source: str, category: str, published: str | None,
              summary: str, region: str = "Global", item_type: str = "article",
              extra: dict | None = None) -> dict | None:
    url = normalize_url(link)
    title = clean_text(title)
    if not url or not title:
        return None
    combined = f"{title} {summary}"
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
        "collected_at": now_iso()
    }
    if extra:
        item.update(extra)
    return item


def fetch_rss(source: dict) -> tuple[list[dict], dict]:
    name = source["name"]
    url = source["url"]
    status = {"source": name, "url": url, "ok": False, "count": 0, "error": None}
    try:
        response = SESSION.get(url, timeout=TIMEOUT)
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
        status.update({"ok": True, "count": len(items)})
        logging.info("%s: %s publicaciones", name, len(items))
        return items, status
    except Exception as exc:
        status["error"] = str(exc)[:300]
        logging.warning("%s: %s", name, status["error"])
        return [], status


def fetch_cisa_kev(source: dict) -> tuple[list[dict], dict]:
    status = {"source": source["name"], "url": source["url"], "ok": False, "count": 0, "error": None}
    try:
        response = SESSION.get(source["url"], timeout=TIMEOUT)
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
        logging.info("%s: %s CVE en catálogo", source["name"], len(items))
        return items, status
    except Exception as exc:
        status["error"] = str(exc)[:300]
        logging.warning("%s: %s", source["name"], status["error"])
        return [], status


def fetch_nvd(source: dict) -> tuple[list[dict], dict]:
    status = {"source": source["name"], "url": source["url"], "ok": False, "count": 0, "error": None}
    try:
        days = int(source.get("lookback_days", 7))
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": min(int(source.get("results_per_page", 100)), 2000),
            "startIndex": 0
        }
        # NVD API dates are UTC; API key is optional but recommended for higher limits.
        api_key = os.getenv("NVD_API_KEY")
        headers = {"apiKey": api_key} if api_key else {}
        response = SESSION.get(source["url"], params=params, headers=headers, timeout=TIMEOUT)
        response.raise_for_status()
        payload = response.json()
        items = []
        for row in payload.get("vulnerabilities", []):
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
        status.update({"ok": True, "count": len(items)})
        logging.info("%s: %s CVE recientes", source["name"], len(items))
        return items, status
    except Exception as exc:
        status["error"] = str(exc)[:300]
        logging.warning("%s: %s", source["name"], status["error"])
        return [], status


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
        else:
            continue
        all_items.extend(items)
        statuses.append(status)
        time.sleep(0.5)

    unique_items = deduplicate(all_items)
    payload = {
        "generated_at": now_iso(),
        "items": unique_items[:1500],
        "source_status": statuses,
        "notice": (
            "Información recopilada de fuentes públicas. Verifica siempre el informe original. "
            "La presencia de una publicación no implica que todos sus datos estén confirmados."
        ),
        "stats": {
            "items_before_deduplication": len(all_items),
            "items_after_deduplication": len(unique_items),
            "sources_ok": sum(1 for s in statuses if s["ok"]),
            "sources_total": len(statuses)
        }
    }
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Conserva collected_at en registros sin cambios y evita commits periódicos
    # cuando el contenido y el estado de las fuentes siguen siendo iguales.
    previous = None
    if OUTPUT_PATH.exists():
        try:
            previous = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            previous = None

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

        def comparable(data: dict) -> dict:
            return {
                "items": [{k: v for k, v in item.items() if k != "collected_at"}
                          for item in data.get("items", [])],
                "source_status": data.get("source_status", []),
                "notice": data.get("notice", ""),
                "stats": data.get("stats", {})
            }

        if comparable(previous) == comparable(payload):
            logging.info("Sin cambios sustantivos; se conserva el archivo publicado para evitar commits innecesarios.")
            return

    OUTPUT_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    logging.info("Guardado %s con %s publicaciones únicas", OUTPUT_PATH, len(unique_items))


if __name__ == "__main__":
    main()

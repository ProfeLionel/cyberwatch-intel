#!/usr/bin/env python3
"""Collect public threat-intelligence data for CyberWatch Intel Threatmap.

Secrets are read only from environment variables and are never written to JSON.
Cloudflare pairs are aggregated L7 statistics; DShield/abuse.ch records are
indicators/observations, not confirmed attacker-victim sessions.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "threatmap.json"
TIMEOUT = 18
USER_AGENT = "CyberWatchIntel/1.0 (+https://github.com/ProfeLionel/cyberwatch-intel)"
GEO_LOOKUPS_PER_RUN = 12  # IPWho.is free endpoint: 1,000 requests/day.
GEO_CACHE_MAX = 300

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, */*"})

# Approximate country centroids used only to draw Cloudflare's country-level
# origin -> target aggregates. No coordinates are inferred for individual attacks.
COUNTRY_CENTROIDS: dict[str, list[float]] = {
    "AR": [-38.4, -63.6], "AU": [-25.3, 133.8], "AT": [47.5, 14.5], "BE": [50.5, 4.5],
    "BO": [-16.3, -63.6], "BR": [-10.8, -52.9], "CA": [56.1, -106.3], "CH": [46.8, 8.2],
    "CL": [-35.7, -71.5], "CN": [35.9, 104.2], "CO": [4.6, -74.1], "CR": [9.75, -83.75],
    "CU": [21.5, -79.5], "CZ": [49.8, 15.5], "DE": [51.2, 10.4], "DK": [56.3, 9.5],
    "DO": [19.0, -70.7], "EC": [-1.8, -78.2], "EG": [26.8, 30.8], "ES": [40.3, -3.7],
    "FI": [64.0, 26.0], "FR": [46.2, 2.2], "GB": [55.4, -3.4], "GR": [39.1, 21.8],
    "GT": [15.8, -90.2], "HK": [22.3, 114.2], "HN": [15.2, -86.2], "HR": [45.1, 15.2],
    "HU": [47.2, 19.5], "ID": [-0.8, 113.9], "IE": [53.1, -8.0], "IL": [31.0, 34.9],
    "IN": [21.0, 78.0], "IT": [41.9, 12.6], "JP": [36.2, 138.3], "KE": [0.2, 37.9],
    "KR": [36.5, 127.9], "MA": [31.8, -7.1], "MX": [23.6, -102.5], "MY": [4.2, 102.0],
    "NG": [9.1, 8.7], "NL": [52.1, 5.3], "NO": [60.5, 8.5], "NZ": [-40.9, 174.9],
    "PA": [8.5, -80.8], "PE": [-9.2, -75.0], "PH": [12.9, 121.8], "PK": [30.4, 69.3],
    "PL": [52.0, 19.1], "PT": [39.4, -8.2], "RO": [45.9, 24.9], "RU": [61.5, 105.3],
    "SA": [23.9, 45.1], "SE": [60.1, 18.6], "SG": [1.35, 103.8], "TH": [15.9, 100.9],
    "TR": [38.9, 35.2], "TW": [23.7, 121.0], "UA": [48.4, 31.2], "US": [39.8, -98.6],
    "UY": [-32.5, -55.8], "VE": [8.0, -66.0], "VN": [16.0, 107.8], "ZA": [-29.0, 24.0],
    "NI": [12.9, -85.2], "PY": [-23.4, -58.4], "SV": [13.8, -88.9], "BZ": [17.2, -88.5],
    "GY": [4.9, -58.9], "SR": [4.0, -56.0], "HT": [19.0, -72.4], "JM": [18.1, -77.3],
    "TT": [10.7, -61.2], "PR": [18.2, -66.5], "BS": [24.3, -76.0], "BB": [13.2, -59.5],
    "AE": [23.4, 53.8], "AL": [41.2, 20.2], "AM": [40.1, 45.0], "AZ": [40.1, 47.6],
    "BD": [23.7, 90.4], "BG": [42.7, 25.5], "BY": [53.7, 27.9], "CY": [35.1, 33.4],
    "EE": [58.6, 25.0], "GE": [42.3, 43.4], "GH": [7.9, -1.0], "IS": [64.9, -18.6],
    "JO": [31.2, 36.2], "KW": [29.3, 47.5], "KZ": [48.0, 67.0], "LB": [33.9, 35.9],
    "LK": [7.9, 80.7], "LT": [55.2, 23.9], "LU": [49.8, 6.1], "LV": [56.9, 24.6],
    "MD": [47.0, 28.5], "ME": [42.7, 19.3], "MK": [41.6, 21.7], "MM": [21.9, 95.9],
    "MT": [35.9, 14.4], "NP": [28.4, 84.1], "OM": [21.5, 55.9], "QA": [25.3, 51.2],
    "RS": [44.0, 21.0], "SI": [46.1, 14.9], "SK": [48.7, 19.7], "TN": [34.0, 9.0],
    "UZ": [41.4, 64.6],
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read_previous() -> dict[str, Any]:
    try:
        return json.loads(OUTPUT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def request_json(url: str, *, method: str = "GET", headers: dict[str, str] | None = None,
                 params: dict[str, Any] | None = None, data: dict[str, Any] | None = None) -> dict[str, Any]:
    response = SESSION.request(method, url, headers=headers, params=params, data=data, timeout=TIMEOUT)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("La respuesta JSON no es un objeto.")
    return payload


def fetch_cloudflare(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    checked = now_iso()
    status: dict[str, Any] = {"key": "cloudflare", "name": "Cloudflare Radar", "ok": False,
                              "checked_at": checked, "count": 0, "error": None}
    if not token:
        status["error"] = "Falta el secreto CLOUDFLARE_RADAR_TOKEN."
        return {}, status
    try:
        payload = request_json(
            "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/attacks",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": 20, "dateRange": "1d", "format": "json"},
        )
        if not payload.get("success"):
            raise ValueError(str(payload.get("errors") or "Cloudflare devolvió success=false")[:240])
        result = payload.get("result") or {}
        meta = result.get("meta") or {}
        pairs = []
        for row in result.get("top_0") or []:
            origin = row.get("originCountryAlpha2")
            target = row.get("targetCountryAlpha2")
            if not origin or not target:
                continue
            try:
                value = float(row.get("value", 0))
            except (TypeError, ValueError):
                value = 0.0
            pairs.append({
                "origin_code": origin,
                "origin_country": row.get("originCountryName") or origin,
                "target_code": target,
                "target_country": row.get("targetCountryName") or target,
                "value_pct": value,
                "origin_coords": COUNTRY_CENTROIDS.get(origin),
                "target_coords": COUNTRY_CENTROIDS.get(target),
                "evidence": "Estadística agregada de ataques L7 mitigados por Cloudflare",
            })
        section = {"pairs": pairs, "meta": {
            "last_updated": meta.get("lastUpdated"),
            "date_range": meta.get("dateRange"),
            "normalization": meta.get("normalization"),
            "units": meta.get("units"),
        }, "checked_at": checked, "last_success_at": checked}
        status.update({"ok": True, "count": len(pairs), "source_updated_at": meta.get("lastUpdated"),
                       "error": None, "stale_data": False})
        return section, status
    except Exception as exc:
        status["error"] = str(exc)[:300]
        return {}, status


def fetch_dshield() -> tuple[dict[str, Any], dict[str, Any]]:
    checked = now_iso()
    status: dict[str, Any] = {"key": "dshield", "name": "DShield / SANS ISC", "ok": False,
                              "checked_at": checked, "count": 0, "error": None}
    try:
        response = SESSION.get("https://feeds.dshield.org/feeds/top10.txt", timeout=TIMEOUT)
        response.raise_for_status()
        ips: list[str] = []
        for raw_line in response.text.splitlines():
            candidate = raw_line.strip().split()[0] if raw_line.strip() else ""
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if address.is_global and candidate not in ips:
                ips.append(candidate)
            if len(ips) >= 10:
                break
        section = {"ips": [{"ip": ip, "geo": None, "source": "DShield"} for ip in ips],
                   "count": len(ips), "checked_at": checked, "last_success_at": checked,
                   "feed_url": "https://feeds.dshield.org/feeds/top10.txt"}
        status.update({"ok": True, "count": len(ips), "error": None, "stale_data": False})
        return section, status
    except Exception as exc:
        status["error"] = str(exc)[:300]
        return {}, status


def fetch_threatfox(auth_key: str) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    checked = now_iso()
    status: dict[str, Any] = {"key": "threatfox", "name": "ThreatFox", "ok": False,
                              "checked_at": checked, "count": 0, "error": None}
    if not auth_key:
        status["error"] = "Falta el secreto ABUSECH_AUTH_KEY."
        return {}, status, []
    try:
        payload = request_json("https://threatfox-api.abuse.ch/api/v1/", method="POST",
                               headers={"Auth-Key": auth_key}, data={"query": "get_iocs", "days": 1})
        query_status = payload.get("query_status")
        if query_status not in {"ok", "no_results"}:
            raise ValueError(f"ThreatFox query_status={query_status}")
        all_rows = payload.get("data") or []
        all_rows = sorted(all_rows, key=lambda x: (x.get("last_seen") or x.get("first_seen") or ""), reverse=True)
        compact = []
        ip_values: list[str] = []
        for row in all_rows[:250]:
            ioc = str(row.get("ioc") or "")[:500]
            ioc_type = str(row.get("ioc_type") or "")
            ip_value = extract_ip(ioc, ioc_type)
            if ip_value and ip_value not in ip_values:
                ip_values.append(ip_value)
            compact.append({
                "id": str(row.get("id") or ""), "ioc": ioc, "ioc_type": ioc_type,
                "threat_type": row.get("threat_type"),
                "threat_type_desc": row.get("threat_type_desc"),
                "malware": row.get("malware_printable") or row.get("malware"),
                "confidence_level": row.get("confidence_level"),
                "first_seen": row.get("first_seen"), "last_seen": row.get("last_seen"),
                "reporter": row.get("reporter"),
                "ip": ip_value, "geo": None,
            })
        section = {"indicator_count": len(all_rows), "indicators": compact,
                   "checked_at": checked, "last_success_at": checked}
        status.update({"ok": True, "count": len(all_rows), "sample_count": len(compact),
                       "error": None, "stale_data": False})
        return section, status, ip_values
    except Exception as exc:
        status["error"] = str(exc)[:300]
        return {}, status, []


def extract_ip(value: str, ioc_type: str = "") -> str | None:
    candidate = value.strip()
    lower_type = ioc_type.lower()
    if lower_type in {"ip:port", "ipv4:port", "ipv6:port"}:
        if candidate.startswith("[") and "]" in candidate:
            candidate = candidate[1:candidate.index("]")]
        elif candidate.count(":") == 1:
            candidate = candidate.rsplit(":", 1)[0]
        elif candidate.count(":") > 1:
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                candidate = candidate.rsplit(":", 1)[0]
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return str(address) if address.is_global else None


def fetch_urlhaus(auth_key: str) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    checked = now_iso()
    status: dict[str, Any] = {"key": "urlhaus", "name": "URLhaus", "ok": False,
                              "checked_at": checked, "count": 0, "error": None}
    if not auth_key:
        status["error"] = "Falta el secreto ABUSECH_AUTH_KEY."
        return {}, status, []
    try:
        response = SESSION.get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/50/",
                               headers={"Auth-Key": auth_key}, timeout=TIMEOUT)
        response.raise_for_status()
        payload = response.json()
        query_status = payload.get("query_status")
        if query_status not in {"ok", "no_results"}:
            raise ValueError(f"URLhaus query_status={query_status}")
        rows = payload.get("urls") or []
        compact = []
        ip_values: list[str] = []
        for row in rows[:50]:
            url = str(row.get("url") or "")[:1000]
            host = urlsplit(url).hostname or ""
            host_ip = extract_ip(host, "ip") if host else None
            if host_ip and host_ip not in ip_values:
                ip_values.append(host_ip)
            compact.append({
                "id": str(row.get("id") or ""), "url": url, "host": host,
                "url_status": row.get("url_status"), "threat": row.get("threat"),
                "date_added": row.get("date_added"), "last_online": row.get("last_online"),
                "tags": row.get("tags") or [], "reporter": row.get("reporter"),
                "ip": host_ip, "geo": None,
            })
        section = {"url_count": len(rows), "urls": compact, "checked_at": checked,
                   "last_success_at": checked}
        status.update({"ok": True, "count": len(rows), "error": None, "stale_data": False})
        return section, status, ip_values
    except Exception as exc:
        status["error"] = str(exc)[:300]
        return {}, status, []


def geo_lookup(ip: str) -> dict[str, Any] | None:
    response = SESSION.get(f"https://ipwho.is/{ip}", timeout=TIMEOUT)
    response.raise_for_status()
    row = response.json()
    if not row.get("success"):
        return None
    try:
        lat = float(row.get("latitude"))
        lon = float(row.get("longitude"))
    except (TypeError, ValueError):
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    return {
        "country": row.get("country"), "country_code": row.get("country_code"),
        "region": row.get("region"), "city": row.get("city"),
        "lat": lat, "lon": lon, "geo_source": "IPWho.is",
        "accuracy_note": "Geolocalización aproximada de una IP; no identifica a una persona ni una víctima.",
        "lookup_at": now_iso(),
    }


def cached_geo(cache: dict[str, Any], ip: str) -> dict[str, Any] | None:
    entry = cache.get(ip)
    if not isinstance(entry, dict):
        return None
    try:
        looked = datetime.fromisoformat(str(entry.get("lookup_at", "")).replace("Z", "+00:00"))
        age = datetime.now(timezone.utc) - looked
        if entry.get("unavailable"):
            return entry if age <= timedelta(hours=24) else None
        if age > timedelta(days=30):
            return None
    except ValueError:
        return None
    return entry


def attach_geo(section: dict[str, Any], field: str, cache: dict[str, Any]) -> None:
    for row in section.get(field, []) or []:
        ip = row.get("ip")
        entry = cached_geo(cache, ip) if ip else None
        row["geo"] = entry if isinstance(entry, dict) and isinstance(entry.get("lat"), (int, float)) and isinstance(entry.get("lon"), (int, float)) else None


def update_stale(previous: dict[str, Any], section_key: str, fresh: dict[str, Any], status: dict[str, Any]) -> dict[str, Any]:
    if status.get("ok") and fresh:
        return fresh
    old = previous.get(section_key) or {}
    has_previous_success = bool(old.get("last_success_at") or old.get("pairs") or old.get("ips") or
                                old.get("indicators") or old.get("urls"))
    status["stale_data"] = has_previous_success
    status["last_success_at"] = old.get("last_success_at")
    return old


def main() -> None:
    previous = read_previous()
    cloudflare, cf_status = fetch_cloudflare(os.getenv("CLOUDFLARE_RADAR_TOKEN", "").strip())
    dshield, ds_status = fetch_dshield()
    threatfox, tf_status, tf_ips = fetch_threatfox(os.getenv("ABUSECH_AUTH_KEY", "").strip())
    urlhaus, uh_status, uh_ips = fetch_urlhaus(os.getenv("ABUSECH_AUTH_KEY", "").strip())

    cloudflare = update_stale(previous, "cloudflare", cloudflare, cf_status)
    dshield = update_stale(previous, "dshield", dshield, ds_status)
    threatfox = update_stale(previous, "threatfox", threatfox, tf_status)
    urlhaus = update_stale(previous, "urlhaus", urlhaus, uh_status)

    geo_cache = dict(previous.get("geo_cache") or {})
    prioritized_ips: list[str] = []
    for row in (dshield.get("ips") or []):
        ip = row.get("ip")
        if ip and ip not in prioritized_ips:
            prioritized_ips.append(ip)
    for ip in tf_ips + uh_ips:
        if ip and ip not in prioritized_ips:
            prioritized_ips.append(ip)

    lookups = 0
    geo_errors = 0
    for ip in prioritized_ips:
        if cached_geo(geo_cache, ip):
            continue
        if lookups >= GEO_LOOKUPS_PER_RUN:
            break
        geo_cache.pop(ip, None)  # No reutilizar una geolocalización vencida.
        try:
            geo = geo_lookup(ip)
            if geo:
                geo_cache[ip] = geo
            else:
                geo_errors += 1
                geo_cache[ip] = {"unavailable": True, "lookup_at": now_iso()}
        except Exception as exc:
            geo_errors += 1
            geo_cache[ip] = {"unavailable": True, "lookup_at": now_iso()}
            logging.warning("Geolocalización omitida para %s: %s", ip, str(exc)[:160])
        lookups += 1
        time.sleep(0.15)

    attach_geo(dshield, "ips", geo_cache)
    attach_geo(threatfox, "indicators", geo_cache)
    attach_geo(urlhaus, "urls", geo_cache)

    if len(geo_cache) > GEO_CACHE_MAX:
        ordered = sorted(geo_cache.items(), key=lambda kv: kv[1].get("lookup_at", ""), reverse=True)
        geo_cache = dict(ordered[:GEO_CACHE_MAX])

    run_time = now_iso()
    statuses = [cf_status, ds_status, tf_status, uh_status]
    dshield_geo_count = sum(1 for row in (dshield.get("ips") or []) if row.get("geo"))
    geolocated_ips = set()
    for rows in (dshield.get("ips") or [], threatfox.get("indicators") or [], urlhaus.get("urls") or []):
        for row in rows:
            if row.get("ip") and row.get("geo"):
                geolocated_ips.add(row["ip"])
    geo_count = len(geolocated_ips)
    statuses.append({"key": "geoip", "name": "Geolocalización IP (IPWho.is)",
                     "ok": geo_errors == 0, "checked_at": run_time, "count": geo_count,
                     "error": f"{geo_errors} consultas sin resultado." if geo_errors else None,
                     "stale_data": bool(geo_errors and geo_cache),
                     "note": "Aproximada; límite de 12 IP nuevas por ejecución."})

    payload = {
        "schema_version": 1,
        "generated_at": run_time,
        "last_checked_at": run_time,
        "notice": "Cloudflare muestra estadísticas agregadas de capa 7. DShield informa IP observadas por sensores. ThreatFox y URLhaus publican IOC. Una IP geolocalizada no identifica a una persona ni demuestra una víctima.",
        "cloudflare": cloudflare,
        "dshield": dshield,
        "threatfox": threatfox,
        "urlhaus": urlhaus,
        "geo_cache": geo_cache,
        "source_status": statuses,
        "stats": {
            "cloudflare_pairs": len(cloudflare.get("pairs") or []),
            "dshield_ips": len(dshield.get("ips") or []),
            "threatfox_iocs_24h": threatfox.get("indicator_count", 0),
            "urlhaus_urls_recent": urlhaus.get("url_count", 0),
            "geolocated_dshield_ips": dshield_geo_count,
            "sources_ok": sum(1 for s in statuses[:4] if s.get("ok")),
            "sources_total": 4,
        },
        "attribution": {
            "cloudflare": "Cloudflare Radar · datos bajo CC BY-NC 4.0",
            "dshield": "SANS Technology Institute, Internet Storm Center · isc.sans.edu",
            "threatfox": "abuse.ch / ThreatFox · uso comunitario sujeto a fair use",
            "urlhaus": "abuse.ch / URLhaus · uso comunitario sujeto a fair use",
            "geoip": "IPWho.is · geolocalización aproximada",
        },
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    logging.info("Threatmap actualizado: Cloudflare=%s pares, DShield=%s IP, ThreatFox=%s IOC, URLhaus=%s URL; fuentes OK=%s/4",
                 payload["stats"]["cloudflare_pairs"], payload["stats"]["dshield_ips"],
                 payload["stats"]["threatfox_iocs_24h"], payload["stats"]["urlhaus_urls_recent"],
                 payload["stats"]["sources_ok"])


if __name__ == "__main__":
    main()

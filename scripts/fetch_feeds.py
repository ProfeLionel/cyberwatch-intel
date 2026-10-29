#!/usr/bin/env python3
"""Baja feeds reales de amenazas y genera data/events.json para el threatmap.

Fuentes (todas gratis):
  - abuse.ch Feodo Tracker  -> Botnet / C2      (sin key)
  - DShield / SANS ISC      -> Reconocimiento   (sin key)
  - blocklist.de ssh        -> Fuerza bruta     (sin key)
  - blocklist.de apache     -> Explotación      (sin key)
  - OpenPhish community     -> Phishing         (sin key)
  - abuse.ch ThreatFox      -> Malware / Ransomware (requiere ABUSECH_AUTH_KEY)
  - abuse.ch URLhaus        -> Malware          (requiere ABUSECH_AUTH_KEY)

Geolocalizacion: ip-api.com (batch, gratis, sin key).
Solo libreria estandar -> no necesita pip en GitHub Actions.
"""
import ipaddress
import json
import os
import random
import re
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

OUT = Path("data/events.json")
GEO_URL = "http://ip-api.com/batch?fields=status,query,country,countryCode,lat,lon"
PER_SOURCE = 25  # eventos maximos por fuente
AUTH_KEY = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
UA = "cyberwatch-intel/1.0 (+https://github.com/profelionel/cyberwatch-intel)"
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
socket.setdefaulttimeout(4)


# ---------------------------------------------------------------- utilidades
def http(url, data=None, headers=None, as_json=True):
    h = {"User-Agent": UA}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h)
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read()
    return json.loads(raw) if as_json else raw.decode("utf-8", "replace")


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def resolve(host):
    """Hostname -> IP (o la misma IP si ya lo es)."""
    if not host:
        return None
    host = host.split(":")[0]
    if IPV4.fullmatch(host):
        return host
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def sample(items, n=PER_SOURCE):
    items = list(items)
    return random.sample(items, n) if len(items) > n else items


def ev(category, source, ip, signature, severity, **extra):
    return {
        "category": category,
        "source": source,
        "ip": ip,
        "signature": signature,
        "severity": severity,
        **extra,
    }


# ---------------------------------------------------------------- fuentes
def src_feodo():
    rows = http("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
    rows.sort(key=lambda r: r.get("last_online") or r.get("first_seen") or "", reverse=True)
    return [
        ev("Botnet / C2", "abuse.ch Feodo Tracker", r["ip_address"],
           f"{r.get('malware') or 'C2'} · puerto {r.get('port')}",
           "ALTA" if r.get("status") == "online" else "MEDIA",
           malware=r.get("malware"), port=r.get("port"))
        for r in rows[:PER_SOURCE]
    ]


def src_dshield():
    txt = http("https://feeds.dshield.org/feeds/topips.txt", as_json=False)
    ips = []
    for line in txt.splitlines():
        if line.startswith("#"):
            continue
        m = IPV4.search(line)
        if m:
            # DShield rellena con ceros (045.010.001.002) -> normalizar
            ips.append(".".join(str(int(o)) for o in m.group(0).split(".")))
    return [
        ev("Reconocimiento", "DShield / SANS ISC", ip,
           "Top atacante reportado por sensores DShield", "MEDIA")
        for ip in ips[:PER_SOURCE]
    ]


def src_blocklist(name, category, signature):
    txt = http(f"https://lists.blocklist.de/lists/{name}.txt", as_json=False)
    ips = [l.strip() for l in txt.splitlines() if IPV4.fullmatch(l.strip())]
    return [
        ev(category, f"blocklist.de ({name})", ip, signature, "MEDIA")
        for ip in sample(ips)
    ]


def src_openphish():
    txt = http("https://openphish.com/feed.txt", as_json=False)
    urls = [u.strip() for u in txt.splitlines() if u.strip().startswith("http")]
    out = []
    for u in sample(urls):
        host = urlparse(u).hostname
        out.append(ev("Phishing", "OpenPhish", None,
                      f"Sitio de phishing · {host}", "ALTA", host=host))
    return out


def src_threatfox():
    if not AUTH_KEY:
        print("  (ThreatFox omitido: falta ABUSECH_AUTH_KEY)")
        return []
    res = http("https://threatfox-api.abuse.ch/api/v1/",
               data=json.dumps({"query": "get_iocs", "days": 1}).encode(),
               headers={"Auth-Key": AUTH_KEY, "Content-Type": "application/json"})
    rows = [r for r in (res.get("data") or []) if r.get("ioc_type") in ("ip:port", "domain", "url")]
    out = []
    for r in sample(rows):
        fam = r.get("malware_printable") or "Malware"
        text = (fam + " " + " ".join(r.get("tags") or [])).lower()
        cat = "Ransomware" if "ransom" in text else (
            "Botnet / C2" if r.get("threat_type") == "botnet_cc" else "Malware")
        ioc = r["ioc"]
        host = urlparse(ioc).hostname if "://" in ioc else ioc.split(":")[0]
        out.append(ev(cat, "abuse.ch ThreatFox", None, f"{fam} · {r.get('threat_type')}",
                      "ALTA" if (r.get("confidence_level") or 0) >= 75 else "MEDIA",
                      host=host, malware=fam))
    return out


def src_urlhaus():
    if not AUTH_KEY:
        print("  (URLhaus omitido: falta ABUSECH_AUTH_KEY)")
        return []
    res = http(f"https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{PER_SOURCE * 4}/",
               headers={"Auth-Key": AUTH_KEY})
    rows = [r for r in (res.get("urls") or []) if r.get("url_status") == "online"] or (res.get("urls") or [])
    return [
        ev("Malware", "abuse.ch URLhaus", None,
           f"Distribución de malware · {', '.join(r.get('tags') or []) or r.get('threat')}",
           "ALTA", host=r.get("host"))
        for r in sample(rows)
    ]


SOURCES = [
    ("Feodo", src_feodo),
    ("DShield", src_dshield),
    ("blocklist.de ssh", lambda: src_blocklist("ssh", "Fuerza bruta", "Fuerza bruta SSH")),
    ("blocklist.de apache", lambda: src_blocklist("apache", "Explotación", "Ataque contra servidor web")),
    ("OpenPhish", src_openphish),
    ("ThreatFox", src_threatfox),
    ("URLhaus", src_urlhaus),
]


# ---------------------------------------------------------------- geo
def geolocate(ips):
    geo = {}
    ips = list(dict.fromkeys(ips))
    for i in range(0, len(ips), 100):
        res = http(GEO_URL, data=json.dumps(ips[i:i + 100]).encode(),
                   headers={"Content-Type": "application/json"})
        for g in res:
            if g.get("status") == "success":
                geo[g["query"]] = g
    return geo


def main():
    events = []
    for name, fn in SOURCES:
        try:
            got = fn()
            print(f"✓ {name}: {len(got)}")
            events += got
        except Exception as e:  # una fuente caida no rompe el resto
            print(f"✗ {name}: {e}")

    # Resolver hostnames a IP (en paralelo)
    pending = [e for e in events if not e["ip"]]
    with ThreadPoolExecutor(max_workers=20) as pool:
        for e, ip in zip(pending, pool.map(lambda x: resolve(x.get("host")), pending)):
            e["ip"] = ip

    events = [e for e in events if e["ip"] and is_public(e["ip"])]
    geo = geolocate([e["ip"] for e in events])

    final = []
    for e in events:
        g = geo.get(e["ip"])
        if not g:
            continue
        e["origin"] = {"country": g["country"], "code": g["countryCode"],
                       "lat": g["lat"], "lon": g["lon"]}
        e["destination"] = None  # los feeds publicos no traen victima
        final.append(e)

    random.shuffle(final)  # mezcla categorias para la animacion
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(final),
        "sources": sorted({e["source"] for e in final}),
        "events": final,
    }, ensure_ascii=False, indent=2))
    print(f"\n{len(final)} eventos -> {OUT}")


if __name__ == "__main__":
    main()

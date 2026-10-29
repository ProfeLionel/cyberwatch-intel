#!/usr/bin/env python3
"""Baja feeds reales de amenazas y genera data/events.json para el threatmap.

Fuente actual: abuse.ch Feodo Tracker (servidores C2 de botnets).
Geolocalizacion: ip-api.com (batch, gratis, sin key).
Solo usa la libreria estandar -> no necesita pip en GitHub Actions.
"""
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
GEO_URL = "http://ip-api.com/batch?fields=status,query,country,countryCode,lat,lon"
OUT = Path("data/events.json")
MAX_IPS = 100  # ip-api acepta hasta 100 IPs por request batch


def get_json(url, data=None):
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "User-Agent": "cyberwatch-intel/1.0",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def fetch_feodo():
    rows = get_json(FEODO_URL)
    # Los mas recientes primero
    rows.sort(
        key=lambda r: r.get("last_online") or r.get("first_seen") or "",
        reverse=True,
    )
    return rows[:MAX_IPS]


def geolocate(ips):
    geo = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i : i + 100]
        res = get_json(GEO_URL, json.dumps(chunk).encode())
        for g in res:
            if g.get("status") == "success":
                geo[g["query"]] = g
    return geo


def main():
    rows = fetch_feodo()
    geo = geolocate([r["ip_address"] for r in rows])

    events = []
    for r in rows:
        g = geo.get(r["ip_address"])
        if not g:
            continue
        events.append(
            {
                "category": "Botnet / C2",
                "source": "abuse.ch Feodo Tracker",
                "ip": r["ip_address"],
                "port": r.get("port"),
                "malware": r.get("malware"),
                "status": r.get("status"),
                "first_seen": r.get("first_seen"),
                "last_online": r.get("last_online"),
                "origin": {
                    "country": g["country"],
                    "code": g["countryCode"],
                    "lat": g["lat"],
                    "lon": g["lon"],
                },
                "destination": None,  # los feeds no traen victima
            }
        )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "count": len(events),
                "events": events,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    print(f"{len(events)} eventos -> {OUT}")


if __name__ == "__main__":
    main()

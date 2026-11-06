#!/usr/bin/env python3
"""Serve RADAR's static pages and local JSON snapshots on localhost."""

from __future__ import annotations

import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser(description="Inicia RADAR en un servidor web local.")
    parser.add_argument("--port", type=int, default=8000, help="Puerto HTTP (predeterminado: 8000).")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("el puerto debe estar entre 1 y 65535")

    handler = partial(SimpleHTTPRequestHandler, directory=str(ROOT))
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    print(f"RADAR local disponible en http://127.0.0.1:{args.port}/")
    print(f"Wallboard: http://127.0.0.1:{args.port}/wallboard.html")
    print(f"Threatmap: http://127.0.0.1:{args.port}/threatmap.html")
    print("Para detenerlo, presiona Ctrl+C.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor local detenido.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

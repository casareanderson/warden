#!/usr/bin/env python3
"""Build world.json for the console's attack map from Natural Earth (public domain, naturalearthdata.com).

  python3 tools/make-world-map.py NE_110M.geojson NE_50M.geojson > world.json

Inputs: ne_110m_admin_0_countries.geojson (shapes) and ne_50m_admin_0_countries.geojson (a label point for every
country, so small ones like Singapore or Malta still get a bubble). Output: Equal Earth projection, already turned into
SVG path strings, so the browser needs no map library and nothing is fetched from a CDN. Antarctica is left out.
"""
import json
import math
import sys

W = 1000.0
A1, A2, A3, A4 = 1.340264, -0.081106, 0.000893, 0.003796
M = math.sqrt(3) / 2
XMAX = 2 * math.sqrt(3) * math.pi / (3 * A1)
S = W / (2 * XMAX)
YMAX = A4 * (math.pi / 3) ** 9 + A3 * (math.pi / 3) ** 7 + A2 * (math.pi / 3) ** 3 + A1 * (math.pi / 3)


def project(lon, lat):
    lam, phi = math.radians(lon), math.radians(max(-89.9, min(89.9, lat)))
    t = math.asin(M * math.sin(phi))
    x = 2 * math.sqrt(3) * lam * math.cos(t) / (3 * (9 * A4 * t ** 8 + 7 * A3 * t ** 6 + 3 * A2 * t ** 2 + A1))
    y = A4 * t ** 9 + A3 * t ** 7 + A2 * t ** 3 + A1 * t
    return (x + XMAX) * S, (YMAX - y) * S


def code(p):
    for k in ("ISO_A2", "ISO_A2_EH", "WB_A2"):
        v = (p.get(k) or "").upper()
        if len(v) == 2 and v.isalpha():
            return v
    return None


def ring_path(ring):
    pts = [project(*c[:2]) for c in ring]
    area = 0.5 * abs(sum(x0 * y1 - x1 * y0 for (x0, y0), (x1, y1) in zip(pts, pts[1:] + pts[:1])))
    if area < 0.6:                                        # specks under ~1 px² add bytes, not information
        return ""
    out, last = [], None
    for x, y in pts:
        r = (round(x, 1), round(y, 1))
        if r != last:
            out.append(f"{r[0]:g},{r[1]:g}")
            last = r
    return "M" + "L".join(out) + "Z" if len(out) > 2 else ""


def main(p110, p50):
    shapes, ymax = [], 0.0
    for f in json.load(open(p110))["features"]:
        p, g = f["properties"], f["geometry"]
        cc = code(p)
        if not cc or cc == "AQ" or not g:
            continue
        polys = g["coordinates"] if g["type"] == "MultiPolygon" else [g["coordinates"]]
        d = "".join(ring_path(r) for poly in polys for r in poly)
        if d:
            shapes.append({"cc": cc, "n": p.get("NAME") or p.get("ADMIN"), "d": d})
            ymax = max(ymax, max(float(v.split(",")[1]) for v in d.replace("M", "L").replace("Z", "").split("L") if v))
    pts = {}
    for f in json.load(open(p50))["features"]:
        p = f["properties"]
        cc = code(p)
        if not cc or cc == "AQ" or p.get("LABEL_X") is None:
            continue
        x, y = project(p["LABEL_X"], p["LABEL_Y"])
        pts[cc] = [round(x, 1), round(y, 1), p.get("NAME") or p.get("ADMIN")]
    json.dump({"source": "Natural Earth 1:110m + 1:50m label points (public domain)", "projection": "Equal Earth",
               "w": W, "h": round(ymax + 4, 1), "shapes": shapes, "points": pts}, sys.stdout, separators=(",", ":"))


if __name__ == "__main__":
    main(*sys.argv[1:3])

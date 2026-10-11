"""tools/make-world-map.py: projection bounds, ISO code fallbacks, Antarctica dropped, label points for tiny countries."""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "make-world-map.py"
spec = importlib.util.spec_from_file_location("mkmap", TOOL)
mk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mk)


def square(lon, lat, d=10):
    return [[[lon, lat], [lon + d, lat], [lon + d, lat + d], [lon, lat + d], [lon, lat]]]


def fc(*feats):
    return {"type": "FeatureCollection", "features": [{"type": "Feature", "properties": p, "geometry": g} for p, g in feats]}


def test_projection_bounds():
    x0, _ = mk.project(-180, 0)
    x1, _ = mk.project(180, 0)
    _, ytop = mk.project(0, 90)
    xc, yc = mk.project(0, 0)
    assert abs(x0) < 0.01 and abs(x1 - mk.W) < 0.01 and abs(ytop) < 0.5
    assert abs(xc - mk.W / 2) < 0.01 and yc > 200


def test_build(tmp_path):
    p110 = tmp_path / "110.geojson"
    p50 = tmp_path / "50.geojson"
    p110.write_text(json.dumps(fc(
        ({"ISO_A2": "GB", "NAME": "United Kingdom"}, {"type": "Polygon", "coordinates": square(-5, 50)}),
        ({"ISO_A2": "-99", "ISO_A2_EH": "FR", "NAME": "France"}, {"type": "MultiPolygon", "coordinates": [square(0, 43)]}),
        ({"ISO_A2": "AQ", "NAME": "Antarctica"}, {"type": "Polygon", "coordinates": square(0, -80)}),
        ({"ISO_A2": "-99", "NAME": "Nowhere"}, {"type": "Polygon", "coordinates": square(20, 20)}),
        ({"ISO_A2": "XS", "NAME": "Speck"}, {"type": "Polygon", "coordinates": square(30, 0, 0.01)}))))
    p50.write_text(json.dumps(fc(
        ({"ISO_A2": "SG", "NAME": "Singapore", "LABEL_X": 103.8, "LABEL_Y": 1.35}, None),
        ({"ISO_A2": "AQ", "NAME": "Antarctica", "LABEL_X": 0, "LABEL_Y": -80}, None))))
    out = subprocess.run([sys.executable, "-I", str(TOOL), str(p110), str(p50)], capture_output=True, text=True, check=True)
    w = json.loads(out.stdout)
    assert [s["cc"] for s in w["shapes"]] == ["GB", "FR"]          # code fallback, AQ + no-code + specks dropped
    assert w["shapes"][0]["d"].startswith("M") and w["shapes"][0]["d"].endswith("Z")
    assert set(w["points"]) == {"SG"} and w["w"] == 1000 and 0 < w["h"] < 500


def test_shipped_world_json_is_sane():
    w = json.loads((ROOT / "world.json").read_text())
    codes = {s["cc"] for s in w["shapes"]}
    assert len(w["shapes"]) > 150 and {"US", "GB", "FR", "NO", "CN", "RU", "BR"} <= codes and "AQ" not in codes
    assert {"SG", "MT", "HK"} <= set(w["points"])                   # too small for 1:110m shapes, still get a bubble
    assert (ROOT / "world.json").stat().st_size < 200_000

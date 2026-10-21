"""AI recommendations for pending approvals.

warden gathers the facts (detectors, scanners, patch plans) and the owner was
having to weigh each one by hand. This adds the missing layer: for every pending
approval the model reads the already-gathered facts in the approval text and
returns a ✅ (approve/accept) or ❌ (reject/keep open) with a one-line reason.

It RECOMMENDS, it never decides. The owner still taps the button — or bulk-applies
the picks. Facts are gathered by warden's detectors; the model only weighs them,
so the estate rule "scripts gather facts, models never invent them" still holds.

Cached per approval id in data/recommend.json so a refresh does not re-call the
model for the same proposal.
"""
import json
import re
import time

from . import config, secrets, notify

CACHE = config.DATA / "recommend.json"
MODEL = "qwen/qwen3.7-flash"          # cheap + tool-capable; these calls are ~200 tokens


def _model_cfg():
    b = config.get("brief") or {}
    url = (b.get("url") or "https://openrouter.ai/api/v1").rstrip("/") + "/chat/completions"
    model = (b.get("recommend_model") or MODEL)
    key = secrets.get(b.get("key_secret") or "OPENROUTER_API_KEY") or ""
    return url, model, key


def _ask(text):
    import requests  # noqa: PLC0415 - only needed here
    url, model, key = _model_cfg()
    try:
        r = requests.post(url, timeout=40,
                          headers={"Authorization": "Bearer " + key} if key else {},
                          json={"model": model, "temperature": 0.1, "max_tokens": 256,
                                "reasoning": {"enabled": False},
                                "messages": [
                                    {"role": "system",
                                     "content": ("You are warden's review assistant. The facts below were already "
                                                 "gathered by warden's detectors. Recommend exactly one decision: "
                                                 "✅ (approve / accept as the new baseline) or ❌ (reject / keep open "
                                                 "for investigation). Reply on ONE line:  ✅|<short reason>  or  "
                                                 "❌|<short reason>. No preamble.")},
                                    {"role": "user", "content": text[:3000]}]})
        msg = (r.json()["choices"][0].get("message") or {})
        out = (msg.get("content") or msg.get("reasoning") or "").strip()
        out = re.sub(r"(?s)<think>.*?</think>", "", out).strip()   # reasoning models
        m = re.match(r"^\s*([✅❌])\s*[|:,\-–]?\s*(.{0,140})", out)
        if m:
            reason = m.group(2).strip().rstrip(".") or "no reason given"
            return model, m.group(1), reason
        return model, None, "unparseable (%s)" % out[:60]
    except Exception as e:  # noqa: BLE001
        return model, None, "%s: %s" % (type(e).__name__, str(e)[:80])


def _load():
    try:
        return json.loads(CACHE.read_text())
    except Exception:  # noqa: BLE001
        return {}


def _save(d):
    config.DATA.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(d, indent=1))


def recommendations(refresh=False):
    """[{id, text, choices, choice, reason, model}] for every pending approval.

    Model calls run in parallel (they are I/O-bound HTTP requests); a run with
    the full pending queue finishes in a few batches instead of one-by-one.
    """
    pending = notify.pending()
    cache = _load()
    by_id = {a["id"]: a for a in pending}
    out = {}
    to_ask = []
    for a in pending:
        rec = cache.get(a["id"])
        if rec and not refresh and rec.get("choice"):
            out[a["id"]] = {**a, "choice": rec["choice"], "reason": rec["reason"], "model": rec["model"]}
        else:
            to_ask.append(a)

    if to_ask:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        answers = {}
        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = {ex.submit(_ask, a["text"]): a["id"] for a in to_ask}
            for fut in as_completed(futs):
                try:
                    model, choice, reason = fut.result()
                except Exception:  # noqa: BLE001
                    model, choice, reason = None, None, "error"
                answers[futs[fut]] = (model, choice, reason)
        changed = False
        for a in to_ask:
            model, choice, reason = answers.get(a["id"], (None, None, "error"))
            rec = {"choice": choice, "reason": reason, "model": model,
                   "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            cache[a["id"]] = rec
            changed = True
            out[a["id"]] = {**a, "choice": choice, "reason": reason, "model": model}
        if changed:
            _save(cache)

    return [out[a["id"]] for a in pending]

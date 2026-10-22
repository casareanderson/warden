"""mentor — AI code review, the engine behind the `mentor` CLI and warden's `review.py` collector.

warden gathers facts (the estate has no code-review record of its own); mentor reads a diff and says what is wrong
with it, in a shape a person can act on. It never edits, commits, pushes, merges or approves anything — it only
reports findings.

Config (warden.yml). Without `review:` it falls back to the same endpoint as the vulnerability briefing:
    review:
      url: https://openrouter.ai/api/v1        # any OpenAI-compatible endpoint (OpenRouter, local Ollama…)
      model: qwen/qwen3.7-flash
      key_secret: OPENROUTER_API_KEY
"""
import json
import re

from . import config, secrets

SYSTEM = """You are mentor, a careful code reviewer for a small homelab/side-business estate.
You are given a git diff (and, if present, the PR title). Review it for things that would actually cause harm or
surprise: security holes (injection, secrets in code/logs, unsafe shell/docker/path handling, broken authz), silent
data loss, a regression, or a mistake the author clearly did not intend. Ignore style, naming and nitpicks unless
they hide a bug. Say nothing that is not visible in the diff.

Reply with JSON only, no markdown fences, no commentary outside the JSON:
{"verdict": "approve" | "comment" | "changes",
 "summary": "one or two sentences",
 "findings": [{"severity": "high" | "med" | "low", "file": "path", "line": 0,
               "title": "short title", "why": "what is wrong and why it matters"}]}
"changes" = must not merge as-is; "comment" = worth fixing, not blocking; "approve" = nothing worth reporting.
A file or line you cannot determine may be empty / 0."""


def _cfg():
    r = config.get("review") or {}
    b = config.get("vuln.brief") or {}
    url = (r.get("url") or b.get("url") or "https://openrouter.ai/api/v1").rstrip("/") + "/chat/completions"
    model = r.get("model") or (b.get("models") or [b.get("model") or "qwen/qwen3.7-flash"])[0]
    key = secrets.get(r.get("key_secret") or b.get("key_secret") or "OPENROUTER_API_KEY") or ""
    return url, model, key


def _parse(text):
    """Pull the JSON out of whatever the model wrapped it in (```json fences, stray prose)."""
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("no JSON in model output: " + text[:120])
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        # a trailing comma or a smart quote is enough to break json.loads — best-effort repair before giving up
        fixed = re.sub(r",\s*([}\]])", r"\1", m.group(0)).replace("\u201c", '"').replace("\u201d", '"')
        return json.loads(fixed)


def review(diff, title="", url=None, model=None, key=None):
    """One diff → {"verdict", "summary", "findings": [...], "model"}. Raises RuntimeError if the model is unreachable."""
    import requests  # noqa: PLC0415 - only needed here
    url = url or _cfg()[0]
    model = model or _cfg()[1]
    key = key if key is not None else _cfg()[2]
    text = (title + "\n\n" if title else "") + (diff or "")[:24000]
    r = requests.post(url, timeout=120,
                      headers={"Authorization": "Bearer " + key} if key else {},
                      json={"model": model, "temperature": 0.1, "max_tokens": 2000,
                            "reasoning": {"enabled": False},
                            "messages": [{"role": "system", "content": SYSTEM},
                                         {"role": "user", "content": text}]})
    r.raise_for_status()
    out = (r.json()["choices"][0].get("message") or {}).get("content") or ""
    out = re.sub(r"(?s)<think>.*?</think>", "", out).strip()   # reasoning models
    d = _parse(out)
    d.setdefault("verdict", "comment")
    d.setdefault("summary", "")
    d.setdefault("findings", [])
    d["model"] = model
    return d

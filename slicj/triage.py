"""Triage: rules propose, a decision model disposes.

For each rule finding we build a `state` (what the model may see) and ask typed
questions. Code makes the final decision with a threshold tuned on training
folds, so the model is one swappable component:

  JevBackend   - TypeSafe Jev (System One decision model) via OpenRouter's
                 Decisions API; returns P(yes) for a Noul question.
  ChatBackend  - any chat LLM via OpenRouter chat completions, asked for a JSON
                 probability (the "LLM baseline").
  ClaudeCLIBackend - the same prompt through the local `claude -p` CLI (fallback
                 when no OpenRouter key is present).

All responses are cached on disk under results/cache/<backend>/<model>/.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .context import explain_rule, features, masked_window, safe_value
from .rules import CWE, LABEL, SECRET, Finding

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "results" / "cache"

# Definitions given to the oracle raters (GLITCH replication package, info-files/smells-description.txt)
DEFINITIONS = {
    "admin_by_default": "Specifying default users as administrative users, or giving more privileges than "
                        "necessary (e.g. running a resource as root or connecting to a database as root).",
    "empty_password": "Using a string of length zero (or nil/undef) as a password.",
    "hardcoded_secret": "Revealing sensitive information such as user names, passwords or private cryptography "
                        "keys as literal configuration values in the script.",
    "invalid_bind": "Assigning the address 0.0.0.0 to a database server or a cloud service/instance.",
    "suspicious_comment": "Comments that reveal defects, missing functionality or weakness of the system, "
                          "e.g. TODO, FIXME, HACK, bug references.",
    "http_without_tls": "Using HTTP without SSL/TLS for communication, which is open to man-in-the-middle attacks.",
    "weak_crypto": "Using weak cryptography algorithms, namely MD5 and SHA-1, for security purposes.",
    "tls_verify_disabled": "Switching off TLS certificate verification (validate_certs: no, curl -k, ...).",
}


def load_env():
    env = ROOT / ".env"
    if env.exists():
        for ln in env.read_text().splitlines():
            if "=" in ln and not ln.strip().startswith("#"):
                k, v = ln.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip("'\""))


# ------------------------------------------------------------------ state
def build_state(f: Finding, lines: list[str], variant: str = "full", tech: str = "") -> dict:
    """variant: 'line'   - smell + rule + the flagged line only
                'full'   - + context features, +-3 line window, file path, module
                'full_nocomments' - 'full' with comments removed from the code window
                'full_strict' - also removed from the flagged line
       Literal secrets are masked in every variant (see context.safe_value)."""
    feat = features(f, lines)
    strict = variant == "full_strict"
    # 'full_strict' also strips comments from the flagged line itself (the v1 mitigation
    # 'full_nocomments' only stripped them from the code window, which left inline comments in)
    line_txt = masked_window(lines, f.line, radius=0, keep_comments=not strict)
    st = {
        "linter_finding": {
            "smell": LABEL[f.smell],
            "cwe": CWE[f.smell],
            "definition": DEFINITIONS[f.smell],
            "why_flagged": explain_rule(f),
            "flagged_name": f.name,
            "flagged_value_preview": safe_value(f),
        },
        "flagged_line": line_txt,
    }
    if variant == "line":
        return st
    keep_comments = variant not in ("full_nocomments", "full_strict")
    st["technology"] = tech
    st["file_path"] = f.file
    st["code_window"] = masked_window(lines, f.line, radius=3, keep_comments=keep_comments)
    st["facts_computed_by_code"] = {
        "token_kind": feat["token_kind"],
        "value_kind": feat["value_kind"],
        "value_shape": feat["value_shape"],
        "looks_like_placeholder": feat["placeholder"],
        "entropy_bucket": feat["entropy_bucket"],
        "known_key_format": feat["key_format"],
        "value_length": feat["value_len"],
        "is_common_system_account": feat["system_user"],
        "url_host_scope": feat["host_scope"],
        "url_kind": feat["url_kind"],
        "path_purpose": feat["path_purpose"],
        "owning_module_or_resource": feat["module"],
    }
    if f.smell == "suspicious_comment" and not keep_comments:
        # the finding *is* a comment; keep its text but mark it as untrusted data
        st["linter_finding"]["comment_text_untrusted"] = f.value[:200]
    return st


QUESTIONS = {
    "real_issue": {
        "type": "noul",
        "instructions": "Is the linter finding a genuine instance of the named security smell in this code, "
                        "according to the definition in linter_finding.definition?",
        "criteria": {
            "true": "The flagged code really matches the smell definition (for example a literal credential or "
                    "user name, a real admin/root default, an http:// endpoint used for communication, a comment "
                    "that admits a defect or missing work).",
            "false": "The flag is a false alarm: the name only looks sensitive, the value is not a credential, "
                     "the URL is not used for communication, the comment does not reveal a defect, or the rule "
                     "matched an unrelated token.",
        },
    },
}
AUX_QUESTIONS = {
    "placeholder": {
        "type": "noul",
        "instructions": "Is the flagged value an example or placeholder rather than a value that would work in a "
                        "real deployment?",
    },
    "purpose": {
        "type": "choice",
        "instructions": "What is the file at file_path most likely used for?",
        "criteria": {"production": "Deploys or configures real systems.",
                     "test_or_ci": "Tests, CI or molecule scenarios.",
                     "example_or_training": "Examples, docs, demos, tutorials or training.",
                     "unclear": "Cannot tell."},
    },
}


# ------------------------------------------------------------------ backends
class _Cache:
    def __init__(self, backend: str, model: str):
        self.dir = CACHE / backend / re.sub(r"[^A-Za-z0-9._-]+", "_", model)
        self.dir.mkdir(parents=True, exist_ok=True)

    def key(self, payload) -> Path:
        h = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:32]
        return self.dir / f"{h}.json"

    def get(self, payload):
        p = self.key(payload)
        return json.loads(p.read_text()) if p.exists() else None

    def put(self, payload, resp):
        self.key(payload).write_text(json.dumps({"request": payload, "response": resp}, indent=1))


class JevBackend:
    URL = "https://openrouter.ai/api/alpha/decisions"

    def __init__(self, model: str = "typesafe/jev-1.13", aux: bool = False):
        load_env()
        self.model = model
        self.aux = aux
        self.key = os.environ.get("OPENROUTER_API_KEY", "")
        self.cache = _Cache("decisions", model)
        self.cost = 0.0
        self.lock = threading.Lock()

    def payload(self, state):
        q = dict(QUESTIONS)
        if self.aux:
            q.update(AUX_QUESTIONS)
        return {"model": self.model, "state": state, "questions": q}

    def ask(self, state) -> dict:
        import requests
        payload = self.payload(state)
        hit = self.cache.get(payload)
        if hit is not None:
            return hit["response"]
        if not self.key:
            raise RuntimeError("OPENROUTER_API_KEY is not set (put it in .env)")
        last = None
        for attempt in range(6):
            t0 = time.time()
            r = requests.post(self.URL, json=payload, timeout=90,
                              headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json",
                                       "X-Title": "SLIC-J research prototype"})
            if r.status_code == 200:
                resp = r.json()
                resp["_latency_s"] = round(time.time() - t0, 3)
                self.cache.put(payload, resp)
                with self.lock:
                    self.cost += float(resp.get("usage", {}).get("cost") or 0)
                return resp
            last = f"{r.status_code} {r.text[:300]}"
            if r.status_code in (400, 401, 402, 403, 404, 413):
                break
            time.sleep(2 ** attempt)
        raise RuntimeError(f"decisions API failed: {last}")

    def prob(self, state) -> float:
        return float(self.ask(state)["answers"]["real_issue"]["noul"])


CHAT_PROMPT = """You triage findings from an infrastructure-as-code security linter.
Decide if the finding is a genuine instance of the named security smell, using the definition given.
Return only JSON: {{"real_issue_probability": <number from 0 to 1>}}

{state}"""


def _parse_prob(text: str) -> float:
    m = re.search(r'"real_issue_probability"\s*:\s*([0-9.]+)', text)
    if not m:
        m = re.search(r"([01](?:\.\d+)?)", text)
    if not m:
        raise ValueError(f"no probability in: {text[:200]}")
    return max(0.0, min(1.0, float(m.group(1))))


class ChatBackend:
    URL = "https://openrouter.ai/api/v1/chat/completions"

    def __init__(self, model: str):
        load_env()
        self.model = model
        self.key = os.environ.get("OPENROUTER_API_KEY", "")
        self.cache = _Cache("chat", model)
        self.cost = 0.0
        self.lock = threading.Lock()

    def payload(self, state):
        return {"model": self.model, "temperature": 0, "max_tokens": 400,
                "messages": [{"role": "user", "content": CHAT_PROMPT.format(state=json.dumps(state, indent=1))}]}

    def prob(self, state) -> float:
        import requests
        payload = self.payload(state)
        hit = self.cache.get(payload)
        if hit is not None:
            return _parse_prob(hit["response"]["choices"][0]["message"]["content"])
        if not self.key:
            raise RuntimeError("OPENROUTER_API_KEY is not set (put it in .env)")
        last = None
        for attempt in range(6):
            t0 = time.time()
            r = requests.post(self.URL, json=payload, timeout=180,
                              headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"})
            if r.status_code == 200:
                resp = r.json()
                resp["_latency_s"] = round(time.time() - t0, 3)
                content = resp["choices"][0]["message"]["content"] or ""
                p = _parse_prob(content)
                self.cache.put(payload, resp)
                with self.lock:
                    self.cost += float(resp.get("usage", {}).get("cost") or 0)
                return p
            last = f"{r.status_code} {r.text[:300]}"
            if r.status_code in (400, 401, 402, 403, 404):
                break
            time.sleep(2 ** attempt)
        raise RuntimeError(f"chat API failed: {last}")


SYSTEM_CLI = "You are a precise classifier for security linter findings. Reply with the requested JSON only."


class ClaudeCLIBackend:
    """Uses the local Claude Code CLI in print mode. No API key needed."""

    def __init__(self, model: str = "haiku"):
        self.model = model
        self.cache = _Cache("claude_cli", model)
        self.cost = 0.0

    def prob(self, state) -> float:
        prompt = CHAT_PROMPT.format(state=json.dumps(state, indent=1))
        payload = {"model": self.model, "prompt": prompt}
        hit = self.cache.get(payload)
        if hit is not None:
            return _parse_prob(hit["response"]["text"])
        t0 = time.time()
        # isolated as far as the CLI allows: no tools, no MCP, no project settings, fixed system prompt
        p = subprocess.run(["claude", "-p", "--model", self.model, "--output-format", "json",
                            "--setting-sources", "project", "--strict-mcp-config", "--tools", "",
                            "--no-session-persistence", "--system-prompt", SYSTEM_CLI],
                           input=prompt, capture_output=True, text=True, timeout=300, cwd=str(ROOT / "results"))
        if p.returncode != 0:
            raise RuntimeError(p.stderr[:300])
        out = json.loads(p.stdout)
        text = out.get("result", "")
        prob = _parse_prob(text)
        self.cache.put(payload, {"text": text, "cost_usd": out.get("total_cost_usd"), "_latency_s": time.time() - t0})
        self.cost += float(out.get("total_cost_usd") or 0)
        return prob


def score_all(backend, states: list[dict], workers: int = 8) -> list[float | None]:
    def one(st):
        try:
            return backend.prob(st)
        except Exception as e:  # keep going; report failures
            print("triage error:", str(e)[:200])
            return None
    with ThreadPoolExecutor(workers) as ex:
        return list(ex.map(one, states))

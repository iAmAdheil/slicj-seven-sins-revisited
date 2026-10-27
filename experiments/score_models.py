"""Score every RQ3 candidate with a decision model or a chat LLM.

  python experiments/score_models.py jev-line      --backend jev  --variant line
  python experiments/score_models.py jev-full      --backend jev  --variant full
  python experiments/score_models.py llm-full      --backend chat --model <openrouter model id> --variant full
Writes results/rq3/scores_<name>.json (one probability per candidate, same
order as experiments/rq3_triage.collect()).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.rq3_triage import OUT, collect  # noqa
from slicj.triage import ChatBackend, ClaudeCLIBackend, JevBackend, build_state, score_all  # noqa


def make_backend(kind, model):
    if kind == "jev":
        return JevBackend(model or "typesafe/jev-1.13")
    if kind == "chat":
        return ChatBackend(model)
    if kind == "claude":
        return ClaudeCLIBackend(model or "haiku")
    raise ValueError(kind)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("--backend", default="jev", choices=["jev", "chat", "claude"])
    ap.add_argument("--model", default=None)
    ap.add_argument("--variant", default="full", choices=["line", "full", "full_nocomments", "full_strict"])
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    rows, _ = collect()
    if a.limit:
        rows = rows[:a.limit]
    states = [build_state(r["finding"], r["lines"], a.variant, r["tech"]) for r in rows]
    be = make_backend(a.backend, a.model)
    t0 = time.time()
    scores = score_all(be, states, workers=a.workers)
    dt = time.time() - t0
    fails = sum(s is None for s in scores)
    out = {"name": a.name, "backend": a.backend, "model": getattr(be, "model", a.model), "variant": a.variant,
           "n": len(scores), "failures": fails, "wall_s": round(dt, 1), "cost_usd": round(be.cost, 6),
           "scores": scores}
    with open(OUT / f"scores_{a.name}.json", "w") as fh:
        json.dump(out, fh, indent=1)
    print(f"{a.name}: {len(scores)} scored, {fails} failures, {dt:.1f}s, new cost ${be.cost:.4f}")


if __name__ == "__main__":
    main()

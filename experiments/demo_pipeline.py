"""Whole SLIC-J pipeline on ONE script, printed stage by stage. Writes no files, never calls the API.

  .venv/bin/python experiments/demo_pipeline.py [FILE] [--threshold 0.5] [--show-state N] [--variant full]

Stages:  input -> parse -> rules -> context facts -> masked state -> Jev answer -> keep/drop -> check vs oracle

The Jev answer is read from the disk cache (results/cache). A finding with no cached answer is shown as
"no cached answer": this script never sends a request. Cached answers exist for the GLITCH oracle files
(files in data/glitch_rootfs/RESULTS/*/oracle-dataset), so use one of those as FILE.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.common import ROOT, oracle  # noqa
from slicj.evaluate import match  # noqa
from slicj.rules import SEVEN  # noqa
from slicj.scanner import language_of, scan_file, tokens_of  # noqa
from slicj.triage import JevBackend, build_state  # noqa

# Chosen because it shows triage clearly (8 findings, 4 false alarms). It is one hand-picked file, not a
# representative sample. For a file where the untuned threshold hurts, try the bifrost Ansible file in
# data/glitch_rootfs/RESULTS/ansible/oracle-dataset/.
DEFAULT = ("data/glitch_rootfs/RESULTS/puppet/oracle-dataset/"
           "quintel@boxen-modules-osx-manifests-recovery_message.pp")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?", default=DEFAULT)
    ap.add_argument("--threshold", type=float, default=0.5, help="keep a finding if P(true) >= this (default 0.5)")
    ap.add_argument("--show-state", type=int, default=1, help="print the full model input for the first N findings")
    ap.add_argument("--variant", default="full", choices=["line", "full", "full_nocomments", "full_strict"])
    ap.add_argument("--model", default="typesafe/jev-1.13")
    a = ap.parse_args()

    path = Path(a.file)
    if not path.is_absolute():
        path = ROOT / path
    tech = language_of(str(path))
    if tech is None:
        sys.exit("unsupported file type (need .pp, .yml/.yaml or .rb)")
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.split("\n")
    base = path.name

    print("=" * 78)
    print("STAGE 0  INPUT")
    print(f"  file: {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}")
    print(f"  language (from extension): {tech}   lines: {len(lines)}")

    toks = tokens_of(str(path), text, str(path))
    print("\nSTAGE 1  PARSE  (script -> SLIC tokens: kind, name, value, line)")
    print(f"  {len(toks)} tokens:", dict(Counter(t.kind for t in toks)))
    for t in toks[:3]:
        print("   e.g.", t)

    fs = [f for f in scan_file(str(path), "slicj", rel=str(path)) if f.smell in SEVEN]
    for f in fs:
        f.file = base          # same naming as the experiments, so the cache keys match
    print("\nSTAGE 2  RULES  (candidate generator, tuned for high recall)")
    print(f"  {len(fs)} candidate findings:", dict(Counter(f.smell for f in fs)))

    orc = [o for o in oracle(tech) if o.file == base] if tech in ("puppet", "ansible", "chef") else []
    labels = match(fs, orc)[0] if orc else [None] * len(fs)
    be = JevBackend(a.model)

    print("\nSTAGE 3-6  CONTEXT FACTS -> MASKED STATE -> JEV -> KEEP/DROP")
    print(f"  variant={a.variant}  model={a.model}  threshold={a.threshold}")
    shown = 0
    rows = []
    for f in fs:
        st = build_state(f, lines, a.variant, tech)
        if shown < a.show_state:
            shown += 1
            print("\n  --- model input for the first finding (this is everything the model sees) ---")
            print(json.dumps(st, indent=2))
            print("  --- the question sent with it ---")
            print(json.dumps(be.payload(st)["questions"], indent=2))
            print("  ---\n")
        hit = be.cache.get(be.payload(st))
        p = float(hit["response"]["answers"]["real_issue"]["noul"]) if hit else None
        rows.append((f, p))

    print(f"  {'line':>4}  {'smell':<18} {'P(true)':>7}  {'decision':<8} {'oracle':<12} value")
    for (f, p), lab in zip(rows, labels):
        dec = "no-model" if p is None else ("KEEP" if p >= a.threshold else "drop")
        o = "n/a" if lab is None else ("real" if lab else "false alarm")
        ps = "  -  " if p is None else f"{p:.3f}"
        print(f"  {f.line:>4}  {f.smell:<18} {ps:>7}  {dec:<8} {o:<12} {(f.value or '')[:34]!r}")

    scored = [(f, p, l) for (f, p), l in zip(rows, labels) if p is not None]
    print("\nSTAGE 7  SUMMARY")
    print(f"  rules produced {len(fs)} findings; Jev answers found in cache for {len(scored)}")
    if scored:
        kept = [(f, p, l) for f, p, l in scored if p >= a.threshold]
        print(f"  kept {len(kept)}, dropped {len(scored) - len(kept)}")
        if all(l is not None for _, _, l in scored):
            tp0 = sum(bool(l) for _, _, l in scored)
            tp1 = sum(bool(l) for _, _, l in kept)
            print(f"  before triage: {tp0} real / {len(scored) - tp0} false alarms   (precision {tp0 / len(scored):.2f})")
            if kept:
                print(f"  after  triage: {tp1} real / {len(kept) - tp1} false alarms   (precision {tp1 / len(kept):.2f})")
            print(f"  real findings lost by triage: {tp0 - tp1}")
        print("  (one file is a tiny sample. The paper's numbers use all 269 candidates and a tuned threshold.)")
    else:
        print("  no cached answers for this file. Use a file from the GLITCH oracle dataset.")


if __name__ == "__main__":
    main()

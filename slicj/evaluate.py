"""Precision / recall against the GLITCH oracle datasets.

Matching follows GLITCH's calculate-metrics.py (ASE'22 replication package):
  * a finding is a TP if the oracle has the same file, category and line;
  * for weak crypto and invalid IP binding, file + category is enough
    (GLITCH relaxed these two because of line-precision problems);
  * every oracle entry matches at most one finding and vice versa;
  * 'No smell' is file-level: TP if the tool reports nothing for a clean file.
Smells outside the seven sins (no integrity check, missing default case) are
not scored, because SLIC never claimed them.
"""
from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass

from .rules import ADMIN, BIND, CRYPTO, EMPTY_PW, HTTP, SECRET, SEVEN, SUSP

ORACLE_CAT = {
    "Admin by default": ADMIN, "Empty password": EMPTY_PW, "Hard-coded secret": SECRET,
    "Unrestricted IP Address": BIND, "Suspicious comment": SUSP, "Use of HTTP without SSL/TLS": HTTP,
    "Use of weak cryptography algorithms": CRYPTO, "none": "none",
    "No integrity check": "other", "Missing Default in Case Statement": "other",
}
GLITCH_ERR = {"admin-by-default": ADMIN, "empty-password": EMPTY_PW, "hardcoded-secret": SECRET,
              "improper ip address binding": BIND, "suspicious comment": SUSP, "use of http": HTTP,
              "weak cryptography algorithms": CRYPTO}
FILE_LEVEL = {CRYPTO, BIND}


@dataclass
class OracleEntry:
    file: str
    line: int
    smell: str
    agreement: int


def load_oracle(path: str) -> list[OracleEntry]:
    out = []
    with open(path) as fh:
        for r in csv.DictReader(fh):
            out.append(OracleEntry(r["PATH"], int(r["LINE"]), ORACLE_CAT[r["CATEGORY"]], int(r.get("AGREEMENT") or 0)))
    return out


def match(findings, oracle: list[OracleEntry]):
    """Label each finding TP/FP. Returns (labels: list[bool], fn: list[OracleEntry])."""
    used = [False] * len(findings)
    labels = [False] * len(findings)
    fn = []
    idx = defaultdict(list)
    for i, f in enumerate(findings):
        idx[(f.file, f.smell)].append(i)
    for o in oracle:
        if o.smell in ("none", "other"):
            continue
        cands = idx.get((o.file, o.smell), [])
        hit = None
        for i in cands:
            if not used[i] and findings[i].line == o.line:
                hit = i
                break
        if hit is None and o.smell in FILE_LEVEL:
            hit = next((i for i in cands if not used[i]), None)
        if hit is None:
            fn.append(o)
        else:
            used[hit] = labels[hit] = True
    return labels, fn


def scores(findings, oracle, keep=None):
    """Per-smell precision/recall/F1. `keep` is an optional mask of findings kept after triage."""
    if keep is None:
        keep = [True] * len(findings)
    labels, _ = match(findings, oracle)
    res = {}
    n_true = defaultdict(int)
    for o in oracle:
        n_true[o.smell] += 1
    for s in SEVEN:
        tp = sum(1 for f, l, k in zip(findings, labels, keep) if k and l and f.smell == s)
        fp = sum(1 for f, l, k in zip(findings, labels, keep) if k and not l and f.smell == s)
        fn = n_true[s] - tp
        res[s] = _prf(tp, fp, fn)
    # file-level 'no smell'
    files = {o.file for o in oracle}
    clean = {o.file for o in oracle if o.smell == "none"}
    flagged = {f.file for f, k in zip(findings, keep) if k and f.smell in SEVEN}
    tp = len(clean - flagged)
    fp = len((files - clean) - flagged)       # smelly file reported clean
    fn = len(clean & flagged)
    res["none"] = _prf(tp, fp, fn)
    tot_tp = sum(res[s]["tp"] for s in SEVEN)
    tot_fp = sum(res[s]["fp"] for s in SEVEN)
    tot_fn = sum(res[s]["fn"] for s in SEVEN)
    res["micro"] = _prf(tot_tp, tot_fp, tot_fn)
    present = [s for s in SEVEN if res[s]["support"] > 0 or res[s]["tp"] + res[s]["fp"] > 0]
    res["macro"] = {
        "precision": _mean([res[s]["precision"] for s in present if res[s]["precision"] is not None]),
        "recall": _mean([res[s]["recall"] for s in present if res[s]["recall"] is not None]),
    }
    return res


def _mean(xs):
    return sum(xs) / len(xs) if xs else None


def _prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * r / (p + r) if p and r else (0.0 if p is not None and r is not None else None)
    return {"tp": tp, "fp": fp, "fn": fn, "support": tp + fn, "precision": p, "recall": r, "f1": f1}


def load_tool_csv(path: str, tech: str):
    """Read SLIC / SLAC / GLITCH output CSVs from the replication package into light findings."""
    from .rules import Finding
    out = []
    with open(path, newline="") as fh:
        rd = csv.reader(fh)
        header = next(rd)
        cols = {h: i for i, h in enumerate(header)}
        for r in rd:
            if not r:
                continue
            err = r[cols["ERROR"]] if "ERROR" in cols else r[1]
            smell = GLITCH_ERR.get(err)
            if smell is None:
                continue
            line = int(r[cols["LINE"]]) if "LINE" in cols else -1
            out.append(Finding(smell, r[cols.get("PATH", 0)], line, "", "", "", ""))
    return out

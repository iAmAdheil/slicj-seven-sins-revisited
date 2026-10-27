"""RQ3: does context + a decision model cut false positives without losing recall?

Candidates = SLIC-J rule findings on the three oracle datasets (seven sins only,
because the oracle has no labels for the new TLS smell). Each candidate gets a
TP/FP label from the oracle (GLITCH matching protocol).

Methods (each yields a score in [0, 1] per candidate):
  rules            keep everything (score 1)
  context-filter   hand-written deterministic rules over the context features
  logreg           logistic regression on the context features (trained in-fold)
  jev-line         Jev, state = finding + flagged line only
  jev-full         Jev, state = finding + context facts + masked +-3 line window
  llm-full         chat LLM baseline, same state as jev-full

Protocol: 5-fold cross-validation grouped by file, repeated over 10 seeds.
Thresholds (and logreg weights) are fit on the training folds only. Recall is
computed against *all* oracle entries, so findings the rules never produced
still count as misses.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.common import ORACLES, ROOT, lines_of, oracle, scan_oracle  # noqa
from slicj.context import features  # noqa
from slicj.evaluate import match  # noqa
from slicj.rules import HTTP, SECRET, SEVEN, SUSP, ADMIN, BIND, CRYPTO, EMPTY_PW  # noqa

OUT = ROOT / "results" / "rq3"
OUT.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------------ data
def collect():
    rows = []
    n_oracle = defaultdict(int)  # (tech, file) -> number of scored oracle entries
    for tech in ORACLES:
        orc = oracle(tech)
        for o in orc:
            if o.smell in SEVEN:
                n_oracle[(tech, o.file)] += 1
        fs = [f for f in scan_oracle(tech) if f.smell in SEVEN]
        labels, fn = match(fs, orc)
        cache = {}
        for f, lab in zip(fs, labels):
            if f.file not in cache:
                cache[f.file] = lines_of(tech, f.file)
            feat = features(f, cache[f.file])
            rows.append({"tech": tech, "finding": f, "label": bool(lab), "feat": feat, "lines": cache[f.file]})
    return rows, n_oracle


# ------------------------------------------------------------------ deterministic context filter
def context_filter(feat) -> float:
    """1 = keep, 0 = drop. Written from the rater guide and the dev split, then frozen."""
    s = feat["smell"]
    if s == SECRET:
        if feat["value_kind"] not in ("literal", "number"):
            return 0.0
        if feat["placeholder"] and feat["secret_sub"] != "user":
            return 0.0
        if feat["value_shape"] in ("file_path", "url"):
            return 0.0
        if feat["secret_sub"] == "user" and feat["value_shape"] != "identifier":
            return 0.0
        if feat["secret_sub"] == "key" and feat["value_shape"] == "identifier" and feat["key_format"] == "none":
            return 0.0
        return 1.0
    if s == HTTP:
        if feat["url_kind"] == "namespace" or feat["host_scope"] in ("loopback", "templated"):
            return 0.0
        return 1.0
    return 1.0


# ------------------------------------------------------------------ learned baseline
CAT = ["smell", "token_kind", "value_kind", "secret_sub", "path_purpose", "value_shape", "entropy_bucket",
       "key_format", "charset", "host_scope", "url_kind", "bind_kind", "comment_word"]
BOOL = ["placeholder", "system_user", "no_log_nearby", "vault_nearby"]


def vectorize(rows):
    from sklearn.feature_extraction import DictVectorizer
    dicts = []
    for r in rows:
        d = {f"{k}={r['feat'][k]}": 1 for k in CAT}
        d.update({k: float(bool(r["feat"][k])) for k in BOOL})
        d["log_len"] = float(np.log1p(r["feat"]["value_len"]))
        d[f"smell_x_shape={r['feat']['smell']}|{r['feat']['value_shape']}"] = 1
        dicts.append(d)
    dv = DictVectorizer(sparse=False)
    return dv.fit_transform(dicts), dv


def logreg_oof(X, y, groups, seed):
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import GroupKFold
    oof = np.zeros(len(y))
    gkf = GroupKFold(n_splits=5)
    perm = np.random.RandomState(seed).permutation(len(np.unique(groups)))
    gmap = {g: perm[i] for i, g in enumerate(np.unique(groups))}
    g2 = np.array([gmap[g] for g in groups])
    for tr, te in gkf.split(X, y, g2):
        m = LogisticRegression(C=1.0, max_iter=2000, class_weight="balanced")
        m.fit(X[tr], y[tr])
        oof[te] = m.predict_proba(X[te])[:, 1]
    return oof


# ------------------------------------------------------------------ evaluation
def prf(keep, y, total_true):
    keep = np.asarray(keep, bool)
    tp = int((keep & y).sum())
    fp = int((keep & ~y).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / total_true if total_true else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f1, tp, fp


def best_threshold(scores, y, total_true, mask):
    """Pick the threshold that maximises F1 on the training rows."""
    cand = np.unique(np.concatenate([[0.0], scores[mask], [1.01]]))
    best = (-1, 0.5)
    tt = total_true
    for t in cand:
        keep = (scores >= t) & mask
        _, _, f1, _, _ = prf(keep[mask], y[mask], tt)
        if f1 > best[0]:
            best = (f1, t)
    return best[1]


def cv_eval(scores, rows, n_oracle, seeds=10, scope=None, tune=True):
    """Grouped 5-fold CV. Returns mean/sd of P, R, F1 over seeds (pooled over folds).

    scope: set of smells the triage applies to; others are always kept."""
    from sklearn.model_selection import GroupKFold
    y = np.array([r["label"] for r in rows])
    groups = np.array([f"{r['tech']}|{r['finding'].file}" for r in rows])
    smell = np.array([r["finding"].smell for r in rows])
    in_scope = np.ones(len(rows), bool) if scope is None else np.isin(smell, list(scope))
    s = np.where(np.isnan(scores), 1.0, scores)
    file_true = defaultdict(int)
    for (tech, f), n in n_oracle.items():
        file_true[f"{tech}|{f}"] = n
    res = []
    for seed in range(seeds):
        uniq = np.unique(groups)
        perm = np.random.RandomState(seed).permutation(len(uniq))
        g2 = np.array([dict(zip(uniq, perm))[g] for g in groups])
        keep = np.zeros(len(rows), bool)
        test_true = 0
        for tr, te in GroupKFold(n_splits=5).split(s, y, g2):
            trm = np.zeros(len(rows), bool)
            trm[tr] = True
            tr_true = sum(file_true[g] for g in np.unique(groups[tr]))
            if tune:
                # tune on in-scope rows; out-of-scope rows count as kept
                t = best_threshold(np.where(in_scope, s, 1.0), y, tr_true, trm)
            else:
                t = 0.5
            keep[te] = (s[te] >= t) | ~in_scope[te]
        all_true = sum(n_oracle.values())
        res.append(prf(keep, y, all_true))
    arr = np.array([r[:3] for r in res])
    return {"P": arr[:, 0].mean(), "P_sd": arr[:, 0].std(), "R": arr[:, 1].mean(), "R_sd": arr[:, 1].std(),
            "F1": arr[:, 2].mean(), "F1_sd": arr[:, 2].std(), "keep_last": keep.tolist()}


def per_smell(keep, rows, n_oracle_smell):
    out = {}
    y = np.array([r["label"] for r in rows])
    sm = np.array([r["finding"].smell for r in rows])
    keep = np.asarray(keep, bool)
    for s in SEVEN:
        m = sm == s
        out[s] = prf(keep[m], y[m], n_oracle_smell.get(s, 0))
    return out


def ece(p, y, bins=10):
    p = np.asarray(p, float)
    y = np.asarray(y, float)
    e = 0.0
    for i in range(bins):
        lo, hi = i / bins, (i + 1) / bins
        m = (p >= lo) & (p < hi) if i < bins - 1 else (p >= lo) & (p <= hi)
        if m.any():
            e += m.mean() * abs(p[m].mean() - y[m].mean())
    return e


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--with", dest="extra", nargs="*", default=[], help="score files in results/rq3/scores_*.json")
    a = ap.parse_args()
    rows, n_oracle = collect()
    y = np.array([r["label"] for r in rows])
    print(f"{len(rows)} candidates, {y.sum()} TP, {(~y).sum()} FP, {sum(n_oracle.values())} oracle smells")

    methods = {"rules": np.ones(len(rows)), "context-filter": np.array([context_filter(r["feat"]) for r in rows])}
    X, dv = vectorize(rows)
    groups = np.array([f"{r['tech']}|{r['finding'].file}" for r in rows])
    methods["logreg"] = np.mean([logreg_oof(X, y.astype(int), groups, s) for s in range(5)], axis=0)
    for name in a.extra:
        with open(OUT / f"scores_{name}.json") as fh:
            d = json.load(fh)
        methods[name] = np.array([np.nan if v is None else v for v in d["scores"]], float)

    # hybrid: code decides with a logistic regression over context features + model probability
    for name in [m for m in a.extra if m in ("jev-full", "jev-line", "llm-anthropic_claude-haiku-5.5")]:
        col = np.nan_to_num(methods[name], nan=0.5).reshape(-1, 1)
        Xh = np.hstack([X, col, (col >= 0.5).astype(float)])
        methods[f"hybrid:{name}"] = np.mean([logreg_oof(Xh, y.astype(int), groups, s) for s in range(5)], axis=0)

    n_smell = defaultdict(int)
    for tech in ORACLES:
        for o in oracle(tech):
            if o.smell in SEVEN:
                n_smell[o.smell] += 1

    summary = {}
    decisions = {}
    noisy = {SECRET, HTTP, SUSP, CRYPTO}
    for name, sc in methods.items():
        for scope_name, scope in (("all", None), ("noisy", noisy)):
            tuned = name not in ("rules", "context-filter")
            r = cv_eval(sc, rows, n_oracle, scope=scope, tune=tuned)
            r0 = cv_eval(sc, rows, n_oracle, scope=scope, tune=False) if tuned else None
            key = f"{name}|{scope_name}"
            decisions[key] = [bool(k) for k in r["keep_last"]]
            summary[key] = {k: v for k, v in r.items() if k != "keep_last"}
            if r0:
                summary[key]["at_0.5"] = {k: v for k, v in r0.items() if k != "keep_last"}
            summary[key]["per_smell_last_seed"] = {k: list(v) for k, v in per_smell(r["keep_last"], rows, n_smell).items()}
            ok = ~np.isnan(sc)
            if tuned and ok.any():
                from sklearn.metrics import roc_auc_score, brier_score_loss
                summary[key]["AUC"] = float(roc_auc_score(y[ok], sc[ok]))
                summary[key]["Brier"] = float(brier_score_loss(y[ok], sc[ok]))
                summary[key]["ECE"] = float(ece(sc[ok], y[ok]))
                sec = ok & (np.array([r["finding"].smell for r in rows]) == SECRET)
                if sec.sum() > 5 and len(set(y[sec])) > 1:
                    summary[key]["AUC_secret"] = float(roc_auc_score(y[sec], sc[sec]))
            print(f"{key:26s} P={r['P']:.3f}±{r['P_sd']:.3f} R={r['R']:.3f}±{r['R_sd']:.3f} F1={r['F1']:.3f}±{r['F1_sd']:.3f}"
                  + (f"  AUC={summary[key].get('AUC', float('nan')):.3f} ECE={summary[key].get('ECE', float('nan')):.3f}"
                     if tuned else ""))
    with open(OUT / "decisions.json", "w") as fh:
        json.dump({"labels": y.tolist(), "groups": groups.tolist(),
                   "smells": [r["finding"].smell for r in rows], "decisions": decisions}, fh)
    with open(OUT / "summary.json", "w") as fh:
        json.dump(summary, fh, indent=1, default=float)
    # per-candidate table for error analysis
    with open(OUT / "candidates.jsonl", "w") as fh:
        for i, r in enumerate(rows):
            f = r["finding"]
            fh.write(json.dumps({"i": i, "tech": r["tech"], "file": f.file, "line": f.line, "smell": f.smell,
                                 "name": f.name, "value": f.value[:80], "label": r["label"],
                                 **{m: (None if np.isnan(v[i]) else float(v[i])) for m, v in methods.items()}}) + "\n")


if __name__ == "__main__":
    main()

"""RQ2 at scale: occurrences, smell density (per KLOC) and proportion of scripts
for SLIC-J (seven sins + TLS verification disabled) on the GLITCH corpora.
Script selection follows GLITCH: by extension (.yml/.yaml, .pp, .rb)."""
import csv, json, os, sys, re
from collections import Counter, defaultdict
from multiprocessing import Pool
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments.common import GL, ROOT  # noqa
from slicj.rules import ALL, TLS_OFF  # noqa
from slicj.scanner import scan_file  # noqa

EXT = {"ansible": (".yml", ".yaml"), "puppet": (".pp",), "chef": (".rb",)}


def one(args):
    tech, path, repo_root = args
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if len(text) > 2_000_000:
        return None
    loc = text.count("\n") + (0 if text.endswith("\n") or not text else 1)
    rel = os.path.relpath(path, repo_root)
    try:
        fs = scan_file(path, "slicj", rel=rel, text=text)
    except Exception as e:  # parser crash: count the script, no findings
        return rel, loc, {}, [], f"{type(e).__name__}"
    c = Counter(f.smell for f in fs)
    tls = [(f.name, f.value[:100]) for f in fs if f.smell == TLS_OFF]
    return rel, loc, dict(c), tls, None


def main(tech):
    root = GL / tech / "repos"
    jobs = [(tech, os.path.join(dp, f), str(root)) for dp, dn, fn in os.walk(root) for f in fn
            if f.lower().endswith(EXT[tech])]
    with Pool(max(2, os.cpu_count() - 1)) as p:
        res = [r for r in p.imap_unordered(one, jobs, chunksize=64) if r]
    occ, files_with, loc_total, errs = Counter(), Counter(), 0, Counter()
    tls_examples = Counter()
    any_smell = 0
    for rel, loc, c, tls, err in res:
        loc_total += loc
        if err:
            errs[err] += 1
        for s, n in c.items():
            occ[s] += n
            files_with[s] += 1
        if any(c.get(s) for s in ALL if s != TLS_OFF):
            any_smell += 1
        for name, val in tls:
            key = name if name else re.sub(r"\s+", " ", val)[:60]
            tls_examples[key] += 1
    n = len(res)
    out = {"tech": tech, "scripts": n, "loc": loc_total, "parser_errors": dict(errs),
           "smells": {s: {"occurrences": occ[s], "density_per_kloc": occ[s] / (loc_total / 1000),
                          "script_pct": 100 * files_with[s] / n} for s in ALL},
           "seven_sins_any_pct": 100 * any_smell / n,
           "seven_sins_density": sum(occ[s] for s in ALL if s != TLS_OFF) / (loc_total / 1000),
           "tls_top_patterns": tls_examples.most_common(25)}
    os.makedirs(ROOT / "results" / "rq2", exist_ok=True)
    with open(ROOT / "results" / "rq2" / f"prevalence_{tech}.json", "w") as fh:
        json.dump(out, fh, indent=1)
    print(json.dumps({k: v for k, v in out.items() if k != "tls_top_patterns"}, indent=1))


if __name__ == "__main__":
    for t in sys.argv[1:]:
        main(t)

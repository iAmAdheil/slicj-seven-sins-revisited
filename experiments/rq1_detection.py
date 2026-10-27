"""RQ1 (reproduction) and RQ2 (portability): detection accuracy on the three
GLITCH oracle datasets.

Tools compared per technology:
  SLIC (original)      - output of the authors' Ruby SLIC, shipped in the GLITCH package (Puppet)
  SLAC (original)      - output of the authors' Ansible port (Ansible), lines recovered from CODE text
  GLITCH ASE'22        - output shipped in the package
  GLITCH v2 (live)     - current GLITCH, run by us
  ours: paper          - our Python SLIC with Table II/III as printed
  ours: code           - our Python SLIC with the released Ruby semantics
  SLIC-J rules         - our port (the candidate generator for RQ3)
"""
from __future__ import annotations

import csv
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.common import GL, ORACLES, ROOT, lines_of, oracle, oracle_files, scan_oracle, split_of  # noqa
from slicj.evaluate import GLITCH_ERR, match, scores  # noqa
from slicj.rules import SECRET, SEVEN, SUSP, Finding  # noqa

OUT = ROOT / "results" / "rq1"
OUT.mkdir(parents=True, exist_ok=True)
V2 = {"sec_hard_user": SECRET, "sec_hard_pass": SECRET, "sec_hard_secr": SECRET, "sec_https": "http_without_tls",
      "sec_susp_comm": SUSP, "sec_def_admin": "admin_by_default", "sec_invalid_bind": "invalid_bind",
      "sec_weak_crypt": "weak_crypto", "sec_empty_pass": "empty_password"}


def dedupe(fs):
    seen, out = set(), []
    for f in fs:
        k = (f.file, f.line, f.smell)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def load_line_csv(path):
    out = []
    with open(path, newline="") as fh:
        rd = csv.DictReader(fh)
        for r in rd:
            s = GLITCH_ERR.get(r["ERROR"])
            if s:
                out.append(Finding(s, os.path.basename(r["PATH"]), int(r["LINE"]), "", "", "", ""))
    return dedupe(out)


def load_glitch_v2(path):
    out = []
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            s = V2.get(r["ERROR"])
            if s:
                out.append(Finding(s, os.path.basename(r["PATH"]), int(r["LINE"]), "", "", "", ""))
    return dedupe(out)


def load_slac_ansible(path, tech="ansible"):
    """SLAC / GLITCH'22 Ansible rows carry 'key:value' or the comment text, not a line.
    We copy GLITCH's matching: a row matches an oracle entry of the same file and
    category if (comment) the oracle line equals the text, or (other) key and value
    both occur in the oracle line. Unmatched rows get the first line that contains
    the text, so they still count as false positives."""
    orc = [o for o in oracle(tech) if o.smell not in ("none", "other")]
    used = set()
    out = []
    with open(path, newline="") as fh:
        for row in csv.reader(fh):
            if len(row) < 3 or row[0] == "PATH":
                continue
            file, err, code = row[0], row[1], ",".join(row[2:])
            s = GLITCH_ERR.get(err)
            if not s:
                continue
            try:
                L = lines_of(tech, file)
            except KeyError:
                continue
            if s == SUSP:
                ok = lambda x: x.strip() == code.strip()
            elif ":" in code:
                k, v = code.split(":", 1)
                k, v = k.strip("\"'"), v.strip("\"'")
                ok = lambda x, k=k, v=v: k in x and v in x
            else:
                ok = lambda x: code.strip() in x
            line = -1
            for i, o in enumerate(orc):
                if i not in used and o.file == file and o.smell == s and 0 < o.line <= len(L) and ok(L[o.line - 1]):
                    used.add(i)
                    line = o.line
                    break
            if line == -1:
                line = next((i + 1 for i, x in enumerate(L) if ok(x)), -1)
            out.append(Finding(s, file, line, "", "", "", ""))
    return out


def tools_for(tech):
    an = GL / tech / "oracle-dataset-analysis"
    t = {}
    if tech == "puppet":
        t["SLIC (original)"] = load_line_csv(an / "SLIC-puppet-oracle.csv")
    if tech == "ansible":
        t["SLAC (original)"] = load_slac_ansible(an / "SLAC-ansible-oracle.csv")
    if tech in ("puppet", "chef"):
        t["GLITCH ASE'22"] = load_line_csv(an / f"GLITCH-{tech}-oracle.csv")
    else:
        t["GLITCH ASE'22"] = load_slac_ansible(an / "GLITCH-ansible-oracle.csv")
    t["GLITCH v2 (live)"] = load_glitch_v2(ROOT / "results" / "baselines" / f"glitch2_{tech}.csv")
    if tech == "puppet":
        t["SLIC (original, re-run)"] = load_line_csv(ROOT / "results" / "baselines" / "slic_original_rerun_puppet.csv")
    t["ours: paper rules"] = scan_oracle(tech, "paper")
    if tech == "puppet":
        from pathlib import Path
        from slicj import slic_original
        t["ours: SLIC code port"] = [f for b, p in sorted(oracle_files(tech).items())
                                     for f in slic_original.detect(Path(p).read_text(errors="replace"), b)]
    else:
        t["ours: code rules"] = scan_oracle(tech, "code")
    t["SLIC-J rules"] = [f for f in scan_oracle(tech, "slicj") if f.smell in SEVEN]
    return t


def subset(fs, orc, split):
    if split == "all":
        return fs, orc
    return [f for f in fs if split_of(f.file) == split], [o for o in orc if split_of(o.file) == split]


def agreement(a, b):
    """Finding-level agreement between two tools (Jaccard on (file, line, smell))."""
    A = {(f.file, f.line, f.smell) for f in a}
    B = {(f.file, f.line, f.smell) for f in b}
    return len(A & B) / len(A | B) if A | B else 1.0, len(A & B), len(A - B), len(B - A)


def main():
    rows = []
    allres = {}
    for tech in ORACLES:
        orc = oracle(tech)
        tools = tools_for(tech)
        for split in ("all", "test"):
            for name, fs in tools.items():
                f2, o2 = subset(fs, orc, split)
                r = scores(f2, o2)
                allres[f"{tech}|{split}|{name}"] = r
                row = {"tech": tech, "split": split, "tool": name}
                for s in SEVEN + ["none"]:
                    row[f"{s}_P"] = r[s]["precision"]
                    row[f"{s}_R"] = r[s]["recall"]
                    row[f"{s}_n"] = r[s]["support"]
                for k in ("tp", "fp", "fn", "precision", "recall", "f1"):
                    row[f"micro_{k}"] = r["micro"][k]
                row["macro_P"] = r["macro"]["precision"]
                row["macro_R"] = r["macro"]["recall"]
                rows.append(row)
        if tech == "puppet":
            for ours in ("ours: paper rules", "ours: SLIC code port", "SLIC-J rules"):
                j, both, only_a, only_b = agreement(tools[ours], tools["SLIC (original)"])
                allres[f"agreement|{ours}|SLIC (original)"] = {"jaccard": j, "both": both, "only_ours": only_a,
                                                             "only_original": only_b}
    with open(OUT / "detection.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    with open(OUT / "detection.json", "w") as fh:
        json.dump(allres, fh, indent=1, default=str)
    # console summary
    fmt = lambda x: "  -  " if x is None else f"{x:.2f}"
    for tech in ORACLES:
        print(f"\n=== {tech} (all files) ===")
        print(f"{'tool':22s} " + " ".join(f"{s[:8]:>9s}" for s in SEVEN) + "   microP microR  microF1")
        for r in rows:
            if r["tech"] == tech and r["split"] == "all":
                print(f"{r['tool']:22s} " + " ".join(f"{fmt(r[s + '_P'])}/{fmt(r[s + '_R'])}"[:9].rjust(9)
                                                     for s in SEVEN) +
                      f"   {fmt(r['micro_precision'])}   {fmt(r['micro_recall'])}   {fmt(r['micro_f1'])}")
    for k, v in allres.items():
        if k.startswith("agreement"):
            print(k, v)


if __name__ == "__main__":
    main()

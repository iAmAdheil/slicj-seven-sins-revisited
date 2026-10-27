"""Command line: python -m slicj scan DIR [--rules slicj|paper|code] [--out FILE.csv]

Writes a CSV like SLIC's: one row per script with the count of each smell,
plus a second CSV (suffix _lines.csv) with one row per finding and its line."""
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter

from .rules import ALL, SEVEN
from .scanner import scan_dir


def main(argv=None):
    ap = argparse.ArgumentParser(prog="slicj")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a directory of Puppet (.pp) and Ansible (.yml) scripts")
    s.add_argument("root")
    s.add_argument("--rules", default="slicj", choices=["slicj", "paper", "code"])
    s.add_argument("--out", default="-")
    a = ap.parse_args(argv)

    findings, loc = scan_dir(a.root, a.rules)
    smells = ALL if a.rules == "slicj" else SEVEN
    per = {f: Counter() for f in loc}
    for f in findings:
        per[f.file][f.smell] += 1
    out = sys.stdout if a.out == "-" else open(a.out, "w", newline="")
    w = csv.writer(out)
    w.writerow(["FILE", "LOC"] + [s.upper() for s in smells] + ["TOTAL"])
    for f in sorted(per):
        c = per[f]
        w.writerow([f, loc[f]] + [c[s] for s in smells] + [sum(c[s] for s in smells)])
    if a.out != "-":
        out.close()
        with open(a.out.rsplit(".", 1)[0] + "_lines.csv", "w", newline="") as fh:
            lw = csv.writer(fh)
            lw.writerow(["FILE", "LINE", "SMELL", "TOKEN", "NAME", "VALUE"])
            for f in sorted(findings, key=lambda x: (x.file, x.line)):
                lw.writerow([f.file, f.line, f.smell, f.kind, f.name, f.value[:120]])
        total = sum(1 for f in findings if f.smell in smells)
        print(f"{len(loc)} scripts, {sum(loc.values())} LOC, {total} smell occurrences -> {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()

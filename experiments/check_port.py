"""Compare our Python port of all_in_one.rb with the original SLIC run."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pathlib import Path
from collections import Counter
from experiments.common import oracle_files, lines_of
from experiments.rq1_detection import load_line_csv, agreement
from slicj import slic_original

orig = load_line_csv("results/baselines/slic_original_rerun_puppet.csv")
ours = []
for base, p in oracle_files("puppet").items():
    ours += slic_original.detect(Path(p).read_text(errors="replace"), base)
print(agreement(ours, orig))
A = {(f.file, f.line, f.smell) for f in ours}; B = {(f.file, f.line, f.smell) for f in orig}
show = int(sys.argv[1]) if len(sys.argv) > 1 else 15
for tag, S in (("ONLY PORT", A - B), ("ONLY ORIG", B - A)):
    print(tag, Counter(s for _, _, s in S))
    for k in sorted(S)[:show]:
        L = lines_of("puppet", k[0]); print("  ", k[2], k[0][:35], k[1], "|", L[k[1]-1].strip()[:90])

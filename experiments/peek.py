import sys
from collections import Counter
sys.path.insert(0, ".")
from experiments.common import *
from slicj.evaluate import match, scores
tech, smell = sys.argv[1], sys.argv[2]
fs = scan_oracle(tech, sys.argv[3] if len(sys.argv) > 3 else "slicj")
orc = oracle(tech)
lab, fn = match(fs, orc)
print("FN:")
for o in [o for o in fn if split_of(o.file)=="dev"]:
    if o.smell == smell:
        L = lines_of(tech, o.file)
        print(f"  {o.file[:60]}:{o.line} | {L[o.line-1].strip()[:110] if 0 < o.line <= len(L) else ''}")
print("FP:")
for f, l in [(f,l) for f,l in zip(fs, lab) if split_of(f.file)=="dev"]:
    if f.smell == smell and not l:
        print(f"  {f.file[:60]}:{f.line} | {f.kind} {f.name}={f.value[:70]!r}")
r = scores(fs, orc)
print({k: (v['tp'], v['fp'], v['fn']) for k, v in r.items() if 'tp' in v})

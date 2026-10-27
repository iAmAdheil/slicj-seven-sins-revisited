"""Draw a fixed random sample of TLS-verification-disabled findings for manual
precision checking. Writes results/rq2/tls_sample.csv (to be labelled)."""
import csv, os, random, sys
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments.common import GL, ROOT  # noqa
from slicj.rules import TLS_OFF  # noqa
from slicj.scanner import scan_file  # noqa

EXT = {"ansible": (".yml", ".yaml"), "puppet": (".pp",), "chef": (".rb",)}
QUOTA = {"ansible": 40, "puppet": 10, "chef": 10}
random.seed(42)
rows = []
for tech, q in QUOTA.items():
    root = GL / tech / "repos"
    files = sorted(os.path.join(dp, f) for dp, _, fn in os.walk(root) for f in fn if f.lower().endswith(EXT[tech]))
    random.shuffle(files)
    found = []
    for p in files:
        try:
            text = Path(p).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not any(k in text for k in ("validate_cert", "verify", "insecure", "-k", "no-check-certificate", "sslverify")):
            continue
        fs = [f for f in scan_file(p, "slicj", rel=os.path.relpath(p, root), text=text) if f.smell == TLS_OFF]
        if fs:
            f = random.choice(fs)
            L = text.split("\n")
            ctx = " ⏎ ".join(x.strip() for x in L[max(0, f.line - 3): f.line + 1])
            found.append([tech, f.file, f.line, f.name, f.value[:140], ctx[:400], "", ""])
        if len(found) >= q:
            break
    rows += found
out = ROOT / "results" / "rq2" / "tls_sample.csv"
with open(out, "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["tech", "file", "line", "name", "value", "context", "label_rater1", "note"])
    w.writerows(rows)
print(len(rows), "->", out)

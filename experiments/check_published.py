"""Check our scorer against the per-smell precision/recall that the GLITCH paper
(ASE 2022, tables for the three oracles) publishes. None = the paper gives N/I or N/D."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments.common import ROOT  # noqa

ORDER = ["admin_by_default", "empty_password", "hardcoded_secret", "invalid_bind", "suspicious_comment", "http_without_tls", "weak_crypto"]
PUB = {
    "puppet|SLIC (original)": [(None, 0.00), (0.60, 0.60), (0.10, 0.73), (1, 1), (0.75, 1), (0.38, 1), (0.43, 0.75)],
    "puppet|GLITCH ASE'22": [(0.81, 0.93), (1, 1), (0.14, 0.82), (1, 1), (0.39, 1), (0.45, 1), (0.57, 1)],
    "ansible|SLAC (original)": [(None, None), (1, 1), (0.32, 1), (1, 1), (0.67, 0.67), (0.71, 1), (None, None)],
    "ansible|GLITCH ASE'22": [(1, 1), (1, 1), (0.42, 1), (1, 1), (0.75, 1), (0.95, 1), (None, None)],
    "chef|SLAC (original)": [(0, 0), (0, 0), (0.13, 0.54), (1, 1), (0.80, 1), (0.71, 0.92), (0.25, 1)],
    "chef|GLITCH ASE'22": [(0.94, 0.41), (1, 0.75), (0.20, 0.69), (1, 1), (0.40, 1), (0.71, 0.92), (0.50, 1)],
}
det = json.load(open(ROOT / "results" / "rq1" / "detection.json"))
checked = bad = 0
for key, vals in PUB.items():
    tech, tool = key.split("|")
    r = det[f"{tech}|all|{tool}"]
    for s, (p, rc) in zip(ORDER, vals):
        for name, pub, got in (("P", p, r[s]["precision"]), ("R", rc, r[s]["recall"])):
            if pub is None:
                continue
            checked += 1
            if got is None or abs(round(got, 2) - pub) > 1e-9:
                bad += 1
                print(f"MISMATCH {key} {s} {name}: published {pub}, ours {got}")
print(f"{checked} published values checked, {bad} mismatches")

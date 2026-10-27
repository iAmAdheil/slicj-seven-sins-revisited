"""Shared helpers for the experiments."""
from __future__ import annotations

import os
from pathlib import Path

from slicj.evaluate import load_oracle
from slicj.scanner import iter_scripts, scan_file

ROOT = Path(__file__).resolve().parents[1]
GL = ROOT / "data" / "glitch_rootfs" / "RESULTS"
ORACLES = {
    "puppet": (GL / "puppet" / "oracle-dataset", GL / "puppet" / "oracle-dataset-analysis" / "oracle-dataset.csv"),
    "ansible": (GL / "ansible" / "oracle-dataset", GL / "ansible" / "oracle-dataset-analysis" / "oracle_dataset.csv"),
    "chef": (GL / "chef" / "oracle-dataset", GL / "chef" / "oracle-dataset-analysis" / "oracle_dataset.csv"),
}


def oracle_files(tech):
    d, _ = ORACLES[tech]
    return {os.path.basename(p): p for p in iter_scripts(str(d))}


def scan_oracle(tech, ruleset="slicj"):
    """Findings with file = basename (the oracle's PATH convention)."""
    out = []
    for base, p in sorted(oracle_files(tech).items()):
        for f in scan_file(p, ruleset, rel=p):
            f.file = base
            out.append(f)
    return out


def oracle(tech):
    return load_oracle(str(ORACLES[tech][1]))


def lines_of(tech, base):
    return Path(oracle_files(tech)[base]).read_text(encoding="utf-8", errors="replace").split("\n")


def split_of(base: str) -> str:
    """Fixed file-level split: 30% dev (rule and threshold tuning), 70% test."""
    import hashlib
    return "dev" if int(hashlib.sha1(base.encode()).hexdigest(), 16) % 10 < 3 else "test"

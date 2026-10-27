"""Walk a directory, parse each IaC script, run a rule set."""
from __future__ import annotations

import os
from pathlib import Path

from .parsers import ansible as ansible_parser
from .parsers import chef as chef_parser
from .parsers import puppet as puppet_parser
from .rules import Finding, detect

PUPPET_EXT = {".pp"}
ANSIBLE_EXT = {".yml", ".yaml"}
CHEF_EXT = {".rb"}


def language_of(path: str) -> str | None:
    ext = Path(path).suffix.lower()
    if ext in PUPPET_EXT:
        return "puppet"
    if ext in ANSIBLE_EXT:
        return "ansible"
    if ext in CHEF_EXT:
        return "chef"
    return None


def tokens_of(path: str, text: str | None = None, rel: str | None = None):
    lang = language_of(path)
    if text is None:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    if lang == "puppet":
        return puppet_parser.parse(text)
    if lang == "ansible":
        return ansible_parser.parse(text, rel or path)
    if lang == "chef":
        return chef_parser.parse(text)
    return []


def scan_file(path: str, ruleset: str = "slicj", rel: str | None = None, text: str | None = None) -> list[Finding]:
    return detect(tokens_of(path, text, rel), rel or path, ruleset)


def iter_scripts(root: str):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if not d.startswith(".")]
        for f in sorted(fn):
            p = os.path.join(dp, f)
            if language_of(p):
                yield p


def scan_dir(root: str, ruleset: str = "slicj") -> tuple[list[Finding], dict[str, int]]:
    """Return findings and LOC per script."""
    findings, loc = [], {}
    for p in iter_scripts(root):
        rel = os.path.relpath(p, root)
        text = Path(p).read_text(encoding="utf-8", errors="replace")
        loc[rel] = text.count("\n") + (0 if text.endswith("\n") or not text else 1)
        findings.extend(scan_file(p, ruleset, rel, text))
    return findings, loc

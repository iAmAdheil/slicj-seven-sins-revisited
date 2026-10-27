"""Ansible (YAML) parser that emits SLIC tokens.

Mapping used for the port (SLIC was Puppet-only, so this is our design):
  * key: scalar under a task / module / play        -> ATTRIBUTE
  * key under vars:, set_fact:, vars/, group_vars/,
    host_vars/, include_vars files                  -> VARIABLE
  * top-level key in a role's defaults/ file        -> PARAMETER (closest analogue
                                                       of a Puppet class parameter default)
  * Jinja call or filter  name(...) / | name         -> FUNCTION
  * '# text' outside quoted and block scalars       -> COMMENT

Line numbers come from ruamel.yaml (1-based in the output). Files that are
not valid YAML (often Jinja-templated) fall back to a line-based reader so
recall does not drop to zero.
"""
from __future__ import annotations

import io
import re

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq, TaggedScalar

from ..tokens import (ATTRIBUTE, BOOL, COMMENT, COMPOUND, EMPTY, FUNCALL, FUNCTION, LITERAL, NULL, NUMBER,
                      PARAMETER, VARIABLE, VARREF, VAULT, Token)

_VAR_SECTIONS = {"vars", "set_fact", "defaults", "facts", "extra_vars", "host_vars", "group_vars"}
_TASK_KEYS = {"name", "when", "with_items", "loop", "register", "become", "become_user", "tags", "notify",
              "ignore_errors", "changed_when", "failed_when", "delegate_to", "run_once", "until", "retries",
              "delay", "args", "environment", "no_log", "loop_control", "vars", "block", "rescue", "always",
              "with_dict", "with_fileglob", "with_together", "with_subelements", "with_nested", "listen",
              "check_mode", "diff", "async", "poll", "local_action", "connection", "remote_user", "any_errors_fatal"}
_JINJA_CALL = re.compile(r"([A-Za-z_][A-Za-z0-9_\.]*)\s*\(([^()]*)\)")
_JINJA_FILTER = re.compile(r"\|\s*([A-Za-z_][A-Za-z0-9_\.]*)")
_YAML11_BOOL = {"yes": "true", "no": "false", "on": "true", "off": "false", "y": "true", "n": "false",
                "true": "true", "false": "false"}
_STR_ARG = re.compile(r"""['"]([^'"]*)['"]""")


def file_role(path: str) -> str:
    p = path.replace("\\", "/").lower()
    if "/defaults/" in p or p.startswith("defaults/"):
        return "defaults"
    if any(s in p for s in ("/vars/", "/group_vars/", "/host_vars/")) or p.startswith(("vars/", "group_vars/", "host_vars/")):
        return "vars"
    return "tasks"


def classify_value(v) -> tuple[str, str]:
    """Return (text, value_kind) for a YAML scalar."""
    if isinstance(v, TaggedScalar):
        tag = str(v.tag.value if hasattr(v.tag, "value") else v.tag)
        return ("<vault>" if "vault" in tag else str(v.value)), (VAULT if "vault" in tag else LITERAL)
    if v is None:
        return "", NULL
    if isinstance(v, bool):
        return str(v).lower(), BOOL
    if isinstance(v, (int, float)):
        return str(v), NUMBER
    if isinstance(v, (CommentedMap, CommentedSeq, dict, list)):
        return "", COMPOUND
    s = str(v)
    if s == "":
        return "", EMPTY
    # Ansible loads YAML 1.1, where plain yes/no/on/off are booleans; ruamel reads 1.2
    if type(v) is str and s.lower() in _YAML11_BOOL:
        return _YAML11_BOOL[s.lower()], BOOL
    if "{{" in s or "{%" in s:
        if re.search(r"\b(lookup|query|q)\s*\(", s):
            return s, FUNCALL
        if re.search(r"\bvault_[A-Za-z0-9_]+", s):
            return s, VAULT
        return s, VARREF
    if s.startswith("$ANSIBLE_VAULT"):
        return "<vault>", VAULT
    return s, LITERAL


def _functions(text: str, line: int) -> list[Token]:
    out = []
    if "{{" not in text and "{%" not in text:
        return out
    for m in _JINJA_CALL.finditer(text):
        out.append(Token(FUNCTION, m.group(1), "", line, FUNCALL, args=_STR_ARG.findall(m.group(2))))
    for m in _JINJA_FILTER.finditer(text):
        out.append(Token(FUNCTION, m.group(1), "", line, FUNCALL))
    return out


def _task_module(node: CommentedMap) -> str:
    for k in node:
        if str(k) not in _TASK_KEYS:
            return str(k)
    return ""


class _Walker:
    def __init__(self, role: str):
        self.role = role
        self.toks: list[Token] = []

    def emit(self, kind, name, v, line, path, module):
        text, vk = classify_value(v)
        self.toks.append(Token(kind, str(name), text, line, vk, path=path, module=module))
        if vk in (VARREF, FUNCALL, VAULT, LITERAL) and isinstance(v, str):
            self.toks.extend(_functions(v, line))

    def walk(self, node, path: str, depth: int, var_ctx: bool, module: str):
        if isinstance(node, CommentedMap):
            if depth >= 1 and any(str(k) not in _TASK_KEYS for k in node) and ("name" in node or len(node) <= 6):
                mod = _task_module(node) or module
            else:
                mod = module
            for k in node:
                v = node[k]
                try:
                    line = node.lc.key(k)[0] + 1
                except Exception:  # pragma: no cover
                    line = 0
                key = str(k)
                sub = f"{path}.{key}" if path else key
                if depth == 0 and self.role == "defaults":
                    kind = PARAMETER
                elif var_ctx or (depth == 0 and self.role == "vars"):
                    kind = VARIABLE
                else:
                    kind = ATTRIBUTE
                if isinstance(v, (CommentedMap, CommentedSeq)):
                    self.emit(kind, key, v, line, sub, mod)
                    self.walk(v, sub, depth + 1, key in _VAR_SECTIONS or (var_ctx and isinstance(v, CommentedMap)),
                              mod if key not in ("block", "rescue", "always", "tasks", "pre_tasks",
                                                 "post_tasks", "handlers") else "")
                else:
                    self.emit(kind, key, v, line, sub, mod)
        elif isinstance(node, CommentedSeq):
            for i, item in enumerate(node):
                sub = f"{path}[{i}]"
                if isinstance(item, (CommentedMap, CommentedSeq)):
                    self.walk(item, sub, depth + 1, var_ctx and isinstance(item, CommentedMap), module)
                else:
                    try:
                        line = node.lc.item(i)[0] + 1
                    except Exception:  # pragma: no cover
                        line = 0
                    # list items have no name of their own (same as SLAC): only value rules apply
                    self.emit(ATTRIBUTE, "", item, line, sub, module)


_BLOCK_START = re.compile(r"^(\s*)(?:-\s+)?(?:[^#'\"]*?:\s*)?[|>][-+0-9]*\s*(#.*)?$")


def comments(text: str) -> list[Token]:
    """YAML comments with 1-based line numbers. Skips block-scalar bodies."""
    out = []
    block_indent = None
    for no, raw in enumerate(text.split("\n"), start=1):
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if block_indent is not None:
            if stripped == "" or indent > block_indent:
                continue
            block_indent = None
        idx = _comment_index(raw)
        if idx is not None:
            body = raw[idx + 1:].strip()
            out.append(Token(COMMENT, "", body, no))
            code = raw[:idx]
        else:
            code = raw
        if _BLOCK_START.match(code.rstrip()) and code.strip() not in ("", "-"):
            block_indent = len(code) - len(code.lstrip())
    return out


def _comment_index(line: str):
    q = None
    for i, ch in enumerate(line):
        if q:
            if ch == q:
                q = None
        elif ch in "'\"":
            # a quote only opens a string at a token start
            if i == 0 or line[i - 1] in " \t:[{,-":
                q = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return i
    return None


_KV = re.compile(r"^\s*(?:-\s+)?([A-Za-z_][A-Za-z0-9_\-\.]*)\s*:\s*(.*?)\s*$")


def _fallback(text: str, role: str) -> list[Token]:
    """Line-based reader for files that ruamel cannot load."""
    toks = []
    for no, raw in enumerate(text.split("\n"), start=1):
        idx = _comment_index(raw)
        code = raw[:idx] if idx is not None else raw
        m = _KV.match(code)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if val in ("", "|", ">", "|-", ">-"):
            continue
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
            val = val[1:-1]
            v = val
        else:
            v = {"true": True, "false": False, "yes": True, "no": False}.get(val.lower(), val)
        kind = PARAMETER if role == "defaults" and not raw.startswith((" ", "\t", "-")) else (
            VARIABLE if role == "vars" else ATTRIBUTE)
        text_v, vk = classify_value(v)
        toks.append(Token(kind, key, text_v, no, vk))
        if isinstance(v, str):
            toks.extend(_functions(v, no))
    return toks


def parse(text: str, path: str = "") -> list[Token]:
    role = file_role(path)
    toks: list[Token] = comments(text)
    yaml = YAML(typ="rt")
    yaml.allow_duplicate_keys = True
    try:
        docs = list(yaml.load_all(io.StringIO(text)))
        w = _Walker(role)
        for d in docs:
            if d is not None:
                w.walk(d, "", 0, False, "")
        toks.extend(w.toks)
    except Exception:
        toks.extend(_fallback(text, role))
    toks.sort(key=lambda t: (t.line, t.kind != COMMENT))
    return toks

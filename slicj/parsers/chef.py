"""Line-level Chef (Ruby DSL) parser that emits SLIC tokens.

Patterns (one statement per line, which covers most cookbook code):
  default['a']['db_password'] = 'x'      -> ATTRIBUTE  name=db_password
  node.default[:a][:user] = "x"          -> ATTRIBUTE
  password 'x'   /  user "x"             -> ATTRIBUTE  (resource property call)
  :password => 'x'  /  password: 'x'     -> ATTRIBUTE  (hash entry)
  db_pass = 'x'                          -> VARIABLE
  Digest::MD5.hexdigest(...)             -> FUNCTION
  # text  /  =begin ... =end             -> COMMENT
"""
from __future__ import annotations

import re

from ..tokens import ATTRIBUTE, BOOL, COMMENT, COMPOUND, EMPTY, FUNCALL, FUNCTION, LITERAL, NULL, NUMBER, VARIABLE, \
    VARREF, Token

_STR = r"""(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|%[qQw]?\{[^}]*\})"""
_VAL = rf"({_STR}|:[A-Za-z_]\w*|-?\d+(?:\.\d+)?|true|false|nil|node\[[^\n]*|\[[^\n]*|\{{[^\n]*|[A-Za-z_][\w.:\[\]'\"]*(?:\([^\n]*\))?)"
_NODE_ATTR = re.compile(rf"^\s*(?:node\s*\.\s*)?(?:default|override|normal|set|force_default|force_override|"
                        rf"node)((?:\s*\[\s*(?:{_STR}|:\w+)\s*\])+)\s*(?:\|\|)?=\s*{_VAL}")
_PROP = re.compile(rf"^\s*([a-z_][a-z0-9_]*[?!]?)\s*(?:\(\s*)?{_VAL}\s*\)?\s*(?:#.*)?$")
_HASH = re.compile(rf"(?:^|[\s,{{(])(?::([A-Za-z_]\w*)\s*=>|([A-Za-z_]\w*):(?!:)|{_STR}\s*=>)\s*{_VAL}")
_HASH_QKEY = re.compile(rf"({_STR})\s*=>\s*{_VAL}")
_LOCAL = re.compile(rf"^\s*([a-z_]\w*)\s*(?:\|\|)?=(?!=|~|>)\s*{_VAL}")
_CALL = re.compile(r"([A-Za-z_][\w:]*(?:\.[A-Za-z_]\w*)*)\s*\(([^()]*)\)")
_KEYS = re.compile(rf"\[\s*({_STR}|:\w+)\s*\]")
_RUBY_KW = {"if", "unless", "elsif", "else", "end", "do", "case", "when", "while", "until", "return", "include_recipe",
            "require", "include", "not_if", "only_if", "action", "notifies", "subscribes", "puts", "raise", "def",
            "class", "module", "begin", "rescue", "ensure", "then", "and", "or", "not", "yield", "next", "break"}


def _unq(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        return s[1:-1]
    m = re.match(r"%[qQw]?\{(.*)\}$", s)
    if m:
        return m.group(1)
    if s.startswith(":"):
        return s[1:]
    return s


def _classify(raw: str) -> tuple[str, str]:
    r = raw.strip().rstrip(",").strip()
    if not r:
        return "", NULL
    if r[0] in "'\"" or r.startswith("%"):
        v = _unq(r)
        if v == "":
            return "", EMPTY
        if r[0] == '"' and re.fullmatch(r"#\{[^}]*\}", v):
            return v, VARREF
        return v, LITERAL
    if r.startswith(":"):
        return r[1:], LITERAL
    if re.fullmatch(r"-?\d+(\.\d+)?", r):
        return r, NUMBER
    if r in ("true", "false"):
        return r, BOOL
    if r == "nil":
        return "", NULL
    if r.startswith(("[", "{")):
        return r, COMPOUND
    if "(" in r:
        return r, FUNCALL
    return r, VARREF


def _code_and_comment(line: str):
    q = None
    i = 0
    while i < len(line):
        ch = line[i]
        if q:
            if ch == "\\":
                i += 2
                continue
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
        elif ch == "#" and not (i + 1 < len(line) and line[i + 1] == "{"):
            return line[:i], line[i + 1:]
        i += 1
    return line, None


def parse(text: str) -> list[Token]:
    toks: list[Token] = []
    in_block = False
    heredoc = None
    for no, raw in enumerate(text.split("\n"), start=1):
        if in_block:
            if raw.startswith("=end"):
                in_block = False
            elif raw.strip():
                toks.append(Token(COMMENT, "", raw.strip(), no))
            continue
        if raw.startswith("=begin"):
            in_block = True
            continue
        if heredoc:
            if raw.strip() == heredoc:
                heredoc = None
            elif raw.strip():
                # command text inside <<-EOH ... EOH: value rules (http, 0.0.0.0, -u root, curl -k) apply
                toks.append(Token(ATTRIBUTE, "", raw.strip(), no, LITERAL))
            continue
        hm0 = re.search(r"<<[-~]?['\"]?([A-Z_][A-Z0-9_]*)['\"]?", raw)
        if hm0:
            heredoc = hm0.group(1)
        code, comment = _code_and_comment(raw)
        if comment is not None and comment.strip():
            toks.append(Token(COMMENT, "", comment.strip(), no))
        if not code.strip():
            continue
        m = _NODE_ATTR.match(code)
        if m:
            keys = [_unq(k) for k in _KEYS.findall(m.group(1))]
            v, vk = _classify(m.group(2))
            toks.append(Token(ATTRIBUTE, keys[-1] if keys else "", v, no, vk, path=".".join(keys), module="node"))
        else:
            m = _LOCAL.match(code)
            if m and m.group(1) not in _RUBY_KW:
                v, vk = _classify(m.group(2))
                toks.append(Token(VARIABLE, m.group(1), v, no, vk))
            else:
                m = _PROP.match(code)
                if m and m.group(1) not in _RUBY_KW:
                    v, vk = _classify(m.group(2))
                    toks.append(Token(ATTRIBUTE, m.group(1), v, no, vk))
        for hm in _HASH.finditer(code):
            name = hm.group(1) or hm.group(2)
            if name:
                v, vk = _classify(hm.group(3))
                toks.append(Token(ATTRIBUTE, name, v, no, vk))
        for hm in _HASH_QKEY.finditer(code):
            v, vk = _classify(hm.group(2))
            toks.append(Token(ATTRIBUTE, _unq(hm.group(1)), v, no, vk))
        for cm in _CALL.finditer(code):
            name = cm.group(1)
            if name.split(".")[-1] in _RUBY_KW:
                continue
            args = [_unq(a) for a in re.findall(_STR, cm.group(2))]
            toks.append(Token(FUNCTION, name, "", no, FUNCALL, args=args))
            # config setters such as make_config('mysql-root-user', "root") are key/value pairs
            m2 = re.fullmatch(rf"\s*({_STR})\s*,\s*({_STR})\s*", cm.group(2))
            if m2:
                v, vk = _classify(m2.group(2))
                toks.append(Token(ATTRIBUTE, _unq(m2.group(1)), v, no, vk, module=name))
        # bare string literals anywhere on the line (URLs, bind addresses in commands)
        for sm in re.finditer(_STR, code):
            s = _unq(sm.group(0))
            if s and not any(t.line == no and t.value == s for t in toks):
                toks.append(Token(ATTRIBUTE, "", s, no, LITERAL))
    return toks

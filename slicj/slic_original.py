"""Faithful Python port of the authors' released SLIC (puppet-lint + all_in_one.rb).

The released checks are positional: for every NAME or VARIABLE token they look
at the next code token and the one after it, on the same line. To mirror them we
need puppet-lint's token stream, so this module has its own lexer that copies
puppet-lint's token types and values (VARIABLE without '$', SSTRING without
quotes, keywords as their own types, interpolated strings split into
DQPRE / VARIABLE / DQMID / DQPOST).
This port exists for RQ1 only: it lets us check that a Python reimplementation
can match the original tool, and it separates "what the paper says" from
"what the code does".
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .rules import ADMIN, BIND, CRYPTO, EMPTY_PW, HTTP, SECRET, SUSP, Finding

KEYWORDS = {"class", "case", "default", "define", "import", "if", "elsif", "else", "inherits", "node", "and", "or",
            "undef", "false", "true", "in", "unless", "function", "type", "attr", "private", "application",
            "consumes", "produces", "site"}
SKIP = {"WHITESPACE", "NEWLINE", "INDENT", "COMMENT", "MLCOMMENT", "SLASH_COMMENT"}
VALUE_PREV = {"NAME", "VARIABLE", "NUMBER", "RPAREN", "RBRACK", "SSTRING", "STRING", "DQPOST", "CLASSREF", "RBRACE",
              "TRUE", "FALSE", "UNDEF"}


@dataclass
class T:
    type: str
    value: str
    line: int


_SIMPLE = [
    ("WHITESPACE", r"[ \t\r]+"), ("NEWLINE", r"\n"), ("COMMENT", r"#[^\n]*"), ("MLCOMMENT", r"/\*.*?\*/"),
    ("SLASH_COMMENT", r"//[^\n]*"),
    ("FARROW", r"=>"), ("PARROW", r"\+>"), ("ISEQUAL", r"=="), ("NOTEQUAL", r"!="), ("MATCH", r"=~"),
    ("NOMATCH", r"!~"), ("GREATEREQUAL", r">="), ("LESSEQUAL", r"<="), ("IN_EDGE", r"->"), ("IN_EDGE_SUB", r"~>"),
    ("OUT_EDGE", r"<-"), ("OUT_EDGE_SUB", r"<~"), ("LLCOLLECT", r"<<\|"), ("RRCOLLECT", r"\|>>"),
    ("LCOLLECT", r"<\|"), ("RCOLLECT", r"\|>"), ("EQUALS", r"="), ("PLUS", r"\+"), ("MINUS", r"-"),
    ("TIMES", r"\*"), ("LBRACK", r"\["), ("RBRACK", r"\]"), ("LBRACE", r"\{"), ("RBRACE", r"\}"),
    ("LPAREN", r"\("), ("RPAREN", r"\)"), ("COMMA", r","), ("SEMIC", r";"), ("COLON", r":"), ("DOT", r"\."),
    ("QMARK", r"\?"), ("NOT", r"!"), ("LESSTHAN", r"<"), ("GREATERTHAN", r">"), ("PIPE", r"\|"), ("AT", r"@"),
    ("MODULO", r"%"),
]
_RX = [(n, re.compile(p, re.S)) for n, p in _SIMPLE]
_VAR = re.compile(r"\$(::)?(\w+::)*\w+(\[[^\]\n]*\])*")
_NUM = re.compile(r"\b(?:0[xX][0-9A-Fa-f]+|0[0-7]*|\d+(?:\.\d+)?(?:[eE]-?\d+)?)\b")
_CLASSREF = re.compile(r"(::)?([A-Z][\w]*::)*[A-Z][\w]*")
_NAME = re.compile(r"(::)?[a-z_][\w\-]*(::[a-z][\w\-]*)*")
_SSTR = re.compile(r"'(?:\\.|[^'\\])*'", re.S)
_DSTR = re.compile(r'"(?:\\.|[^"\\])*"', re.S)
_REGEX = re.compile(r"/(?:\\.|[^/\n\\])+/")


def _dq_tokens(body: str, line: int) -> list[T]:
    if "${" not in body and not re.search(r"\$[a-z_:]", body):
        return [T("STRING", body, line)]
    out, pos, first = [], 0, True
    for m in re.finditer(r"\$\{([^}]*)\}|\$((?:::)?(?:\w+::)*\w+)", body):
        out.append(T("DQPRE" if first else "DQMID", body[pos:m.start()], line))
        first = False
        out.append(T("VARIABLE" if m.group(1) is not None else "UNENC_VARIABLE", (m.group(1) or m.group(2) or "").strip(),
                     line))
        pos = m.end()
    out.append(T("DQPOST", body[pos:], line))
    return out


def lex(text: str) -> list[T]:
    out: list[T] = []
    i, line, n = 0, 1, len(text)
    while i < n:
        c = text[i]
        if c == "'":
            m = _SSTR.match(text, i)
            if m:
                out.append(T("SSTRING", m.group(0)[1:-1], line))
                line += m.group(0).count("\n")
                i = m.end()
                continue
        if c == '"':
            m = _DSTR.match(text, i)
            if m:
                out.extend(_dq_tokens(m.group(0)[1:-1], line))
                line += m.group(0).count("\n")
                i = m.end()
                continue
        if c == "$":
            m = _VAR.match(text, i)
            if m:
                out.append(T("VARIABLE", m.group(0)[1:], line))
                i = m.end()
                continue
        if c == "/" and not text.startswith("/*", i) and not text.startswith("//", i):
            prev = next((t for t in reversed(out) if t.type not in SKIP), None)
            if prev is None or prev.type not in VALUE_PREV:
                m = _REGEX.match(text, i)
                if m:
                    out.append(T("REGEX", m.group(0)[1:-1], line))
                    i = m.end()
                    continue
        if c.isdigit():
            m = _NUM.match(text, i)
            if m:
                out.append(T("NUMBER", m.group(0), line))
                i = m.end()
                continue
        m = _CLASSREF.match(text, i)
        if m and m.group(0) and (m.group(0)[0].isupper() or m.group(0).startswith("::")) and \
                re.match(r"(::)?[A-Z]", m.group(0)):
            out.append(T("CLASSREF", m.group(0), line))
            i = m.end()
            continue
        m = _NAME.match(text, i)
        if m and m.group(0):
            v = m.group(0)
            out.append(T(v.upper() if v in KEYWORDS else "NAME", v, line))
            i = m.end()
            continue
        for name, rx in _RX:
            m = rx.match(text, i)
            if m:
                if name != "WHITESPACE":
                    out.append(T(name, m.group(0), line))
                line += m.group(0).count("\n")
                i = m.end()
                break
        else:
            i += 1  # unknown char
    return out


def _next_code(toks, i):
    j = i + 1
    while j < len(toks) and toks[j].type in SKIP:
        j += 1
    return j if j < len(toks) else None


INVALID = ['(', 'undef', 'true', 'false', 'hiera', 'secret', 'union', '$', '{', 'regsubst', 'hiera_hash', 'pick',
           'get_ssl_property', 'inline_template', 'under', 'mysql_password', '/', 'ssl_ciphersuite', '::']
_V1 = ["pwd", "password", "pass", "key", "crypt", "secret", "certificate", "cert", "ssh_key", "md5", "rsa", "ssl",
       "dsa", "user"]
_KEYW = ["key", "crypt", "secret", "certificate", "cert", "ssh_key", "md5", "rsa", "ssl", "dsa"]
_LOC = ["rsa", "ssh", "pem", "crt", "key", "ssl", "certificate", "crl", "pub"]
_SUSP = ["hack", "fixme", "later", "later2", "todo", "ticket", "launchpad", "bug", "to-do"]


def detect(text: str, file: str, secret_location: bool = False) -> list[Finding]:
    """secret_location=False mirrors the released pipeline: all_in_one.rb prints
    'EXPOSING_SECRET_LOCATION:::' but SLIC's driver searches for
    'EXPOSING_SECRET_LOCATION_', so those warnings never reach the output."""
    toks = lex(text)
    hits: set[tuple[int, str]] = set()
    for i, t in enumerate(toks):
        if t.type in SKIP:
            if t.type in ("COMMENT", "MLCOMMENT", "SLASH_COMMENT"):
                pass
            else:
                continue
        low = t.value.lower()
        if t.type != "COMMENT":   # the Ruby checks only exclude '#' comments
            if "0.0.0.0" in low:
                hits.add((t.line, BIND))
            if "http://" in low:
                hits.add((t.line, HTTP))
            if "md5" in low or "sha1" in low:
                hits.add((t.line, CRYPTO))
        if t.type in SKIP:
            continue
        j = _next_code(toks, i)
        if j is None:
            continue
        k = _next_code(toks, j)
        if k is None:
            continue
        nx, nn = toks[j], toks[k]
        nnv = nn.value.lower()
        same = t.line == nn.line
        # admin by default: VARIABLE EQUALS SSTRING on one line
        if t.type == "VARIABLE" and nx.type == "EQUALS" and nn.type == "SSTRING" and t.line == nx.line == nn.line:
            if ("admin" in nnv and "user" in low) or ("admin" in low and "user" in low):
                hits.add((t.line, ADMIN))
        # empty password
        if t.type in ("NAME", "VARIABLE", "SSTRING") and same:
            if any(w in low for w in ("pwd", "password", "pass")) and (len(nnv) <= 0 or nnv == " ") and "$" not in nnv:
                hits.add((t.line, EMPTY_PW))
        if t.type in ("NAME", "VARIABLE") and same:
            base_ok = ("provider" not in low and nn.type != "VARIABLE" and nnv not in INVALID and len(nnv) > 1)
            # v1 / uname / password / key variants (all reported as hard-coded secret)
            if base_ok and "::" not in nnv and any(w in low for w in _V1) and "::" not in low and "passive" not in low:
                hits.add((t.line, SECRET))
            if base_ok and "::" not in nnv and "user" in low and "::" not in low:
                hits.add((t.line, SECRET))
            if base_ok and "::" not in nnv and any(w in low for w in ("pwd", "password", "pass")) and \
                    "passive" not in low:
                hits.add((t.line, SECRET))
            if base_ok and any(w in low for w in _KEYW) and "::" not in low:
                hits.add((t.line, SECRET))
            if len(nnv) > 0 and nn.type != "VARIABLE" and "ssh-rsa" in nnv:
                hits.add((t.line, SECRET))
        # exposing secret location (reported as hard-coded secret by GLITCH's mapping)
        if secret_location and t.type in ("NAME", "VARIABLE", "SSTRING") and same and nn.type == "SSTRING":
            if any(w in nnv for w in _LOC) and (nnv.startswith("/") or "\\" in nnv) and \
                    ("$" not in nnv or "{" not in nnv):
                hits.add((t.line, SECRET))
    # suspicious comments use raw lines
    for no, raw in enumerate(text.split("\n"), start=1):
        if "#" in raw:
            s = raw.lower().strip()
            if any(w in s for w in _SUSP) and "debug" not in s:
                hits.add((no, SUSP))
    return [Finding(s, file, ln, "", "", "", "") for ln, s in sorted(hits)]

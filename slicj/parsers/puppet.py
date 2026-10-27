"""Token-level Puppet parser.

The original SLIC sits on top of puppet-lint and works only at token level
(it looks at a token, the next code token and the one after that). This
module rebuilds that behaviour in Python: a small lexer, then a pass that
turns lexeme patterns into SLIC tokens.

  $name = <value>            -> VARIABLE   (PARAMETER inside class/define params)
  name => <value>            -> ATTRIBUTE  (also 'quoted key' => value in hashes)
  name(<args>)               -> FUNCTION
  # text  or  /* text */     -> COMMENT
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..tokens import (ATTRIBUTE, BOOL, COMMENT, COMPOUND, EMPTY, FUNCALL, FUNCTION, LITERAL, NULL, NUMBER,
                      PARAMETER, VARIABLE, VARREF, Token)


@dataclass
class Lexeme:
    type: str
    value: str
    line: int


_KEYWORDS = {"if", "elsif", "else", "unless", "case", "default", "class", "define", "node", "inherits", "and",
             "or", "in", "function", "type", "include", "require", "contain", "notice", "fail", "each", "map",
             "filter", "reduce", "with", "lambda", "application", "site", "produces", "consumes"}

_LEX_RULES = [
    ("WS", r"[ \t\r\f]+"),
    ("NL", r"\n"),
    ("COMMENT", r"#[^\n]*"),
    ("MLCOMMENT", r"/\*.*?\*/"),
    ("HEREDOC", r"@\(\s*\"?([A-Za-z0-9_]+)\"?[^)]*\)"),
    ("SSTRING", r"'(?:\\.|[^'\\])*'"),
    ("DQSTRING", r'"(?:\\.|[^"\\])*"'),
    ("VARIABLE", r"\$\{?(?:::)?[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*\}?"),
    ("FARROW", r"=>|\+>"),
    ("OP", r"==|!=|=~|!~|<=|>=|->|~>|<-|<~|<<|>>|\+=|-="),
    ("EQUALS", r"="),
    ("NUMBER", r"0x[0-9A-Fa-f]+|\d+(?:\.\d+)?(?:[eE][-+]?\d+)?"),
    ("NAME", r"(?:::)?[A-Za-z_][A-Za-z0-9_\-]*(?:::[A-Za-z_][A-Za-z0-9_\-]*)*"),
    ("LPAREN", r"\("), ("RPAREN", r"\)"), ("LBRACE", r"\{"), ("RBRACE", r"\}"),
    ("LBRACK", r"\["), ("RBRACK", r"\]"), ("COMMA", r","), ("COLON", r":"), ("SEMIC", r";"),
    ("OTHER", r"."),
]
_LEX_RE = re.compile("|".join(f"(?P<{n}>{p})" for n, p in _LEX_RULES), re.S)


def lex(text: str) -> list[Lexeme]:
    out: list[Lexeme] = []
    pos, line = 0, 1
    n = len(text)
    while pos < n:
        m = _LEX_RE.match(text, pos)
        if not m:  # pragma: no cover - OTHER matches any char
            pos += 1
            continue
        kind = m.lastgroup
        val = m.group(kind)
        if kind == "HEREDOC":
            # body runs from the next line until a line "| END" or "|- END" (or just END)
            tag = re.match(r"@\(\s*\"?([A-Za-z0-9_]+)", val).group(1)
            end_re = re.compile(r"^[ \t]*\|?-?[ \t]*" + re.escape(tag) + r"[ \t]*$", re.M)
            body_start = text.find("\n", m.end())
            body_start = n if body_start < 0 else body_start + 1
            em = end_re.search(text, body_start)
            body_end = em.start() if em else n
            new_pos = em.end() if em else n
            out.append(Lexeme("DQSTRING", '"' + text[body_start:body_end] + '"', line))
            line += text.count("\n", pos, new_pos)
            # keep the rest of the heredoc opening line (e.g. ', ensure => ...') in the stream
            rest = text[m.end():body_start]
            if rest.strip():
                for lx in lex(rest):
                    lx.line = line - text.count("\n", pos, new_pos)
                    out.append(lx)
            pos = new_pos
            continue
        if kind not in ("WS", "NL"):
            out.append(Lexeme(kind, val, line))
        line += val.count("\n")
        pos = m.end()
    return out


def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        return s[1:-1]
    return s


_INTERP_ONLY = re.compile(r"^\$\{?[A-Za-z0-9_:]+\}?$")


def _value_at(lx: list[Lexeme], i: int) -> tuple[str, str, int]:
    """Read the configuration value that starts at lexeme i.

    Returns (value_text, value_kind, index_after_value)."""
    if i >= len(lx):
        return "", NULL, i
    t = lx[i]
    if t.type in ("SSTRING", "DQSTRING"):
        raw = _unquote(t.value)
        if raw == "":
            return "", EMPTY, i + 1
        if t.type == "DQSTRING" and _INTERP_ONLY.match(raw.strip()):
            return raw, VARREF, i + 1
        return raw, LITERAL, i + 1
    if t.type == "VARIABLE":
        return t.value, VARREF, i + 1
    if t.type == "NUMBER":
        return t.value, NUMBER, i + 1
    if t.type == "NAME":
        if i + 1 < len(lx) and lx[i + 1].type == "LPAREN":
            return t.value + "(...)", FUNCALL, i + 1
        if i + 1 < len(lx) and lx[i + 1].type == "LBRACK":   # resource reference Service['x']
            return t.value + "[...]", VARREF, i + 1
        low = t.value.lower()
        if low in ("true", "false"):
            return t.value, BOOL, i + 1
        if low == "undef":
            return t.value, NULL, i + 1
        return t.value, LITERAL, i + 1
    if t.type in ("LBRACK", "LBRACE"):
        return t.value, COMPOUND, i + 1
    return t.value, LITERAL, i + 1


def _func_args(lx: list[Lexeme], i: int) -> list[str]:
    """Literal string / name args of a call whose '(' is at index i."""
    depth, args = 0, []
    for t in lx[i:]:
        if t.type == "LPAREN":
            depth += 1
        elif t.type == "RPAREN":
            depth -= 1
            if depth == 0:
                break
        elif t.type in ("SSTRING", "DQSTRING"):
            args.append(_unquote(t.value))
        elif t.type == "NAME":
            args.append(t.value)
    return args


def parse(text: str) -> list[Token]:
    lx = lex(text)
    toks: list[Token] = []
    # track class/define parameter lists: 'class NAME (' ... matching ')'
    param_depth = 0          # paren depth inside a parameter list (0 = not inside)
    pending_params = False   # saw 'class|define NAME', waiting for '('
    resource = ""            # last resource type seen before '{' (e.g. 'user', 'postgres::user')
    n = len(lx)
    for i, t in enumerate(lx):
        # ---- comments
        if t.type == "COMMENT":
            toks.append(Token(COMMENT, "", t.value.lstrip("#").strip(), t.line))
            continue
        if t.type == "MLCOMMENT":
            body = t.value[2:-2]
            for k, ln in enumerate(body.split("\n")):
                if ln.strip().strip("*").strip():
                    toks.append(Token(COMMENT, "", ln.strip().strip("*").strip(), t.line + k))
            continue
        # ---- parameter list tracking
        if t.type == "NAME" and t.value in ("class", "define"):
            pending_params = True
            continue
        if pending_params and t.type == "LPAREN":
            param_depth = 1
            pending_params = False
            continue
        if pending_params and t.type in ("LBRACE",):
            pending_params = False
        if param_depth:
            if t.type == "LPAREN":
                param_depth += 1
            elif t.type == "RPAREN":
                param_depth -= 1
                continue
        if t.type == "NAME" and i + 1 < n and lx[i + 1].type == "LBRACE" and t.value not in _KEYWORDS:
            resource = t.value
        # ---- $var = value
        if t.type == "VARIABLE" and i + 2 <= n - 1 and lx[i + 1].type == "EQUALS":
            val, kind, _ = _value_at(lx, i + 2)
            name = t.value.strip("${}")
            toks.append(Token(PARAMETER if param_depth == 1 else VARIABLE, "$" + name, val, t.line, kind,
                              module="class-param" if param_depth == 1 else ""))
            continue
        # ---- name => value  /  'key' => value
        if t.type in ("NAME", "SSTRING", "DQSTRING") and i + 2 <= n - 1 and lx[i + 1].type == "FARROW":
            val, kind, _ = _value_at(lx, i + 2)
            toks.append(Token(ATTRIBUTE, _unquote(t.value), val, t.line, kind, module=resource))
            continue
        # ---- function call
        if t.type == "NAME" and i + 1 < n and lx[i + 1].type == "LPAREN" and t.value.lower() not in _KEYWORDS:
            toks.append(Token(FUNCTION, t.value, "", t.line, FUNCALL, args=_func_args(lx, i + 1)))
            continue
    return toks

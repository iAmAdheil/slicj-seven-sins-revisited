"""SLIC rule engine (paper Table II + Table III) and the SLIC-J variants.

Three rule sets:
  paper  - Table II rules with Table III string patterns, as printed.
  code   - the released SLIC Ruby checks (akondrahman/IacSec, SPrules4pupp),
           which are broader than the printed table.
  slicj  - our port: the same seven smells with name segmentation and
           value-kind checks, plus the new smell 'TLS verification disabled'.

The rule layer aims for high recall. Context-aware filtering is a separate
step (context.py, triage.py).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict

from .tokens import (ATTRIBUTE, BOOL, COMMENT, EMPTY, FUNCTION, LITERAL, NULL, NUMBER, PARAMETER, VARIABLE,
                     VARREF, Token)

ADMIN = "admin_by_default"
EMPTY_PW = "empty_password"
SECRET = "hardcoded_secret"
BIND = "invalid_bind"
SUSP = "suspicious_comment"
HTTP = "http_without_tls"
CRYPTO = "weak_crypto"
TLS_OFF = "tls_verify_disabled"     # new smell (not one of the seven sins)

SEVEN = [ADMIN, EMPTY_PW, SECRET, BIND, SUSP, HTTP, CRYPTO]
ALL = SEVEN + [TLS_OFF]
CWE = {ADMIN: "CWE-250", EMPTY_PW: "CWE-258", SECRET: "CWE-798", BIND: "CWE-284", SUSP: "CWE-546",
       HTTP: "CWE-319", CRYPTO: "CWE-327", TLS_OFF: "CWE-295"}
LABEL = {ADMIN: "Admin by default", EMPTY_PW: "Empty password", SECRET: "Hard-coded secret",
         BIND: "Invalid IP address binding", SUSP: "Suspicious comment", HTTP: "Use of HTTP without TLS",
         CRYPTO: "Use of weak crypto. algo.", TLS_OFF: "TLS verification disabled"}


@dataclass
class Finding:
    smell: str
    file: str
    line: int
    kind: str
    name: str
    value: str
    value_kind: str
    module: str = ""
    path: str = ""
    sub: str = ""          # for hard-coded secret: user / password / key

    def key(self):
        return (self.file, self.line, self.smell)

    def as_dict(self):
        return asdict(self)


def _assign(t: Token) -> bool:
    return t.kind in (ATTRIBUTE, VARIABLE, PARAMETER)


# ---------------------------------------------------------------- paper (Table III)
_P_BUGINFO = [re.compile(r"bug[#nt]*[0-9]+"), re.compile(r"show_bug\.cgi\?id=[0-9]+")]
_P_WRONG = ["bug", "hack", "fixme", "later", "later2", "todo"]
# Table III prints '[pvt|priv]+*[cert|key|rsa|secret|ssl]+', which is not a valid
# regex ('+*' is a double quantifier). We use the evident intent: 'pvt' or 'priv'
# followed (anywhere later) by one of the key words.
_P_PVTKEY = re.compile(r"(pvt|priv).*(cert|key|rsa|secret|ssl)")


def _p_user(n): return "user" in n
def _p_pass(n): return any(w in n for w in ("pwd", "pass", "password"))
def _p_pvt(n): return bool(_P_PVTKEY.search(n))


def paper_rules(t: Token):
    n = t.name.lower()
    v = t.value
    if t.kind == PARAMETER and "admin" in n and _p_user(n):
        yield ADMIN, ""
    if _assign(t) and len(v) == 0 and t.value_kind == EMPTY and _p_pass(n):
        yield EMPTY_PW, ""
    # the paper's examples (Table I) are all literal strings; a variable is not "hard-coded"
    if _assign(t) and (_p_user(n) or _p_pass(n) or _p_pvt(n)) and len(v) > 0 and t.value_kind in (LITERAL, NUMBER):
        yield SECRET, ("password" if _p_pass(n) else "user" if _p_user(n) else "key")
    if _assign(t) and "0.0.0.0" in v:
        yield BIND, ""
    if t.kind == COMMENT:
        low = v.lower()
        if any(w in low for w in _P_WRONG) or any(r.search(low) for r in _P_BUGINFO):
            yield SUSP, ""
    if _assign(t) and "http:" in v.lower():
        yield HTTP, ""
    if t.kind == FUNCTION and any(w in n for w in ("md5", "sha1")):
        yield CRYPTO, ""


# ---------------------------------------------------------------- code (released Ruby)
_C_SECRET = ["pwd", "password", "pass", "uuid", "key", "crypt", "secret", "certificate", "id", "cert", "token",
             "ssh_key", "md5", "rsa", "ssl"]
_C_SUSP = ["show_bug", "hack", "fixme", "later", "later2", "todo", "ticket", "launchpad", "bug"]


def code_rules(t: Token, raw_line: str = ""):
    n = t.name.lower()
    v = t.value
    # no_default_admin: VARIABLE = SSTRING with (value has admin and name has user) or name has admin+user
    if t.kind in (VARIABLE, PARAMETER) and t.value_kind == LITERAL and (
            ("admin" in v.lower() and "user" in n) or ("admin" in n and "user" in n)):
        yield ADMIN, ""
    if _assign(t) and any(w in n for w in ("pwd", "password", "pass")) and t.value_kind == EMPTY:
        yield EMPTY_PW, ""
    if _assign(t) and any(w in n for w in _C_SECRET) and len(v) > 0 and t.value_kind not in (VARREF,) \
            and "(" not in n:
        yield SECRET, ("password" if _p_pass(n) else "user" if _p_user(n) else "key")
    if _assign(t) and "ssh-rsa" in v.lower() and t.value_kind != VARREF:
        yield SECRET, "key"
    if t.kind == COMMENT and any(w in v.lower() for w in _C_SUSP):
        yield SUSP, ""
    if t.kind != COMMENT and "http://" in v.lower():
        yield HTTP, ""
    if t.kind != COMMENT and "0.0.0.0" in v:
        yield BIND, ""
    if t.kind != COMMENT and ("md5" in v.lower() or (t.kind == FUNCTION and "md5" in n)):
        yield CRYPTO, ""


# ---------------------------------------------------------------- SLIC-J
_SEG = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")


def segments(name: str) -> list[str]:
    name = name.strip("$:{}'\"")
    parts = re.split(r"[^A-Za-z0-9]+", name)
    out = []
    for p in parts:
        out.extend(s.lower() for s in _SEG.findall(p))
    return out


_PW_SEGS = {"pass", "pwd", "password", "passwd", "passphrase", "passwords", "pw", "pword", "pass_no"}
_USER_SEGS = {"user", "username", "uname", "usr", "login", "userid", "loginid"}
_KEY_SECRETS = {"secret", "token", "apikey", "credential", "credentials", "privkey", "pvtkey"}


def is_password(name: str) -> bool:
    segs = segments(name)
    return any(s in _PW_SEGS or s.startswith("passw") for s in segs)


def is_user(name: str) -> bool:
    segs = segments(name)
    return any(s in _USER_SEGS or (s.endswith("user") and len(s) <= 12) or s.endswith("username") for s in segs)


def is_key(name: str) -> bool:
    segs = segments(name)
    if any(s in _KEY_SECRETS for s in segs):
        return True
    joined = "_".join(segs)
    if re.search(r"(pvt|priv|private).*(cert|key|rsa|secret|ssl)", joined):
        return True
    return bool(re.search(r"(api|access|secret|auth|ssh|encryption|master|signing|session)_key\b", joined)) \
        or bool(re.search(r"\bauth_token\b|\bssh_key\b", joined))


_ROOT_CMD = re.compile(r"(?:^|\s)(?:-u\s*root|--user[= ]root|-U\s*root)\b")
_BIND_RE = re.compile(r"(?<![\d.])0\.0\.0\.0(?![\d.])")
_HTTP_RE = re.compile(r"\bhttp://", re.I)
_SUSP_WORDS = re.compile(r"\b(todo|to-do|to_do|fixme|hack|xxx|bug|bugs|later|ticket|incorrect|workaround|"
                         r"to be implemented|not implemented|not yet implemented)\b|issues?/\d+", re.I)
_BUGINFO = re.compile(r"bug[#\s]*[0-9]+|show_bug\.cgi\?id=[0-9]+|launchpad\.net/[^\s]*\+bug/[0-9]+|\bbug/[0-9]+", re.I)
_WEAK = re.compile(r"(?<![a-z0-9])(md5|sha1|sha-1|md4|arcfour\w*|rc4)(?![0-9])", re.I)
_CIPHER_NAMES = re.compile(r"cipher|macs?$|_macs?_|kex|algorithm|digest|hmac", re.I)
_HASH_NAMES = re.compile(r"hash|crypt|digest|algo|checksum|scheme|cipher|signature|mac", re.I)

# --- TLS verification disabled
_TLS_FALSE_NAMES = {"validate_certs", "validate_cert", "verify_ssl", "ssl_verify", "sslverify", "verify_certs",
                    "tls_verify", "verify_tls", "check_certificate", "validate_certificate", "ssl_verify_peer",
                    "verify_peer", "ssl_verify_host", "verify_host", "verifyssl", "ssl_check", "cert_validation",
                    "validate_ssl", "verify_certificate", "ca_verify", "repo_gpgcheck_ssl", "http_ssl_verify",
                    "git_ssl_verify", "sslverifypeer", "tls_verify_server"}
_TLS_TRUE_NAMES = {"insecure", "insecure_skip_tls_verify", "insecure_skip_verify", "skip_tls_verify",
                   "ssl_insecure", "tls_insecure", "disable_ssl_verification", "skip_ssl_verify",
                   "no_check_certificate", "skip_verify", "allow_insecure", "ignore_certs", "ignore_ssl_errors"}
_TLS_CMD = re.compile(r"(?:\bcurl\b[^\n|;&]*\s(?:-k\b|--insecure\b|-[A-Za-z]*k[A-Za-z]*\b))"
                      r"|--no-check-certificate|--insecure-skip-tls-verify(?:=true)?\b|--tls-verify=false"
                      r"|GIT_SSL_NO_VERIFY\s*=\s*(?:1|true)|http\.sslVerify\s*(?:=\s*)?false|sslverify\s*=\s*(?:0|false|no)"
                      r"|PYTHONHTTPSVERIFY\s*=\s*0|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|verify\s*=\s*False"
                      r"|--disable-ssl-verification|--skip-tls-verify|--insecure-registry|strict-ssl\s+false", re.I)
_FALSEY = {"false", "no", "0", "off", "n", "none_verify"}
_TRUEY = {"true", "yes", "1", "on", "y"}


def _norm_name(n: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", n.lower().strip("$:{}'\"")).strip("_")


def tls_rules(t: Token):
    n = _norm_name(t.name)
    v = t.value.strip().strip("'\"").lower()
    if _assign(t) and t.value_kind in (BOOL, LITERAL, NUMBER):
        if n in _TLS_FALSE_NAMES and v in _FALSEY:
            yield TLS_OFF, ""
            return
        if n in _TLS_TRUE_NAMES and v in _TRUEY:
            yield TLS_OFF, ""
            return
    if t.kind != COMMENT and t.value and _TLS_CMD.search(t.value):
        yield TLS_OFF, ""


def slicj_rules(t: Token):
    n = t.name
    v = t.value
    lit = t.value_kind in (LITERAL, NUMBER)
    # The oracle's rater guide widens the paper's definition: "every time more privileges are
    # being given than necessary". So any user-like setting (not only class parameters) counts.
    if _assign(t) and (is_user(n) or _norm_name(n) in ("runas", "run_as", "become_user", "remote_user")) and \
            t.value_kind == LITERAL and re.fullmatch(r"\s*(admin|administrator|root|superuser|sa)\s*", v, re.I):
        yield ADMIN, ""
    elif t.kind != COMMENT and t.value_kind in (LITERAL, VARREF) and _ROOT_CMD.search(v):
        yield ADMIN, ""
    # GLITCH's null_values = ["nil", ""]: an undef/nil/null password default is also empty
    if _assign(t) and is_password(n) and (t.value_kind == EMPTY or (t.value_kind == NULL and t.kind != ATTRIBUTE)):
        yield EMPTY_PW, ""
    if _assign(t) and lit and len(v) > 0 and not (t.value_kind == NUMBER and not is_password(n)):
        if is_password(n):
            yield SECRET, "password"
        elif is_user(n) and t.value_kind == LITERAL:
            yield SECRET, "user"
        elif is_key(n):
            yield SECRET, "key"
    if _assign(t) and t.value_kind == LITERAL and ("ssh-rsa " in v or "-----BEGIN" in v and "PRIVATE KEY" in v):
        if not (is_password(n) or is_user(n) or is_key(n)):
            yield SECRET, "key"
    if t.kind != COMMENT and t.kind != FUNCTION and _BIND_RE.search(v):
        yield BIND, ""
    if t.kind == COMMENT and (_SUSP_WORDS.search(v) or _BUGINFO.search(v)):
        yield SUSP, ""
    if t.kind != COMMENT and t.kind != FUNCTION and _HTTP_RE.search(v):
        yield HTTP, ""
    if t.kind == FUNCTION and (_WEAK.search(t.name) or any(_WEAK.fullmatch(a.strip()) or
                                                          re.fullmatch(r"(md5|sha1)_crypt", a.strip(), re.I)
                                                          for a in t.args)):
        yield CRYPTO, ""
    elif _assign(t) and t.value_kind == LITERAL and _HASH_NAMES.search(n) and \
            re.fullmatch(r"\s*(md5|sha1|sha-1|md4|md5_crypt|sha1_crypt|apr_md5_crypt|\{sha\}|\{md5\})\s*", v, re.I):
        yield CRYPTO, ""
    elif _assign(t) and t.value_kind == LITERAL and _CIPHER_NAMES.search(_norm_name(n)) and _WEAK.search(v):
        yield CRYPTO, ""   # e.g. $macs = 'hmac-sha2-512,...,hmac-sha1' or ciphers with arcfour
    yield from tls_rules(t)


RULESETS = {"paper": paper_rules, "code": code_rules, "slicj": slicj_rules}


def detect(tokens: list[Token], file: str, ruleset: str = "slicj") -> list[Finding]:
    fn = RULESETS[ruleset]
    out: list[Finding] = []
    seen = set()
    for t in tokens:
        for smell, sub in fn(t):
            f = Finding(smell, file, t.line, t.kind, t.name, t.value, t.value_kind, t.module, t.path, sub)
            k = (f.file, f.line, f.smell, f.name)
            if k in seen:
                continue
            seen.add(k)
            out.append(f)
    return out

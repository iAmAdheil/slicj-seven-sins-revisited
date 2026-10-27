"""Context layer: deterministic features for each finding.

Every feature is computed in code. The triage model only receives these
features plus a masked code window; it never has to resolve variables or
judge randomness itself (both are known weak spots of System One models).

Privacy rule: a literal that could be a working credential is never sent
out in clear. We send its shape (length, character classes, entropy bucket,
known-format class) and a masked preview. Placeholders and short dictionary
words are sent in clear because they carry no secret.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlparse

from .rules import BIND, CRYPTO, EMPTY_PW, HTTP, SECRET, SUSP, TLS_OFF, Finding, ADMIN

PLACEHOLDER_WORDS = {
    "changeme", "change_me", "change-me", "changethis", "example", "examplepass", "sample", "dummy", "test",
    "testing", "test123", "foo", "bar", "foobar", "baz", "secret", "password", "passw0rd", "pass", "password123",
    "xxx", "xxxx", "xxxxx", "todo", "fixme", "replace", "replaceme", "replace_me", "your_password", "yourpassword",
    "mypassword", "mysecret", "default", "none", "null", "nil", "undef", "tbd", "placeholder", "insert", "fake",
    "notasecret", "not-a-secret", "redacted", "hidden", "secretpassword", "letmein", "qwerty", "abc123", "123456",
    "12345678", "1234", "admin", "root", "toor", "demo", "vagrant", "ubuntu", "pa55word", "s3cr3t", "supersecret",
}
PLACEHOLDER_RE = re.compile(r"^(<[^>]+>|\*+|x{3,}|\.\.\.|%\w+%|__\w+__|@@\w+@@|\$\{[^}]*\}|your[_-]?\w+|"
                            r"(change|replace)[_-]?(me|this|it)\w*|.*(example|sample|dummy|placeholder|fake|test).*)$",
                            re.I)
SYSTEM_USERS = {"root", "admin", "www-data", "nginx", "apache", "httpd", "postgres", "mysql", "jenkins", "ubuntu",
                "centos", "ec2-user", "vagrant", "nobody", "daemon", "git", "redis", "elasticsearch", "kibana",
                "rabbitmq", "keystone", "nova", "glance", "neutron", "cinder", "swift", "heat", "puppet", "ansible",
                "deploy", "deployer", "zabbix", "nagios", "tomcat", "docker", "grafana", "prometheus", "memcache",
                "memcached", "mongodb", "consul", "vault", "hadoop", "hdfs", "yarn", "zookeeper", "kafka", "ceph",
                "openstack", "stack", "debian", "user", "guest", "operator", "sa", "administrator", "wheel", "staff",
                "users", "adm", "sys", "bin", "mail", "ftp", "sshd", "ntp", "syslog", "systemd", "backup"}
KEY_FORMATS = [
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe_key", re.compile(r"\b[sr]k_(live|test)_[0-9A-Za-z]{16,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("ssh_public_key", re.compile(r"\bssh-(rsa|ed25519|dss)\s+AAAA[0-9A-Za-z+/=]{20,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.")),
    ("password_hash", re.compile(r"^\$(1|2[aby]?|5|6|apr1)\$[./A-Za-z0-9]{1,22}\$[./A-Za-z0-9]{8,}$")),
    ("hex_digest", re.compile(r"^[0-9a-fA-F]{32,128}$")),
    ("uuid", re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")),
]
PURPOSE_DIRS = [
    ("test_or_ci", re.compile(r"(^|/)(tests?|spec|specs|molecule|ci|\.github|\.gitlab|integration|fixtures?|"
                              r"test_\w+|\w+_tests?|kitchen|\.kitchen|zuul\.d|playbooks/tests?)(/|$)", re.I)),
    ("example_or_training", re.compile(r"(^|/)(examples?|samples?|demo|demos|tutorials?|training|docs?|"
                                       r"vagrant|sandbox|playground|quickstart|lab|labs|workshop)(/|$|[-_.])", re.I)),
    ("dev", re.compile(r"(^|/)(dev|devel|development|local|localdev|devstack|devbox)(/|$|[-_.])", re.I)),
]
NAMESPACE_HOSTS = re.compile(r"(^|\.)(w3\.org|xmlns\.com|schemas\.\w+|purl\.org|apache\.org/xml|"
                             r"java\.sun\.com|xml\.org|docbook\.org|openoffice\.org|maven\.apache\.org/POM|"
                             r"json-schema\.org|ns\.adobe\.com)$", re.I)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def charset(s: str) -> str:
    parts = []
    if re.search(r"[a-z]", s): parts.append("lower")
    if re.search(r"[A-Z]", s): parts.append("upper")
    if re.search(r"\d", s): parts.append("digit")
    if re.search(r"[^A-Za-z0-9]", s): parts.append("symbol")
    return "+".join(parts) or "none"


def entropy_bucket(s: str) -> str:
    e, n = entropy(s), len(s)
    if n < 8 or e < 2.5:
        return "low"
    if n >= 16 and e >= 3.5:
        return "high"
    return "medium"


def key_format(s: str) -> str:
    for name, rx in KEY_FORMATS:
        if rx.search(s):
            return name
    return "none"


def is_placeholder(s: str) -> bool:
    v = s.strip().strip("'\"").lower()
    if not v:
        return False
    return v in PLACEHOLDER_WORDS or bool(PLACEHOLDER_RE.match(v))


def value_shape(s: str) -> str:
    v = s.strip()
    if not v:
        return "empty"
    if v.startswith(("/", "~/", "./", "../")) or re.match(r"^[A-Za-z]:\\", v) or \
            re.search(r"\.(pem|key|crt|cer|p12|pfx|jks|pub|keytab|gpg|asc)$", v, re.I):
        return "file_path"
    if re.match(r"^[a-z][a-z0-9+.-]*://", v, re.I):
        return "url"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}", v) and entropy_bucket(v) != "high":
        return "identifier"
    if re.fullmatch(r"\d+", v):
        return "number"
    if " " in v and len(v.split()) > 2:
        return "text"
    return "token"


def host_scope(host: str) -> str:
    h = (host or "").strip("[]").lower()
    if not h:
        return "none"
    if "{{" in h or "$" in h or "%{" in h or "<%" in h:
        return "templated"
    if h in ("localhost", "localhost.localdomain", "ip6-localhost") or h.endswith(".localhost"):
        return "loopback"
    try:
        ip = ipaddress.ip_address(h)
        if ip.is_loopback:
            return "loopback"
        if ip.is_unspecified:
            return "any"
        if ip.is_private or ip.is_link_local:
            return "private"
        return "public"
    except ValueError:
        pass
    if "." not in h or h.endswith((".local", ".internal", ".lan", ".localdomain", ".intranet", ".corp", ".home",
                                   ".svc", ".cluster.local", ".consul", ".novalocal", ".example")) \
            or h in ("example.com", "example.org", "example.net") or h.endswith((".example.com", ".example.org")):
        return "private_or_example"
    return "public"


_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)


def url_info(value: str) -> dict:
    m = _URL_RE.search(value or "")
    if not m:
        return {"host_scope": "none", "url_kind": "none"}
    url = m.group(0)
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        host = ""
    if "{{" in url[:40] or "$" in url[:12]:
        scope = "templated"
    else:
        scope = host_scope(host)
    if NAMESPACE_HOSTS.search(host) or re.search(r"xmlns|/schema|/ns/|\.dtd$|\.xsd$", url, re.I):
        kind = "namespace"
    elif re.search(r"\.(iso|tar|tgz|gz|bz2|xz|zip|rpm|deb|sh|run|bin|jar|msi|exe|whl)(\?|$)", url, re.I):
        kind = "download"
    elif re.search(r"(repo|mirror|apt|yum|dnf|packages?|dl\.|download)", url, re.I):
        kind = "package_repo"
    elif re.search(r":\d{2,5}(/|$)", url):
        kind = "service_endpoint"
    else:
        kind = "web"
    return {"host_scope": scope, "url_kind": kind}


def bind_info(value: str) -> str:
    v = value or ""
    if re.search(r"0\.0\.0\.0/0", v):
        return "cidr_any"
    if re.search(r"0\.0\.0\.0:\d+", v):
        return "bind_with_port"
    if v.strip() == "0.0.0.0":
        return "bare"
    return "embedded"


def path_purpose(path: str) -> str:
    # datasets often flatten paths into one name (repo@dir-sub-file.yml), so '-' and '@' also separate parts
    p = re.sub(r"[-@]", "/", path.replace("\\", "/"))
    for name, rx in PURPOSE_DIRS:
        if rx.search(p):
            return name
    return "unspecified"


def mask(s: str) -> str:
    """Masked preview: keep shape, hide content."""
    v = s.strip()
    if len(v) <= 4:
        return "*" * len(v)
    return v[:2] + "*" * min(len(v) - 4, 12) + v[-2:] + f" (len {len(v)})"


def safe_value(f: Finding) -> str:
    """What may leave the machine for this finding's value."""
    v = f.value or ""
    if f.smell != SECRET:
        return v[:200]
    if is_placeholder(v) or (value_shape(v) in ("identifier", "file_path", "url") and entropy_bucket(v) != "high"):
        return v[:120]
    return mask(v)


SENSITIVE_LINE = re.compile(r"(pass|pwd|secret|token|key|cred|auth)", re.I)


def masked_window(lines: list[str], line: int, radius: int = 3, keep_comments: bool = True) -> str:
    """Code window around a finding, with likely-secret literals masked."""
    lo, hi = max(1, line - radius), min(len(lines), line + radius)
    out = []
    for no in range(lo, hi + 1):
        raw = lines[no - 1]
        if not keep_comments:
            raw = _strip_comment(raw)
            if not raw.strip():
                continue
        if SENSITIVE_LINE.search(raw):
            raw = re.sub(r"(['\"])([^'\"]{6,})\1",
                         lambda m: m.group(1) + (m.group(2) if is_placeholder(m.group(2)) or
                                                 entropy_bucket(m.group(2)) == "low" else mask(m.group(2))) + m.group(1),
                         raw)
            raw = re.sub(r"(:\s+)([^\s'\"{#][^\s#]{7,})\s*$",
                         lambda m: m.group(1) + (m.group(2) if is_placeholder(m.group(2)) or
                                                 entropy_bucket(m.group(2)) == "low" else mask(m.group(2))), raw)
        marker = ">>" if no == line else "  "
        out.append(f"{marker}{no:4d}| {raw}")
    return "\n".join(out)


def _strip_comment(raw: str) -> str:
    from .parsers.ansible import _comment_index
    idx = _comment_index(raw)
    return raw[:idx].rstrip() if idx is not None else raw


def features(f: Finding, lines: list[str] | None = None, readme: str = "") -> dict:
    v = f.value or ""
    feat = {
        "smell": f.smell,
        "token_kind": f.kind,
        "value_kind": f.value_kind,
        "secret_sub": f.sub or "none",
        "path_purpose": path_purpose(f.file),
        "module": (f.module or "none")[:40],
        "value_shape": value_shape(v),
        "placeholder": is_placeholder(v),
        "entropy_bucket": entropy_bucket(v),
        "key_format": key_format(v),
        "value_len": len(v),
        "charset": charset(v),
        "system_user": v.strip().lower() in SYSTEM_USERS,
        "host_scope": "none",
        "url_kind": "none",
        "bind_kind": "none",
        "comment_word": "none",
    }
    if f.smell in (HTTP, TLS_OFF):
        feat.update(url_info(v))
    if f.smell == BIND:
        feat["bind_kind"] = bind_info(v)
    if f.smell == SUSP:
        m = re.search(r"\b(todo|fixme|hack|xxx|bug|later)\b", v, re.I) or re.search(r"(bug|todo|fixme|hack)", v, re.I)
        feat["comment_word"] = m.group(1).lower() if m else "buginfo"
    # mitigation hints that code can see without a model
    if lines:
        win = "\n".join(lines[max(0, f.line - 4): f.line + 3]).lower()
        feat["no_log_nearby"] = "no_log: true" in win or "no_log: yes" in win
        feat["vault_nearby"] = "vault" in win or "lookup(" in win or "hiera(" in win or "lookup('" in win
    else:
        feat["no_log_nearby"] = feat["vault_nearby"] = False
    return feat


def explain_rule(f: Finding) -> str:
    return {
        ADMIN: "a default user parameter is set to an administrative account",
        EMPTY_PW: "a password-like name is assigned an empty string",
        SECRET: f"a {f.sub or 'secret'}-like name is assigned a literal value",
        BIND: "a value contains the address 0.0.0.0 (all interfaces)",
        SUSP: "a comment contains a defect keyword (todo/fixme/hack/bug/later) or bug-tracker reference",
        HTTP: "a value contains an http:// URL (no TLS)",
        CRYPTO: "a weak hash algorithm (MD5/SHA-1) is used",
        TLS_OFF: "TLS certificate verification is switched off",
    }[f.smell]

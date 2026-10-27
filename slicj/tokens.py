"""SLIC token model.

SLIC's Parser turns a script into vectors such as
<VARIABLE, '$vcenter_password', 'password'> (paper, Fig. 5). We keep the
same four token types and add PARAMETER (Table II uses isParameter) plus a
few fields that the context layer and the triage step need later.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

VARIABLE = "VARIABLE"
ATTRIBUTE = "ATTRIBUTE"
PARAMETER = "PARAMETER"   # class/define parameter (Puppet) or role default (Ansible)
COMMENT = "COMMENT"
FUNCTION = "FUNCTION"

# value_kind tells the rules what the right-hand side is. SLIC only looks at
# literal strings; the released Ruby code skips values that are variables.
LITERAL = "literal"       # quoted or bare string
EMPTY = "empty"           # string of length zero
VARREF = "varref"         # $var, {{ var }}, or other reference
FUNCALL = "funcall"       # value computed by a function / lookup
VAULT = "vault"           # Ansible !vault or vault_* reference
NUMBER = "number"
BOOL = "bool"
NULL = "null"             # key present, no value (YAML null)
COMPOUND = "compound"     # list / hash


@dataclass
class Token:
    kind: str
    name: str
    value: str
    line: int
    value_kind: str = LITERAL
    path: str = ""          # e.g. "tasks[2].mysql_user.password" (Ansible) or resource title
    module: str = ""        # Ansible module / Puppet resource type that owns the attribute
    args: list[str] = field(default_factory=list)  # literal args for FUNCTION tokens

    def as_dict(self) -> dict:
        return asdict(self)

    def __str__(self) -> str:  # SLIC-style vector
        if self.kind == COMMENT:
            return f"<COMMENT, '{self.value}'>"
        return f"<{self.kind}, '{self.name}', '{self.value}'>"

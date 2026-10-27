from pathlib import Path

from slicj.parsers import puppet, ansible
from slicj.rules import (ADMIN, BIND, CRYPTO, EMPTY_PW, HTTP, SECRET, SUSP, TLS_OFF, detect, segments, is_password,
                         is_user)
from slicj.tokens import ATTRIBUTE, COMMENT, PARAMETER, VARIABLE

FX = Path(__file__).parent / "fixtures"


def smells(path, ruleset, parser):
    text = (FX / path).read_text()
    toks = parser(text) if parser is puppet.parse else parser(text, path)
    return {(f.smell, f.line) for f in detect(toks, path, ruleset)}


def test_fig5_parser_vectors():
    toks = puppet.parse("#This is an example Puppet script\n$token = 'XXXYYYZZZ'\n\n$os_name = 'Windows'\n"
                        "auth_protocol => 'http'\n$vcenter_password = 'password'\n")
    got = [str(t) for t in toks]
    assert got == ["<COMMENT, 'This is an example Puppet script'>", "<VARIABLE, '$token', 'XXXYYYZZZ'>",
                   "<VARIABLE, '$os_name', 'Windows'>", "<ATTRIBUTE, 'auth_protocol', 'http'>",
                   "<VARIABLE, '$vcenter_password', 'password'>"]


def test_fig4_slicj_finds_all_seven_kinds():
    s = smells("fig4.pp", "slicj", puppet.parse)
    kinds = {k for k, _ in s}
    assert {ADMIN, EMPTY_PW, SECRET, BIND, SUSP, HTTP, CRYPTO} <= kinds
    assert (ADMIN, 3) in s and (SECRET, 4) in s and (BIND, 7) in s and (HTTP, 9) in s
    assert (EMPTY_PW, 20) in s and (CRYPTO, 26) in s and (SUSP, 1) in s
    # variable references are not hard-coded secrets
    assert (SECRET, 14) not in s


def test_fig4_paper_rules():
    s = smells("fig4.pp", "paper", puppet.parse)
    assert (SECRET, 3) in s and (SECRET, 4) in s and (BIND, 7) in s and (HTTP, 9) in s
    assert (EMPTY_PW, 20) in s and (CRYPTO, 26) in s and (SUSP, 1) in s
    # Table II says isAdmin(x.name) AND isUser(x.name); '$power_username' has no 'admin', so the
    # printed rule misses the paper's own Fig. 4 example. This is a reproduction finding.
    assert not any(k == ADMIN for k, _ in s)


def test_parameters_detected():
    toks = puppet.parse((FX / "fig4.pp").read_text())
    params = [t for t in toks if t.kind == PARAMETER]
    assert [t.name for t in params] == ["$power_username", "$power_password"]


def test_ansible_tokens_and_lines():
    toks = ansible.parse((FX / "site.yml").read_text(), "site.yml")
    by = {(t.kind, t.name): t for t in toks}
    assert by[(VARIABLE, "db_password")].line == 6
    assert by[(ATTRIBUTE, "validate_certs")].value == "false"
    comments = [t for t in toks if t.kind == COMMENT]
    assert [c.line for c in comments] == [2]   # the comment inside the block scalar is not a YAML comment


def test_ansible_smells():
    s = smells("site.yml", "slicj", ansible.parse)
    assert (SUSP, 2) in s
    assert (SECRET, 5) in s and (SECRET, 6) in s          # db_user: admin, db_password literal
    assert (SECRET, 7) not in s                           # vault reference
    assert (EMPTY_PW, 8) in s
    assert (BIND, 14) in s and (HTTP, 17) in s
    assert (TLS_OFF, 19) in s and (TLS_OFF, 24) in s
    assert (CRYPTO, 22) in s


def test_segments():
    assert segments("$vcenter_password") == ["vcenter", "password"]
    assert segments("dbPassword") == ["db", "password"]
    assert is_password("mysql_root_pass") and not is_password("passive_mode") and not is_password("bypass")
    assert is_user("admin_user") and is_user("dbuser") and not is_user("users")


def test_tls_rule_and_chef_parser():
    from slicj.parsers import chef
    from slicj.rules import TLS_OFF
    toks = chef.parse("remote_file '/tmp/x' do\n  source 'http://example.com/x.tgz'\n  verify_ssl false\nend\n"
                      "execute 'get' do\n  command 'curl -k https://10.0.0.1/a'\nend\n")
    s = {(f.smell, f.line) for f in detect(toks, "x.rb", "slicj")}
    assert (HTTP, 2) in s and (TLS_OFF, 3) in s and (TLS_OFF, 6) in s


def test_slic_code_port_fig4():
    from slicj import slic_original
    fs = slic_original.detect((FX / "fig4.pp").read_text(), "fig4.pp")
    got = {(f.smell, f.line) for f in fs}
    # released SLIC semantics: admin via value, md5 anywhere outside comments, http, bind
    assert (ADMIN, 3) in got and (BIND, 7) in got and (HTTP, 9) in got and (CRYPTO, 26) in got


def test_masking_never_leaks_high_entropy_secret():
    from slicj.context import safe_value
    from slicj.rules import Finding
    f = Finding(SECRET, "a.yml", 1, "VARIABLE", "db_password", "Zx9#qL2!vT7pW4rK", "literal", sub="password")
    assert "Zx9#qL2!vT7pW4rK" not in safe_value(f)
    g = Finding(SECRET, "a.yml", 1, "VARIABLE", "db_password", "changeme", "literal", sub="password")
    assert safe_value(g) == "changeme"

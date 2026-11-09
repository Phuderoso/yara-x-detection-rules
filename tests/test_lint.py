"""Testes do lint (scripts/lint_rules.py): regra boa passa, cada defeito é apontado."""

from __future__ import annotations

import re
import uuid
from pathlib import Path

import pytest

import lint_rules
import yrlib

GOOD_RULE = """\
import "pe"

rule MAL_Win_Test_Good_Anchor {{
  meta:
    id           = "{id}"
    version      = 1
    author       = "tests"
    date         = "2026-01-01"
    modified     = "2026-01-02"
    description  = "regra válida para o lint"
    hash         = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    status       = "{status}"
    confidence   = "{confidence}"
    purpose      = "{purpose}"
    mitre_attack = "{mitre}"
    scope        = "{scope}"

  strings:
    $anchor = "UNIQUE::FAMILY::MARKER" ascii
    $ctx    = "WriteProcessMemory" ascii

  condition:
    uint16(0) == 0x5A4D and filesize < 2MB and pe.is_pe and $anchor and $ctx
}}
"""


def make_rule(**overrides: str) -> str:
    params = {
        "id": str(uuid.uuid4()),
        "status": "test",
        "confidence": "high",
        "purpose": "triage",
        "mitre": "T1055.002, T1027",
        "scope": "file",
    }
    params.update(overrides)
    return GOOD_RULE.format(**params)


def write_rule(tmp_path: Path, text: str, name: str = "MAL_Win_Test.yar") -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def run_lint(*paths: Path, check_fmt: bool = False) -> lint_rules.Report:
    return lint_rules.lint(list(paths), check_fmt=check_fmt)


def errors_matching(rep: lint_rules.Report, pattern: str) -> list[str]:
    return [e for e in rep.errors if re.search(pattern, e)]


def test_good_rule_passes(tmp_path: Path) -> None:
    rep = run_lint(write_rule(tmp_path, make_rule()))
    assert rep.ok, rep.errors
    assert rep.rules == 1


def test_good_rule_is_formatted(tmp_path: Path) -> None:
    """A regra de referência dos testes deve passar também pelo check de formatação,
    para que o próprio teste não dependa de --no-format."""
    src = make_rule().encode()
    assert yrlib.format_source(src) == src


def test_repo_rules_pass_lint() -> None:
    rep = lint_rules.lint(yrlib.rule_files(), check_fmt=True)
    assert rep.ok, rep.errors


@pytest.mark.parametrize(
    ("override", "pattern"),
    [
        ({"id": "not-a-uuid"}, r"id=.*não é um UUID"),
        ({"status": "prod"}, r"status='prod' inválido"),
        ({"purpose": "prevent"}, r"purpose='prevent' inválido"),
        ({"confidence": "sure"}, r"confidence='sure' inválido"),
        ({"mitre": "T10"}, r"mitre_attack 'T10'"),
        ({"mitre": "T1055, attack"}, r"mitre_attack 'attack'"),
    ],
)
def test_metadata_value_errors(tmp_path: Path, override: dict[str, str], pattern: str) -> None:
    rep = run_lint(write_rule(tmp_path, make_rule(**override)))
    assert errors_matching(rep, pattern), rep.errors


def test_mitre_none_is_allowed(tmp_path: Path) -> None:
    rep = run_lint(write_rule(tmp_path, make_rule(mitre="none")))
    assert rep.ok, rep.errors


def test_blocking_requires_stable_and_high(tmp_path: Path) -> None:
    rep = run_lint(write_rule(tmp_path, make_rule(purpose="blocking", status="test", confidence="medium")))
    assert errors_matching(rep, r"blocking exige status=stable")
    assert errors_matching(rep, r"blocking exige confidence=high")

    rep = run_lint(write_rule(tmp_path, make_rule(purpose="blocking", status="stable", confidence="high")))
    assert rep.ok, rep.errors


def test_deprecated_cannot_be_blocking(tmp_path: Path) -> None:
    rep = run_lint(write_rule(tmp_path, make_rule(purpose="blocking", status="deprecated", confidence="high")))
    assert errors_matching(rep, r"deprecated não pode ser blocking")


def test_modified_before_date(tmp_path: Path) -> None:
    text = make_rule().replace('modified     = "2026-01-02"', 'modified     = "2025-12-31"')
    rep = run_lint(write_rule(tmp_path, text))
    assert errors_matching(rep, r"modified .* é anterior a date")


def test_bad_date_format(tmp_path: Path) -> None:
    text = make_rule().replace('date         = "2026-01-01"', 'date         = "01/01/2026"')
    rep = run_lint(write_rule(tmp_path, text))
    assert errors_matching(rep, r"date='01/01/2026' não está em YYYY-MM-DD")


def test_bad_hash(tmp_path: Path) -> None:
    text = re.sub(r'hash\s+= "[0-9a-f]+"', 'hash         = "nothash"', make_rule())
    rep = run_lint(write_rule(tmp_path, text))
    assert errors_matching(rep, r"hash 'nothash'")


def test_missing_required_metadata_is_compiler_warning(tmp_path: Path) -> None:
    text = re.sub(r'\n\s*mitre_attack\s+= "[^"]*"', "", make_rule())
    rep = run_lint(write_rule(tmp_path, text))
    assert errors_matching(rep, r"required metadata `mitre_attack` not found")


def test_rule_name_regex(tmp_path: Path) -> None:
    text = make_rule().replace("rule MAL_Win_Test_Good_Anchor", "rule bad_name")
    rep = run_lint(write_rule(tmp_path, text))
    assert errors_matching(rep, r"invalid_rule_name")


def test_unused_pattern_is_compile_error(tmp_path: Path) -> None:
    text = make_rule().replace(
        '$ctx    = "WriteProcessMemory" ascii',
        '$ctx    = "WriteProcessMemory" ascii\n    $unused = "CreateRemoteThread" ascii',
    )
    rep = run_lint(write_rule(tmp_path, text))
    assert errors_matching(rep, r"unused pattern")


def test_deprecated_pe_field_is_error(tmp_path: Path) -> None:
    text = make_rule().replace("pe.is_pe and", "pe.is_pe and pe.number_of_sections < 12 and")
    rep = run_lint(write_rule(tmp_path, text))
    assert errors_matching(rep, r"deprecated")


def test_short_text_string(tmp_path: Path) -> None:
    text = make_rule().replace('"UNIQUE::FAMILY::MARKER"', '"cmd"')
    rep = run_lint(write_rule(tmp_path, text))
    assert errors_matching(rep, r"\$anchor tem 3 bytes")


def test_short_text_string_allowlisted(tmp_path: Path) -> None:
    text = make_rule().replace('"UNIQUE::FAMILY::MARKER" ascii', '"cmd" ascii // yara-lint: allow-short')
    rep = run_lint(write_rule(tmp_path, text))
    assert not errors_matching(rep, r"bytes \(<")


@pytest.mark.parametrize(
    ("hexpat", "pattern"),
    [
        ("{ 4D 5A ?? ?? ?? ?? ?? ?? }", r"tem só 2 bytes fixos"),
        ("{ 48 8B 0D [4] 48 85 C9 74 ?? ?? ?? ?? ?? ?? ?? }", r"mais wildcards/jumps"),
    ],
)
def test_weak_hex_patterns(tmp_path: Path, hexpat: str, pattern: str) -> None:
    text = make_rule().replace('"UNIQUE::FAMILY::MARKER" ascii', hexpat)
    rep = run_lint(write_rule(tmp_path, text))
    assert errors_matching(rep, pattern), rep.errors


def test_good_hex_pattern(tmp_path: Path) -> None:
    text = make_rule().replace(
        '"UNIQUE::FAMILY::MARKER" ascii', "{ 48 8B 0D [4] 48 85 C9 74 ?? 0F B6 01 34 ?? 88 01 48 FF C1 }"
    )
    rep = run_lint(write_rule(tmp_path, text))
    assert rep.ok, rep.errors


def test_duplicate_id_across_files(tmp_path: Path) -> None:
    rid = str(uuid.uuid4())
    a = write_rule(tmp_path, make_rule(id=rid), "A.yar")
    b = write_rule(tmp_path, make_rule(id=rid).replace("MAL_Win_Test_Good_Anchor", "MAL_Win_Test_Other"), "B.yar")
    rep = run_lint(a, b)
    assert errors_matching(rep, rf"id duplicado {rid}")


def test_duplicate_name_across_files(tmp_path: Path) -> None:
    a = write_rule(tmp_path, make_rule(), "A.yar")
    b = write_rule(tmp_path, make_rule(), "B.yar")
    rep = run_lint(a, b)
    assert errors_matching(rep, r"nome de regra duplicado 'MAL_Win_Test_Good_Anchor'")


def test_unformatted_rule_fails_format_check(tmp_path: Path) -> None:
    text = make_rule().replace("  meta:\n", "  meta:\n\n\n")
    rep = run_lint(write_rule(tmp_path, text), check_fmt=True)
    assert errors_matching(rep, r"não está formatado")


def test_cli_exit_codes(tmp_path: Path) -> None:
    good = write_rule(tmp_path, make_rule(), "good.yar")
    assert lint_rules.main([str(good)]) == 0
    bad = write_rule(tmp_path, make_rule(purpose="prevent"), "bad.yar")
    assert lint_rules.main([str(bad)]) == 1


# ---------------------------------------------------------------- scope


def test_scope_invalid_value(tmp_path: Path) -> None:
    rep = run_lint(write_rule(tmp_path, make_rule(scope="ram")))
    assert any("scope='ram'" in e for e in rep.errors)


def test_license_meta_must_be_cc0(tmp_path: Path) -> None:
    good = make_rule().replace('scope        = "file"', 'scope        = "file"\n    license      = "CC0-1.0"')
    assert run_lint(write_rule(tmp_path, good)).ok
    bad = make_rule().replace('scope        = "file"', 'scope        = "file"\n    license      = "MIT"')
    rep = run_lint(write_rule(tmp_path, bad))
    assert any("license='MIT'" in e for e in rep.errors)


def test_repo_license_is_cc0_everywhere() -> None:
    text = (yrlib.REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "CC0 1.0 Universal" in text
    assert not (yrlib.REPO_ROOT / "LICENSE-RULES.md").exists()
    assert not (yrlib.REPO_ROOT / "LICENSE-SCRIPTS.md").exists()
    for f in yrlib.rule_files():
        for info in yrlib.parse_rule_infos(f):
            assert info.meta.get("license", yrlib.LICENSE_ID) == yrlib.LICENSE_ID


@pytest.mark.parametrize("scope", ["memory", "both"])
def test_memory_scope_rejects_file_only_conditions(tmp_path: Path, scope: str) -> None:
    rep = run_lint(write_rule(tmp_path, make_rule(scope=scope)))
    msgs = "\n".join(rep.errors)
    assert "uintN(0)" in msgs and "filesize" in msgs and "módulo pe" in msgs


def test_memory_scope_accepts_memory_safe_condition(tmp_path: Path) -> None:
    text = make_rule(scope="memory").replace(
        "uint16(0) == 0x5A4D and filesize < 2MB and pe.is_pe and $anchor and $ctx",
        "// filesize e pe.* em comentário não contam\n    $anchor and $ctx",
    )
    text = text.replace('import "pe"\n\n', "")
    rep = run_lint(write_rule(tmp_path, text))
    assert rep.ok, rep.errors


def test_repo_has_memory_rule_without_file_dependencies() -> None:
    infos = [i for f in yrlib.rule_files() for i in yrlib.parse_rule_infos(f)]
    mem = [i for i in infos if i.scope in ("memory", "both")]
    assert mem, "o repo deveria ter ao menos uma regra de memória"
    for i in mem:
        assert "filesize" not in i.condition and "pe." not in i.condition

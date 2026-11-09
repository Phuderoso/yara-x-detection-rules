"""Teste de aceitação do extrator de âncoras (tools/anchors/extract_anchors.py).

O caso é o que já existe em tests/cases.py: dois builds sintéticos do decoder
da FamilyX, relinkados com disp32/rel8/imm diferentes. O extrator tem que achar
sozinho o padrão equivalente ao `$decode` da regra, com os wildcards só nos
operandos que variam, e o rascunho gerado tem que passar no lint e casar as
fixtures positivas sem casar as negativas.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path

import capstone  # type: ignore[import-untyped]
import pytest
import yara_x

import extract_anchors as ea
import lint_rules
from cases import CASES, DECODER_BUILD_A, DECODER_BUILD_B, INJECT_APIS
from fakepe import build_pe, cstrings

EXPECTED_DECODE = "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 0F B6 01 34 ?? 88 01 48 FF C1"

# Prólogo compartilhado por todas as amostras E pelo goodware: tem que ser descartado.
PROLOGUE = bytes.fromhex(
    "554889E54883EC20488D4DE8488945F8"
)  # push rbp; mov rbp,rsp; sub rsp,0x20; lea rcx,[rbp-0x18]; mov [rbp-8],rax


def _case(name: str) -> bytes:
    return next(c for c in CASES if c.name == name).build()


def _sample_from_bytes(name: str, data: bytes) -> ea.Sample:
    arch, regions = ea._code_regions_pe(data)
    return ea.Sample(name=name, sha256=hashlib.sha256(data).hexdigest(), arch=arch, regions=regions)


def _expand(pattern: str) -> str:
    """`[4]` -> `?? ?? ?? ??` para comparar padrões."""
    out: list[str] = []
    for tok in pattern.split():
        if tok.startswith("["):
            out.extend(["??"] * int(tok.strip("[]")))
        else:
            out.append(tok)
    return " ".join(out)


# ---------------------------------------------------------------- máscara por operando


def _mask(code: bytes, arch: str = "x64", policy: ea.Policy | None = None) -> list[tuple[str, str]]:
    md = ea._disassembler(arch)
    out = []
    for insn in md.disasm(code, 0):
        wild = ea.wild_mask(insn, policy or ea.Policy())
        out.append((insn.mnemonic, " ".join("??" if w else f"{b:02X}" for b, w in zip(insn.bytes, wild, strict=True))))
    return out


def test_wildcards_only_on_variable_operands() -> None:
    masked = _mask(DECODER_BUILD_A)
    assert [m for m, _ in masked] == ["mov", "test", "je", "movzx", "xor", "mov", "inc"]
    assert " ".join(p for _, p in masked) == EXPECTED_DECODE
    # o mesmo decoder relinkado normaliza para o mesmo token
    assert masked == _mask(DECODER_BUILD_B)


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("E810000000", "E8 ?? ?? ?? ??"),  # call rel32
        ("0F8410000000", "0F 84 ?? ?? ?? ??"),  # je rel32
        ("B82A000000", "B8 ?? ?? ?? ??"),  # mov eax, imm32
        ("48B80102030405060708", "48 B8 ?? ?? ?? ?? ?? ?? ?? ??"),  # mov rax, imm64
        ("488D0544332211", "48 8D 05 ?? ?? ?? ??"),  # lea rax, [rip+disp32]
        ("C70511223344 55667788", "C7 05 ?? ?? ?? ?? ?? ?? ?? ??"),  # mov [rip+disp32], imm32
        ("8945E0", "89 45 E0"),  # mov [rbp-0x20], eax: disp8 fica fixo
        ("4885C9", "48 85 C9"),  # sem operando variável
        ("C1E003", "C1 E0 ??"),  # shl eax, 3: imm8 é wildcard por padrão
    ],
)
def test_mask_policy_default(code: str, expected: str) -> None:
    assert _mask(bytes.fromhex(code.replace(" ", "")))[0][1] == expected


def test_mask_policy_keep_imm8_and_wild_disp8() -> None:
    policy = ea.Policy(wild_imm8=False, wild_disp8=True)
    assert _mask(bytes.fromhex("C1E003"), policy=policy)[0][1] == "C1 E0 03"
    assert _mask(bytes.fromhex("8945E0"), policy=policy)[0][1] == "89 45 ??"


def test_opcodes_never_wildcarded() -> None:
    md = ea._disassembler("x64")
    for insn in md.disasm(DECODER_BUILD_A + bytes.fromhex("E810000000B82A000000"), 0):
        wild = ea.wild_mask(insn, ea.Policy())
        assert not wild[0], f"primeiro byte (opcode/prefixo) mascarado em {insn.mnemonic}"
        if insn.modrm_offset:
            assert not wild[insn.modrm_offset], f"ModRM mascarado em {insn.mnemonic}"


# ---------------------------------------------------------------- aceitação: decoder da FamilyX


@pytest.fixture(scope="module")
def familyx_samples() -> list[ea.Sample]:
    return [
        _sample_from_bytes("build_a", _case("familyx_decoder_build_a")),
        _sample_from_bytes("build_b", _case("familyx_decoder_build_b")),
    ]


def test_finds_decoder_in_existing_fixtures(familyx_samples: list[ea.Sample], tmp_path: Path) -> None:
    gw = tmp_path / "gw"
    gw.mkdir()
    for name in ("generic_injector_apis_only", "marker_without_context"):
        (gw / f"{name}.bin").write_bytes(_case(name))
    accepted, rejected = ea.extract(familyx_samples, ea.Options(goodware=[gw]))
    assert accepted, "nenhum candidato aceito"
    top = accepted[0]
    assert _expand(top.pattern) == EXPECTED_DECODE
    assert top.coverage == {0, 1} and top.fixed == 16 and top.wild == 6
    assert top.mnemonics == ["mov", "test", "je", "movzx", "xor", "mov", "inc"]
    assert not rejected
    # nada degenerado (nop sled / int3 / zero-fill) sobrevive
    for c in accepted:
        assert len(set(c.mnemonics)) >= 3


def test_shared_prologue_in_goodware_is_rejected(tmp_path: Path) -> None:
    sa = build_pe(text=PROLOGUE + b"\x90" * 40 + DECODER_BUILD_A + b"\xc3", rdata=cstrings(*INJECT_APIS), seed=41)
    sb = build_pe(text=PROLOGUE + b"\xcc" * 70 + DECODER_BUILD_B + b"\xc3", rdata=cstrings(*INJECT_APIS), seed=42)
    gw = tmp_path / "gw"
    gw.mkdir()
    (gw / "clean.bin").write_bytes(build_pe(text=PROLOGUE + b"\x90" * 200 + b"\xc3", seed=43))
    samples = [_sample_from_bytes("a", sa), _sample_from_bytes("b", sb)]
    accepted, rejected = ea.extract(samples, ea.Options(goodware=[gw]))
    patterns = [_expand(c.pattern) for c in accepted]
    # o `ret` depois do decoder também é comum aos dois builds, então pode vir junto
    assert any(EXPECTED_DECODE in p for p in patterns)
    assert all("55 48 89 E5" not in p for p in patterns), "prólogo presente no goodware não foi descartado"
    assert any("55 48 89 E5" in _expand(c.pattern) for c in rejected)


def test_k_of_n_coverage(familyx_samples: list[ea.Sample]) -> None:
    other = _sample_from_bytes("marker_only", _case("familyx_marker_build1"))
    samples = [*familyx_samples, other]
    strict, _ = ea.extract(samples, ea.Options(k=3))
    assert all(_expand(c.pattern) != EXPECTED_DECODE for c in strict)
    relaxed, _ = ea.extract(samples, ea.Options(k=2))
    assert _expand(relaxed[0].pattern) == EXPECTED_DECODE and relaxed[0].coverage == {0, 1}


def test_superset_suffix_artifacts_are_suppressed(familyx_samples: list[ea.Sample]) -> None:
    accepted, _ = ea.extract(familyx_samples, ea.Options())
    expanded = [_expand(c.pattern) for c in accepted]
    assert expanded.count(EXPECTED_DECODE) == 1
    assert all(not EXPECTED_DECODE.endswith(p) or p == EXPECTED_DECODE for p in expanded)


# ---------------------------------------------------------------- rascunho


def test_draft_passes_lint_and_fixtures(familyx_samples: list[ea.Sample], tmp_path: Path) -> None:
    accepted, _ = ea.extract(familyx_samples, ea.Options())
    text = ea.format_draft(
        ea.draft_rule(
            accepted,
            familyx_samples,
            rule_name="SUSP_Win_FamilyX_CodeAnchors",
            family="FamilyX",
            author="tests",
            today=dt.date(2026, 11, 9),
        )
    )
    draft = tmp_path / "SUSP_Win_FamilyX_CodeAnchors.yar"
    draft.write_text(text, encoding="utf-8")

    rep = lint_rules.lint([draft], check_fmt=True)
    assert rep.ok, rep.errors
    assert 'status       = "experimental"' in text and 'scope        = "file"' in text
    assert "$code_1 = { 48 8B 0D [4] 48 85 C9 74 ?? 0F B6 01 34 ?? 88 01 48 FF C1 }" in text

    rules = yara_x.compile(text)
    for case in CASES:
        matched = bool(rules.scan(case.build()).matching_rules)
        if case.name in ("familyx_decoder_build_a", "familyx_decoder_build_b"):
            assert matched, f"rascunho não casou {case.name}"
        elif case.expect_no_match:
            assert not matched, f"rascunho casou negativo {case.name}"


def test_cli_end_to_end(tmp_path: Path) -> None:
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(_case("familyx_decoder_build_a"))
    b.write_bytes(_case("familyx_decoder_build_b"))
    draft = tmp_path / "out" / "SUSP_Win_FamilyX_CodeAnchors.yar"
    out = tmp_path / "cands.json"
    rc = ea.main([str(a), str(b), "--family", "FamilyX", "--draft", str(draft), "--json", str(out)])
    assert rc == 0 and draft.exists() and out.exists()
    assert lint_rules.lint([draft]).ok


def test_capstone_available() -> None:
    assert tuple(int(x) for x in capstone.__version__.split(".")[:2]) >= (5, 0)

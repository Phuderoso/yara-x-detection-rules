"""EICAR: a fixture é o alvo publicado (sha256 conferido), e o texto literal nunca entra no repo."""

from __future__ import annotations

import hashlib
import subprocess
import zipfile
from pathlib import Path

import yara_x

import yrlib
from eicar import EICAR_LEN, EICAR_SHA256, eicar, eicar_zip

REPO = Path(__file__).resolve().parents[1]


def test_generated_bytes_are_the_published_file() -> None:
    data = eicar()
    assert len(data) == EICAR_LEN
    assert hashlib.sha256(data).hexdigest() == EICAR_SHA256
    assert data.startswith(b"X5O!") and data.endswith(b"H+H*")
    assert b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data


def test_rules_match_the_published_target_and_zip_variants() -> None:
    rules, _ = yrlib.load_all_rules(strict=False)

    def names(data: bytes) -> set[str]:
        return {m.identifier for m in rules.scan(data).matching_rules}

    assert names(eicar()) == {"TEST_Multi_EICAR_File"}
    assert names(eicar(b"\n")) == {"TEST_Multi_EICAR_File"}
    assert names(eicar_zip(stored=True)) == {"TEST_Multi_EICAR_InZip_Stored"}
    assert names(eicar_zip(stored=True, padding=2, name="dir/eicar.com")) == {"TEST_Multi_EICAR_InZip_Stored"}
    # limite documentado: deflate esconde os bytes
    assert names(eicar_zip(stored=False)) == set()
    # a string fora da especificação (no meio de um texto) não é o arquivo de teste
    assert names(b"notes\n" * 10 + eicar() + b"\n") == set()


def test_zip_fixture_is_a_valid_archive_holding_the_target() -> None:
    import io

    with zipfile.ZipFile(io.BytesIO(eicar_zip(stored=True))) as zf:
        assert zf.read("eicar.com") == eicar()
        assert zf.getinfo("eicar.com").compress_type == zipfile.ZIP_STORED


def test_literal_eicar_string_never_appears_in_tracked_files() -> None:
    """Qualquer arquivo versionado com os 68 bytes em claro dispararia AV no checkout.
    O EICAR só existe em hex (regras, tests/eicar.py) e em memória (fixtures)."""
    needle = eicar()
    tracked = subprocess.run(  # nosec B603 B607
        ["git", "ls-files", "-z"], cwd=REPO, capture_output=True, check=True
    ).stdout.split(b"\0")
    untracked = subprocess.run(  # nosec B603 B607
        ["git", "ls-files", "-z", "--others", "--exclude-standard"], cwd=REPO, capture_output=True, check=True
    ).stdout.split(b"\0")
    offenders = []
    for rel in tracked + untracked:
        if not rel:
            continue
        p = REPO / rel.decode("utf-8", "surrogateescape")
        if p.is_file() and needle in p.read_bytes():
            offenders.append(str(rel))
    assert offenders == []


def test_compiled_hex_equals_generated_bytes() -> None:
    """A regra em hex e a fixture em hex vêm da mesma string; se um dos dois for editado
    e o outro não, o scan acima falha, mas este teste diz onde."""
    src = (REPO / "rules" / "multi" / "TEST_Multi_EICAR_File.yar").read_text(encoding="utf-8")
    hex_line = next(ln for ln in src.splitlines() if "$eicar" in ln and "{" in ln)
    body = hex_line.split("{", 1)[1].split("}", 1)[0]
    assert bytes.fromhex(body.replace(" ", "")) == eicar()
    rules = yara_x.compile(src)
    assert [m.identifier for m in rules.scan(eicar()).matching_rules] == ["TEST_Multi_EICAR_File"]

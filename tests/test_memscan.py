"""memscan.py: só regras de escopo memory/both, dump sintético, chunks sobrepostos, saída ECS."""

from __future__ import annotations

import json
from pathlib import Path

import yara_x

import memscan
import yrlib
from cases import DECODER_BUILD_A, DECODER_BUILD_B, memory_region
from fakepe import cstrings

MEM_RULE = "MAL_Win_Loader_FamilyX_InMemory"
FILE_RULE = "MAL_Win_Loader_FamilyX_ConfigMarker"


def _dump(path: Path, *, size: int = 3 << 20, seed: int = 5) -> Path:
    data = memory_region(
        cstrings("CONFIG_START::mutex_id::", "mutex_id=Global\\FamilyX_7f3a"), DECODER_BUILD_A, size=size, seed=seed
    )
    path.write_bytes(data)
    return path


def test_only_memory_scope_rules_are_compiled() -> None:
    rules, index = memscan.load_memory_rules()
    assert MEM_RULE in index and FILE_RULE not in index
    names = {name for src in memscan.memory_sources().values() for name in _rule_names(src)}
    assert names == {MEM_RULE}
    # a regra de arquivo não casa nem de longe num blob sem MZ; a de memória casa
    region = memory_region(DECODER_BUILD_B, seed=7)
    assert [m.identifier for m in rules.scan(region).matching_rules] == [MEM_RULE]


def _rule_names(src: str) -> list[str]:
    import re

    return re.findall(r"^\s*rule\s+([A-Za-z0-9_]+)", src, flags=re.M)


def test_raw_backend_finds_artifacts_with_offsets(tmp_path: Path) -> None:
    dump = _dump(tmp_path / "proc.dmp")
    rules, _ = memscan.load_memory_rules()
    hits = memscan.scan_raw(dump, rules)
    by_pattern = {h["pattern"]: h for h in hits}
    assert set(by_pattern) == {"$marker", "$cfg", "$decode"}
    data = dump.read_bytes()
    assert data[by_pattern["$marker"]["offset"] :].startswith(b"CONFIG_START::mutex_id::")
    assert data[by_pattern["$decode"]["offset"] :].startswith(DECODER_BUILD_A)
    assert by_pattern["$decode"]["length"] == len(DECODER_BUILD_A)


def test_raw_backend_chunk_overlap_dedupes_and_crosses_boundaries(tmp_path: Path) -> None:
    dump = _dump(tmp_path / "proc.dmp")
    rules, _ = memscan.load_memory_rules()
    full = memscan.scan_raw(dump, rules)
    # chunk de 64KB com overlap de 4KB: os artefatos (em 0xC0000...) caem em várias janelas
    chunked = memscan.scan_raw(dump, rules, chunk=64 << 10, overlap=4 << 10)
    key = lambda h: (h["rule"], h["pattern"], h["offset"])  # noqa: E731
    assert sorted(map(key, chunked)) == sorted(map(key, full))
    # marker atravessando a borda de um chunk
    data = bytearray(memory_region(size=1 << 20, seed=9))
    boundary = 256 << 10
    marker = b"CONFIG_START::mutex_id::"
    data[boundary - 10 : boundary - 10 + len(marker)] = marker
    data[boundary + 100 : boundary + 100 + len(DECODER_BUILD_B)] = DECODER_BUILD_B
    p = tmp_path / "edge.dmp"
    p.write_bytes(data)
    hits = memscan.scan_raw(p, rules, chunk=256 << 10, overlap=4 << 10)
    assert {h["pattern"] for h in hits} == {"$marker", "$decode"}
    assert len(hits) == 2


def test_cli_native_and_ecs_output(tmp_path: Path, capsys: object) -> None:
    dump = _dump(tmp_path / "proc.dmp")
    out = tmp_path / "hits.jsonl"
    assert memscan.main([str(dump), "--backend", "raw", "--jsonl", str(out), "--format", "ecs"]) == 0
    docs = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(docs) == 1
    doc = docs[0]
    assert doc["rule"]["name"] == MEM_RULE and doc["rule"]["id"]
    assert doc["yara"]["scope"] == "memory" and doc["yara"]["memory"]["backend"] == "raw"
    assert doc["event"]["category"] == ["malware", "process"] and doc["event"]["dataset"] == "yara.memscan"
    assert doc["file"]["hash"]["sha256"] and doc["file"]["size"] == dump.stat().st_size
    assert doc["threat"]["technique"]["id"] == ["T1055.002", "T1027"]
    assert "process" not in doc  # sem PID no backend raw

    native = tmp_path / "native.jsonl"
    assert memscan.main([str(dump), "--backend", "raw", "--jsonl", str(native)]) == 0
    rec = json.loads(native.read_text().splitlines()[0])
    assert rec["rule"] == MEM_RULE and rec["backend"] == "raw" and len(rec["matches"]) == 3
    assert [m["offset"] for m in rec["matches"]] == sorted(m["offset"] for m in rec["matches"])


def test_parse_vol_json_vadyarascan_shape() -> None:
    rows = [
        {
            "Offset": 140701000000000,
            "PID": 4242,
            "Process": "svchost.exe",
            "Rule": "memory/MAL_Win_Loader_FamilyX_InMemory.yar.MAL_Win_Loader_FamilyX_InMemory",
            "Component": "$marker",
            "Value": "43 4f 4e 46 49 47",
            "__children": [],
        },
        {
            "Offset": 1,
            "PID": 4242,
            "Process": "svchost.exe",
            "Rule": "default.Other",
            "Component": "$x",
            "Value": "",
            "__children": [],
        },
    ]
    hits = memscan.parse_vol_json(json.dumps(rows))
    assert [h["rule"] for h in hits] == ["Other", MEM_RULE]
    assert hits[1]["pid"] == 4242 and hits[1]["process"] == "svchost.exe" and hits[1]["offset"] == 140701000000000
    assert memscan.parse_vol_json("") == []


def test_combined_source_compiles_for_vol3(tmp_path: Path) -> None:
    out = tmp_path / "memory.yar"
    memscan.write_combined_source(memscan.memory_sources(), out)
    text = out.read_text()
    assert text.count("import ") <= 1  # imports deduplicados no topo
    rules = yara_x.compile(text)
    assert [m.identifier for m in rules.scan(memory_region(DECODER_BUILD_B, seed=3)).matching_rules] == [MEM_RULE]


def test_vol3_backend_falls_back_to_raw_on_unknown_image(tmp_path: Path) -> None:
    import pytest

    if memscan.vol_command() is None:
        pytest.skip("volatility3 não instalado")
    dump = _dump(tmp_path / "proc.dmp", size=1 << 20)
    try:
        memscan.scan_vol3(dump, memscan.memory_sources(), plugin="yarascan.YaraScan", extra=[])
    except LookupError:
        pass  # esperado: sem OS detectado, requisito de camada insatisfeito
    else:
        raise AssertionError("vol3 deveria recusar um blob sem OS")
    out = tmp_path / "auto.jsonl"
    assert memscan.main([str(dump), "--backend", "auto", "--jsonl", str(out)]) == 0
    assert json.loads(out.read_text().splitlines()[0])["backend"] == "raw"


def test_subset_source_keeps_imports_and_private_rules(tmp_path: Path) -> None:
    f = tmp_path / "x.yar"
    f.write_text(
        'import "pe"\n\n'
        "private rule P {\n  condition:\n    true\n}\n\n"
        'rule A {\n  meta:\n    scope = "memory"\n\n  condition:\n    P\n}\n\n'
        'rule B {\n  meta:\n    scope = "file"\n\n  condition:\n    pe.is_pe\n}\n'
    )
    subset = yrlib.subset_source([f], lambda i: i.scope == "memory" or i.name == "P")
    src = next(iter(subset.values()))
    assert 'import "pe"' in src and "rule A" in src and "rule P" in src and "rule B" not in src
    infos = {i.name: i for i in yrlib.parse_rule_infos(f)}
    assert infos["B"].condition.strip() == "pe.is_pe" and infos["A"].scope == "memory"


def test_record_activity_writes_memscan_source(tmp_path: Path) -> None:
    dump = _dump(tmp_path / "proc.dmp")
    activity = tmp_path / "activity.json"
    # sem a flag: nada é escrito
    assert memscan.main([str(dump), "--backend", "raw", "--activity", str(activity)]) == 0
    assert not activity.exists()
    # com a flag: a regra de memória que casou entra com source=memscan e a data de hoje
    assert memscan.main([str(dump), "--backend", "raw", "--record-activity", "--activity", str(activity)]) == 0
    data = yrlib.load_activity(activity)
    assert list(data["rules"]) == [MEM_RULE]
    entry = data["rules"][MEM_RULE]
    assert entry["source"] == "memscan" and len(entry["last_match"]) == 10
    # segundo run no mesmo dia: idempotente (conteúdo igual)
    before = activity.read_text()
    assert memscan.main([str(dump), "--backend", "raw", "--record-activity", "--activity", str(activity)]) == 0
    assert activity.read_text() == before
    # o repo não foi tocado
    assert yrlib.load_activity()["rules"].get(MEM_RULE) is None


def test_record_activity_without_hits_writes_nothing(tmp_path: Path) -> None:
    clean = tmp_path / "clean.dmp"
    clean.write_bytes(memory_region(cstrings("nothing to see here"), seed=9))
    activity = tmp_path / "activity.json"
    assert memscan.main([str(clean), "--backend", "raw", "--record-activity", "--activity", str(activity)]) == 0
    assert not activity.exists()

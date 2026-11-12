"""Testes das ferramentas ao redor das regras: fixtures, bundles, diff, manifesto, ECS."""

from __future__ import annotations

import datetime as dt
import io
import json
import sys
from pathlib import Path

import yara_x

import build_bundles
import corpus_manifest
import diff_report
import fetch_samples
import hunt
import test_rules as fixture_runner
import yrlib
from cases import CASES
from fakepe import build_pe, cstrings


def test_fakepe_is_valid_pe() -> None:
    data = build_pe(rdata=cstrings("hello"), extra_sections=2)
    rules = yara_x.compile(
        'import "pe" rule t { condition: pe.is_pe and pe.sections.len() == 5 and pe.machine == pe.MACHINE_AMD64 }'
    )
    assert [m.identifier for m in rules.scan(data).matching_rules] == ["t"]
    assert len(data) >= 12 * 1024


def test_fakepe_min_size_respected() -> None:
    assert len(build_pe(min_size=3 * 1024 * 1024)) >= 3 * 1024 * 1024


def test_fixtures_pass_and_every_rule_is_covered() -> None:
    assert fixture_runner.main(["--strict"]) == 0


def test_every_rule_has_positive_and_negative() -> None:
    _rules, index = yrlib.load_all_rules(strict=False)
    for name in index:
        assert any(name in c.expect_match for c in CASES), f"{name} sem positivo"
        assert any(name in c.expect_no_match for c in CASES), f"{name} sem negativo"


def test_bundles_are_cumulative_and_exclude_deprecated(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    from test_lint import make_rule

    (rules_dir / "a.yar").write_text(
        make_rule(purpose="blocking", status="stable", confidence="high").replace("Good_Anchor", "A")
    )
    (rules_dir / "b.yar").write_text(make_rule(purpose="triage").replace("Good_Anchor", "B"))
    (rules_dir / "c.yar").write_text(make_rule(purpose="hunting").replace("Good_Anchor", "C"))
    (rules_dir / "d.yar").write_text(make_rule(purpose="hunting", status="deprecated").replace("Good_Anchor", "D"))

    out = tmp_path / "dist"
    assert build_bundles.main(["--version", "v9.9.9", "--rules", str(rules_dir), "--out", str(out)]) == 0
    manifest = json.loads((out / "manifest.json").read_text())
    by_name = {b["name"]: sorted(r["name"] for r in b["rules"]) for b in manifest["bundles"]}
    assert by_name["blocking"] == ["MAL_Win_Test_A"]
    assert by_name["triage"] == ["MAL_Win_Test_A", "MAL_Win_Test_B"]
    assert by_name["hunting"] == ["MAL_Win_Test_A", "MAL_Win_Test_B", "MAL_Win_Test_C"]
    assert [d["name"] for d in manifest["deprecated"]] == ["MAL_Win_Test_D"]
    assert manifest["version"] == "v9.9.9"

    # .yar concatenado compila e o .yarc desserializa
    yara_x.compile((out / "hunting.yar").read_text())
    with (out / "hunting.yarc").open("rb") as fh:
        yara_x.Rules.deserialize_from(fh)

    sums = (out / "SHA256SUMS").read_text().splitlines()
    assert any(line.endswith("  hunting.yar") for line in sums)
    assert not any(line.endswith("  SHA256SUMS") for line in sums)


def _report(hits: list[dict[str, object]], seconds: float, fixtures_ok: bool = True) -> dict[str, object]:
    return {
        "schema": 1,
        "git": {"sha": "abc"},
        "rules": {"R": {"purpose": "triage", "status": "test"}},
        "corpus": {"files": 1, "bytes": 1, "wall_seconds": 0},
        "timings": {"f.yar": {"seconds": seconds, "rules": ["R"], "timeouts": 0}},
        "hits": hits,
        "fixtures": {"c": {"matched": ["R"], "expect_match": ["R"], "expect_no_match": [], "ok": fixtures_ok}},
    }


def test_diff_report_new_hit_and_regression() -> None:
    hit = {"rule": "R", "purpose": "triage", "file": "/x", "sha256": "0" * 64, "size": 1, "strings": ["$a"]}
    base = _report([], seconds=2.0)
    head = _report([hit], seconds=4.0)
    md, failures = diff_report.build_markdown(head, base, fail_on_new_hits=True)
    assert "| `R` | triage | 0 | 1 | 1 | 0 |" in md
    assert any("hit novo" in f for f in failures)
    assert any("regressão" in f or "vs" in f for f in failures)


def test_diff_report_ignores_noise_below_floor() -> None:
    base = _report([], seconds=0.01)
    head = _report([], seconds=0.05)  # +400%, mas abaixo de regression_floor_seconds
    _md, failures = diff_report.build_markdown(head, base, fail_on_new_hits=True)
    assert failures == []


def test_diff_report_budget_exceeded() -> None:
    head = _report([], seconds=diff_report.MAX_RULE_SECONDS + 1)
    _md, failures = diff_report.build_markdown(head, None, fail_on_new_hits=False)
    assert any("acima" in f or ">" in f for f in failures)


def test_diff_report_fixture_failure() -> None:
    head = _report([], seconds=0.1, fixtures_ok=False)
    _md, failures = diff_report.build_markdown(head, None, fail_on_new_hits=False)
    assert any("fixture" in f for f in failures)


def test_diff_report_cli_survives_cp1252_stdout(tmp_path: Path) -> None:
    """O passo Windows do CI cai se print(md) for para um stdout cp1252 (Δ no cabeçalho)."""
    head_path = tmp_path / "head.json"
    head_path.write_text(json.dumps(_report([], seconds=0.1, fixtures_ok=True)), encoding="utf-8")
    out = tmp_path / "reports" / "diff.md"
    fake = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict", newline="\n")
    old = sys.stdout
    try:
        sys.stdout = fake
        rc = diff_report.main(["--head", str(head_path), "--out", str(out)])
        fake.flush()
    finally:
        sys.stdout = old
        fake.close()
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "Δ" in text
    assert "Nenhum hit. FP gate ok." in text


def test_corpus_manifest_diff(tmp_path: Path) -> None:
    (tmp_path / "a.bin").write_bytes(b"a")
    (tmp_path / "b.bin").write_bytes(b"b")
    m1 = corpus_manifest.build([tmp_path], max_size=1 << 20)
    (tmp_path / "b.bin").write_bytes(b"B")
    (tmp_path / "c.bin").write_bytes(b"c")
    m2 = corpus_manifest.build([tmp_path], max_size=1 << 20)
    d = corpus_manifest.diff(m1, m2)
    assert [Path(p).name for p in d["added"]] == ["c.bin"]
    assert [Path(p).name for p in d["changed"]] == ["b.bin"]
    assert d["removed"] == []
    assert "alterados: 1" in corpus_manifest.diff_markdown(m1, m2)


def test_hunt_ecs_mapping() -> None:
    _rules, index = yrlib.load_all_rules(strict=False)
    name, info = next(iter(index.items()))
    rec = {
        "ts": 1_700_000_000,
        "rule": name,
        "purpose": info.purpose,
        "file": "/evidence/x.bin",
        "size": 10,
        "sha256": "f" * 64,
        "matches": [{"id": "$a", "offset": 1, "len": 2}],
    }
    ecs = hunt.to_ecs(rec, info)
    assert ecs["file"]["hash"]["sha256"] == "f" * 64
    assert ecs["rule"]["name"] == name
    assert ecs["rule"]["id"] == info.rule_id
    assert ecs["threat"]["technique"]["id"] == info.mitre
    assert ecs["@timestamp"].endswith("Z")


def test_samples_lock_entries_are_public_families_with_existing_rules() -> None:
    samples = fetch_samples.parse_lock(yrlib.REPO_ROOT / "tests" / "samples.lock")
    infos = {i.name: i for f in yrlib.rule_files() for i in yrlib.parse_rule_infos(f)}
    families = {i.family for i in infos.values() if i.family}
    assert samples, "o lock deve ter ao menos uma família pública (WannaCry) para o job real-samples"
    for s in samples:
        assert s.family != "FamilyX", "a FamilyX é fictícia: não pode ter amostra real"
        assert s.family in families, f"{s.family} não bate com nenhum meta.malware"
        assert s.source and s.expect_rules, "cada linha cita a fonte e a(s) regra(s) que devem casar"
        for r in s.expect_rules:
            assert r in infos, f"{r} não existe em rules/"
            assert infos[r].family == s.family
        # o hash da linha é também o hash citado em meta.hash da regra: uma fonte só
        assert any(s.sha256 in (infos[r].meta.get("hash") or "") for r in s.expect_rules)


def test_samples_lock_parse_format(tmp_path: Path) -> None:
    lock = tmp_path / "s.lock"
    lock.write_text("# c\n" + "a" * 64 + "\tFam\tmalwarebazaar\tR1, R2\tnota\n" + "b" * 64 + "\tFam\tvt\t-\n")
    s = fetch_samples.parse_lock(lock)
    assert s[0].expect_rules == ["R1", "R2"] and s[0].note == "nota"
    assert s[1].expect_rules == []


def test_fetch_samples_without_key_is_noop(monkeypatch: object) -> None:
    import os

    os.environ.pop("MALWAREBAZAAR_API_KEY", None)
    assert fetch_samples.main([]) == 0


# ---------------------------------------------------------------- painel de cobertura


def test_coverage_panel_is_up_to_date_and_deterministic() -> None:
    import coverage as cov

    assert cov.main(["--check"]) == 0
    infos = [i for f in yrlib.rule_files() for i in yrlib.parse_rule_infos(f)]
    a = cov.render(infos, as_of=dt.date(2026, 11, 9), stale_days=90)
    b = cov.render(list(reversed(infos)), as_of=dt.date(2026, 11, 9), stale_days=90)
    assert a == b
    for section in (
        "## Por técnica MITRE ATT&CK",
        "## Por purpose × status",
        "## Por scope",
        "## Por família",
        "## Inventário",
    ):
        assert section in a
    assert "[T1055.002](https://attack.mitre.org/techniques/T1055/002/)" in a


def test_coverage_check_fails_when_stale(tmp_path: Path) -> None:
    import coverage as cov

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    from test_lint import make_rule

    (rules_dir / "a.yar").write_text(make_rule(status="experimental").replace("Good_Anchor", "Old"))
    out = tmp_path / "coverage.md"
    # date = 2026-01-01: com 31 dias não está na lista
    assert cov.main(["--rules", str(rules_dir), "--out", str(out), "--as-of", "2026-02-01"]) == 0
    assert cov.main(["--rules", str(rules_dir), "--out", str(out), "--check", "--as-of", "2026-02-01"]) == 0
    assert cov.main(["--rules", str(rules_dir), "--out", str(out), "--check", "--as-of", "2026-03-01"]) == 0
    # cruzou 90 dias: entra na lista e o painel commitado fica desatualizado
    assert cov.main(["--rules", str(rules_dir), "--out", str(out), "--check", "--as-of", "2026-06-01"]) == 1
    assert cov.main(["--rules", str(rules_dir), "--out", str(out), "--as-of", "2026-06-01"]) == 0
    text = out.read_text()
    assert "MAL_Win_Test_Old" in text and "| > 90 dias |" in text
    # dentro da mesma faixa o painel é estável dia após dia
    assert cov.main(["--rules", str(rules_dir), "--out", str(out), "--check", "--as-of", "2026-06-02"]) == 0
    assert cov.main(["--rules", str(rules_dir), "--out", str(out), "--check", "--as-of", "2026-06-28"]) == 0  # 178 dias
    # cruzou 180: nova faixa
    assert cov.main(["--rules", str(rules_dir), "--out", str(out), "--check", "--as-of", "2026-07-05"]) == 1  # 185 dias
    # regra nova muda o painel -> check falha
    (rules_dir / "b.yar").write_text(make_rule(purpose="hunting").replace("Good_Anchor", "New"))
    assert cov.main(["--rules", str(rules_dir), "--out", str(out), "--check", "--as-of", "2026-06-01"]) == 1


# ---------------------------------------------------------------- dataset.jsonl


def test_dataset_jsonl_is_up_to_date_and_valid() -> None:
    import dataset_jsonl

    assert dataset_jsonl.main(["--check"]) == 0
    lines = (yrlib.REPO_ROOT / "dataset.jsonl").read_text(encoding="utf-8").splitlines()
    rows = [json.loads(ln) for ln in lines]
    infos = [i for f in yrlib.rule_files() for i in yrlib.parse_rule_infos(f)]
    assert sorted(r["name"] for r in rows) == sorted(i.name for i in infos)
    by_case = {c.name for c in CASES}
    for r in rows:
        assert (yrlib.REPO_ROOT / r["path"]).is_file()
        assert r["meta"]["status"] in yrlib.STATUSES
        assert r["tests"]["positive"] and r["tests"]["negative"]
        assert set(r["tests"]["positive"]) | set(r["tests"]["negative"]) <= by_case


def test_dataset_jsonl_check_fails_when_stale(tmp_path: Path) -> None:
    import dataset_jsonl

    rules_dir = tmp_path / "rules" / "windows"
    rules_dir.mkdir(parents=True)
    from test_lint import make_rule

    (rules_dir / "a.yar").write_text(make_rule().replace("Good_Anchor", "Old"))
    out = tmp_path / "dataset.jsonl"
    assert dataset_jsonl.main(["--rules", str(tmp_path / "rules"), "--out", str(out)]) == 0
    row = json.loads(out.read_text())
    assert row["name"] == "MAL_Win_Test_Old" and row["platform"] == "windows"
    assert isinstance(row["meta"]["version"], int)
    assert dataset_jsonl.main(["--rules", str(tmp_path / "rules"), "--out", str(out), "--check"]) == 0
    (rules_dir / "b.yar").write_text(make_rule().replace("Good_Anchor", "New"))
    assert dataset_jsonl.main(["--rules", str(tmp_path / "rules"), "--out", str(out), "--check"]) == 1
    out.write_text("{not json\n")
    assert dataset_jsonl.main(["--rules", str(tmp_path / "rules"), "--out", str(out), "--check"]) == 1


def test_hunt_record_activity_to_custom_path(tmp_path: Path) -> None:
    from cases import INJECT_APIS
    from fakepe import build_pe, cstrings

    sample = tmp_path / "s.bin"
    sample.write_bytes(build_pe(rdata=cstrings("CONFIG_START::mutex_id::", *INJECT_APIS), seed=11))
    activity = tmp_path / "activity.json"
    assert hunt.main([str(sample), "--record-activity", "--activity", str(activity)]) == 0
    data = yrlib.load_activity(activity)
    assert data["rules"]["MAL_Win_Loader_FamilyX_ConfigMarker"]["source"] == "hunt"
    assert yrlib.load_activity()["rules"].get("MAL_Win_Loader_FamilyX_ConfigMarker") is None

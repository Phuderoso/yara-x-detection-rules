"""docs/health.md: gerado do meta + baseline + activity, determinístico, conferido na CI."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import health
import yrlib
from test_lint import make_rule

AS_OF = dt.date(2026, 11, 9)


def _infos(rules_dir: Path) -> list[yrlib.RuleInfo]:
    return [i for f in yrlib.rule_files(rules_dir) for i in yrlib.parse_rule_infos(f)]


def _repo(tmp_path: Path, *, fp: bool, last_match: str | None) -> tuple[Path, Path, Path]:
    rules = tmp_path / "rules"
    rules.mkdir(parents=True)
    (rules / "a.yar").write_text(make_rule().replace("Good_Anchor", "Old"), encoding="utf-8")
    name = "MAL_Win_Test_Old"
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "schema": 1,
                "generated": "2026-11-01",
                "rules": {
                    name: {
                        "status": "test",
                        "purpose": "triage",
                        "known_fp": [{"sha256": "a" * 64, "file": "/usr/bin/x", "first_seen": "2026-10-01"}]
                        if fp
                        else [],
                        "last_fp": "2026-10-01" if fp else None,
                        "fp_total": 1 if fp else 0,
                    }
                },
            }
        )
    )
    activity = tmp_path / "activity.json"
    activity.write_text(
        json.dumps({"schema": 1, "rules": {name: {"last_match": last_match, "source": "hunt"}} if last_match else {}})
    )
    return rules, baseline, activity


def test_repo_health_panel_is_up_to_date() -> None:
    assert health.main(["--check"]) == 0


def test_render_is_deterministic_and_has_sections(tmp_path: Path) -> None:
    rules, baseline, activity = _repo(tmp_path, fp=True, last_match="2026-11-05")
    infos = _infos(rules)
    b = health.load_baseline(baseline)
    a = yrlib.load_activity(activity)
    t1 = health.render(health.assess(infos, b, a, as_of=AS_OF, stale_weeks=12), as_of=AS_OF, stale_weeks=12, baseline=b)
    t2 = health.render(
        health.assess(list(reversed(infos)), b, a, as_of=AS_OF, stale_weeks=12), as_of=AS_OF, stale_weeks=12, baseline=b
    )
    assert t1 == t2
    for section in ("## Por regra", "## Candidatas a `deprecated`", "## Sem prova fora das fixtures", "## Sinais"):
        assert section in t1


def test_deprecate_candidate_requires_fp_and_staleness(tmp_path: Path) -> None:
    def candidates(fp: bool, last_match: str | None) -> list[str]:
        rules, baseline, activity = _repo(tmp_path / f"{fp}-{last_match}", fp=fp, last_match=last_match)
        rows = health.assess(
            _infos(rules), health.load_baseline(baseline), yrlib.load_activity(activity), as_of=AS_OF, stale_weeks=12
        )
        return [r["info"].name for r in rows if r["deprecate_candidate"]]

    assert candidates(fp=True, last_match=None) == ["MAL_Win_Test_Old"]  # FP e nunca casou
    assert candidates(fp=True, last_match="2026-06-01") == ["MAL_Win_Test_Old"]  # FP e match há > 12 semanas
    assert candidates(fp=True, last_match="2026-11-01") == []  # FP mas casou recentemente
    assert candidates(fp=False, last_match=None) == []  # sem FP: sem custo, não é candidata


def test_unproven_flag_and_bands(tmp_path: Path) -> None:
    rules, baseline, activity = _repo(tmp_path, fp=False, last_match=None)
    rows = health.assess(
        _infos(rules), health.load_baseline(baseline), yrlib.load_activity(activity), as_of=AS_OF, stale_weeks=12
    )
    assert rows[0]["unproven"] is True
    assert health.age_band(rows[0]["age_days"]) == "180–365 d"  # date = 2026-01-01
    assert health.age_band(10) == "< 30 d" and health.age_band(400) == "> 1 ano" and health.age_band(None) == "?"
    assert health.weeks_band(None, 12) == "nunca"
    assert health.weeks_band(3, 12) == "esta semana"
    assert health.weeks_band(50, 12) == "≤ 12 sem"
    assert health.weeks_band(100, 12) == "> 12 sem"


def test_check_fails_when_stale_and_ignores_reference_date(tmp_path: Path) -> None:
    rules, baseline, activity = _repo(tmp_path, fp=False, last_match=None)
    out = tmp_path / "health.md"
    common = ["--rules", str(rules), "--baseline", str(baseline), "--activity", str(activity), "--out", str(out)]
    assert health.main([*common, "--as-of", "2026-11-09"]) == 0
    assert health.main([*common, "--check", "--as-of", "2026-11-09"]) == 0
    assert health.main([*common, "--check", "--as-of", "2026-11-10"]) == 0  # só a data de referência mudou
    assert health.main([*common, "--check", "--as-of", "2027-03-01"]) == 1  # cruzou a faixa "> 1 ano"
    # FP novo na baseline muda o painel
    b = json.loads(baseline.read_text())
    b["rules"]["MAL_Win_Test_Old"]["fp_total"] = 1
    b["rules"]["MAL_Win_Test_Old"]["last_fp"] = "2026-11-08"
    baseline.write_text(json.dumps(b))
    assert health.main([*common, "--check", "--as-of", "2026-11-09"]) == 1


def test_record_activity_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "activity.json"
    assert yrlib.record_activity(["R2", "R1"], "hunt", path=p, today="2026-11-09") == 2
    data = yrlib.load_activity(p)
    assert list(data["rules"]) == ["R1", "R2"] and data["rules"]["R1"] == {"last_match": "2026-11-09", "source": "hunt"}
    assert yrlib.record_activity(["R1"], "hunt", path=p, today="2026-11-09") == 0  # idempotente no mesmo dia
    assert yrlib.record_activity(["R1"], "ir", path=p, today="2026-11-09") == 1

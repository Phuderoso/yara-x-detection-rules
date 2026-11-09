"""Vigia de FP: comparação com a baseline e idempotência da issue (GitHub mockado)."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest

import fp_watch
import yrlib

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def report(
    hits: list[dict[str, Any]] | None = None,
    *,
    seconds: float = 0.5,
    purpose: str = "triage",
    rule: str = "MAL_Win_Test_Rule",
) -> dict[str, Any]:
    return {
        "schema": 1,
        "label": "t",
        "filter": {"status": ["stable", "test"]},
        "rules": {
            rule: {"id": "00000000-0000-4000-8000-000000000001", "purpose": purpose, "status": "test", "version": 1}
        },
        "corpus": {"paths": ["/usr/bin"], "files": 10},
        "timings": {"windows/x.yar": {"seconds": seconds, "rules": [rule], "timeouts": 0}},
        "hits": [
            {"rule": rule, "purpose": purpose, "file": h["file"], "sha256": h["sha256"], "size": 1, "strings": ["$a"]}
            for h in (hits or [])
        ],
    }


def baseline(
    known: list[str] | None = None, *, seconds: float = 0.5, rule: str = "MAL_Win_Test_Rule"
) -> dict[str, Any]:
    return {
        "schema": 1,
        "generated": "2026-11-01",
        "corpus": {"manifest_sha256": "m1"},
        "rules": {
            rule: {
                "status": "test",
                "purpose": "triage",
                "seconds": seconds,
                "known_fp": [
                    {"sha256": s, "file": f"/usr/bin/{s[:4]}", "first_seen": "2026-11-01"} for s in known or []
                ],
                "last_fp": "2026-11-01" if known else None,
                "fp_total": len(known or []),
            }
        },
    }


# ---------------------------------------------------------------- compare


def test_clean_report_is_not_a_regression() -> None:
    d = fp_watch.compare(report(), baseline())
    assert d["regression"] is False
    assert d["new_hits"] == [] and d["budget"] == [] and d["regressions"] == []
    assert "limpo" in fp_watch.markdown(d)


def test_new_hit_on_triage_rule_is_a_regression() -> None:
    d = fp_watch.compare(report([{"file": "/usr/bin/x", "sha256": SHA_A}]), baseline())
    assert d["regression"] is True
    assert [h["sha256"] for h in d["new_hits"]] == [SHA_A]
    md = fp_watch.markdown(d)
    assert "REGRESSÃO" in md and SHA_A[:12] in md and "/usr/bin/x" in md


def test_known_fp_is_accepted() -> None:
    d = fp_watch.compare(report([{"file": "/usr/bin/x", "sha256": SHA_A}]), baseline([SHA_A]))
    assert d["regression"] is False and d["new_hits"] == [] and d["gone"] == []


def test_same_file_new_content_is_new_fp() -> None:
    # runner atualizou o binário: mesmo caminho, sha diferente -> conta como novo
    d = fp_watch.compare(report([{"file": "/usr/bin/aaaa", "sha256": SHA_B}]), baseline([SHA_A]))
    assert d["regression"] is True
    assert len(d["new_hits"]) == 1 and len(d["gone"]) == 1


def test_new_hit_on_hunting_rule_is_only_a_warning() -> None:
    d = fp_watch.compare(report([{"file": "/usr/bin/x", "sha256": SHA_A}], purpose="hunting"), baseline())
    assert d["regression"] is False
    assert len(d["hunting_hits"]) == 1
    assert "Aviso" in fp_watch.markdown(d)


def test_known_fp_gone_is_informational() -> None:
    d = fp_watch.compare(report(), baseline([SHA_A]))
    assert d["regression"] is False
    assert [g["sha256"] for g in d["gone"]] == [SHA_A]
    assert "não apareceu" in fp_watch.markdown(d)


def test_budget_exceeded_is_a_regression() -> None:
    limit = float(yrlib.CONFIG["performance"]["max_rule_seconds"])
    d = fp_watch.compare(report(seconds=limit + 1), baseline())
    assert d["regression"] is True and len(d["budget"]) == 1


def test_time_regression_respects_floor_and_pct() -> None:
    perf = yrlib.CONFIG["performance"]
    floor = float(perf["regression_floor_seconds"])
    pct = float(perf["max_regression_pct"])
    # abaixo do piso: ruído, não regressão
    d = fp_watch.compare(report(seconds=floor * 0.9), baseline(seconds=floor * 0.3))
    assert d["regressions"] == []
    # acima do piso e acima do percentual
    base = floor * 2
    d = fp_watch.compare(report(seconds=base * (1 + pct / 100) * 1.1), baseline(seconds=base))
    assert d["regression"] is True and len(d["regressions"]) == 1
    # acima do piso, dentro do percentual
    d = fp_watch.compare(report(seconds=base * (1 + pct / 100) * 0.9), baseline(seconds=base))
    assert d["regressions"] == []


def test_corpus_change_is_flagged_but_not_a_regression() -> None:
    d = fp_watch.compare(report(), baseline(), manifest_sha256="m2")
    assert d["corpus_changed"] is True and d["regression"] is False
    assert "corpus mudou" in fp_watch.markdown(d)
    assert fp_watch.compare(report(), baseline(), manifest_sha256="m1")["corpus_changed"] is False


def test_empty_baseline_everything_new() -> None:
    d = fp_watch.compare(report([{"file": "/usr/bin/x", "sha256": SHA_A}]), fp_watch.empty_baseline())
    assert d["regression"] is True


# ---------------------------------------------------------------- baseline


def test_update_baseline_accumulates_history() -> None:
    today = dt.date(2026, 11, 9)
    b1 = fp_watch.update_baseline(report([{"file": "/usr/bin/x", "sha256": SHA_A}]), None, today=today)
    r = b1["rules"]["MAL_Win_Test_Rule"]
    assert [fp["sha256"] for fp in r["known_fp"]] == [SHA_A]
    assert r["last_fp"] == "2026-11-09" and r["fp_total"] == 1
    assert r["known_fp"][0]["first_seen"] == "2026-11-09"

    later = dt.date(2026, 12, 1)
    b2 = fp_watch.update_baseline(
        report([{"file": "/usr/bin/x", "sha256": SHA_A}, {"file": "/usr/bin/y", "sha256": SHA_B}]), b1, today=later
    )
    r = b2["rules"]["MAL_Win_Test_Rule"]
    assert r["fp_total"] == 2 and r["last_fp"] == "2026-12-01"
    assert {fp["sha256"]: fp["first_seen"] for fp in r["known_fp"]} == {SHA_A: "2026-11-09", SHA_B: "2026-12-01"}

    # FP corrigido: some de known_fp, mas a história (fp_total, last_fp) fica
    b3 = fp_watch.update_baseline(report(), b2, today=dt.date(2027, 1, 1))
    r = b3["rules"]["MAL_Win_Test_Rule"]
    assert r["known_fp"] == [] and r["fp_total"] == 2 and r["last_fp"] == "2026-12-01"


def test_baseline_roundtrip_through_cli(tmp_path: Path) -> None:
    rep = tmp_path / "report.json"
    rep.write_text(json.dumps(report([{"file": "/usr/bin/x", "sha256": SHA_A}])))
    out = tmp_path / "baseline.json"
    assert fp_watch.main(["baseline", "--report", str(rep), "--out", str(out), "--today", "2026-11-09"]) == 0
    diff = tmp_path / "diff.json"
    md = tmp_path / "diff.md"
    assert (
        fp_watch.main(
            [
                "compare",
                "--report",
                str(rep),
                "--baseline",
                str(out),
                "--out",
                str(diff),
                "--markdown",
                str(md),
                "--fail",
            ]
        )
        == 0
    )
    assert json.loads(diff.read_text())["regression"] is False
    rep.write_text(
        json.dumps(report([{"file": "/usr/bin/x", "sha256": SHA_A}, {"file": "/usr/bin/z", "sha256": SHA_C}]))
    )
    assert (
        fp_watch.main(
            [
                "compare",
                "--report",
                str(rep),
                "--baseline",
                str(out),
                "--out",
                str(diff),
                "--markdown",
                str(md),
                "--fail",
            ]
        )
        == 1
    )
    assert fp_watch.MARKER in md.read_text()


def test_repo_baseline_is_consistent_with_rules() -> None:
    b = fp_watch.load_baseline()
    watched = {i.name for f in yrlib.rule_files() for i in yrlib.parse_rule_infos(f) if i.status in ("stable", "test")}
    assert set(b["rules"]) >= watched
    for r in b["rules"].values():
        for fp in r["known_fp"]:
            assert len(fp["sha256"]) == 64


# ---------------------------------------------------------------- issue (GitHub mockado)


class FakeGitHub:
    """Só o que o fp_watch usa: listar issues abertas por label, criar, editar, comentar, label."""

    def __init__(self, issues: list[dict[str, Any]] | None = None) -> None:
        self.issues: list[dict[str, Any]] = issues or []
        self.calls: list[tuple[str, str]] = []
        self.comments: list[str] = []
        self._next = 100 + len(self.issues)

    def __call__(self, method: str, path: str, body: dict[str, Any] | None) -> Any:
        self.calls.append((method, path))
        if method == "GET" and path.startswith("/issues?"):
            return [i for i in self.issues if i["state"] == "open" and fp_watch.LABEL in i["labels"]]
        if method == "POST" and path == "/labels":
            return {}
        if method == "POST" and path == "/issues":
            assert body is not None
            self._next += 1
            issue = {
                "number": self._next,
                "state": "open",
                "labels": body["labels"],
                "title": body["title"],
                "body": body["body"],
            }
            self.issues.append(issue)
            return issue
        if method == "PATCH" and path.startswith("/issues/"):
            assert body is not None
            num = int(path.split("/")[2])
            issue = next(i for i in self.issues if i["number"] == num)
            issue.update(body)
            return issue
        if method == "POST" and path.endswith("/comments"):
            assert body is not None
            self.comments.append(body["body"])
            return {}
        raise AssertionError(f"chamada inesperada {method} {path}")

    def writes(self) -> list[tuple[str, str]]:
        return [c for c in self.calls if c[0] != "GET"]


def _regression() -> tuple[dict[str, Any], str]:
    d = fp_watch.compare(report([{"file": "/usr/bin/x", "sha256": SHA_A}]), baseline())
    return d, fp_watch.markdown(d, run_url="https://example/run/1")


def test_issue_created_once_then_unchanged() -> None:
    gh = FakeGitHub()
    d, md = _regression()
    r1 = fp_watch.sync_issue(gh, d, md)
    assert r1["action"] == "created"
    assert len([i for i in gh.issues if i["state"] == "open"]) == 1
    issue = gh.issues[0]
    assert (
        fp_watch.LABEL in issue["labels"] and fp_watch.MARKER in issue["body"] and fp_watch.DIGEST_RE in issue["body"]
    )

    # mesmo diff, outro run (URL diferente): nenhuma escrita
    before = len(gh.writes())
    d2, md2 = _regression()
    md2 = md2.replace("https://example/run/1", "https://example/run/2")
    r2 = fp_watch.sync_issue(gh, d2, md2)
    assert r2 == {"action": "unchanged", "number": str(issue["number"])}
    assert len(gh.writes()) == before
    assert len(gh.issues) == 1


def test_issue_updated_in_place_when_diff_changes() -> None:
    gh = FakeGitHub()
    d, md = _regression()
    fp_watch.sync_issue(gh, d, md)
    d2 = fp_watch.compare(
        report([{"file": "/usr/bin/x", "sha256": SHA_A}, {"file": "/usr/bin/y", "sha256": SHA_B}]), baseline()
    )
    r = fp_watch.sync_issue(gh, d2, fp_watch.markdown(d2))
    assert r["action"] == "updated"
    assert len(gh.issues) == 1 and SHA_B[:12] in gh.issues[0]["body"]
    assert "2 hit(s)" in gh.issues[0]["title"]


def test_issue_closed_once_when_clean() -> None:
    gh = FakeGitHub()
    d, md = _regression()
    fp_watch.sync_issue(gh, d, md)
    clean = fp_watch.compare(report(), baseline())
    r = fp_watch.sync_issue(gh, clean, fp_watch.markdown(clean), run_url="https://example/run/3")
    assert r["action"] == "closed"
    assert gh.issues[0]["state"] == "closed" and len(gh.comments) == 1 and "run/3" in gh.comments[0]
    # já fechada: nada a fazer, nenhuma escrita
    before = len(gh.writes())
    assert fp_watch.sync_issue(gh, clean, fp_watch.markdown(clean))["action"] == "none"
    assert len(gh.writes()) == before


def test_issue_ignores_foreign_issues_with_same_label() -> None:
    foreign = {"number": 7, "state": "open", "labels": [fp_watch.LABEL], "title": "manual", "body": "aberta por humano"}
    gh = FakeGitHub([foreign])
    d, md = _regression()
    assert fp_watch.sync_issue(gh, d, md)["action"] == "created"
    assert len(gh.issues) == 2 and gh.issues[0]["body"] == "aberta por humano"


def test_digest_ignores_run_url_only() -> None:
    _d, md = _regression()
    assert fp_watch.digest_of(md) == fp_watch.digest_of(md.replace("run/1", "run/99"))
    assert fp_watch.digest_of(md) != fp_watch.digest_of(md.replace(SHA_A[:12], SHA_B[:12]))


def test_issue_cli_requires_repo_and_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    d, md = _regression()
    (tmp_path / "d.json").write_text(json.dumps(d))
    (tmp_path / "d.md").write_text(md)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    args = ["issue", "--diff", str(tmp_path / "d.json"), "--markdown", str(tmp_path / "d.md")]
    assert fp_watch.main([*args, "--dry-run"]) == 0
    assert fp_watch.main([*args, "--repo", "o/r"]) == 2


# ---------------------------------------------------------------- corpus


def test_pip_corpus_is_pinned_by_hash() -> None:
    text = fp_watch.PIP_CORPUS.read_text(encoding="utf-8")
    reqs = [ln for ln in text.splitlines() if ln and not ln.startswith("#") and "==" in ln]
    hashes = [ln for ln in text.splitlines() if "--hash=sha256:" in ln]
    assert reqs and len(reqs) == len(hashes)
    for h in hashes:
        digest = h.split("--hash=sha256:")[1].strip()
        assert len(digest) == 64 and int(digest, 16) >= 0


def test_zip_slip_is_rejected(tmp_path: Path) -> None:
    import zipfile

    wheels = tmp_path / "wheels"
    wheels.mkdir()
    bad = wheels / "evil-1.0-py3-none-any.whl"
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("../../escape.txt", "x")
    with pytest.raises(ValueError, match="caminho suspeito"):
        fp_watch.build_pip_corpus(tmp_path / "none.txt", tmp_path, pip=["true"])

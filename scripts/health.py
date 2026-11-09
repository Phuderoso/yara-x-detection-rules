#!/usr/bin/env python3
"""Painel de saúde das regras (docs/health.md), gerado e conferido na CI como o coverage.

Por regra: status, purpose, scope, idade (desde `date`), última mudança (`modified`),
FP conhecidos e último FP (tests/goodware/baseline.json, mantido pelo fp-watch), último
match verdadeiro fora das fixtures (tests/activity.json). Lista as candidatas a
`deprecated`: têm FP registrado E não casam nada há mais de N semanas (ou nunca casaram
fora das fixtures). Idades em faixas para o arquivo não mudar todo dia.

Uso:
    python scripts/health.py                 # reescreve docs/health.md
    python scripts/health.py --check         # exit 1 se estiver desatualizado
    python scripts/health.py --as-of 2026-11-09 --stale-weeks 12
"""

from __future__ import annotations

import argparse
import datetime as dt
import difflib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yrlib

DEFAULT_OUT = yrlib.REPO_ROOT / "docs" / "health.md"
BASELINE_PATH = yrlib.REPO_ROOT / "tests" / "goodware" / "baseline.json"
GENERATED_MARK = "<!-- gerado por scripts/health.py; não edite à mão -->"
AGE_BANDS = ((30, "< 30 d"), (90, "30–90 d"), (180, "90–180 d"), (365, "180–365 d"))


def _parse_date(s: str | None) -> dt.date | None:
    try:
        return dt.date.fromisoformat(s) if s else None
    except ValueError:
        return None


def age_band(days: int | None) -> str:
    if days is None:
        return "?"
    for limit, label in AGE_BANDS:
        if days < limit:
            return label
    return "> 1 ano"


def weeks_band(days: int | None, stale_weeks: int) -> str:
    """Para 'último match' e 'último FP': 'esta semana', '< N semanas', '> N semanas'."""
    if days is None:
        return "nunca"
    if days < 7:
        return "esta semana"
    if days <= stale_weeks * 7:
        return f"≤ {stale_weeks} sem"
    return f"> {stale_weeks} sem"


def _rel(info: yrlib.RuleInfo) -> str:
    try:
        return str(info.path.relative_to(yrlib.REPO_ROOT)).replace("\\", "/")
    except ValueError:
        return str(info.path)


def _link(info: yrlib.RuleInfo) -> str:
    return f"[`{info.name}`](../{_rel(info)})"


def load_baseline(path: Path = BASELINE_PATH) -> dict[str, Any]:
    if not path.exists():
        return {"rules": {}}
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    data.setdefault("rules", {})
    return data


def assess(
    infos: list[yrlib.RuleInfo],
    baseline: dict[str, Any],
    activity: dict[str, Any],
    *,
    as_of: dt.date,
    stale_weeks: int,
) -> list[dict[str, Any]]:
    """Uma linha por regra, com os sinais já calculados. Puro."""
    rows: list[dict[str, Any]] = []
    for i in sorted(infos, key=lambda r: r.name):
        b = baseline.get("rules", {}).get(i.name, {})
        a = activity.get("rules", {}).get(i.name, {})
        created = _parse_date(i.meta.get("date"))
        modified = _parse_date(i.meta.get("modified"))
        last_fp = _parse_date(b.get("last_fp"))
        last_match = _parse_date(a.get("last_match"))
        fp_known = len(b.get("known_fp", []))
        fp_total = int(b.get("fp_total", 0))
        has_fp = fp_known > 0 or fp_total > 0
        days_since_match = (as_of - last_match).days if last_match else None
        stale = days_since_match is None or days_since_match > stale_weeks * 7
        watched = i.status in ("stable", "test")
        rows.append(
            {
                "info": i,
                "age_days": (as_of - created).days if created else None,
                "modified_days": (as_of - modified).days if modified else None,
                "fp_known": fp_known,
                "fp_total": fp_total,
                "last_fp_days": (as_of - last_fp).days if last_fp else None,
                "last_match_days": days_since_match,
                "match_source": a.get("source"),
                "watched": watched,
                "deprecate_candidate": has_fp and stale and i.status != "deprecated",
                "unproven": not has_fp and last_match is None and i.status in ("test", "stable"),
            }
        )
    return rows


def render(rows: list[dict[str, Any]], *, as_of: dt.date, stale_weeks: int, baseline: dict[str, Any]) -> str:
    out: list[str] = []
    w = out.append
    w("# Saúde das regras")
    w("")
    w(GENERATED_MARK)
    w("")
    w(
        f"{len(rows)} regra(s). Referência: {as_of.isoformat()}. Regenerar: `make health`. "
        f"FP vem de `tests/goodware/baseline.json` (fp-watch semanal); match verdadeiro vem de "
        f"`tests/activity.json` (`hunt.py --record-activity`). Idades em faixas: o arquivo só muda ao cruzar uma."
    )
    w("")
    gen = baseline.get("generated")
    n_watch = sum(1 for r in rows if r["watched"])
    w(
        f"Baseline de FP: {gen or 'nenhuma'}; {n_watch} regra(s) sob vigia (stable/test); "
        f"{sum(r['fp_known'] for r in rows)} FP conhecido(s) aceito(s)."
    )
    w("")

    w("## Por regra")
    w("")
    w(
        "| Regra | status | purpose | scope | idade | alterada há | FP conhecidos | FP total | último FP | último match | fonte |"
    )
    w("|---|---|---|---|---|---|---:|---:|---|---|---|")
    for r in rows:
        i = r["info"]
        w(
            f"| {_link(i)} | {i.status} | {i.purpose} | {i.scope} | {age_band(r['age_days'])} | "
            f"{age_band(r['modified_days'])} | {r['fp_known']} | {r['fp_total']} | "
            f"{weeks_band(r['last_fp_days'], stale_weeks)} | {weeks_band(r['last_match_days'], stale_weeks)} | "
            f"{r['match_source'] or '-'} |"
        )
    w("")

    w(f"## Candidatas a `deprecated` (FP registrado e sem match há > {stale_weeks} semanas)")
    w("")
    cands = [r for r in rows if r["deprecate_candidate"]]
    if cands:
        w("| Regra | status | FP total | último FP | último match |")
        w("|---|---|---:|---|---|")
        for r in cands:
            i = r["info"]
            w(
                f"| {_link(i)} | {i.status} | {r['fp_total']} | {weeks_band(r['last_fp_days'], stale_weeks)} | "
                f"{weeks_band(r['last_match_days'], stale_weeks)} |"
            )
        w("")
        w('Deprecar = `status = "deprecated"`, `version + 1`, motivo no PR. A regra fica no repo; sai dos bundles.')
    else:
        w("Nenhuma.")
    w("")

    w("## Sem prova fora das fixtures")
    w("")
    unproven = [r for r in rows if r["unproven"]]
    if unproven:
        w(
            "Regras `test`/`stable` sem FP e sem match registrado em `tests/activity.json`: limpas, mas ainda não "
            "mostraram serviço. Rode `hunt.py --record-activity` ou `memscan.py --record-activity` num caso real, "
            "ou o job `real-samples` com uma linha em `tests/samples.lock`."
        )
        w("")
        for r in unproven:
            w(f"- {_link(r['info'])} ({r['info'].status}, {r['info'].purpose})")
    else:
        w("Todas as regras `test`/`stable` têm FP ou match registrado.")
    w("")

    w("## Sinais")
    w("")
    w(
        "- **FP conhecidos**: hits no corpus limpo aceitos na baseline (`fp_watch.py baseline`). Zero é o alvo para `triage`/`blocking`."
    )
    w("- **FP total**: acumulado desde a primeira baseline, mesmo os já corrigidos. Mede quanto a regra já custou.")
    w(
        "- **último match**: hunting real, amostra do `samples.lock` ou IR. Fixture não conta; fixture é o que a regra promete, não o que entregou."
    )
    w(
        "- **candidata a deprecated**: tem custo (FP) e não tem retorno (match) há mais de N semanas. Não é automático; é pauta de revisão."
    )
    w("")
    return "\n".join(out)


def _comparable(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if "Referência: " not in ln]


def _display(path: Path) -> str:
    try:
        return str(path.relative_to(yrlib.REPO_ROOT))
    except ValueError:
        return str(path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", type=Path, default=yrlib.RULES_DIR)
    ap.add_argument("--baseline", type=Path, default=BASELINE_PATH)
    ap.add_argument("--activity", type=Path, default=yrlib.ACTIVITY_PATH)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--check", action="store_true", help="não escreve; exit 1 se o arquivo estiver desatualizado")
    ap.add_argument("--as-of", type=dt.date.fromisoformat, default=None, help="data de referência (default hoje)")
    ap.add_argument("--stale-weeks", type=int, default=12)
    args = ap.parse_args(argv)

    infos = [i for f in yrlib.rule_files(args.rules) for i in yrlib.parse_rule_infos(f)]
    baseline = load_baseline(args.baseline)
    activity = yrlib.load_activity(args.activity)
    as_of = args.as_of or dt.date.today()
    rows = assess(infos, baseline, activity, as_of=as_of, stale_weeks=args.stale_weeks)
    text = render(rows, as_of=as_of, stale_weeks=args.stale_weeks, baseline=baseline)

    if args.check:
        current = args.out.read_text(encoding="utf-8") if args.out.exists() else ""
        if _comparable(current) == _comparable(text):
            print(f"{_display(args.out)} atualizado")
            return 0
        diff = difflib.unified_diff(
            current.splitlines(), text.splitlines(), fromfile="commitado", tofile="gerado", lineterm="", n=1
        )
        print("\n".join(diff))
        print(f"\n::error::{args.out.name} desatualizado; rode `make health` e commite", file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    print(
        f"{_display(args.out)}: {len(rows)} regra(s), {sum(1 for r in rows if r['deprecate_candidate'])} candidata(s) a deprecated"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Painel de cobertura gerado a partir do `meta` das regras (docs/coverage.md).

Conta regras por técnica MITRE ATT&CK, por purpose × status, por scope, por
família e por engine, e lista as regras `experimental` há mais de N dias
(candidatas a promoção ou descarte). A CI roda `--check`: se o arquivo
commitado não bate com o gerado, falha e mostra o diff.

Uso:
    python scripts/coverage.py                 # reescreve docs/coverage.md
    python scripts/coverage.py --check         # exit 1 se estiver desatualizado
    python scripts/coverage.py --as-of 2026-11-09 --stale-days 90
"""

from __future__ import annotations

import argparse
import datetime as dt
import difflib
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yrlib

DEFAULT_OUT = yrlib.REPO_ROOT / "docs" / "coverage.md"
ATTACK_URL = "https://attack.mitre.org/techniques/{}/"
GENERATED_MARK = "<!-- gerado por scripts/coverage.py; não edite à mão -->"


def _link(tech: str) -> str:
    path = tech.replace(".", "/")
    return f"[{tech}]({ATTACK_URL.format(path)})"


def _rel(info: yrlib.RuleInfo) -> str:
    try:
        return str(info.path.relative_to(yrlib.REPO_ROOT)).replace("\\", "/")
    except ValueError:
        return str(info.path)


def _rule_link(info: yrlib.RuleInfo) -> str:
    return f"[`{info.name}`](../{_rel(info)})"


def _parse_date(s: str | None) -> dt.date | None:
    try:
        return dt.date.fromisoformat(s) if s else None
    except ValueError:
        return None


def _age_bucket(days: int, stale_days: int) -> str:
    for limit in (730, 365, 180):
        if days > limit >= stale_days:
            return f"> {limit} dias"
    return f"> {stale_days} dias"


def render(infos: list[yrlib.RuleInfo], *, as_of: dt.date, stale_days: int) -> str:
    infos = sorted(infos, key=lambda i: i.name)
    out: list[str] = []
    w = out.append
    w("# Cobertura das regras")
    w("")
    w(GENERATED_MARK)
    w("")
    files = {i.path for i in infos}
    w(f"{len(infos)} regra(s) em {len(files)} arquivo(s). Regenerar: `make coverage`.")
    w("")

    # MITRE
    w("## Por técnica MITRE ATT&CK")
    w("")
    by_tech: dict[str, list[yrlib.RuleInfo]] = defaultdict(list)
    for i in infos:
        for t in i.mitre or ["(nenhuma)"]:
            by_tech[t].append(i)
    w("| Técnica | Regras | Quais |")
    w("|---|---:|---|")
    for tech in sorted(by_tech, key=lambda t: (t == "(nenhuma)", t)):
        rules = by_tech[tech]
        label = _link(tech) if tech != "(nenhuma)" else "(nenhuma)"
        w(f"| {label} | {len(rules)} | {', '.join(_rule_link(r) for r in rules)} |")
    w("")
    tactics_hint = sum(1 for i in infos if i.mitre)
    w(
        f'{tactics_hint}/{len(infos)} regra(s) com técnica mapeada; `mitre_attack = "none"` é válido quando não há técnica honesta.'
    )
    w("")

    # purpose × status
    w("## Por purpose × status")
    w("")
    w("| purpose \\ status | " + " | ".join(yrlib.STATUSES) + " | total |")
    w("|---|" + "---:|" * (len(yrlib.STATUSES) + 1))
    matrix: Counter[tuple[str, str]] = Counter((i.purpose, i.status) for i in infos)
    for p in yrlib.PURPOSES:
        row = [str(matrix[(p, s)]) for s in yrlib.STATUSES]
        w(f"| {p} | " + " | ".join(row) + f" | {sum(matrix[(p, s)] for s in yrlib.STATUSES)} |")
    w(
        "| total | "
        + " | ".join(str(sum(matrix[(p, s)] for p in yrlib.PURPOSES)) for s in yrlib.STATUSES)
        + f" | {len(infos)} |"
    )
    w("")
    w("Gate de promoção: `blocking` exige `stable` + `confidence = high`; `deprecated` fica fora dos bundles.")
    w("")

    # scope
    w("## Por scope")
    w("")
    w("| scope | Regras | Quais |")
    w("|---|---:|---|")
    by_scope: dict[str, list[yrlib.RuleInfo]] = defaultdict(list)
    for i in infos:
        by_scope[i.scope].append(i)
    for sc in yrlib.SCOPES:
        rules = by_scope.get(sc, [])
        w(f"| {sc} | {len(rules)} | {', '.join(_rule_link(r) for r in rules) or '-'} |")
    w("")
    w(
        "`memory`/`both` não podem depender de `uintN(0)`, `filesize` ou `pe.*` (lint); `scripts/memscan.py` usa só essas."
    )
    w("")

    # família
    w("## Por família")
    w("")
    w("| Família | Regras | purpose | status | scope |")
    w("|---|---:|---|---|---|")
    by_family: dict[str, list[yrlib.RuleInfo]] = defaultdict(list)
    for i in infos:
        by_family[i.family or "(sem `malware`)"].append(i)
    for fam in sorted(by_family, key=lambda f: (f.startswith("("), f.lower())):
        rules = by_family[fam]

        def _set(attr: str, rules: list[yrlib.RuleInfo] = rules) -> str:
            return ", ".join(sorted({getattr(r, attr) for r in rules}))

        w(f"| {fam} | {len(rules)} | {_set('purpose')} | {_set('status')} | {_set('scope')} |")
    w("")

    # engine
    w("## Por engine")
    w("")
    eng: Counter[str] = Counter(i.meta.get("engine", "any") for i in infos)
    w("| engine | Regras |")
    w("|---|---:|")
    for e in yrlib.ENGINES:
        w(f"| {e} | {eng.get(e, 0)} |")
    w("")
    w("`yara-x` = usa sintaxe/módulo que não compila em YARA 4.x (ver matriz em `scripts/compat_yara4.py`).")
    w("")

    # stale experimental
    w(f"## Experimentais há mais de {stale_days} dias")
    w("")
    w(f"Referência: {as_of.isoformat()}. Candidatas a promoção (`test`) ou descarte; idade conta desde `date`.")
    w("")
    stale: list[tuple[int, yrlib.RuleInfo]] = []
    for i in infos:
        if i.status != "experimental":
            continue
        d = _parse_date(i.meta.get("date"))
        if d is None:
            continue
        age = (as_of - d).days
        if age > stale_days:
            stale.append((age, i))
    if stale:
        # Faixas, não dias exatos: o painel é comparado na CI e não pode mudar todo dia.
        w("| Regra | Desde | Idade | purpose | Família |")
        w("|---|---|---|---|---|")
        for age, i in sorted(stale, key=lambda t: (-t[0], t[1].name)):
            w(
                f"| {_rule_link(i)} | {i.meta.get('date')} | {_age_bucket(age, stale_days)} | {i.purpose} | {i.family or '-'} |"
            )
    else:
        n_exp = sum(1 for i in infos if i.status == "experimental")
        w(f"Nenhuma ({n_exp} experimental(is) no total, todas com menos de {stale_days} dias).")
    w("")

    # inventário
    w("## Inventário")
    w("")
    w("| Regra | id | v | status | purpose | scope | Família | MITRE | Arquivo |")
    w("|---|---|---:|---|---|---|---|---|---|")
    for i in infos:
        mitre = ", ".join(i.mitre) if i.mitre else "none"
        w(
            f"| `{i.name}` | `{i.rule_id or '?'}` | {i.meta.get('version', '?')} | {i.status} | {i.purpose} | {i.scope} "
            f"| {i.family or '-'} | {mitre} | `{_rel(i)}` |"
        )
    w("")
    return "\n".join(out)


def _display(path: Path) -> str:
    try:
        return str(path.relative_to(yrlib.REPO_ROOT))
    except ValueError:
        return str(path)


def _comparable(text: str) -> list[str]:
    """Linhas que entram na comparação do --check (a data de referência não)."""
    return [ln for ln in text.splitlines() if not ln.startswith("Referência: ")]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", type=Path, default=yrlib.RULES_DIR)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--check", action="store_true", help="não escreve; exit 1 se o arquivo estiver desatualizado")
    ap.add_argument("--as-of", type=dt.date.fromisoformat, default=None, help="data de referência (default hoje)")
    ap.add_argument("--stale-days", type=int, default=90)
    args = ap.parse_args(argv)

    infos = [i for f in yrlib.rule_files(args.rules) for i in yrlib.parse_rule_infos(f)]
    text = render(infos, as_of=args.as_of or dt.date.today(), stale_days=args.stale_days)

    if args.check:
        current = args.out.read_text(encoding="utf-8") if args.out.exists() else ""
        if _comparable(current) == _comparable(text):
            print(f"{_display(args.out)} atualizado")
            return 0
        diff = difflib.unified_diff(
            current.splitlines(), text.splitlines(), fromfile="commitado", tofile="gerado", lineterm="", n=1
        )
        print("\n".join(diff))
        print(f"\n::error::{args.out.name} desatualizado; rode `make coverage` e commite", file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    print(f"{_display(args.out)}: {len(infos)} regra(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

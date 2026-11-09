#!/usr/bin/env python3
"""Testa as regras contra as fixtures sintéticas de tests/cases.py.

Para cada caso: constrói o arquivo em memória, escaneia com TODAS as regras do
repo e verifica:
  - cada regra em `expect_match` casou;
  - nenhuma regra em `expect_no_match` casou;
  - (--strict) nenhuma regra fora da lista casou por acidente.

Também falha se alguma regra em rules/ não tiver cobertura (>= 1 positivo e
>= 1 negativo). Regra sem teste negativo é regra sem prova de que não é um
detector genérico.

Uso:
    python scripts/test_rules.py [--strict] [--dump DIR] [-v]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
import yrlib
from cases import CASES


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--strict", action="store_true", help="falhar se uma regra não listada casar")
    ap.add_argument("--dump", metavar="DIR", help="gravar as fixtures geradas em DIR (para `yr scan -s` manual)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    rules, index = yrlib.load_all_rules(strict=False)
    failures: list[str] = []
    positives: dict[str, int] = dict.fromkeys(index, 0)
    negatives: dict[str, int] = dict.fromkeys(index, 0)

    dump_dir = Path(args.dump) if args.dump else None
    if dump_dir:
        dump_dir.mkdir(parents=True, exist_ok=True)

    for case in CASES:
        data = case.build()
        if dump_dir:
            (dump_dir / f"{case.name}.bin").write_bytes(data)
        for r in case.expect_match + case.expect_no_match:
            if r not in index:
                failures.append(f"[{case.name}] referencia regra inexistente: {r}")
        matched = {m.identifier for m in rules.scan(data).matching_rules}

        for r in case.expect_match:
            positives[r] = positives.get(r, 0) + 1
            if r not in matched:
                failures.append(f"[{case.name}] esperado casar {r}, não casou ({case.note})")
        for r in case.expect_no_match:
            negatives[r] = negatives.get(r, 0) + 1
            if r in matched:
                failures.append(f"[{case.name}] NÃO deveria casar {r}, casou ({case.note})")
        if args.strict:
            for r in matched - set(case.expect_match):
                failures.append(f"[{case.name}] regra não listada casou: {r}")

        status = "ok " if not any(case.name in f for f in failures) else "FAIL"
        if args.verbose or status == "FAIL":
            print(f"{status} {case.name:40s} {yrlib.human_size(len(data)):>8s}  matched={sorted(matched) or '-'}")

    for name in index:
        if positives.get(name, 0) == 0:
            failures.append(f"regra {name} não tem nenhum caso positivo em tests/cases.py")
        if negatives.get(name, 0) == 0:
            failures.append(f"regra {name} não tem nenhum caso negativo em tests/cases.py")

    print()
    for f in failures:
        print(f"FAIL {f}")
    print(f"{len(CASES)} caso(s), {len(index)} regra(s), {len(failures)} falha(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Matriz de compatibilidade: cada arquivo de regra compila em YARA 4.x (yara-python)?

O repositório é YARA-X, mas muito produto (EDR, sandbox) ainda roda o motor
antigo. Este script tenta compilar cada arquivo com `yara-python` e cruza com
`meta.engine`:

  compila em YARA 4 + engine ausente/any   -> ok, portável
  não compila   + engine = "yara-x"        -> ok, declarado
  não compila   + engine ausente/any       -> AVISO (ou erro com --strict): declare engine = "yara-x"
  compila       + engine = "yara-x"        -> info: a declaração pode ser removida

Saída: tabela Markdown (stdout e $GITHUB_STEP_SUMMARY) e JSON com --json.
Se yara-python não estiver instalado, sai com aviso e código 0.

Uso:
    python scripts/compat_yara4.py [--strict] [--json compat.json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yrlib


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--rules", type=Path, default=yrlib.RULES_DIR)
    args = ap.parse_args(argv)

    try:
        import yara
    except ImportError:
        print("::warning::yara-python não instalado; matriz de compatibilidade pulada")
        return 0

    rows: list[dict[str, Any]] = []
    problems: list[str] = []
    for f in yrlib.rule_files(args.rules):
        infos = yrlib.parse_rule_infos(f)
        declared = {i.meta.get("engine", "any") for i in infos}
        engine = "yara-x" if "yara-x" in declared else "any"
        try:
            yara.compile(filepath=str(f))
            ok, err = True, ""
        except yara.Error as e:  # SyntaxError e WarningError herdam de Error
            ok, err = False, str(e)

        if ok and engine == "any":
            verdict = "portável"
        elif not ok and engine == "yara-x":
            verdict = "só YARA-X (declarado)"
        elif not ok:
            verdict = "só YARA-X (NÃO declarado)"
            problems.append(f'{yrlib.namespace_for(f)}: não compila em YARA 4 e não declara engine = "yara-x" ({err})')
        else:
            verdict = "portável (engine=yara-x pode ser removido)"
        rows.append(
            {
                "file": yrlib.namespace_for(f),
                "rules": [i.name for i in infos],
                "yara4_compiles": ok,
                "yara4_error": err,
                "declared_engine": engine,
                "verdict": verdict,
            }
        )

    md = [f"### Compatibilidade YARA 4.x (yara-python {yara.__version__})\n"]
    md.append("| Arquivo | regras | YARA 4 | engine | veredito |")
    md.append("|---|---|:-:|---|---|")
    for r in rows:
        md.append(
            f"| `{r['file']}` | {', '.join(r['rules'])} | {'sim' if r['yara4_compiles'] else 'não'} | "
            f"{r['declared_engine']} | {r['verdict']}" + (f" — `{r['yara4_error']}`" if r["yara4_error"] else "") + " |"
        )
    md.append("")
    portable = sum(1 for r in rows if r["yara4_compiles"])
    md.append(f"{portable}/{len(rows)} arquivo(s) compilam em YARA 4.x.\n")
    text = "\n".join(md)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps({"yara_python": yara.__version__, "files": rows}, indent=2), encoding="utf-8")

    for p in problems:
        print(("ERROR " if args.strict else "WARN  ") + p)
    return 1 if (problems and args.strict) else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Formata os arquivos em rules/ com o formatter do YARA-X (equivale a `yr fmt`).

Uso:
    python scripts/fmt_rules.py           # reescreve in place
    python scripts/fmt_rules.py --check   # só verifica; exit 1 se algo mudaria
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yrlib


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)

    changed: list[Path] = []
    for f in yrlib.rule_files():
        src = f.read_bytes()
        out = yrlib.format_source(src)
        if out != src:
            changed.append(f)
            if not args.check:
                f.write_bytes(out)

    rel = [str(p.relative_to(yrlib.REPO_ROOT)) for p in changed]
    if args.check:
        for p in rel:
            print(f"precisa formatar: {p}")
        return 1 if changed else 0
    for p in rel:
        print(f"formatado: {p}")
    print(f"{len(changed)} arquivo(s) alterado(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

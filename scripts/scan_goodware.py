#!/usr/bin/env python3
"""Gate de falso-positivo: escaneia um corpus limpo e falha conforme o `purpose`.

Política padrão (alinhada ao meta.purpose de cada regra):
  blocking  -> qualquer hit no goodware FALHA
  triage    -> hit FALHA (use --triage-warn para só avisar)
  hunting   -> hit só avisa (regra larga por definição)

Imprime cada hit com a string que casou, porque é ela que você vai matar ou
rebaixar para "contexto". Com --jsonl grava os hits em JSON Lines para alimentar
telemetria (hits/semana, % FP por regra).

Uso:
    python scripts/scan_goodware.py DIR [DIR ...] [--max-size 32MB] [--jsonl out.jsonl]
    python scripts/scan_goodware.py "C:\\Windows\\System32" "C:\\Program Files"
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

import yara_x

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yrlib

_cfg = yrlib.CONFIG.get("goodware", {})


def parse_size(s: str) -> int:
    try:
        return yrlib.parse_size(s)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from e


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", type=Path, help="diretórios/arquivos do corpus limpo")
    ap.add_argument("--rules", type=Path, default=yrlib.RULES_DIR, help="diretório de regras (default rules/)")
    ap.add_argument(
        "--max-size",
        type=parse_size,
        default=str(_cfg.get("max_file_size", "32MB")),
        help="ignorar arquivos maiores (default rules-ci.toml ou 32MB)",
    )
    ap.add_argument(
        "--timeout",
        type=int,
        default=int(_cfg.get("scan_timeout_seconds", 30)),
        help="timeout por arquivo, em segundos",
    )
    ap.add_argument("--triage-warn", action="store_true", help="hits de regras triage não falham")
    ap.add_argument("--jsonl", type=Path, help="gravar hits em JSON Lines")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    rules, index = yrlib.load_all_rules(strict=False, root=args.rules)
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(args.timeout)

    fail_purposes = {"blocking"} | (set() if args.triage_warn else {"triage"})
    hits: list[dict[str, Any]] = []
    scanned = skipped = 0
    t0 = time.time()

    for path in yrlib.iter_files(args.paths, max_size=args.max_size):
        data = yrlib.read_file(path)
        if data is None:
            skipped += 1
            continue
        scanned += 1
        try:
            result = scanner.scan(data)
        except yara_x.TimeoutError:
            print(f"TIMEOUT {path}", file=sys.stderr)
            skipped += 1
            continue
        for m in result.matching_rules:
            info = index.get(m.identifier)
            purpose = info.purpose if info else "hunting"
            matched_strings = sorted({p.identifier for p in m.patterns if p.matches})
            hits.append(
                {
                    "rule": m.identifier,
                    "rule_id": info.rule_id if info else None,
                    "purpose": purpose,
                    "file": str(path),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                    "strings": matched_strings,
                    "ts": int(time.time()),
                }
            )
            level = "FAIL" if purpose in fail_purposes else "WARN"
            if not args.quiet or level == "FAIL":
                print(f"{level} {m.identifier} [{purpose}] {path}  strings={matched_strings}")

    if args.jsonl:
        with args.jsonl.open("a", encoding="utf-8") as fh:
            for h in hits:
                fh.write(json.dumps(h, ensure_ascii=False) + "\n")

    failing = [h for h in hits if h["purpose"] in fail_purposes]
    by_rule: dict[str, int] = {}
    for h in hits:
        by_rule[h["rule"]] = by_rule.get(h["rule"], 0) + 1

    print(f"\n{scanned} arquivo(s) escaneado(s), {skipped} ignorado(s), {len(hits)} hit(s) em {time.time() - t0:.1f}s")
    for rule, n in sorted(by_rule.items(), key=lambda kv: -kv[1]):
        print(f"  {n:6d}  {rule} [{index[rule].purpose if rule in index else '?'}]")
    if failing:
        print(f"\nFP gate: {len(failing)} hit(s) em regra(s) {sorted(fail_purposes)} -> FALHOU")
        return 1
    print("\nFP gate: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""dataset.jsonl: uma linha JSON por regra, gerada do `meta` e de tests/cases.py.

Só fatos que já estão no repositório: caminho, linha, nome, plataforma (o
diretório em rules/), os campos de `meta` como escritos, imports do arquivo,
identificadores das strings (sem os valores) e os nomes dos casos em
tests/cases.py que devem e que não devem casar com a regra. Nada é inferido.
`status` segue o ciclo de vida local (quatro dos cinco valores do Sigma).

A CI roda `--check`: se o arquivo commitado não bate com o gerado, falha e
mostra o diff.

Uso:
    python scripts/dataset_jsonl.py            # reescreve dataset.jsonl
    python scripts/dataset_jsonl.py --check    # exit 1 se estiver desatualizado
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
import yrlib

DEFAULT_OUT = yrlib.REPO_ROOT / "dataset.jsonl"
SCHEMA = 1
_STRING_ID_RE = re.compile(r"^\s*(\$[A-Za-z0-9_]*)\s*=", re.M)
_STRINGS_BLOCK_RE = re.compile(r"\bstrings\s*:(.*?)\bcondition\s*:", re.S)
_INT_RE = re.compile(r"^-?\d+$")


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(yrlib.REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _meta_value(raw: str) -> Any:
    """yrlib devolve tudo como str; inteiros e booleanos sem aspas voltam ao tipo."""
    if _INT_RE.match(raw):
        return int(raw)
    if raw in ("true", "false"):
        return raw == "true"
    return raw


def _raw_meta(source: str) -> dict[str, Any]:
    """Meta na ordem do arquivo, distinguindo `"3"` (string) de `3` (inteiro)."""
    m = yrlib._META_BLOCK_RE.search(source)
    out: dict[str, Any] = {}
    if not m:
        return out
    for k, raw in yrlib._META_LINE_RE.findall(m.group(1)):
        out[k] = yrlib._unescape(raw[1:-1]) if raw.startswith('"') else _meta_value(raw)
    return out


def _string_ids(source: str) -> list[str]:
    m = _STRINGS_BLOCK_RE.search(source)
    return _STRING_ID_RE.findall(m.group(1)) if m else []


def _platform(path: Path, rules_root: Path) -> str:
    try:
        parts = path.resolve().relative_to(rules_root.resolve()).parts
    except ValueError:
        return ""
    return parts[0] if len(parts) > 1 else ""


def _tests(name: str) -> dict[str, list[str]]:
    from cases import CASES

    return {
        "positive": sorted(c.name for c in CASES if name in c.expect_match),
        "negative": sorted(c.name for c in CASES if name in c.expect_no_match),
    }


def rows(rules_root: Path = yrlib.RULES_DIR) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in yrlib.rule_files(rules_root):
        imports = [re.sub(r'^\s*import\s+"([^"]+)"', r"\1", s) for s in yrlib.file_imports(f)]
        for info in yrlib.parse_rule_infos(f):
            out.append(
                {
                    "schema": SCHEMA,
                    "path": _rel(info.path),
                    "line": info.line,
                    "name": info.name,
                    "platform": _platform(info.path, rules_root),
                    "meta": _raw_meta(info.source),
                    "imports": imports,
                    "strings": _string_ids(info.source),
                    "tests": _tests(info.name),
                }
            )
    out.sort(key=lambda r: (r["path"], r["line"]))
    return out


def render(data: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in data)


def _display(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(yrlib.REPO_ROOT))
    except ValueError:
        return str(path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", type=Path, default=yrlib.RULES_DIR)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--check", action="store_true", help="não escreve; exit 1 se o arquivo estiver desatualizado")
    args = ap.parse_args(argv)

    data = rows(args.rules)
    text = render(data)

    if args.check:
        current = args.out.read_text(encoding="utf-8") if args.out.exists() else ""
        for n, line in enumerate(current.splitlines(), 1):
            try:
                json.loads(line)
            except json.JSONDecodeError as e:
                print(f"::error::{args.out.name}:{n}: JSON inválido ({e})", file=sys.stderr)
                return 1
        if current == text:
            print(f"{_display(args.out)} atualizado ({len(data)} regra(s))")
            return 0
        diff = difflib.unified_diff(
            current.splitlines(), text.splitlines(), fromfile="commitado", tofile="gerado", lineterm="", n=0
        )
        print("\n".join(diff))
        print(f"\n::error::{args.out.name} desatualizado; rode `make dataset` e commite", file=sys.stderr)
        return 1

    args.out.write_text(text, encoding="utf-8")
    print(f"{_display(args.out)}: {len(data)} regra(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

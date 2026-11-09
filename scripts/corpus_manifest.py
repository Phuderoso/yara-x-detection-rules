#!/usr/bin/env python3
"""Manifesto do corpus de goodware: caminho → sha256 + tamanho, fixado em JSON.

Sem isso um FP na CI é irreproduzível ("casou em algo no System32 do runner de
terça"). Com o manifesto, o hit aponta para um sha256 que você pode buscar no
VT, e a mudança da imagem do runner aparece como diff (arquivos adicionados,
removidos, alterados), não como mistério.

Uso:
    python scripts/corpus_manifest.py build /usr/bin /usr/lib/x86_64-linux-gnu -o manifest.json
    python scripts/corpus_manifest.py diff tests/goodware/manifests/ubuntu-latest.json manifest.json
    python scripts/corpus_manifest.py diff old.json new.json --markdown   # para o job summary
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yrlib


def sha256_file(path: Path) -> str | None:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def build(paths: list[Path], max_size: int) -> dict[str, Any]:
    files: dict[str, dict[str, Any]] = {}
    for p in yrlib.iter_files(paths, max_size=max_size):
        digest = sha256_file(p)
        if digest is None:
            continue
        files[str(p)] = {"sha256": digest, "size": p.stat().st_size}
    return {
        "schema": 1,
        "generated": int(time.time()),
        "platform": platform.platform(),
        # ImageVersion é o nome real da variável no GitHub Actions (CamelCase)
        "runner": (os.environ.get("RUNNER_OS", "") + " " + os.environ.get("ImageVersion", "")).strip(),  # noqa: SIM112
        "paths": [str(p) for p in paths],
        "max_size": max_size,
        "count": len(files),
        "files": dict(sorted(files.items())),
    }


def diff(old: dict[str, Any], new: dict[str, Any]) -> dict[str, list[str]]:
    of, nf = old.get("files", {}), new.get("files", {})
    added = sorted(set(nf) - set(of))
    removed = sorted(set(of) - set(nf))
    changed = sorted(k for k in set(of) & set(nf) if of[k]["sha256"] != nf[k]["sha256"])
    return {"added": added, "removed": removed, "changed": changed}


def diff_markdown(old: dict[str, Any], new: dict[str, Any], limit: int = 50) -> str:
    d = diff(old, new)
    lines = ["### Drift do corpus de goodware\n"]
    lines.append(
        f"Manifesto fixado: {old.get('count', 0)} arquivo(s) ({old.get('runner') or old.get('platform', '')}). "
        f"Runner atual: {new.get('count', 0)} arquivo(s) ({new.get('runner') or new.get('platform', '')}).\n"
    )
    lines.append(
        f"- adicionados: {len(d['added'])}\n- removidos: {len(d['removed'])}\n- alterados: {len(d['changed'])}\n"
    )
    for key in ("added", "removed", "changed"):
        if d[key]:
            lines.append(f"<details><summary>{key} ({len(d[key])})</summary>\n")
            lines.extend(f"- `{p}`" for p in d[key][:limit])
            if len(d[key]) > limit:
                lines.append(f"- … e mais {len(d[key]) - limit}")
            lines.append("\n</details>\n")
    if not any(d.values()):
        lines.append("Sem drift: o corpus é idêntico ao manifesto fixado.\n")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="gerar manifesto")
    b.add_argument("paths", nargs="+", type=Path)
    b.add_argument("-o", "--out", type=Path, required=True)
    b.add_argument("--max-size", default=yrlib.CONFIG.get("goodware", {}).get("max_file_size", "32MB"))
    d = sub.add_parser("diff", help="comparar dois manifestos")
    d.add_argument("old", type=Path)
    d.add_argument("new", type=Path)
    d.add_argument("--markdown", action="store_true")
    d.add_argument("--fail-on-drift", action="store_true")
    args = ap.parse_args(argv)

    if args.cmd == "build":
        m = build(args.paths, yrlib.parse_size(args.max_size))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(m, indent=1), encoding="utf-8")
        print(f"{m['count']} arquivo(s) -> {args.out}")
        return 0

    old = json.loads(args.old.read_text(encoding="utf-8"))
    new = json.loads(args.new.read_text(encoding="utf-8"))
    if args.markdown:
        md = diff_markdown(old, new)
        print(md)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write(md + "\n")
    else:
        print(json.dumps(diff(old, new), indent=1))
    drift = any(diff(old, new).values())
    return 1 if (drift and args.fail_on_drift) else 0


if __name__ == "__main__":
    sys.exit(main())

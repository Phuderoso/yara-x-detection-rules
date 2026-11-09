#!/usr/bin/env python3
"""Gera os bundles de release por purpose.

Semântica cumulativa, que é o que o consumidor quer:
  blocking.yar  = só regras purpose=blocking          (EDR prevent / quarentena)
  triage.yar    = blocking + triage                   (sandbox, fila de triagem)
  hunting.yar   = blocking + triage + hunting         (Livehunt, retro, SIEM)

Regras com status=deprecated ficam fora de todos os bundles. Para cada bundle
saem três artefatos:
  <purpose>.yar       fonte concatenada (portável; compila em YARA-X e, quando a
                      regra permite, em YARA 4.x)
  <purpose>.yarc      compilado/serializado pelo YARA-X (formato atrelado à versão
                      do yara-x; carregue com `yr scan -C` ou Rules.deserialize_from)
  manifest.json       versão, data, regras incluídas (nome, id, version, status,
                      arquivo, sha256 do fonte) e versão do yara-x
Mais SHA256SUMS de tudo.

Uso:
    python scripts/build_bundles.py --version v1.2.0 --out dist/
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import sys
import time
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Any

import yara_x

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yrlib

BUNDLES: dict[str, tuple[str, ...]] = {
    "blocking": ("blocking",),
    "triage": ("blocking", "triage"),
    "hunting": ("blocking", "triage", "hunting"),
}


def git_version() -> str:
    try:
        return yrlib.git("describe", "--tags", "--always", "--dirty").strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "0.0.0-dev"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_bundle(
    name: str, purposes: tuple[str, ...], files: list[Path], version: str, out_dir: Path
) -> dict[str, Any]:
    selected: list[tuple[Path, list[yrlib.RuleInfo]]] = []
    for f in files:
        infos = [i for i in yrlib.parse_rule_infos(f) if i.status != "deprecated" and i.purpose in purposes]
        if infos:
            selected.append((f, infos))

    header = (
        f"// yara-x-detection-rules bundle: {name}\n"
        f"// version: {version}\n"
        f"// generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
        f"// purposes: {', '.join(purposes)}  (status=deprecated excluídas)\n"
        f"// rules: {sum(len(i) for _, i in selected)}\n"
        f"// license: {yrlib.LICENSE_ID} (public domain; see LICENSE in the repository)\n\n"
    )
    parts = [header]
    manifest_rules: list[dict[str, Any]] = []
    for f, infos in selected:
        src = f.read_text(encoding="utf-8")
        parts.append(f"// ---- {yrlib.namespace_for(f)} ----\n{src.rstrip()}\n\n")
        for i in infos:
            manifest_rules.append(
                {
                    "name": i.name,
                    "id": i.rule_id,
                    "version": int(i.meta.get("version", "0") or 0),
                    "purpose": i.purpose,
                    "status": i.status,
                    "scope": i.scope,
                    "mitre_attack": i.mitre,
                    "file": yrlib.namespace_for(f),
                    "source_sha256": sha256_bytes(src.encode("utf-8")),
                }
            )
    source = "".join(parts)

    # Compila o bundle inteiro (prova que a concatenação é válida) e serializa.
    compiler = yara_x.Compiler(relaxed_re_syntax=False, error_on_slow_pattern=False)
    compiler.add_source(source, origin=f"{name}.yar")
    rules = compiler.build()
    buf = io.BytesIO()
    rules.serialize_into(buf)

    (out_dir / f"{name}.yar").write_text(source, encoding="utf-8")
    (out_dir / f"{name}.yarc").write_bytes(buf.getvalue())
    return {"name": name, "purposes": list(purposes), "rules": manifest_rules}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", default=None, help="ex.: v1.2.0 (default: git describe)")
    ap.add_argument("--out", type=Path, default=yrlib.REPO_ROOT / "dist")
    ap.add_argument("--rules", type=Path, default=yrlib.RULES_DIR)
    args = ap.parse_args(argv)

    version = args.version or git_version()
    files = yrlib.rule_files(args.rules)
    if not files:
        print("nenhuma regra", file=sys.stderr)
        return 1
    args.out.mkdir(parents=True, exist_ok=True)

    bundles = [build_bundle(name, purposes, files, version, args.out) for name, purposes in BUNDLES.items()]
    manifest = {
        "schema": 1,
        "version": version,
        "generated": int(time.time()),
        "yara_x": pkg_version("yara-x"),
        "bundles": bundles,
        "deprecated": [
            {"name": i.name, "id": i.rule_id, "file": yrlib.namespace_for(f)}
            for f in files
            for i in yrlib.parse_rule_infos(f)
            if i.status == "deprecated"
        ],
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    sums = []
    for p in sorted(args.out.iterdir()):
        if p.name == "SHA256SUMS" or not p.is_file():
            continue
        sums.append(f"{sha256_bytes(p.read_bytes())}  {p.name}")
    (args.out / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")

    for b in bundles:
        print(f"{b['name']:9s} {len(b['rules']):4d} regra(s)")
    print(f"versão {version} -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Varredura de memória com as regras de escopo `memory`/`both`.

Regras de arquivo (MZ no offset 0, filesize, pe.*) são cegas em memória: o
cabeçalho pode ter sido apagado, a imagem está mapeada por seções e o que era
cifrado em disco está em claro. Este script só compila as regras que declaram
`scope = "memory"` ou `"both"` e sai em JSONL nativo ou ECS, como o hunt.py.

Backends:
  raw   bytes brutos (VAD dump, procdump, `vol windows.memmap --dump`, região
        extraída): YARA-X direto, em chunks com sobreposição.
  vol3  imagem completa via Volatility 3 (`vol -r json ... yarascan`), que já
        usa YARA-X quando o módulo está instalado. Precisa do OS detectado
        (symbol tables); `windows.vadyarascan.VadYaraScan` dá PID/processo.
  auto  tenta vol3; se o Volatility não reconhecer a imagem, cai para raw.

Uso:
    python scripts/memscan.py proc_1234.dmp --jsonl hits.jsonl --format ecs
    python scripts/memscan.py memory.raw --backend vol3 --plugin windows.vadyarascan.VadYaraScan
    python scripts/memscan.py region.bin --backend raw -s
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import yara_x

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yrlib
from hunt import to_ecs

MEMORY_SCOPES = ("memory", "both")
DEFAULT_CHUNK = 64 << 20
DEFAULT_OVERLAP = 1 << 20
VOL_PLUGINS = ("yarascan.YaraScan", "windows.vadyarascan.VadYaraScan", "linux.yarascan.YaraScan")


# ---------------------------------------------------------------- regras


def memory_sources(root: Path = yrlib.RULES_DIR, scopes: tuple[str, ...] = MEMORY_SCOPES) -> dict[str, str]:
    """Fonte por namespace só com as regras de escopo de memória."""
    return yrlib.subset_source(yrlib.rule_files(root), lambda i: i.scope in scopes)


def load_memory_rules(
    root: Path = yrlib.RULES_DIR, scopes: tuple[str, ...] = MEMORY_SCOPES
) -> tuple[yara_x.Rules, dict[str, yrlib.RuleInfo]]:
    sources = memory_sources(root, scopes)
    if not sources:
        sys.exit(f'nenhuma regra com scope em {list(scopes)} em {root}; marque scope = "memory" nas regras de memória')
    c = yrlib.new_compiler(strict=False)
    for ns, src in sources.items():
        c.new_namespace(ns)
        c.add_source(src, origin=ns)
    rules = c.build()
    index = {i.name: i for i in yrlib.index_rules(yrlib.rule_files(root)).values() if i.scope in scopes}
    return rules, index


def write_combined_source(sources: dict[str, str], path: Path) -> None:
    """Um único .yar para passar ao Volatility (que recebe um arquivo, não namespaces)."""
    imports: set[str] = set()
    bodies: list[str] = []
    for ns, src in sources.items():
        lines = src.splitlines()
        imports.update(ln for ln in lines if ln.startswith("import "))
        body = "\n".join(ln for ln in lines if not ln.startswith("import "))
        bodies.append(f"// ---- {ns} ----\n{body.strip()}\n")
    path.write_text("\n".join(sorted(imports)) + "\n\n" + "\n".join(bodies), encoding="utf-8")


# ---------------------------------------------------------------- backend raw


def scan_raw(
    path: Path,
    rules: yara_x.Rules,
    *,
    chunk: int = DEFAULT_CHUNK,
    overlap: int = DEFAULT_OVERLAP,
    timeout: int = 120,
) -> list[dict[str, Any]]:
    """Escaneia o arquivo em janelas sobrepostas; um match é identificado por
    (regra, string, offset absoluto), então o que cai na sobreposição conta uma vez.
    Matches maiores que `overlap` que cruzam a borda podem ser perdidos."""
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(timeout)
    seen: set[tuple[str, str, int]] = set()
    hits: list[dict[str, Any]] = []
    size = path.stat().st_size
    with path.open("rb") as fh:
        pos = 0
        while pos < size:
            fh.seek(pos)
            data = fh.read(chunk)
            if not data:
                break
            try:
                result = scanner.scan(data)
            except yara_x.TimeoutError:
                print(f"TIMEOUT {path} @0x{pos:x}", file=sys.stderr)
                result = None
            if result is not None:
                for m in result.matching_rules:
                    for p in m.patterns:
                        for mt in p.matches:
                            key = (m.identifier, p.identifier, pos + mt.offset)
                            if key in seen:
                                continue
                            seen.add(key)
                            hits.append(
                                {
                                    "rule": m.identifier,
                                    "pattern": p.identifier,
                                    "offset": pos + mt.offset,
                                    "length": mt.length,
                                    "value": data[mt.offset : mt.offset + min(mt.length, 48)].hex(),
                                }
                            )
            if pos + len(data) >= size:
                break
            pos += max(1, len(data) - overlap)
    return hits


# ---------------------------------------------------------------- backend vol3


def vol_command() -> list[str] | None:
    exe = shutil.which("vol") or shutil.which("vol3")
    return [exe] if exe else None


def parse_vol_json(text: str) -> list[dict[str, Any]]:
    """Converte a saída `-r json` do yarascan/vadyarascan em hits normalizados.

    Colunas: Offset, Rule (`namespace.nome` com YARA-X), Component, Value e,
    no vadyarascan, PID e Process."""
    rows = json.loads(text) if text.strip() else []
    hits: list[dict[str, Any]] = []
    stack = list(rows)
    while stack:
        row = stack.pop()
        stack.extend(row.get("__children", []))
        rule = str(row.get("Rule", ""))
        if not rule:
            continue
        value = row.get("Value", "")
        hits.append(
            {
                "rule": rule.rsplit(".", 1)[-1],
                "pattern": row.get("Component"),
                "offset": int(row.get("Offset", 0)),
                "length": None,
                "value": value if isinstance(value, str) else str(value),
                "pid": row.get("PID"),
                "process": row.get("Process"),
            }
        )
    hits.sort(key=lambda h: (h["offset"], h["rule"]))
    return hits


def scan_vol3(path: Path, sources: dict[str, str], *, plugin: str, extra: list[str]) -> list[dict[str, Any]]:
    cmd = vol_command()
    if cmd is None:
        raise RuntimeError("Volatility 3 (`vol`) não encontrado no PATH; pip install volatility3")
    with tempfile.TemporaryDirectory(prefix="memscan-") as tmp:
        rules_file = Path(tmp) / "memory.yar"
        write_combined_source(sources, rules_file)
        argv = [*cmd, "-q", "-r", "json", "-f", str(path), plugin, "--yara-file", str(rules_file), *extra]
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)  # nosec B603
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout).strip()
        if "Unsatisfied requirement" in err or "Unable to validate the plugin requirements" in err:
            raise LookupError(err)
        raise RuntimeError(err.splitlines()[-1] if err else f"vol saiu com {proc.returncode}")
    return parse_vol_json(proc.stdout)


# ---------------------------------------------------------------- CLI


def sha256_file(path: Path, limit: int) -> str | None:
    if path.stat().st_size > limit:
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("images", nargs="+", type=Path, help="dumps de processo/região ou imagens de memória")
    ap.add_argument("--backend", choices=("auto", "raw", "vol3"), default="auto")
    ap.add_argument(
        "--plugin", default="windows.vadyarascan.VadYaraScan", help=f"plugin do vol3; ex.: {', '.join(VOL_PLUGINS)}"
    )
    ap.add_argument("--vol-arg", action="append", default=[], help="argumento extra para o vol (repetível)")
    ap.add_argument("--rules", type=Path, default=yrlib.RULES_DIR)
    ap.add_argument("--scope", choices=MEMORY_SCOPES, action="append", help="restringir (default: memory e both)")
    ap.add_argument("--chunk", type=yrlib.parse_size, default=str(DEFAULT_CHUNK))
    ap.add_argument("--overlap", type=yrlib.parse_size, default=str(DEFAULT_OVERLAP))
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--hash-limit", type=yrlib.parse_size, default="2GB", help="não calcular sha256 acima disso")
    ap.add_argument("-s", "--strings", action="store_true", help="imprimir string casada + offset")
    ap.add_argument("--jsonl", type=Path)
    ap.add_argument("--format", choices=("native", "ecs"), default="native")
    args = ap.parse_args(argv)

    scopes = tuple(args.scope) if args.scope else MEMORY_SCOPES
    rules, index = load_memory_rules(args.rules, scopes)
    sources = memory_sources(args.rules, scopes)
    print(f"{len(index)} regra(s) de memória: {', '.join(sorted(index))}", file=sys.stderr)

    out = args.jsonl.open("a", encoding="utf-8") if args.jsonl else None
    n_hits = 0
    for image in args.images:
        backend = args.backend
        hits: list[dict[str, Any]] = []
        if backend in ("auto", "vol3"):
            try:
                hits = scan_vol3(image, sources, plugin=args.plugin, extra=args.vol_arg)
                backend = "vol3"
            except LookupError as e:
                if args.backend == "vol3":
                    print(f"vol3 não reconheceu {image}: {e}", file=sys.stderr)
                    return 2
                print(f"::notice::vol3 não reconheceu {image} como imagem com OS; usando backend raw", file=sys.stderr)
                backend = "raw"
            except RuntimeError as e:
                if args.backend == "vol3":
                    print(str(e), file=sys.stderr)
                    return 2
                print(f"::notice::{e}; usando backend raw", file=sys.stderr)
                backend = "raw"
        if backend == "raw":
            hits = scan_raw(image, rules, chunk=args.chunk, overlap=args.overlap, timeout=args.timeout)

        sha = sha256_file(image, args.hash_limit) if backend == "raw" else None
        by_rule: dict[tuple[str, Any], list[dict[str, Any]]] = {}
        for h in hits:
            by_rule.setdefault((h["rule"], h.get("pid")), []).append(h)
        for (rule, pid), group in sorted(by_rule.items(), key=lambda kv: (kv[0][0], str(kv[0][1]))):
            info = index.get(rule)
            n_hits += 1
            rec: dict[str, Any] = {
                "ts": int(time.time()),
                "rule": rule,
                "rule_id": info.rule_id if info else None,
                "purpose": info.purpose if info else None,
                "scope": info.scope if info else None,
                "malware": info.meta.get("malware") if info else None,
                "severity": info.meta.get("severity") if info else None,
                "mitre_attack": info.mitre if info else [],
                "file": str(image),
                "size": image.stat().st_size,
                "sha256": sha,
                "backend": backend,
                "dataset": "yara.memscan",
                "provider": "volatility3+yara-x" if backend == "vol3" else "yara-x",
                "offset": min(h["offset"] for h in group),
                "pid": pid,
                "process": group[0].get("process"),
                "matches": [
                    {"id": h["pattern"], "offset": h["offset"], "len": h.get("length"), "value": h.get("value")}
                    for h in sorted(group, key=lambda h: h["offset"])
                ],
            }
            where = f" pid={pid} ({group[0].get('process')})" if pid is not None else ""
            print(
                f"{rule} [{rec['purpose']}/{rec['scope']}] {image}{where}  @0x{rec['offset']:x}  {len(group)} string(s)"
            )
            if args.strings:
                for h in sorted(group, key=lambda h: h["offset"]):
                    print(f"    0x{h['offset']:x}:{h['pattern']}: {h.get('value')}")
            if out:
                doc = to_ecs(rec, info) if args.format == "ecs" else rec
                out.write(json.dumps(doc, ensure_ascii=False) + "\n")
    if out:
        out.close()
    print(f"\n{len(args.images)} imagem(ns), {n_hits} hit(s) (regra × processo)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

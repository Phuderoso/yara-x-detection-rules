#!/usr/bin/env python3
"""Relatório de uma rodada: hits no corpus + resultado das fixtures + tempo por regra.

É a unidade de comparação da CI: roda no branch base e no branch do PR e
`scripts/diff_report.py` compara os dois (hits novos/removidos, regressão de
tempo, mudanças nas fixtures).

Medição de tempo: os bindings do YARA-X não expõem profiling por regra (o
`yr --profiling` exige build com a feature `rules-profiling`). A alternativa
aqui é compilar cada ARQUIVO de regra isoladamente e cronometrar o scan dele
sobre o corpus inteiro. Com uma regra por arquivo (convenção do repo) isso é
tempo por regra. Cada arquivo do corpus é lido do disco uma única vez.

Uso:
    python scripts/report.py --corpus /usr/bin --out head.json
    python scripts/report.py --rules ../base/rules --corpus /usr/bin --out base.json
    python scripts/report.py --no-fixtures --corpus C:\\Windows\\System32 --out win.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import yara_x

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yrlib


def git_info(repo: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, cmd in (("sha", ["rev-parse", "HEAD"]), ("ref", ["rev-parse", "--abbrev-ref", "HEAD"])):
        try:
            out[key] = yrlib.git(*cmd, repo=repo).strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            out[key] = ""
    return out


def run_fixtures(rules: yara_x.Rules) -> dict[str, Any]:
    tests_dir = yrlib.REPO_ROOT / "tests"
    sys.path.insert(0, str(tests_dir))
    from cases import CASES

    results: dict[str, Any] = {}
    for case in CASES:
        data = case.build()
        matched = sorted(m.identifier for m in rules.scan(data).matching_rules)
        results[case.name] = {
            "matched": matched,
            "expect_match": sorted(case.expect_match),
            "expect_no_match": sorted(case.expect_no_match),
            "ok": all(r in matched for r in case.expect_match) and not any(r in matched for r in case.expect_no_match),
        }
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", type=Path, default=yrlib.RULES_DIR, help="diretório de regras (default: rules/)")
    ap.add_argument("--corpus", type=Path, nargs="*", default=[], help="diretórios/arquivos do corpus limpo")
    ap.add_argument("--max-size", default=yrlib.CONFIG.get("goodware", {}).get("max_file_size", "32MB"))
    ap.add_argument(
        "--timeout", type=int, default=int(yrlib.CONFIG.get("goodware", {}).get("scan_timeout_seconds", 30))
    )
    ap.add_argument("--no-fixtures", action="store_true", help="não rodar tests/cases.py")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--label", default="", help="rótulo livre (ex.: base, head)")
    ap.add_argument(
        "--status", type=yrlib.parse_statuses, default=(), help='só regras com estes status, ex.: "stable,test"'
    )
    args = ap.parse_args(argv)

    max_size = yrlib.parse_size(args.max_size)
    files = yrlib.filter_files_by_status(yrlib.rule_files(args.rules), args.status) if args.rules.exists() else []
    if not files:
        # Branch base sem regras (repo novo) ainda precisa de um relatório para o diff.
        print(f"::notice::nenhuma regra em {args.rules}; gerando relatório vazio")
        empty: dict[str, Any] = {
            "schema": 1,
            "label": args.label,
            "generated": int(time.time()),
            "platform": platform.platform(),
            "git": git_info(args.rules if args.rules.exists() else yrlib.REPO_ROOT),
            "filter": {"status": list(args.status)},
            "rules": {},
            "corpus": {"paths": [str(p) for p in args.corpus], "files": 0, "bytes": 0, "wall_seconds": 0},
            "timings": {},
            "hits": [],
            "fixtures": {},
        }
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(empty, indent=2), encoding="utf-8")
        return 0
    index = yrlib.index_rules(files)

    all_rules, _w, errors = yrlib.compile_rules(files, strict=False)
    if errors:
        for e in errors:
            print(e["text"], file=sys.stderr)
        return 1

    # Um scanner por arquivo de regra, para cronometrar isoladamente.
    per_file: list[tuple[str, yara_x.Scanner, list[str]]] = []
    for f in files:
        ns = (
            yrlib.namespace_for(f)
            if f.is_relative_to(yrlib.RULES_DIR)
            else str(f.relative_to(args.rules)).replace("\\", "/")
        )
        sc = yara_x.Scanner(yrlib.compile_file(f))
        sc.set_timeout(args.timeout)
        per_file.append((ns, sc, [i.name for i in yrlib.parse_rule_infos(f)]))

    timings: dict[str, dict[str, Any]] = {
        ns: {"seconds": 0.0, "rules": names, "timeouts": 0} for ns, _sc, names in per_file
    }
    hits: list[dict[str, Any]] = []
    n_files = n_bytes = 0
    t_start = time.perf_counter()

    for path in yrlib.iter_files(args.corpus, max_size=max_size):
        data = yrlib.read_file(path)
        if data is None:
            continue
        n_files += 1
        n_bytes += len(data)
        sha256: str | None = None
        for ns, sc, _names in per_file:
            t0 = time.perf_counter()
            try:
                res = sc.scan(data)
            except yara_x.TimeoutError:
                timings[ns]["timeouts"] += 1
                timings[ns]["seconds"] += time.perf_counter() - t0
                continue
            timings[ns]["seconds"] += time.perf_counter() - t0
            for m in res.matching_rules:
                if sha256 is None:
                    sha256 = hashlib.sha256(data).hexdigest()
                info = index.get(m.identifier)
                hits.append(
                    {
                        "rule": m.identifier,
                        "purpose": info.purpose if info else "hunting",
                        "file": str(path),
                        "sha256": sha256,
                        "size": len(data),
                        "strings": sorted({p.identifier for p in m.patterns if p.matches}),
                    }
                )

    for t in timings.values():
        t["seconds"] = round(t["seconds"], 4)

    report: dict[str, Any] = {
        "schema": 1,
        "label": args.label,
        "generated": int(time.time()),
        "platform": platform.platform(),
        "git": git_info(args.rules),
        "filter": {"status": list(args.status)},
        "rules": {
            name: {
                "id": info.rule_id,
                "purpose": info.purpose,
                "status": info.status,
                "version": info.meta.get("version"),
            }
            for name, info in index.items()
        },
        "corpus": {
            "paths": [str(p) for p in args.corpus],
            "files": n_files,
            "bytes": n_bytes,
            "wall_seconds": round(time.perf_counter() - t_start, 2),
        },
        "timings": timings,
        "hits": sorted(hits, key=lambda h: (h["rule"], h["file"])),
        "fixtures": {} if args.no_fixtures else run_fixtures(all_rules),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(
        f"{n_files} arquivo(s) ({yrlib.human_size(n_bytes)}), {len(hits)} hit(s), "
        f"{len(per_file)} arquivo(s) de regra, {report['corpus']['wall_seconds']}s -> {args.out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

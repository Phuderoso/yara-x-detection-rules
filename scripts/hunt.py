#!/usr/bin/env python3
"""Varredura de hunting: escaneia caminhos com todas as regras do repo e
emite um registro por hit, pronto para enriquecimento (hash → VT/sandbox →
identidade → timeline).

Diferente do `yr scan`, já sai com sha256, purpose da regra e as strings que
casaram (com offset), em texto ou JSON Lines. Com `--format ecs` o JSON segue
o Elastic Common Schema (file.hash.sha256, rule.name, rule.id,
threat.technique.id, ...) para ingestão direta em SIEM.

Uso:
    python scripts/hunt.py /evidence/2026 --jsonl hits.jsonl
    python scripts/hunt.py /evidence/2026 --jsonl hits.ndjson --format ecs
    python scripts/hunt.py sample.bin -s          # mostrar strings + offsets
    python scripts/hunt.py dump.dmp --max-size 4GB
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yara_x

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yrlib
from scan_goodware import parse_size

# ECS event.severity é numérico e livre; mapeamos a escala do repo para faixas 0-99.
SEVERITY_SCORE = {"low": 21, "medium": 47, "high": 73, "critical": 99}


def to_ecs(rec: dict[str, Any], info: yrlib.RuleInfo | None) -> dict[str, Any]:
    """Converte um registro nativo do hunt.py para um documento ECS 8.x."""
    meta = info.meta if info else {}
    ts = datetime.fromtimestamp(rec["ts"], tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    in_memory = "offset" in rec
    doc: dict[str, Any] = {
        "@timestamp": ts,
        "ecs": {"version": "8.11.0"},
        "event": {
            "kind": "alert",
            "category": ["malware", "process"] if in_memory else ["malware", "file"],
            "type": ["info"],
            "module": "yara",
            "dataset": rec.get("dataset", "yara.hunt"),
            "provider": rec.get("provider", "yara-x"),
        },
        "file": {
            "path": rec["file"],
            "name": Path(rec["file"]).name,
        },
        "rule": {
            "name": rec["rule"],
            "ruleset": info.path.parent.name if info else None,
            "category": rec.get("purpose"),
        },
        "yara": {
            "purpose": rec.get("purpose"),
            "scope": info.scope if info else None,
            "strings": rec.get("matches", []),
        },
    }
    if rec.get("size") is not None:
        doc["file"]["size"] = rec["size"]
    if rec.get("sha256"):
        doc["file"]["hash"] = {"sha256": rec["sha256"]}
    if in_memory:
        doc["yara"]["memory"] = {"offset": rec["offset"], "backend": rec.get("backend")}
        if rec.get("pid") is not None:
            doc["process"] = {"pid": rec["pid"], "name": rec.get("process")}
    if info:
        doc["rule"].update(
            {
                "id": info.rule_id,
                "version": meta.get("version"),
                "author": meta.get("author"),
                "description": meta.get("description"),
                "reference": meta.get("reference"),
            }
        )
        doc["rule"] = {k: v for k, v in doc["rule"].items() if v is not None}
        threat: dict[str, Any] = {"framework": "MITRE ATT&CK", "technique": {"id": info.mitre}}
        if meta.get("malware"):
            threat["software"] = {"name": meta["malware"]}
        doc["threat"] = threat
        sev = meta.get("severity")
        if sev in SEVERITY_SCORE:
            doc["event"]["severity"] = SEVERITY_SCORE[sev]
    return doc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("-s", "--strings", action="store_true", help="imprimir strings casadas com offset")
    ap.add_argument("--max-size", type=parse_size, default="256MB")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--purpose", choices=yrlib.PURPOSES, action="append", help="só regras com esse purpose (repetível)")
    ap.add_argument("--jsonl", type=Path, help="gravar hits em JSON Lines")
    ap.add_argument("--format", choices=("native", "ecs"), default="native", help="esquema do JSON (default native)")
    ap.add_argument(
        "--record-activity",
        action="store_true",
        help="marcar last_match=hoje em tests/activity.json para as regras que casaram (alimenta docs/health.md)",
    )
    args = ap.parse_args(argv)

    rules, index = yrlib.load_all_rules(strict=False)
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(args.timeout)

    out = args.jsonl.open("a", encoding="utf-8") if args.jsonl else None
    n_files = n_hits = 0
    matched_rules: set[str] = set()

    for path in yrlib.iter_files(args.paths, max_size=args.max_size):
        data = yrlib.read_file(path)
        if data is None:
            continue
        n_files += 1
        try:
            result = scanner.scan(data)
        except yara_x.TimeoutError:
            print(f"TIMEOUT {path}", file=sys.stderr)
            continue
        if not result.matching_rules:
            continue
        sha256 = hashlib.sha256(data).hexdigest()
        for m in result.matching_rules:
            info = index.get(m.identifier)
            if args.purpose and (info is None or info.purpose not in args.purpose):
                continue
            n_hits += 1
            matched_rules.add(m.identifier)
            spans: list[tuple[str, int, int]] = [
                (p.identifier, mt.offset, mt.length) for p in m.patterns for mt in p.matches
            ]
            rec: dict[str, Any] = {
                "ts": int(time.time()),
                "rule": m.identifier,
                "rule_id": info.rule_id if info else None,
                "purpose": info.purpose if info else None,
                "malware": info.meta.get("malware") if info else None,
                "severity": info.meta.get("severity") if info else None,
                "mitre_attack": info.mitre if info else [],
                "file": str(path),
                "size": len(data),
                "sha256": sha256,
                "matches": [{"id": i, "offset": o, "len": n} for i, o, n in spans],
            }
            print(f"{m.identifier} [{rec['purpose']}] {path}  sha256={sha256}")
            if args.strings:
                for ident, offset, length in spans:
                    snippet = data[offset : offset + min(length, 48)]
                    print(f"    0x{offset:x}:{ident}: {snippet!r}")
            if out:
                doc = to_ecs(rec, info) if args.format == "ecs" else rec
                out.write(json.dumps(doc, ensure_ascii=False) + "\n")

    if out:
        out.close()
    if args.record_activity and matched_rules:
        n = yrlib.record_activity(matched_rules, "hunt")
        print(f"activity: {n} regra(s) atualizada(s) em {yrlib.ACTIVITY_PATH.name}", file=sys.stderr)
    print(f"\n{n_files} arquivo(s), {n_hits} hit(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Gera o CHANGELOG de uma release a partir do git.

Duas fontes, porque commits sozinhos não dizem o que mudou nas regras:
  1. diff de rules/ entre a tag anterior e HEAD: regras adicionadas, removidas,
     atualizadas (com version antiga → nova) e mudanças de status/purpose;
  2. commits no intervalo, agrupados por prefixo convencional
     (feat, fix, rule, ci, docs, chore, ...).

Uso:
    python scripts/changelog.py --version v1.2.0 [--since v1.1.0] [--out dist/CHANGELOG.md]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yrlib

GROUPS = [
    ("rule", "Regras"),
    ("feat", "Funcionalidades"),
    ("fix", "Correções"),
    ("perf", "Performance"),
    ("ci", "CI"),
    ("docs", "Documentação"),
    ("test", "Testes"),
    ("chore", "Manutenção"),
]
PREFIX_RE = re.compile(r"^(\w+)(?:\([^)]*\))?!?:\s*(.+)$")


git = yrlib.git


def previous_tag(head: str) -> str | None:
    try:
        return git("describe", "--tags", "--abbrev=0", f"{head}^").strip() or None
    except subprocess.CalledProcessError:
        return None


def rules_at(rev: str) -> dict[str, yrlib.RuleInfo]:
    """Índice de regras num revision, lendo os arquivos via `git show`."""
    try:
        listing = git("ls-tree", "-r", "--name-only", rev, "--", "rules/").split()
    except subprocess.CalledProcessError:
        return {}
    index: dict[str, yrlib.RuleInfo] = {}
    with tempfile.TemporaryDirectory() as td:
        for rel in listing:
            name = Path(rel).name
            if not rel.endswith((".yar", ".yara")) or name.startswith("_"):
                continue
            content = git("show", f"{rev}:{rel}")
            tmp = Path(td) / rel.replace("/", "__")
            tmp.write_text(content, encoding="utf-8")
            for info in yrlib.parse_rule_infos(tmp):
                info.path = Path(rel)
                index[info.name] = info
    return index


def rules_section(prev: str | None, head: str) -> list[str]:
    new = rules_at(head)
    old = rules_at(prev) if prev else {}
    lines: list[str] = []
    for name in sorted(set(new) - set(old)):
        i = new[name]
        lines.append(
            f"- adicionada `{name}` v{i.meta.get('version', '?')} ({i.purpose}, {i.status}) — {i.meta.get('description', '')}"
        )
    for name in sorted(set(old) - set(new)):
        lines.append(f"- removida `{name}`")
    for name in sorted(set(old) & set(new)):
        o, n = old[name], new[name]
        changes = []
        if o.meta.get("version") != n.meta.get("version"):
            changes.append(f"v{o.meta.get('version', '?')} → v{n.meta.get('version', '?')}")
        if o.status != n.status:
            changes.append(f"status {o.status} → {n.status}")
        if o.purpose != n.purpose:
            changes.append(f"purpose {o.purpose} → {n.purpose}")
        if changes:
            lines.append(f"- atualizada `{name}`: " + ", ".join(changes))
    return lines


def commits_section(prev: str | None, head: str) -> list[str]:
    rng = f"{prev}..{head}" if prev else head
    try:
        raw = git("log", "--no-merges", "--format=%h%x09%s", rng)
    except subprocess.CalledProcessError:
        return []
    grouped: dict[str, list[str]] = {}
    for line in raw.splitlines():
        sha, _, subject = line.partition("\t")
        m = PREFIX_RE.match(subject)
        key, text = (m.group(1).lower(), m.group(2)) if m else ("other", subject)
        grouped.setdefault(key, []).append(f"- {text} (`{sha}`)")
    lines: list[str] = []
    for key, title in GROUPS:
        if key in grouped:
            lines.append(f"\n#### {title}\n")
            lines.extend(grouped.pop(key))
    rest = [item for items in grouped.values() for item in items]
    if rest:
        lines.append("\n#### Outros\n")
        lines.extend(rest)
    return lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", required=True)
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--since", help="tag/commit anterior (default: tag anterior ao head)")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)

    prev = args.since or previous_tag(args.head)
    date = git("log", "-1", "--format=%cs", args.head).strip()
    md = [f"## {args.version} ({date})\n"]
    md.append(f"Comparado com `{prev}`." if prev else "Primeira release.")
    rules = rules_section(prev, args.head)
    md.append("\n### Regras\n")
    md.extend(rules or ["- sem mudanças em rules/"])
    md.append("\n### Commits\n")
    md.extend(commits_section(prev, args.head) or ["- nenhum"])
    text = "\n".join(md) + "\n"
    print(text)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

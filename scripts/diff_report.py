#!/usr/bin/env python3
"""Compara dois relatórios de scripts/report.py (base vs PR) e aplica o orçamento
de performance de rules-ci.toml.

Saída: Markdown (stdout, --out, e/ou $GITHUB_STEP_SUMMARY) com:
  - hits novos e removidos no corpus, por regra (com sha256 para reproduzir);
  - tempo por arquivo de regra, base vs head, com % de variação;
  - fixtures que mudaram de resultado;
  - regras adicionadas/removidas.

Exit 1 se: alguma regra exceder `max_rule_seconds`, regredir mais que
`max_regression_pct` (só quando acima de `regression_floor_seconds`, para
ignorar ruído), ou (com --fail-on-new-hits) houver hit novo em regra
triage/blocking.

Uso:
    python scripts/diff_report.py --head head.json [--base base.json] [--out diff.md] [--fail-on-new-hits]
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

PERF = yrlib.CONFIG.get("performance", {})
MAX_RULE_SECONDS = float(PERF.get("max_rule_seconds", 20.0))
MAX_REGRESSION_PCT = float(PERF.get("max_regression_pct", 50.0))
REGRESSION_FLOOR = float(PERF.get("regression_floor_seconds", 1.0))


def _hit_key(h: dict[str, Any]) -> tuple[str, str]:
    return (h["rule"], h["sha256"])


def _group(hits: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for h in hits:
        out.setdefault(h["rule"], []).append(h)
    return out


def _fmt_pct(base: float, head: float) -> str:
    if base <= 0:
        return "n/a"
    return f"{(head - base) / base * 100:+.0f}%"


def build_markdown(head: dict[str, Any], base: dict[str, Any] | None, fail_on_new_hits: bool) -> tuple[str, list[str]]:
    failures: list[str] = []
    md: list[str] = []
    md.append("## Relatório de regras\n")
    corpus = head.get("corpus", {})
    md.append(
        f"Corpus: {corpus.get('files', 0)} arquivo(s), {yrlib.human_size(corpus.get('bytes', 0))}, "
        f"{corpus.get('wall_seconds', 0)}s · head `{head.get('git', {}).get('sha', '')[:12]}`"
        + (f" · base `{base.get('git', {}).get('sha', '')[:12]}`" if base else "")
        + "\n"
    )

    # ---- Regras adicionadas / removidas ----
    head_rules = set(head.get("rules", {}))
    base_rules = set(base.get("rules", {})) if base else set()
    if base is not None and (head_rules ^ base_rules):
        md.append("### Regras\n")
        for r in sorted(head_rules - base_rules):
            md.append(f"- adicionada: `{r}` ({head['rules'][r].get('purpose')}, {head['rules'][r].get('status')})")
        for r in sorted(base_rules - head_rules):
            md.append(f"- removida: `{r}`")
        md.append("")

    # ---- Hits ----
    head_hits = {_hit_key(h): h for h in head.get("hits", [])}
    base_hits = {_hit_key(h): h for h in base.get("hits", [])} if base else {}
    new_hits = [head_hits[k] for k in head_hits.keys() - base_hits.keys()]
    gone_hits = [base_hits[k] for k in base_hits.keys() - head_hits.keys()]

    md.append("### Hits no corpus limpo\n")
    if not head_hits and not gone_hits:
        md.append("Nenhum hit. FP gate ok.\n")
    else:
        md.append("| Regra | purpose | base | head | novos | removidos |")
        md.append("|---|---|---:|---:|---:|---:|")
        all_rules = sorted({h["rule"] for h in [*head_hits.values(), *base_hits.values()]})
        gh, gb = _group(list(head_hits.values())), _group(list(base_hits.values()))
        gn, gg = _group(new_hits), _group(gone_hits)
        for r in all_rules:
            purpose = head.get("rules", {}).get(r, {}).get("purpose") or (gb.get(r) or gh.get(r) or [{}])[0].get(
                "purpose", "?"
            )
            md.append(
                f"| `{r}` | {purpose} | {len(gb.get(r, []))} | {len(gh.get(r, []))} | {len(gn.get(r, []))} | {len(gg.get(r, []))} |"
            )
        md.append("")
        if new_hits:
            md.append("<details><summary>Hits novos (arquivo · sha256 · strings)</summary>\n")
            for h in sorted(new_hits, key=lambda h: (h["rule"], h["file"]))[:200]:
                md.append(f"- `{h['rule']}` · `{h['file']}` · `{h['sha256']}` · {', '.join(h['strings']) or '-'}")
                if fail_on_new_hits and h.get("purpose") in ("triage", "blocking"):
                    failures.append(f"hit novo em regra {h['purpose']}: {h['rule']} em {h['file']}")
            if len(new_hits) > 200:
                md.append(f"- … e mais {len(new_hits) - 200}")
            md.append("\n</details>\n")
        if gone_hits:
            md.append("<details><summary>Hits removidos</summary>\n")
            for h in sorted(gone_hits, key=lambda h: (h["rule"], h["file"]))[:200]:
                md.append(f"- `{h['rule']}` · `{h['file']}` · `{h['sha256']}`")
            md.append("\n</details>\n")

    # ---- Performance ----
    md.append("### Performance por arquivo de regra\n")
    md.append(
        f"Orçamento: máx. {MAX_RULE_SECONDS:.0f}s por regra; regressão máx. {MAX_REGRESSION_PCT:.0f}% acima de {REGRESSION_FLOOR:.1f}s.\n"
    )
    md.append("| Arquivo | regras | base (s) | head (s) | Δ | status |")
    md.append("|---|---|---:|---:|---:|---|")
    ht, bt = head.get("timings", {}), (base.get("timings", {}) if base else {})
    for ns in sorted(ht):
        hs = float(ht[ns]["seconds"])
        bs = float(bt.get(ns, {}).get("seconds", 0.0)) if ns in bt else None
        status = "ok"
        if ht[ns].get("timeouts"):
            status = f"{ht[ns]['timeouts']} timeout(s)"
            failures.append(f"{ns}: {ht[ns]['timeouts']} timeout(s) no corpus")
        if hs > MAX_RULE_SECONDS:
            status = "acima do orçamento"
            failures.append(f"{ns}: {hs:.2f}s > {MAX_RULE_SECONDS}s")
        elif bs is not None and bs > 0 and hs > REGRESSION_FLOOR and (hs - bs) / bs * 100 > MAX_REGRESSION_PCT:
            status = "regressão"
            failures.append(f"{ns}: {hs:.2f}s vs {bs:.2f}s ({_fmt_pct(bs, hs)})")
        md.append(
            f"| `{ns}` | {', '.join(ht[ns].get('rules', []))} | {'-' if bs is None else f'{bs:.2f}'} | {hs:.2f} | "
            f"{'-' if bs is None else _fmt_pct(bs, hs)} | {status} |"
        )
    md.append("")

    # ---- Fixtures ----
    hf, bf = head.get("fixtures", {}), (base.get("fixtures", {}) if base else {})
    if hf:
        bad = [c for c, r in hf.items() if not r.get("ok")]
        changed = [c for c in hf if c in bf and bf[c].get("matched") != hf[c].get("matched")]
        md.append("### Fixtures sintéticas\n")
        md.append(
            f"{len(hf)} caso(s), {len(bad)} falhando" + (f", {len(changed)} mudaram vs base" if base else "") + ".\n"
        )
        for c in bad:
            md.append(
                f"- FALHA `{c}`: matched={hf[c]['matched']} expect_match={hf[c]['expect_match']} expect_no_match={hf[c]['expect_no_match']}"
            )
            failures.append(f"fixture {c} falhou")
        for c in changed:
            md.append(f"- mudou `{c}`: {bf[c]['matched']} → {hf[c]['matched']}")
        md.append("")

    if failures:
        md.append("### Falhas\n")
        md.extend(f"- {f}" for f in failures)
        md.append("")
    return "\n".join(md), failures


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--head", type=Path, required=True)
    ap.add_argument("--base", type=Path)
    ap.add_argument("--out", type=Path, help="gravar o markdown aqui")
    ap.add_argument("--fail-on-new-hits", action="store_true", help="hit novo em triage/blocking falha")
    args = ap.parse_args(argv)

    head = json.loads(args.head.read_text(encoding="utf-8"))
    base = json.loads(args.base.read_text(encoding="utf-8")) if args.base and args.base.exists() else None
    md, failures = build_markdown(head, base, args.fail_on_new_hits)

    print(md)
    if args.out:
        args.out.write_text(md, encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(md + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

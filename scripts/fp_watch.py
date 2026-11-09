#!/usr/bin/env python3
"""Vigia de falso positivo: corpus reprodutível, comparação com a baseline e UMA issue.

Usado por .github/workflows/fp-watch.yml (semanal + manual), mas roda igual na mão.

Subcomandos:
  corpus    baixa as wheels de tests/goodware/pip-corpus.txt (fixadas por sha256) e
            descompacta em <out>/pip/. Junto com /usr/bin e /usr/lib do runner, é o
            corpus limpo. Nada é instalado nem executado.
  compare   lê o report.json (scripts/report.py --status stable,test) e a baseline
            versionada (tests/goodware/baseline.json): hit novo em regra triage/blocking,
            estouro do orçamento (rules-ci.toml) ou regressão de tempo = regressão.
            Hits novos em regra hunting são aviso. Escreve diff.json + diff.md.
  baseline  grava/atualiza a baseline a partir de um report: os hits atuais viram
            `known_fp` (FP conhecidos e aceitos), e `last_fp`/`fp_total` por regra
            alimentam docs/health.md.
  issue     abre OU atualiza uma única issue rotulada `fp-regression` com o diff.
            Idempotente: mesma regressão = nenhuma chamada de escrita; regressão
            mudou = edita o corpo; tudo limpo = comenta e fecha a issue aberta, uma vez.
            Só precisa do GITHUB_TOKEN padrão (issues: write).

Exemplos:
    python scripts/fp_watch.py corpus --out build/fp-corpus
    python scripts/report.py --status stable,test --no-fixtures --corpus /usr/bin build/fp-corpus/pip --out build/report.json
    python scripts/fp_watch.py compare --report build/report.json --out build/diff.json --markdown build/diff.md
    python scripts/fp_watch.py baseline --report build/report.json          # aceitar o estado atual
    python scripts/fp_watch.py issue --diff build/diff.json --markdown build/diff.md --repo owner/name
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yrlib

BASELINE_PATH = yrlib.REPO_ROOT / "tests" / "goodware" / "baseline.json"
PIP_CORPUS = yrlib.REPO_ROOT / "tests" / "goodware" / "pip-corpus.txt"
LABEL = "fp-regression"
MARKER = "<!-- fp-watch -->"
DIGEST_RE = "<!-- fp-watch:digest="
PIP_PLATFORM_ARGS = (
    "--only-binary=:all:",
    "--platform",
    "manylinux2014_x86_64",
    "--python-version",
    "3.12",
    "--implementation",
    "cp",
    "--abi",
    "cp312",
)
FAIL_PURPOSES = ("triage", "blocking")

Api = Callable[[str, str, dict[str, Any] | None], Any]


# ---------------------------------------------------------------- corpus


def build_pip_corpus(requirements: Path, out: Path, *, pip: list[str] | None = None) -> list[Path]:
    """`pip download --require-hashes` + unzip. Devolve os diretórios descompactados."""
    wheels = out / "wheels"
    wheels.mkdir(parents=True, exist_ok=True)
    cmd = [
        *(pip or [sys.executable, "-m", "pip"]),
        "download",
        "-q",
        "--no-deps",
        "--require-hashes",
        *PIP_PLATFORM_ARGS,
        "-r",
        str(requirements),
        "-d",
        str(wheels),
    ]
    subprocess.run(cmd, check=True)  # nosec B603 - argumentos fixos, sem shell
    unpacked: list[Path] = []
    for whl in sorted(wheels.glob("*.whl")):
        dest = out / "pip" / whl.stem
        if not dest.exists():
            with zipfile.ZipFile(whl) as zf:
                for member in zf.infolist():
                    # zip-slip: nunca escrever fora de dest
                    target = (dest / member.filename).resolve()
                    if not target.is_relative_to(dest.resolve()):
                        raise ValueError(f"caminho suspeito na wheel {whl.name}: {member.filename}")
                zf.extractall(dest)  # nosec B202 - membros validados acima
        unpacked.append(dest)
    return unpacked


# ---------------------------------------------------------------- compare


def _perf() -> dict[str, float]:
    cfg = yrlib.CONFIG.get("performance", {})
    return {
        "max_rule_seconds": float(cfg.get("max_rule_seconds", 20.0)),
        "max_regression_pct": float(cfg.get("max_regression_pct", 50.0)),
        "regression_floor_seconds": float(cfg.get("regression_floor_seconds", 1.0)),
    }


def empty_baseline() -> dict[str, Any]:
    return {"schema": 1, "generated": None, "corpus": {}, "rules": {}}


def load_baseline(path: Path = BASELINE_PATH) -> dict[str, Any]:
    if not path.exists():
        return empty_baseline()
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    data.setdefault("rules", {})
    data.setdefault("corpus", {})
    return data


def compare(report: dict[str, Any], baseline: dict[str, Any], *, manifest_sha256: str | None = None) -> dict[str, Any]:
    """Classifica o report contra a baseline. Puro: não lê disco."""
    perf = _perf()
    base_rules: dict[str, Any] = baseline.get("rules", {})
    rules_meta: dict[str, Any] = report.get("rules", {})

    known: dict[str, set[str]] = {
        name: {fp["sha256"] for fp in entry.get("known_fp", [])} for name, entry in base_rules.items()
    }
    seen: dict[str, set[str]] = {}
    new_hits: list[dict[str, Any]] = []
    hunting_hits: list[dict[str, Any]] = []
    for h in report.get("hits", []):
        rule = h["rule"]
        seen.setdefault(rule, set()).add(h["sha256"])
        if h["sha256"] in known.get(rule, set()):
            continue
        purpose = rules_meta.get(rule, {}).get("purpose") or h.get("purpose", "hunting")
        entry = {
            "rule": rule,
            "purpose": purpose,
            "file": h["file"],
            "sha256": h["sha256"],
            "strings": h.get("strings", []),
        }
        (new_hits if purpose in FAIL_PURPOSES else hunting_hits).append(entry)

    gone: list[dict[str, Any]] = []
    for rule, entry in base_rules.items():
        for fp in entry.get("known_fp", []):
            if fp["sha256"] not in seen.get(rule, set()):
                gone.append({"rule": rule, "file": fp.get("file", ""), "sha256": fp["sha256"]})

    budget: list[dict[str, Any]] = []
    regressions: list[dict[str, Any]] = []
    for ns, t in report.get("timings", {}).items():
        secs = float(t.get("seconds", 0.0))
        names = t.get("rules", [])
        if secs > perf["max_rule_seconds"]:
            budget.append({"file": ns, "rules": names, "seconds": secs, "max": perf["max_rule_seconds"]})
        base_secs = max((float(base_rules.get(n, {}).get("seconds", 0.0)) for n in names), default=0.0)
        if base_secs > 0 and secs > perf["regression_floor_seconds"] and base_secs > perf["regression_floor_seconds"]:
            pct = (secs - base_secs) / base_secs * 100.0
            if pct > perf["max_regression_pct"]:
                regressions.append(
                    {"file": ns, "rules": names, "seconds": secs, "baseline_seconds": base_secs, "pct": round(pct, 1)}
                )

    base_manifest = baseline.get("corpus", {}).get("manifest_sha256")
    corpus_changed = bool(manifest_sha256 and base_manifest and manifest_sha256 != base_manifest)

    return {
        "schema": 1,
        "regression": bool(new_hits or budget or regressions),
        "new_hits": sorted(new_hits, key=lambda h: (h["rule"], h["file"])),
        "hunting_hits": sorted(hunting_hits, key=lambda h: (h["rule"], h["file"])),
        "gone": sorted(gone, key=lambda h: (h["rule"], h["file"])),
        "budget": budget,
        "regressions": regressions,
        "corpus_changed": corpus_changed,
        "corpus": {
            "files": report.get("corpus", {}).get("files"),
            "paths": report.get("corpus", {}).get("paths", []),
            "manifest_sha256": manifest_sha256,
            "baseline_manifest_sha256": base_manifest,
        },
        "rules_checked": sorted(rules_meta),
        "report_label": report.get("label", ""),
        "report_git": report.get("git", {}),
        "baseline_generated": baseline.get("generated"),
    }


def _short(sha: str) -> str:
    return sha[:12]


def markdown(diff: dict[str, Any], *, run_url: str = "") -> str:
    out: list[str] = []
    w = out.append
    w(MARKER)
    status = "**REGRESSÃO**" if diff["regression"] else "limpo"
    w(f"# FP watch: {status}")
    w("")
    c = diff["corpus"]
    w(
        f"Corpus: {c.get('files')} arquivo(s) em `{'`, `'.join(c.get('paths', []))}`"
        + (f" · manifesto `{_short(c['manifest_sha256'])}`" if c.get("manifest_sha256") else "")
        + (" · **corpus mudou desde a baseline**" if diff["corpus_changed"] else "")
    )
    w(f"Regras verificadas (stable/test): {', '.join(f'`{r}`' for r in diff['rules_checked']) or 'nenhuma'}")
    if diff.get("baseline_generated"):
        w(f"Baseline: {diff['baseline_generated']}")
    if run_url:
        w(f"Run: {run_url}")
    w("")
    if diff["new_hits"]:
        w(f"## FP novo em regra triage/blocking ({len(diff['new_hits'])})")
        w("")
        w("| Regra | purpose | Arquivo | sha256 | strings |")
        w("|---|---|---|---|---|")
        for h in diff["new_hits"]:
            w(
                f"| `{h['rule']}` | {h['purpose']} | `{h['file']}` | `{_short(h['sha256'])}` | {', '.join(h['strings'])} |"
            )
        w("")
    if diff["budget"]:
        w(f"## Orçamento de tempo estourado ({len(diff['budget'])})")
        w("")
        for b in diff["budget"]:
            w(f"- `{b['file']}` ({', '.join(b['rules'])}): {b['seconds']:.2f}s > {b['max']:.1f}s")
        w("")
    if diff["regressions"]:
        w(f"## Regressão de tempo vs baseline ({len(diff['regressions'])})")
        w("")
        for r in diff["regressions"]:
            w(f"- `{r['file']}`: {r['baseline_seconds']:.2f}s → {r['seconds']:.2f}s (+{r['pct']}%)")
        w("")
    if diff["hunting_hits"]:
        w(f"## Aviso: hit novo em regra hunting ({len(diff['hunting_hits'])}, não falha)")
        w("")
        for h in diff["hunting_hits"]:
            w(f"- `{h['rule']}` em `{h['file']}` (`{_short(h['sha256'])}`; {', '.join(h['strings'])})")
        w("")
    if diff["gone"]:
        w(f"## FP conhecido que não apareceu ({len(diff['gone'])})")
        w("")
        w("Arquivo saiu do corpus ou a regra foi apertada. Se for definitivo, atualize a baseline.")
        for g in diff["gone"]:
            w(f"- `{g['rule']}`: `{g['file']}` (`{_short(g['sha256'])}`)")
        w("")
    if not diff["regression"] and not diff["hunting_hits"] and not diff["gone"]:
        w("Nenhum hit fora da baseline, nenhuma regra acima do orçamento.")
        w("")
    w("Como agir: para cada FP, `scripts/hunt.py -s` no arquivo mostra a string que casou; rebaixe-a")
    w("para contexto ou adicione exclusão, incremente `version`, e o próximo run fecha esta issue.")
    w("Para aceitar o estado atual como baseline: `make fp-baseline REPORT=build/report.json`.")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- baseline


def update_baseline(
    report: dict[str, Any],
    previous: dict[str, Any] | None,
    *,
    manifest_sha256: str | None = None,
    today: dt.date | None = None,
) -> dict[str, Any]:
    """Hits atuais viram known_fp; last_fp/fp_total acumulam a história por regra."""
    today = today or dt.date.today()
    prev_rules: dict[str, Any] = (previous or {}).get("rules", {})
    rules: dict[str, Any] = {}
    hits_by_rule: dict[str, list[dict[str, Any]]] = {}
    for h in report.get("hits", []):
        hits_by_rule.setdefault(h["rule"], []).append(h)
    # tempo por regra: o timing é por arquivo de regra
    secs_by_rule: dict[str, float] = {}
    for t in report.get("timings", {}).values():
        for n in t.get("rules", []):
            secs_by_rule[n] = float(t.get("seconds", 0.0))

    for name, meta in sorted(report.get("rules", {}).items()):
        prev = prev_rules.get(name, {})
        prev_known = {fp["sha256"]: fp for fp in prev.get("known_fp", [])}
        known: list[dict[str, Any]] = []
        new_count = 0
        for h in sorted(hits_by_rule.get(name, []), key=lambda h: h["sha256"]):
            old = prev_known.get(h["sha256"])
            if old is None:
                new_count += 1
            known.append(
                {
                    "sha256": h["sha256"],
                    "file": h["file"],
                    "strings": h.get("strings", []),
                    "first_seen": old.get("first_seen", today.isoformat()) if old else today.isoformat(),
                }
            )
        last_fp = today.isoformat() if known else prev.get("last_fp")
        rules[name] = {
            "id": meta.get("id"),
            "status": meta.get("status"),
            "purpose": meta.get("purpose"),
            "version": meta.get("version"),
            "seconds": secs_by_rule.get(name, 0.0),
            "known_fp": known,
            "last_fp": last_fp,
            "fp_total": int(prev.get("fp_total", 0)) + new_count,
        }
    # regras que saíram do filtro (ex.: voltaram a experimental) mantêm a história
    for name, prev in prev_rules.items():
        if name not in rules:
            rules[name] = {**prev, "known_fp": prev.get("known_fp", []), "seconds": prev.get("seconds", 0.0)}

    return {
        "schema": 1,
        "generated": today.isoformat(),
        "filter": report.get("filter", {}),
        "corpus": {
            "paths": report.get("corpus", {}).get("paths", []),
            "files": report.get("corpus", {}).get("files"),
            "manifest_sha256": manifest_sha256,
            "platform": report.get("platform"),
        },
        "rules": rules,
    }


# ---------------------------------------------------------------- issue


def github_api(repo: str, token: str) -> Api:
    base = f"https://api.github.com/repos/{repo}"

    def call(method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(  # noqa: S310 - URL fixa em api.github.com
            base + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "fp-watch",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310  # nosec B310
                text = resp.read().decode("utf-8")
                return json.loads(text) if text else {}
        except urllib.error.HTTPError as e:
            if e.code == 422 and path == "/labels":
                return {}  # label já existe
            raise RuntimeError(
                f"GitHub API {method} {path}: {e.code} {e.read().decode('utf-8', 'replace')[:300]}"
            ) from e

    return call


def digest_of(markdown_text: str) -> str:
    # ignora as linhas voláteis (run URL) para a idempotência
    stable = "\n".join(ln for ln in markdown_text.splitlines() if not ln.startswith("Run: "))
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()[:16]


def find_open_issue(api: Api) -> dict[str, Any] | None:
    issues = api("GET", f"/issues?state=open&labels={LABEL}&per_page=20", None) or []
    for it in issues:
        if "pull_request" in it:
            continue
        if MARKER in (it.get("body") or ""):
            return dict(it)
    return None


def sync_issue(api: Api, diff: dict[str, Any], md: str, *, run_url: str = "") -> dict[str, str]:
    """Garante: regressão → exatamente uma issue aberta e atual; limpo → nenhuma aberta.

    Devolve {"action": created|updated|unchanged|closed|none, "number": "..."}."""
    digest = digest_of(md)
    body = f"{md}\n{DIGEST_RE}{digest} -->\n"
    existing = find_open_issue(api)

    if diff["regression"]:
        title = (
            f"FP regression: {len(diff['new_hits'])} hit(s) novo(s)"
            if diff["new_hits"]
            else f"FP watch: orçamento/regressão de tempo ({len(diff['budget']) + len(diff['regressions'])})"
        )
        if existing is None:
            api("POST", "/labels", {"name": LABEL, "color": "b60205", "description": "fp-watch: FP novo ou regressão"})
            created = api("POST", "/issues", {"title": title, "body": body, "labels": [LABEL]})
            return {"action": "created", "number": str(created.get("number", ""))}
        if f"{DIGEST_RE}{digest} -->" in (existing.get("body") or ""):
            return {"action": "unchanged", "number": str(existing["number"])}
        api("PATCH", f"/issues/{existing['number']}", {"title": title, "body": body})
        return {"action": "updated", "number": str(existing["number"])}

    if existing is not None:
        note = "Run limpo: nenhum hit fora da baseline e nenhuma regra acima do orçamento. Fechando."
        if run_url:
            note += f"\n\n{run_url}"
        api("POST", f"/issues/{existing['number']}/comments", {"body": note})
        api("PATCH", f"/issues/{existing['number']}", {"state": "closed", "state_reason": "completed"})
        return {"action": "closed", "number": str(existing["number"])}
    return {"action": "none", "number": ""}


# ---------------------------------------------------------------- CLI


def _manifest_sha(path: Path | None) -> str | None:
    if path is None or not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    files = data.get("files", {})
    # hash do conteúdo (sha256 por arquivo), não do JSON inteiro (que tem timestamp)
    blob = "\n".join(f"{p} {v['sha256']}" for p, v in sorted(files.items()))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _gh_output(**kv: str) -> None:
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            for k, v in kv.items():
                fh.write(f"{k}={v}\n")


def main(argv: list[str] | None = None) -> int:  # noqa: PLR0911 - um return por subcomando
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("corpus", help="baixa e descompacta as wheels fixadas por hash")
    c.add_argument("--out", type=Path, default=yrlib.REPO_ROOT / "build" / "fp-corpus")
    c.add_argument("--requirements", type=Path, default=PIP_CORPUS)

    cp = sub.add_parser("compare", help="report vs baseline")
    cp.add_argument("--report", type=Path, required=True)
    cp.add_argument("--baseline", type=Path, default=BASELINE_PATH)
    cp.add_argument("--manifest", type=Path, help="manifesto do corpus (corpus_manifest.py build)")
    cp.add_argument("--out", type=Path, required=True, help="diff.json")
    cp.add_argument("--markdown", type=Path, help="diff.md")
    cp.add_argument("--run-url", default=os.environ.get("FP_WATCH_RUN_URL", ""))
    cp.add_argument("--fail", action="store_true", help="exit 1 se houver regressão")

    b = sub.add_parser("baseline", help="aceita o report como baseline")
    b.add_argument("--report", type=Path, required=True)
    b.add_argument("--out", type=Path, default=BASELINE_PATH)
    b.add_argument("--manifest", type=Path)
    b.add_argument("--today", type=dt.date.fromisoformat, default=None)

    i = sub.add_parser("issue", help="abre/atualiza/fecha a issue única")
    i.add_argument("--diff", type=Path, required=True)
    i.add_argument("--markdown", type=Path, required=True)
    i.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    i.add_argument("--token-env", default="GITHUB_TOKEN")
    i.add_argument("--run-url", default=os.environ.get("FP_WATCH_RUN_URL", ""))
    i.add_argument("--dry-run", action="store_true", help="não chama a API; só imprime a ação")

    args = ap.parse_args(argv)

    if args.cmd == "corpus":
        dirs = build_pip_corpus(args.requirements, args.out)
        for d in dirs:
            print(d)
        print(f"{len(dirs)} pacote(s) em {args.out / 'pip'}", file=sys.stderr)
        _gh_output(pip_corpus=str(args.out / "pip"))
        return 0

    if args.cmd == "compare":
        report = json.loads(args.report.read_text(encoding="utf-8"))
        diff = compare(report, load_baseline(args.baseline), manifest_sha256=_manifest_sha(args.manifest))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(diff, indent=2, ensure_ascii=False), encoding="utf-8")
        md = markdown(diff, run_url=args.run_url)
        if args.markdown:
            args.markdown.write_text(md, encoding="utf-8")
        print(md)
        _gh_output(regression="true" if diff["regression"] else "false")
        if diff["regression"]:
            print("::error::fp-watch: regressão (FP novo ou orçamento estourado)", file=sys.stderr)
            return 1 if args.fail else 0
        return 0

    if args.cmd == "baseline":
        report = json.loads(args.report.read_text(encoding="utf-8"))
        prev = load_baseline(args.out) if args.out.exists() else None
        new = update_baseline(report, prev, manifest_sha256=_manifest_sha(args.manifest), today=args.today)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(new, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        n_fp = sum(len(r["known_fp"]) for r in new["rules"].values())
        print(f"{args.out}: {len(new['rules'])} regra(s), {n_fp} FP conhecido(s)")
        return 0

    if args.cmd == "issue":
        diff = json.loads(args.diff.read_text(encoding="utf-8"))
        md = args.markdown.read_text(encoding="utf-8")
        if args.dry_run:
            print(f"dry-run: regression={diff['regression']} digest={digest_of(md)}")
            return 0
        token = os.environ.get(args.token_env, "")
        if not args.repo or not token:
            print(f"--repo e ${args.token_env} são obrigatórios (ou use --dry-run)", file=sys.stderr)
            return 2
        result = sync_issue(github_api(args.repo, token), diff, md, run_url=args.run_url)
        print(f"issue: {result['action']} {('#' + result['number']) if result['number'] else ''}".rstrip())
        _gh_output(issue_action=result["action"], issue_number=result["number"])
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())

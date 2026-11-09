#!/usr/bin/env python3
"""Lint do repositório de regras.

Falha (exit 1) se qualquer regra em rules/ tiver:
  - erro de compilação no YARA-X;
  - warning do compilador (metadata obrigatória ausente, nome fora do padrão,
    pattern lento, campo deprecado, etc.);
  - `id` que não é UUID, ou duplicado no repositório;
  - nome de regra duplicado no repositório (mesmo em arquivos diferentes);
  - `version` que não é inteiro >= 1;
  - `status` fora de {experimental, test, stable, deprecated};
  - `purpose` fora de {hunting, triage, blocking};
  - gate de promoção: `purpose = blocking` exige `status = stable` e `confidence = high`;
  - `date`/`modified` fora de YYYY-MM-DD, ou `modified` anterior a `date`;
  - `hash` que não é md5/sha1/sha256;
  - `mitre_attack` que não é lista de técnicas (T1055, T1055.002) ou "none";
  - `scope` fora de {file, memory, both}; `memory`/`both` com condição que
    depende de uint16(0), filesize ou pe.* (não existem em memória);
  - string de texto com menos de 6 bytes (quase sempre FP);
  - hex pattern com menos de 6 bytes fixos ou mais wildcard do que byte fixo;
  - formatação diferente do `yr fmt` (desative com --no-format).

Escape hatch, por linha, para as heurísticas de strings:
    $x = "cmd" ascii   // yara-lint: allow-short
    $y = { 4D 5A ?? ?? ?? ?? }   // yara-lint: allow-wildcards

Uso:
    python scripts/lint_rules.py [--no-format] [--allow-warnings] [PATH ...]
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yrlib

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
HASH_RE = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
TEXT_STRING_RE = re.compile(r"^\s*(\$[A-Za-z0-9_]*)\s*=\s*\"((?:[^\"\\]|\\.)*)\"")
HEX_STRING_RE = re.compile(r"^\s*(\$[A-Za-z0-9_]*)\s*=\s*\{([^}]*)\}")
# O que só faz sentido em arquivo: magic no offset 0, filesize e o módulo pe.
FILE_ONLY_CONDITIONS = (
    ("magic no offset 0 (uintN(0))", re.compile(r"\buint(?:8|16|32)(?:be)?\s*\(\s*0\s*\)")),
    ("filesize", re.compile(r"\bfilesize\b")),
    ("módulo pe", re.compile(r"\bpe\.")),
)

_lint_cfg = yrlib.CONFIG.get("lint", {})
MIN_TEXT_LEN = int(_lint_cfg.get("min_text_string_bytes", 6))
MIN_FIXED_HEX_BYTES = int(_lint_cfg.get("min_fixed_hex_bytes", 6))


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files: int = 0
    rules: int = 0

    def error(self, where: str, msg: str) -> None:
        self.errors.append(f"{where}: {msg}")

    def warn(self, where: str, msg: str) -> None:
        self.warnings.append(f"{where}: {msg}")

    @property
    def ok(self) -> bool:
        return not self.errors


def _parse_date(s: str) -> date | None:
    try:
        return date.fromisoformat(s)
    except ValueError:
        return None


def check_metadata(info: yrlib.RuleInfo, rep: Report) -> None:
    where = info.where
    meta = info.meta

    rid = meta.get("id")
    if rid is not None and not UUID_RE.match(rid):
        rep.error(where, f"id={rid!r} não é um UUID (minúsculo, 8-4-4-4-12)")

    ver = meta.get("version")
    if ver is not None and (not re.fullmatch(r"\d+", ver) or int(ver) < 1):
        rep.error(where, f"version={ver!r} precisa ser inteiro >= 1")

    for key, allowed in (
        ("status", yrlib.STATUSES),
        ("purpose", yrlib.PURPOSES),
        ("confidence", yrlib.CONFIDENCES),
        ("severity", yrlib.SEVERITIES),
        ("tlp", yrlib.TLPS),
        ("engine", yrlib.ENGINES),
        ("scope", yrlib.SCOPES),
        ("license", (yrlib.LICENSE_ID,)),
    ):
        val = meta.get(key)
        if val is not None and val not in allowed:
            rep.error(where, f"{key}={val!r} inválido; use um de {list(allowed)}")

    parsed: dict[str, date] = {}
    for key in ("date", "modified"):
        val = meta.get(key)
        if val is None:
            continue
        d = _parse_date(val) if DATE_RE.match(val) else None
        if d is None:
            rep.error(where, f"{key}={val!r} não está em YYYY-MM-DD")
        else:
            parsed[key] = d
    if "date" in parsed and "modified" in parsed and parsed["modified"] < parsed["date"]:
        rep.error(where, f"modified ({meta['modified']}) é anterior a date ({meta['date']})")

    h = meta.get("hash")
    if h is not None:
        for part in re.split(r"[\s,;]+", h.strip()):
            if part and not HASH_RE.match(part):
                rep.error(where, f"hash {part!r} não parece md5/sha1/sha256")

    mitre = meta.get("mitre_attack")
    if mitre is not None and mitre.strip().lower() != "none":
        for tech in (t.strip() for t in mitre.split(",")):
            if not MITRE_RE.match(tech):
                rep.error(
                    where,
                    f'mitre_attack {tech!r} não é técnica ATT&CK (ex.: T1055, T1055.002); use "none" se não houver',
                )

    # Escopo de memória: sem cabeçalho PE, sem filesize, seções mapeadas.
    if meta.get("scope") in ("memory", "both"):
        cond = re.sub(r"/\*.*?\*/", "", info.condition, flags=re.S)
        cond = re.sub(r"//[^\n]*", "", cond)
        for label, rx in FILE_ONLY_CONDITIONS:
            if rx.search(cond):
                rep.error(
                    where,
                    f"scope={meta['scope']!r} mas a condição depende de {label}, que não existe em memória; "
                    'use scope = "file" ou remova a dependência',
                )

    # Gate de promoção
    purpose = meta.get("purpose")
    status = meta.get("status")
    confidence = meta.get("confidence")
    if purpose == "blocking":
        if status != "stable":
            rep.error(where, f"purpose=blocking exige status=stable (atual: {status!r})")
        if confidence != "high":
            rep.error(where, f"purpose=blocking exige confidence=high (atual: {confidence!r})")
    if status == "deprecated" and purpose == "blocking":
        rep.error(where, "regra deprecated não pode ser blocking; rebaixe o purpose ou remova a regra")


def check_uniqueness(infos: list[yrlib.RuleInfo], rep: Report) -> None:
    by_id: dict[str, list[yrlib.RuleInfo]] = {}
    by_name: dict[str, list[yrlib.RuleInfo]] = {}
    for info in infos:
        by_name.setdefault(info.name, []).append(info)
        if info.rule_id:
            by_id.setdefault(info.rule_id, []).append(info)
    for name, dups in by_name.items():
        if len(dups) > 1:
            rep.error("repo", f"nome de regra duplicado {name!r} em: " + ", ".join(d.where for d in dups))
    for rid, dups in by_id.items():
        if len(dups) > 1:
            rep.error("repo", f"id duplicado {rid} em: " + ", ".join(d.where for d in dups))


def _unescape_len(s: str) -> int:
    """Tamanho aproximado em bytes de um literal YARA (trata \\xNN e escapes simples)."""
    s = re.sub(r"\\x[0-9a-fA-F]{2}", "X", s)
    s = re.sub(r"\\.", "X", s)
    return len(s)


def _rel(path: Path) -> Path:
    try:
        return path.relative_to(yrlib.REPO_ROOT)
    except ValueError:
        return path


def check_strings(path: Path, rep: Report) -> None:
    rel = _rel(path)
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        code = line.split("//", 1)[0]
        comment = line[len(code) :]
        where = f"{rel}:{lineno}"

        m = TEXT_STRING_RE.match(code)
        if m and "allow-short" not in comment:
            ident, lit = m.group(1), m.group(2)
            n = _unescape_len(lit)
            if n < MIN_TEXT_LEN:
                rep.error(where, f"{ident} tem {n} bytes (< {MIN_TEXT_LEN}); string curta demais para ser âncora")
            continue

        m = HEX_STRING_RE.match(code)
        if m and "allow-wildcards" not in comment:
            ident, body = m.group(1), m.group(2)
            body = re.sub(r"\[[^\]]*\]", " JUMP ", body)
            tokens = body.split()
            fixed = sum(1 for t in tokens if re.fullmatch(r"[0-9A-Fa-f]{2}", t))
            wild = sum(1 for t in tokens if "?" in t or t == "JUMP")
            if fixed < MIN_FIXED_HEX_BYTES:
                rep.error(where, f"{ident} tem só {fixed} bytes fixos (< {MIN_FIXED_HEX_BYTES})")
            elif wild > fixed:
                rep.error(where, f"{ident} tem mais wildcards/jumps ({wild}) do que bytes fixos ({fixed})")


def check_format(path: Path, rep: Report) -> None:
    src = path.read_bytes()
    if yrlib.format_source(src) != src:
        rep.error(str(_rel(path)), "não está formatado; rode `make fmt`")


# Warnings do compilador que uma regra pode silenciar com um comentário na MESMA linha.
# text_as_hex: hex de propósito quando o texto literal é perigoso (EICAR dispara AV no checkout).
SUPPRESSIBLE_WARNINGS = {"text_as_hex": "allow-hex-as-text"}


def _warning_suppressed(w: dict[str, Any]) -> bool:
    marker = SUPPRESSIBLE_WARNINGS.get(str(w.get("code", "")))
    if not marker:
        return False
    for label in w.get("labels", []):
        origin, line = label.get("code_origin"), label.get("line")
        if not origin or not line:
            continue
        try:
            src_line = Path(origin).read_text(encoding="utf-8").splitlines()[int(line) - 1]
        except (OSError, IndexError, ValueError):
            return False
        if "//" in src_line and marker in src_line.split("//", 1)[1]:
            return True
    return False


def lint(files: list[Path], *, check_fmt: bool = True, allow_warnings: bool = False) -> Report:
    rep = Report(files=len(files))
    if not files:
        rep.error("repo", "nenhum arquivo .yar encontrado")
        return rep

    _rules, warnings, errors = yrlib.compile_rules(files, strict=True)
    for e in errors:
        rep.error(e["file"], "\n" + e["text"])
    for w in warnings:
        if _warning_suppressed(w):
            continue
        text = w.get("text", str(w))
        (rep.warn if allow_warnings else rep.error)("compiler", "\n" + text)

    all_infos: list[yrlib.RuleInfo] = []
    for f in files:
        infos = yrlib.parse_rule_infos(f)
        all_infos.extend(infos)
        for info in infos:
            check_metadata(info, rep)
        check_strings(f, rep)
        if check_fmt:
            check_format(f, rep)
    rep.rules = len(all_infos)
    check_uniqueness(all_infos, rep)
    return rep


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", type=Path, help="arquivos/diretórios (default: rules/)")
    ap.add_argument("--no-format", action="store_true", help="não checar formatação")
    ap.add_argument("--allow-warnings", action="store_true", help="warnings do compilador não falham o lint")
    args = ap.parse_args(argv)

    files: list[Path] = []
    for p in args.paths or [yrlib.RULES_DIR]:
        files.extend([p] if p.is_file() else yrlib.rule_files(p))

    rep = lint(files, check_fmt=not args.no_format, allow_warnings=args.allow_warnings)
    for w in rep.warnings:
        print(f"WARN  {w}")
    for e in rep.errors:
        print(f"ERROR {e}")
    print(f"\n{rep.files} arquivo(s), {rep.rules} regra(s): {len(rep.errors)} erro(s), {len(rep.warnings)} warning(s)")
    return 0 if rep.ok else 1


if __name__ == "__main__":
    sys.exit(main())

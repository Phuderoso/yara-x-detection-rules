"""Funções compartilhadas pelos scripts do repositório de regras.

Tudo aqui usa os bindings Python do YARA-X (pacote `yara-x`), então nenhum
script depende do binário `yr` estar instalado.
"""

from __future__ import annotations

import io
import os
import re
import subprocess
import sys
import tomllib
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yara_x

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
CONFIG_PATH = REPO_ROOT / "rules-ci.toml"

RULE_NAME_REGEX = r"^(MAL|HUNT|SUSP)_[A-Za-z0-9]+_[A-Za-z0-9_]+$"
PURPOSES = ("hunting", "triage", "blocking")
STATUSES = ("experimental", "test", "stable", "deprecated")
CONFIDENCES = ("low", "medium", "high")
SEVERITIES = ("low", "medium", "high", "critical")
TLPS = ("clear", "green", "amber", "red")
ENGINES = ("any", "yara-x")
SCOPES = ("file", "memory", "both")

# (identificador, tipo, obrigatório). O stub tipa os membros de MetaType como int.
REQUIRED_METADATA: tuple[tuple[str, Any, bool], ...] = (
    ("id", yara_x.MetaType.STRING, True),
    ("version", yara_x.MetaType.INTEGER, True),
    ("author", yara_x.MetaType.STRING, True),
    ("date", yara_x.MetaType.STRING, True),
    ("modified", yara_x.MetaType.STRING, True),
    ("description", yara_x.MetaType.STRING, True),
    ("hash", yara_x.MetaType.STRING, True),
    ("status", yara_x.MetaType.STRING, True),
    ("purpose", yara_x.MetaType.STRING, True),
    ("mitre_attack", yara_x.MetaType.STRING, True),
    ("scope", yara_x.MetaType.STRING, True),
    ("reference", yara_x.MetaType.STRING, False),
    ("malware", yara_x.MetaType.STRING, False),
    ("confidence", yara_x.MetaType.STRING, False),
    ("severity", yara_x.MetaType.STRING, False),
    ("tlp", yara_x.MetaType.STRING, False),
    ("engine", yara_x.MetaType.STRING, False),
    ("license", yara_x.MetaType.STRING, False),
)
LICENSE_ID = "CC0-1.0"  # o repositório inteiro é CC0; meta.license, se presente, repete isso

_RULE_HEADER_RE = re.compile(r"^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)
_META_LINE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\"(?:[^\"\\]|\\.)*\"|-?\d+|true|false)", re.M)
_META_BLOCK_RE = re.compile(r"\bmeta\s*:(.*?)(?=\b(?:strings|condition)\s*:)", re.S)
_CONDITION_RE = re.compile(r"\bcondition\s*:(.*)\}\s*$", re.S)
_IMPORT_RE = re.compile(r'^\s*import\s+"[^"]+"', re.M)


_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}


def _unescape(s: str) -> str:
    r"""Escapes de string YARA (\\, \", \t, \n, \xNN) sem passar por unicode_escape, que estraga UTF-8."""

    def repl(m: re.Match[str]) -> str:
        e = m.group(1)
        if e.startswith("x"):
            return chr(int(e[1:], 16))
        return _ESCAPES.get(e, "\\" + e)

    return re.sub(r"\\(x[0-9a-fA-F]{2}|.)", repl, s)


def load_config() -> dict[str, Any]:
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open("rb") as fh:
            return tomllib.load(fh)
    return {}


CONFIG = load_config()


@dataclass
class RuleInfo:
    name: str
    path: Path
    line: int
    meta: dict[str, str] = field(default_factory=dict)
    condition: str = ""
    source: str = ""

    @property
    def purpose(self) -> str:
        return self.meta.get("purpose", "hunting")

    @property
    def status(self) -> str:
        return self.meta.get("status", "experimental")

    @property
    def rule_id(self) -> str | None:
        return self.meta.get("id")

    @property
    def scope(self) -> str:
        return self.meta.get("scope", "file")

    @property
    def family(self) -> str | None:
        return self.meta.get("malware") or None

    @property
    def mitre(self) -> list[str]:
        raw = self.meta.get("mitre_attack", "")
        if raw.strip().lower() in ("", "none"):
            return []
        return [t.strip() for t in raw.split(",") if t.strip()]

    @property
    def where(self) -> str:
        try:
            rel = self.path.relative_to(REPO_ROOT)
        except ValueError:
            rel = self.path
        return f"{rel}:{self.line}:{self.name}"


def rule_files(root: Path = RULES_DIR) -> list[Path]:
    """Todos os .yar/.yara abaixo de `root`, ignorando arquivos com prefixo `_`
    (templates e rascunhos que não devem ser compilados)."""
    files = []
    for p in sorted(root.rglob("*")):
        if p.suffix.lower() not in (".yar", ".yara"):
            continue
        if p.name.startswith("_"):
            continue
        files.append(p)
    return files


def parse_rule_infos(path: Path) -> list[RuleInfo]:
    """Extrai nome e bloco `meta` de cada regra do arquivo, sem compilar.

    É um parse textual propositalmente simples: a validação sintática real é
    feita pelo compilador do YARA-X. Aqui só precisamos do `meta` de *todas* as
    regras (os bindings só expõem metadata de regras que casaram num scan).
    """
    src = path.read_text(encoding="utf-8")
    headers = list(_RULE_HEADER_RE.finditer(src))
    infos: list[RuleInfo] = []
    for i, h in enumerate(headers):
        start = h.end()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(src)
        body = src[start:end]
        meta: dict[str, str] = {}
        m = _META_BLOCK_RE.search(body)
        if m:
            for k, raw in _META_LINE_RE.findall(m.group(1)):
                meta[k] = _unescape(raw[1:-1]) if raw.startswith('"') else raw
        cm = _CONDITION_RE.search(body)
        condition = cm.group(1).strip() if cm else ""
        line = src.count("\n", 0, h.start()) + 1
        infos.append(
            RuleInfo(
                name=h.group(1),
                path=path,
                line=line,
                meta=meta,
                condition=condition,
                source=src[h.start() : end].rstrip() + "\n",
            )
        )
    return infos


def file_imports(path: Path) -> list[str]:
    """Linhas `import "..."` do arquivo (para recompor subconjuntos de regras)."""
    return sorted({m.group(0) for m in _IMPORT_RE.finditer(path.read_text(encoding="utf-8"))})


def subset_source(files: Iterable[Path], keep: Callable[[RuleInfo], bool]) -> dict[str, str]:
    """Fonte por namespace contendo só as regras aceitas por `keep`, com os imports do arquivo.

    Regras `private` referenciadas por outras precisam ser aceitas também; o
    compilador aponta se faltar alguma."""
    out: dict[str, str] = {}
    for f in files:
        infos = [i for i in parse_rule_infos(f) if keep(i)]
        if not infos:
            continue
        imports = "\n".join(file_imports(f))
        out[namespace_for(f)] = (imports + "\n\n" if imports else "") + "\n".join(i.source for i in infos)
    return out


def namespace_for(path: Path) -> str:
    try:
        return str(path.relative_to(RULES_DIR)).replace(os.sep, "/")
    except ValueError:
        return path.name


def new_compiler(strict: bool = True) -> yara_x.Compiler:
    """Compilador com as políticas do repo aplicadas (nome, metadata, patterns lentos)."""
    c = yara_x.Compiler(relaxed_re_syntax=False, error_on_slow_pattern=strict)
    c.allowed_rule_name(RULE_NAME_REGEX)
    for ident, mtype, required in REQUIRED_METADATA:
        # O stub lista um 4º parâmetro `regexp` que a versão instalada não aceita posicionalmente.
        c.allowed_metadata(ident, mtype, required)  # type: ignore[call-arg]
    return c


def compile_rules(
    files: Iterable[Path], strict: bool = True
) -> tuple[yara_x.Rules, list[dict[str, Any]], list[dict[str, str]]]:
    """Compila todos os arquivos num único conjunto. Retorna (rules, warnings, errors).

    Cada arquivo entra no namespace relativo a `rules/` (ex.: `windows/Foo.yar`),
    o que evita colisão de nomes entre pastas e facilita rastrear a origem.
    """
    c = new_compiler(strict=strict)
    errors: list[dict[str, str]] = []
    for f in files:
        c.new_namespace(namespace_for(f))
        try:
            c.add_source(f.read_text(encoding="utf-8"), origin=str(f))
        except yara_x.CompileError as e:
            errors.append({"file": str(f), "text": str(e)})
    warnings = list(c.warnings())
    rules = c.build()
    return rules, warnings, errors


def format_source(src: bytes) -> bytes:
    """Formata fonte YARA com o formatter do YARA-X (equivale a `yr fmt`)."""
    out = io.BytesIO()
    # O stub declara TextIO, mas a implementação aceita (e devolve) bytes.
    yara_x.Formatter().format(io.BytesIO(src), out)  # type: ignore[arg-type]
    return out.getvalue()


def compile_file(path: Path) -> yara_x.Rules:
    """Compila um único arquivo (usado para medir tempo por regra)."""
    c = yara_x.Compiler(relaxed_re_syntax=False, error_on_slow_pattern=False)
    c.add_source(path.read_text(encoding="utf-8"), origin=str(path))
    return c.build()


def index_rules(files: Iterable[Path]) -> dict[str, RuleInfo]:
    index: dict[str, RuleInfo] = {}
    for f in files:
        for info in parse_rule_infos(f):
            index[info.name] = info
    return index


def load_all_rules(strict: bool = True, root: Path = RULES_DIR) -> tuple[yara_x.Rules, dict[str, RuleInfo]]:
    """Compila tudo em `root` e devolve também um índice nome → RuleInfo.

    Falha (SystemExit) se houver erro de compilação; warnings são responsabilidade
    do lint, não do scanner.
    """
    files = rule_files(root)
    if not files:
        sys.exit(f"nenhum arquivo .yar encontrado em {root}")
    rules, _warnings, errors = compile_rules(files, strict=strict)
    if errors:
        for e in errors:
            print(e["text"], file=sys.stderr)
        sys.exit(f"{len(errors)} arquivo(s) com erro de compilação")
    return rules, index_rules(files)


def iter_files(paths: Iterable[Path], max_size: int | None = None) -> Iterator[Path]:
    """Percorre arquivos regulares recursivamente, ignorando symlinks e arquivos
    acima de `max_size` (bytes)."""
    for root in map(Path, paths):
        if root.is_file():
            candidates: Iterable[Path] = [root]
        else:
            candidates = (Path(dp) / fn for dp, _dirs, fns in os.walk(root, followlinks=False) for fn in fns)
        for p in candidates:
            try:
                if p.is_symlink() or not p.is_file():
                    continue
                if max_size is not None and p.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            yield p


def read_file(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except (OSError, PermissionError):
        return None


def git(*args: str, repo: Path | None = None) -> str:
    """Roda `git <args>` no repo e devolve stdout. Só argumentos fixos dos scripts; nada vem de input externo."""
    cmdline = ["git", "-C", str(repo or REPO_ROOT), *args]
    return subprocess.check_output(cmdline, text=True, stderr=subprocess.DEVNULL)  # nosec B603


def parse_size(s: str) -> int:
    m = re.fullmatch(r"(\d+)\s*([KMG]?B?)", str(s).strip(), re.I)
    if not m:
        raise ValueError(f"tamanho inválido: {s}")
    n, unit = int(m.group(1)), m.group(2).upper().rstrip("B")
    return n * {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30}[unit]


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n}B"

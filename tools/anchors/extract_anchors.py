#!/usr/bin/env python3
"""Extrator de âncoras de código sem overfit.

Recebe N amostras da mesma família (PE ou blobs de código), desmonta as seções
executáveis com capstone e procura sequências de instruções compartilhadas por
pelo menos K amostras. Os bytes que o compilador/linker muda entre builds
(disp32 RIP-relative, rel8/rel32 de jumps e calls, imediatos, RVAs) viram `??`
usando a informação de operando do capstone; opcodes, prefixos, ModRM e SIB
ficam fixos. Candidatos que acendem no corpus de goodware são descartados e o
resto é ranqueado por bytes fixos, raridade e cobertura. O resultado pode sair
como rascunho de regra `status = experimental`, já no formato do lint.

Método (resumo):
  1. "Superset disassembly": toda posição da seção vira início de instrução
     (não depende de acertar o começo da função; ruído some na interseção).
  2. Cada instrução vira um token hex com `??` nos operandos variáveis.
  3. Janelas de `--min-insns` instruções são a semente; as comuns a >= K
     amostras são estendidas à direita enquanto continuarem comuns.
  4. Filtros: bytes fixos mínimos, wildcards <= fixos, nada degenerado
     (nop sled, int3, zero-fill), zero hits no goodware.
  5. Score = fixos × cobertura × raridade × bônus de lógica (xor/rol/shift…),
     com penalidade para prólogo/epílogo puro.

Uso:
    python tools/anchors/extract_anchors.py samples/*.exe --goodware /mnt/goodware \\
        --family FamilyX --draft rules/windows/SUSP_Win_Loader_FamilyX_CodeAnchors.yar
    python tools/anchors/extract_anchors.py a.bin b.bin --raw --arch x64 --json out.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import capstone  # type: ignore[import-untyped]
import yara_x

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import yrlib  # noqa: E402

X86_BRANCH_GROUPS = {capstone.CS_GRP_JUMP, capstone.CS_GRP_CALL, capstone.CS_GRP_BRANCH_RELATIVE}
LOGIC_MNEMONICS = {
    "xor", "rol", "ror", "shl", "shr", "sar", "sal", "imul", "mul", "div", "idiv", "not", "neg", "bswap",
    "pxor", "pshufb", "paddb", "psubb", "aesenc", "aesdec", "crc32", "popcnt", "and", "or",
}  # fmt: skip
BOILERPLATE_MNEMONICS = {"push", "pop", "mov", "ret", "nop", "int3", "leave", "endbr64", "endbr32"}

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000


@dataclass
class Policy:
    """O que vira wildcard. O padrão segue o que muda entre builds da mesma fonte."""

    wild_disp32: bool = True
    wild_disp8: bool = False
    wild_rel: bool = True
    wild_imm32: bool = True
    wild_imm8: bool = True


@dataclass
class Insn:
    offset: int  # offset no arquivo
    size: int
    mnemonic: str
    op_str: str
    raw: bytes
    wild: tuple[bool, ...]  # True = byte variável

    @property
    def token(self) -> str:
        return "".join("??" if w else f"{b:02x}" for b, w in zip(self.raw, self.wild, strict=True))

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass
class Sample:
    name: str
    sha256: str
    arch: str
    regions: list[tuple[int, bytes]]  # (file offset, bytes) das áreas de código
    insns: dict[int, Insn] = field(default_factory=dict)


Occ = dict[int, list[tuple[int, int]]]  # amostra -> [(início, fim)] de cada ocorrência


@dataclass
class Candidate:
    hexbytes: list[str]  # por byte: "XX" ou "??"
    mnemonics: list[str]
    disasm: str
    coverage: set[int]
    occurrences: dict[int, int]
    spans: Occ = field(default_factory=dict)
    goodware_hits: int = 0
    score: float = 0.0

    @property
    def fixed(self) -> int:
        return sum(1 for b in self.hexbytes if b != "??")

    @property
    def wild(self) -> int:
        return len(self.hexbytes) - self.fixed

    @property
    def pattern(self) -> str:
        """Hex YARA com `[n]` para runs de 4+ wildcards."""
        out: list[str] = []
        run = 0
        for b in [*self.hexbytes, None]:
            if b == "??":
                run += 1
                continue
            if run:
                out.extend(["??"] * run if run < 4 else [f"[{run}]"])
                run = 0
            if b is not None:
                out.append(b.upper())
        return " ".join(out)

    @property
    def key(self) -> str:
        return " ".join(self.hexbytes)

    def as_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern,
            "fixed": self.fixed,
            "wild": self.wild,
            "coverage": sorted(self.coverage),
            "occurrences": dict(sorted(self.occurrences.items())),
            "goodware_hits": self.goodware_hits,
            "score": round(self.score, 3),
            "mnemonics": self.mnemonics,
            "disasm": self.disasm,
        }


# ---------------------------------------------------------------- carga


def _code_regions_pe(data: bytes) -> tuple[str, list[tuple[int, bytes]]]:
    import pefile  # type: ignore[import-untyped]

    pe = pefile.PE(data=data, fast_load=True)
    machine = pe.FILE_HEADER.Machine
    arch = {0x14C: "x86", 0x8664: "x64"}.get(machine)
    if arch is None:
        raise ValueError(f"máquina PE não suportada: 0x{machine:x}")
    regions: list[tuple[int, bytes]] = []
    for s in pe.sections:
        if not (s.Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)):
            continue
        off, size = int(s.PointerToRawData), int(s.SizeOfRawData)
        if size and off < len(data):
            regions.append((off, data[off : off + size]))
    if not regions:  # packed / sem flags: olha tudo, com aviso
        print("aviso: nenhuma seção executável; usando todas as seções", file=sys.stderr)
        regions = [
            (int(s.PointerToRawData), data[s.PointerToRawData : s.PointerToRawData + s.SizeOfRawData])
            for s in pe.sections
        ]
    return arch, regions


def load_sample(path: Path, *, raw: bool = False, arch: str = "x64", max_code_bytes: int = 0) -> Sample:
    data = path.read_bytes()
    if raw or data[:2] != b"MZ":
        regions = [(0, data)]
    else:
        arch, regions = _code_regions_pe(data)
    if max_code_bytes:
        budget = max_code_bytes
        trimmed = []
        for off, blob in regions:
            if budget <= 0:
                break
            trimmed.append((off, blob[:budget]))
            budget -= len(blob)
        regions = trimmed
    return Sample(name=path.name, sha256=hashlib.sha256(data).hexdigest(), arch=arch, regions=regions)


# ---------------------------------------------------------------- disassembly


def _disassembler(arch: str) -> Any:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if arch == "x64" else capstone.CS_MODE_32)
    md.detail = True
    return md


def wild_mask(insn: Any, policy: Policy) -> tuple[bool, ...]:
    """Quais bytes da instrução variam entre builds, segundo os offsets de operando do capstone."""
    mask = [False] * insn.size
    if insn.disp_size and ((insn.disp_size >= 4 and policy.wild_disp32) or (insn.disp_size < 4 and policy.wild_disp8)):
        for i in range(insn.disp_offset, insn.disp_offset + insn.disp_size):
            mask[i] = True
    if insn.imm_size:
        groups = set(insn.groups)
        is_rel = bool(groups & X86_BRANCH_GROUPS)
        if (
            (is_rel and policy.wild_rel)
            or (not is_rel and insn.imm_size >= 4 and policy.wild_imm32)
            or (not is_rel and insn.imm_size < 4 and policy.wild_imm8)
        ):
            for i in range(insn.imm_offset, insn.imm_offset + insn.imm_size):
                mask[i] = True
    return tuple(mask)


def disassemble(sample: Sample, policy: Policy, *, sweep: str = "superset") -> None:
    """Preenche sample.insns. `superset`: toda posição vira início de instrução
    (cadeias se fundem quando ressincronizam); `linear`: varredura simples."""
    md = _disassembler(sample.arch)
    chunk = 512  # janela de decode: evita copiar o resto do buffer a cada início
    for base, blob in sample.regions:
        starts = range(len(blob)) if sweep == "superset" else [0]
        for start in starts:
            pos = start
            while pos < len(blob) and base + pos not in sample.insns:
                last_end = None
                merged = False
                for raw_insn in md.disasm(blob[pos : pos + chunk], base + pos):
                    off = raw_insn.address
                    if off in sample.insns:
                        merged = True
                        break
                    sample.insns[off] = Insn(
                        offset=off,
                        size=raw_insn.size,
                        mnemonic=raw_insn.mnemonic,
                        op_str=raw_insn.op_str,
                        raw=bytes(raw_insn.bytes),
                        wild=wild_mask(raw_insn, policy),
                    )
                    last_end = off + raw_insn.size - base
                if merged or last_end is None:
                    break  # fundiu com cadeia existente, ou byte inválido: esta posição não é instrução
                if last_end < pos + chunk - 15:
                    break  # parou antes do fim da janela: opcode inválido
                pos = last_end  # instrução cortada na borda da janela: continua de onde parou


# ---------------------------------------------------------------- mineração


def _window(sample: Sample, start: int, n: int) -> tuple[list[Insn], int] | None:
    insns: list[Insn] = []
    off = start
    for _ in range(n):
        i = sample.insns.get(off)
        if i is None:
            return None
        insns.append(i)
        off = i.end
    return insns, off


def mine(samples: list[Sample], *, k: int, min_insns: int = 4, max_insns: int = 16) -> list[tuple[list[Insn], Occ]]:
    seeds: dict[str, Occ] = defaultdict(lambda: defaultdict(list))
    for si, s in enumerate(samples):
        for start in s.insns:
            w = _window(s, start, min_insns)
            if w is None:
                continue
            key = " ".join(i.token for i in w[0])
            seeds[key][si].append((start, w[1]))

    results: dict[str, tuple[list[Insn], Occ]] = {}
    # (amostra, fim) -> menor início já emitido: janela que termina no mesmo
    # ponto começando depois é sufixo de uma já conhecida (artefato do superset).
    covered: dict[tuple[int, int], int] = {}
    for occ in seeds.values():
        if len(occ) < k:
            continue
        si0, spans0 = next(iter(occ.items()))
        first = _window(samples[si0], spans0[0][0], min_insns)
        if first is None:  # não acontece: a semente foi construída a partir desta posição
            continue
        insns = list(first[0])
        cur: Occ = {si: list(v) for si, v in occ.items()}
        while len(insns) < max_insns:
            groups: dict[str, Occ] = defaultdict(lambda: defaultdict(list))
            rep: dict[str, Insn] = {}
            for si, spans in cur.items():
                for st, en in spans:
                    nxt = samples[si].insns.get(en)
                    if nxt is None:
                        continue
                    groups[nxt.token][si].append((st, nxt.end))
                    rep.setdefault(nxt.token, nxt)
            best = max(groups.items(), key=lambda kv: (len(kv[1]), sum(len(v) for v in kv[1].values())), default=None)
            if best is None or len(best[1]) < k:
                break
            insns.append(rep[best[0]])
            cur = best[1]
        full_key = " ".join(i.token for i in insns)
        if full_key in results:
            continue
        if all(covered.get((si, en), 1 << 62) <= st for si, spans in cur.items() for st, en in spans):
            continue
        for si, spans in cur.items():
            for st, en in spans:
                covered[(si, en)] = min(covered.get((si, en), st), st)
        results[full_key] = (insns, cur)
    return list(results.values())


FILLER_MNEMONICS = {"nop", "int3"}


def _is_filler(i: Insn) -> bool:
    """Preenchimento entre funções/seções: zero-fill (`add [rax], al`), int3, nop."""
    return i.mnemonic in FILLER_MNEMONICS or not any(i.raw)


def _trim_filler(insns: list[Insn], occ: Occ) -> tuple[list[Insn], Occ]:
    """Apara filler nas bordas da janela e ajusta os spans. Evita que padding
    comum (fim de seção zerada) vire parte da âncora."""
    lead = 0
    while lead < len(insns) and _is_filler(insns[lead]):
        lead += 1
    trail = 0
    while trail < len(insns) - lead and _is_filler(insns[-1 - trail]):
        trail += 1
    if not lead and not trail:
        return insns, occ
    lead_bytes = sum(i.size for i in insns[:lead])
    trail_bytes = sum(i.size for i in insns[len(insns) - trail :])
    trimmed = {si: [(st + lead_bytes, en - trail_bytes) for st, en in spans] for si, spans in occ.items()}
    return insns[lead : len(insns) - trail], trimmed


def to_candidate(insns: list[Insn], occ: Occ, samples: list[Sample]) -> Candidate:
    insns, occ = _trim_filler(insns, occ)
    if not insns:
        return Candidate(hexbytes=[], mnemonics=[], disasm="", coverage=set(occ), occurrences={}, spans=occ)
    hexbytes = [b for i in insns for b in (("??" if w else f"{x:02x}") for x, w in zip(i.raw, i.wild, strict=True))]
    while hexbytes and hexbytes[0] == "??":
        hexbytes.pop(0)
    while hexbytes and hexbytes[-1] == "??":
        hexbytes.pop()
    si0, spans = next(iter(occ.items()))
    w = _window(samples[si0], spans[0][0], len(insns))
    disasm = "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in (w[0] if w else insns))
    return Candidate(
        hexbytes=hexbytes,
        mnemonics=[i.mnemonic for i in insns],
        disasm=disasm,
        coverage=set(occ),
        occurrences={si: len(v) for si, v in occ.items()},
        spans=occ,
    )


def is_degenerate(c: Candidate, *, min_distinct_insns: int = 3, min_distinct_bytes: int = 4) -> bool:
    distinct_insns = len(set(c.mnemonics))
    distinct_bytes = len({b for b in c.hexbytes if b != "??"})
    return distinct_insns < min_distinct_insns or distinct_bytes < min_distinct_bytes


def _subsumed(short: list[str], long: list[str]) -> bool:
    """`short` casa dentro de `long` com, no máximo, bytes fixos onde `long` tem `??`.

    Cobre o artefato clássico do superset disassembly: uma cadeia que começa no
    meio de um operando variável (ex.: no último byte `00` de um disp32)."""
    n, m = len(short), len(long)
    if n > m:
        return False
    for off in range(m - n + 1):
        if all(lo in ("??", sh) for sh, lo in zip(short, long[off : off + n], strict=True)):
            return True
    return False


def dedupe(cands: list[Candidate]) -> list[Candidate]:
    """Remove candidato subsumido por outro mais longo que cobre as mesmas amostras."""
    kept: list[Candidate] = []
    for c in sorted(cands, key=lambda c: (-len(c.hexbytes), -c.fixed)):
        if any(k.coverage >= c.coverage and _subsumed(c.hexbytes, k.hexbytes) for k in kept):
            continue
        kept.append(c)
    return kept


def _overlap_ratio(a: Occ, b: Occ) -> float:
    """Fração dos bytes das ocorrências de `a` cobertos por ocorrências de `b`."""
    total = covered = 0
    for si, spans in a.items():
        for st, en in spans:
            total += en - st
            covered += max(
                (min(en, e2) - max(st, s2) for s2, e2 in b.get(si, []) if min(en, e2) > max(st, s2)), default=0
            )
    return covered / total if total else 0.0


def suppress_overlaps(ranked: list[Candidate], *, max_overlap: float = 0.5) -> list[Candidate]:
    """Non-maximum suppression: janelas deslocadas da mesma região ficam só com a de maior score."""
    kept: list[Candidate] = []
    for c in ranked:
        if any(_overlap_ratio(c.spans, k.spans) > max_overlap for k in kept):
            continue
        kept.append(c)
    return kept


def score(c: Candidate, n_samples: int) -> float:
    coverage = len(c.coverage) / n_samples
    mean_occ = sum(c.occurrences.values()) / max(1, len(c.occurrences))
    rarity = 1.0 / mean_occ
    bonus = 1.25 if set(c.mnemonics) & LOGIC_MNEMONICS else 1.0
    if set(c.mnemonics) <= BOILERPLATE_MNEMONICS:
        bonus *= 0.5
    return c.fixed * coverage * rarity * bonus


# ---------------------------------------------------------------- goodware


def goodware_hits(cands: list[Candidate], corpus: list[Path], *, max_size: int) -> None:
    if not cands or not corpus:
        return
    src = "\n".join(f"rule c{i} {{ strings: $a = {{ {c.pattern} }} condition: $a }}" for i, c in enumerate(cands))
    rules = yara_x.compile(src)
    scanner = yara_x.Scanner(rules)
    hits: Counter[str] = Counter()
    for path in yrlib.iter_files(corpus, max_size=max_size):
        data = yrlib.read_file(path)
        if data is None:
            continue
        for m in scanner.scan(data).matching_rules:
            hits[m.identifier] += 1
    for i, c in enumerate(cands):
        c.goodware_hits = hits.get(f"c{i}", 0)


# ---------------------------------------------------------------- pipeline


@dataclass
class Options:
    k: int = 0  # 0 = todas as amostras
    min_insns: int = 4
    max_insns: int = 16
    min_fixed: int = 8
    sweep: str = "superset"
    policy: Policy = field(default_factory=Policy)
    goodware: list[Path] = field(default_factory=list)
    goodware_max_hits: int = 0
    goodware_max_size: int = 32 << 20
    max_candidates_to_scan: int = 500
    max_overlap: float = 0.5


def extract(samples: list[Sample], opts: Options) -> tuple[list[Candidate], list[Candidate]]:
    """Retorna (aceitos ranqueados, descartados pelo goodware)."""
    k = opts.k or len(samples)
    for s in samples:
        disassemble(s, opts.policy, sweep=opts.sweep)
    raw = [
        to_candidate(i, o, samples) for i, o in mine(samples, k=k, min_insns=opts.min_insns, max_insns=opts.max_insns)
    ]
    cands = [c for c in raw if c.fixed >= opts.min_fixed and c.wild <= c.fixed and not is_degenerate(c)]
    cands = dedupe(cands)
    for c in cands:
        c.score = score(c, len(samples))
    cands.sort(key=lambda c: -c.score)
    cands = suppress_overlaps(cands, max_overlap=opts.max_overlap)
    cands = cands[: opts.max_candidates_to_scan]
    goodware_hits(cands, opts.goodware, max_size=opts.goodware_max_size)
    accepted = [c for c in cands if c.goodware_hits <= opts.goodware_max_hits]
    rejected = [c for c in cands if c.goodware_hits > opts.goodware_max_hits]
    return accepted, rejected


# ---------------------------------------------------------------- rascunho


def draft_rule(
    cands: list[Candidate],
    samples: list[Sample],
    *,
    rule_name: str,
    family: str,
    author: str,
    min_match: int = 1,
    max_strings: int = 3,
    today: dt.date | None = None,
) -> str:
    today = today or dt.date.today()
    chosen = cands[:max_strings]
    if not chosen:
        raise ValueError("nenhum candidato para o rascunho")
    k = min(len(samples), max(len(c.coverage) for c in chosen))
    hashes = ", ".join(s.sha256 for s in samples[:3])
    strings = []
    for i, c in enumerate(chosen, start=1):
        strings.append(f"    // {c.disasm}")
        strings.append(
            f"    //   fixos={c.fixed} wild={c.wild} cobertura={len(c.coverage)}/{len(samples)} score={c.score:.1f}"
        )
        strings.append(f"    $code_{i} = {{ {c.pattern} }}")
    cond_strings = f"{min_match} of ($code_*)" if len(chosen) > 1 else "$code_1"
    return (
        'import "pe"\n\n'
        f"rule {rule_name} {{\n"
        "  meta:\n"
        f'    id           = "{uuid.uuid4()}"\n'
        "    version      = 1\n"
        f'    author       = "{author}"\n'
        f'    date         = "{today.isoformat()}"\n'
        f'    modified     = "{today.isoformat()}"\n'
        f'    description  = "{family}: âncoras de código extraídas automaticamente de {len(samples)} amostra(s) '
        f'(comuns a >= {k}); revisar antes de promover"\n'
        f'    malware      = "{family}"\n'
        '    status       = "experimental"\n'
        '    confidence   = "low"\n'
        '    severity     = "medium"\n'
        '    tlp          = "amber"\n'
        '    reference    = "tools/anchors/extract_anchors.py"\n'
        f'    hash         = "{hashes}"\n'
        '    purpose      = "hunting"\n'
        '    mitre_attack = "none"\n'
        '    scope        = "file"\n\n'
        "  strings:\n" + "\n".join(strings) + "\n\n"
        "  condition:\n"
        "    uint16(0) == 0x5A4D and\n"
        "    filesize < 5MB and\n"
        "    pe.is_pe and\n"
        f"    {cond_strings}\n"
        "}\n"
    )


def format_draft(text: str) -> str:
    return yrlib.format_source(text.encode("utf-8")).decode("utf-8")


# ---------------------------------------------------------------- CLI


def _print_table(accepted: list[Candidate], rejected: list[Candidate], n: int, top: int) -> None:
    print(f"{len(accepted)} candidato(s) aceito(s), {len(rejected)} descartado(s) pelo goodware\n")
    print(f"{'#':>3} {'score':>7} {'fix':>4} {'wild':>4} {'cov':>5} {'occ':>4}  padrão")
    for i, c in enumerate(accepted[:top], start=1):
        occ = sum(c.occurrences.values())
        print(f"{i:>3} {c.score:>7.1f} {c.fixed:>4} {c.wild:>4} {len(c.coverage):>2}/{n:<2} {occ:>4}  {c.pattern}")
        print(f"{'':>33}  {c.disasm}")
    for c in rejected[:5]:
        print(f"  x goodware={c.goodware_hits:<4} {c.pattern}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("samples", nargs="+", type=Path, help="amostras da mesma família (PE) ou blobs com --raw")
    ap.add_argument("--raw", action="store_true", help="tratar entradas como código bruto (sem parse de PE)")
    ap.add_argument("--arch", choices=("x86", "x64"), default="x64", help="arquitetura para --raw")
    ap.add_argument(
        "-k", type=int, default=0, help="mínimo de amostras que a sequência precisa cobrir (default: todas)"
    )
    ap.add_argument("--min-insns", type=int, default=4)
    ap.add_argument("--max-insns", type=int, default=16)
    ap.add_argument("--min-fixed", type=int, default=8, help="bytes fixos mínimos (lint exige 6)")
    ap.add_argument("--sweep", choices=("superset", "linear"), default="superset")
    ap.add_argument("--wild-disp8", action="store_true", help="também mascarar disp8 (ex.: [rbp-0x20])")
    ap.add_argument("--keep-imm8", action="store_true", help="manter imediatos de 1 byte fixos")
    ap.add_argument("--max-code-bytes", type=yrlib.parse_size, default="8MB", help="limite de código por amostra")
    ap.add_argument("--goodware", type=Path, action="append", default=[], help="corpus limpo (repetível)")
    ap.add_argument("--goodware-max-hits", type=int, default=0)
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--json", type=Path, help="gravar candidatos em JSON")
    ap.add_argument("--draft", type=Path, help="gravar rascunho de regra .yar")
    ap.add_argument("--rule-name", help="nome da regra do rascunho (default SUSP_Win_<Family>_CodeAnchors)")
    ap.add_argument("--family", default="Unknown")
    ap.add_argument("--author", default="tools/anchors")
    ap.add_argument("--min-match", type=int, default=1, help="N of ($code_*) no rascunho")
    ap.add_argument("--draft-strings", type=int, default=3, help="quantos candidatos entram no rascunho")
    args = ap.parse_args(argv)

    samples = [load_sample(p, raw=args.raw, arch=args.arch, max_code_bytes=args.max_code_bytes) for p in args.samples]
    opts = Options(
        k=args.k,
        min_insns=args.min_insns,
        max_insns=args.max_insns,
        min_fixed=args.min_fixed,
        sweep=args.sweep,
        policy=Policy(wild_disp8=args.wild_disp8, wild_imm8=not args.keep_imm8),
        goodware=args.goodware,
        goodware_max_hits=args.goodware_max_hits,
    )
    accepted, rejected = extract(samples, opts)
    _print_table(accepted, rejected, len(samples), args.top)

    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "samples": [{"name": s.name, "sha256": s.sha256, "arch": s.arch} for s in samples],
                    "accepted": [c.as_dict() for c in accepted],
                    "rejected": [c.as_dict() for c in rejected],
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
    if args.draft:
        if not accepted:
            print("sem candidatos aceitos; rascunho não gerado", file=sys.stderr)
            return 1
        name = args.rule_name or f"SUSP_Win_{args.family}_CodeAnchors"
        text = format_draft(
            draft_rule(
                accepted,
                samples,
                rule_name=name,
                family=args.family,
                author=args.author,
                min_match=args.min_match,
                max_strings=args.draft_strings,
            )
        )
        args.draft.parent.mkdir(parents=True, exist_ok=True)
        args.draft.write_text(text, encoding="utf-8")
        print(f"\nrascunho: {args.draft}  (rode: python scripts/lint_rules.py {args.draft})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

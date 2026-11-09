#!/usr/bin/env python3
"""Barra binários executáveis em rules/ e tests/ (pre-commit e CI).

Samples nunca entram no repositório, nem "só para testar". Fixtures são geradas
em memória por tests/fakepe.py. Este check olha o magic dos arquivos passados
(ou de todo rules/ e tests/) e falha se achar PE, ELF, Mach-O, zip/jar ou
qualquer coisa que pareça payload.

Uso:
    python scripts/check_no_binaries.py [FILE ...]
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yrlib

ALLOWED_SUFFIXES = {".py", ".yar", ".yara", ".md", ".lock", ".json", ".toml", ".txt", ".yml", ".yaml"}
MAGICS: dict[bytes, str] = {
    b"MZ": "PE (MZ)",
    b"\x7fELF": "ELF",
    b"\xfe\xed\xfa\xce": "Mach-O 32",
    b"\xfe\xed\xfa\xcf": "Mach-O 64",
    b"\xcf\xfa\xed\xfe": "Mach-O 64 (LE)",
    b"\xca\xfe\xba\xbe": "Mach-O fat / Java class",
    b"PK\x03\x04": "ZIP/JAR/APK/OOXML",
    b"Rar!": "RAR",
    b"7z\xbc\xaf": "7z",
    b"%PDF": "PDF",
    b"\xd0\xcf\x11\xe0": "OLE2 (doc/xls legado)",
    b"#!": "script com shebang",
}


def classify(path: Path) -> str | None:
    try:
        head = path.read_bytes()[:8]
    except OSError:
        return None
    return next((name for magic, name in MAGICS.items() if head.startswith(magic)), None)


def main(argv: list[str] | None = None) -> int:
    args = [Path(a) for a in (argv if argv is not None else sys.argv[1:])]
    roots = args or [yrlib.REPO_ROOT / "rules", yrlib.REPO_ROOT / "tests"]
    bad: list[str] = []
    for p in yrlib.iter_files(roots):
        if p.suffix.lower() in ALLOWED_SUFFIXES and p.suffix.lower() != ".py":
            continue
        kind = classify(p)
        if kind and not (p.suffix.lower() == ".py" and kind == "script com shebang"):
            bad.append(f"{p}: {kind}")
    for b in bad:
        print(f"ERROR binário commitado: {b}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

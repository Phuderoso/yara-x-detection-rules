#!/usr/bin/env python3
"""Baixa as amostras de tests/samples.lock do MalwareBazaar, escaneia e apaga.

Regras de segurança deste script (não relaxe sem revisar):
  - os arquivos vão para um diretório temporário criado com mkdtemp e removido
    no `finally`, mesmo em erro;
  - o conteúdo extraído é gravado com permissão 0600 e NUNCA é executado,
    importado ou aberto por outro programa: só é lido como bytes e passado ao
    scanner do YARA-X;
  - o sha256 do arquivo extraído é conferido contra o lock antes do scan;
  - nada é copiado para fora do tmpdir; a CI não faz upload de artifact deste job.

A API exige uma chave (header `Auth-Key`). Passe via MALWAREBAZAAR_API_KEY.
Sem a chave o script sai com código 0 e um aviso, para o job da CI ser pulado
sem falhar.

Uso:
    MALWAREBAZAAR_API_KEY=... python scripts/fetch_samples.py [--lock tests/samples.lock] [--strict]
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import yara_x

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yrlib

MB_API = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD = b"infected"
MAX_SAMPLE_BYTES = 64 * 1024 * 1024


@dataclass
class Sample:
    sha256: str
    family: str
    source: str
    expect_rules: list[str]
    note: str


def parse_lock(path: Path) -> list[Sample]:
    samples: list[Sample] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = raw.rstrip("\n").split("\t")
        if len(parts) < 4:
            sys.exit(f"{path}:{lineno}: esperado >= 4 colunas separadas por TAB")
        sha, family, source, expect = (p.strip() for p in parts[:4])
        note = parts[4].strip() if len(parts) > 4 else ""
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha.lower()):
            sys.exit(f"{path}:{lineno}: sha256 inválido {sha!r}")
        rules = [] if expect in ("", "-") else [r.strip() for r in expect.split(",") if r.strip()]
        samples.append(Sample(sha.lower(), family, source, rules, note))
    return samples


def mb_download(sha256: str, api_key: str) -> bytes:
    data = urllib.parse.urlencode({"query": "get_file", "sha256_hash": sha256}).encode()
    req = urllib.request.Request(
        MB_API, data=data, headers={"Auth-Key": api_key, "User-Agent": "yara-x-detection-rules-ci"}
    )
    # URL fixa (constante MB_API, https); o esquema não vem de input.
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 # nosec B310
        body: bytes = resp.read(MAX_SAMPLE_BYTES + 1)
    if len(body) > MAX_SAMPLE_BYTES:
        raise RuntimeError("resposta maior que o limite")
    if body[:2] != b"PK":
        try:
            msg = json.loads(body.decode("utf-8", "replace")).get("query_status", "?")
        except json.JSONDecodeError:
            msg = repr(body[:120])
        raise RuntimeError(f"MalwareBazaar: {msg}")
    return body


def extract_sample(zip_bytes: bytes, dest_dir: Path) -> Path:
    import pyzipper

    with pyzipper.AESZipFile(io.BytesIO(zip_bytes)) as zf:
        zf.setpassword(ZIP_PASSWORD)
        names = [n for n in zf.namelist() if not n.endswith("/")]
        if len(names) != 1:
            raise RuntimeError(f"zip com {len(names)} entradas; esperado 1")
        info = zf.getinfo(names[0])
        if info.file_size > MAX_SAMPLE_BYTES:
            raise RuntimeError("amostra maior que o limite")
        out = dest_dir / "sample.bin"
        with zf.open(info) as src, out.open("wb") as dst:
            shutil.copyfileobj(src, dst, 1 << 20)
    os.chmod(out, 0o600)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lock", type=Path, default=yrlib.REPO_ROOT / "tests" / "samples.lock")
    ap.add_argument("--strict", action="store_true", help="falhar se expect_rules não casar")
    args = ap.parse_args(argv)

    api_key = os.environ.get("MALWAREBAZAAR_API_KEY", "").strip()
    if not api_key:
        print("::warning::MALWAREBAZAAR_API_KEY ausente; pulando download de amostras reais")
        return 0

    samples = parse_lock(args.lock)
    if not samples:
        print("samples.lock sem entradas ativas; nada a fazer")
        return 0

    rules, _index = yrlib.load_all_rules(strict=False)
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(120)

    failures: list[str] = []
    tmp = Path(tempfile.mkdtemp(prefix="yara-samples-"))
    os.chmod(tmp, 0o700)
    try:
        for s in samples:
            work = tmp / s.sha256[:16]
            work.mkdir(mode=0o700)
            try:
                zip_bytes = mb_download(s.sha256, api_key)
                path = extract_sample(zip_bytes, work)
                data = path.read_bytes()
                actual = hashlib.sha256(data).hexdigest()
                if actual != s.sha256:
                    failures.append(f"{s.sha256[:16]}: sha256 do arquivo extraído difere ({actual[:16]})")
                    continue
                matched = sorted(m.identifier for m in scanner.scan(data).matching_rules)
                missing = [r for r in s.expect_rules if r not in matched]
                status = "ok" if not missing else "MISS"
                print(
                    f"{status} {s.sha256[:16]} {s.family:20s} matched={matched or '-'} expected={s.expect_rules or '-'}"
                )
                if missing:
                    failures.append(f"{s.sha256[:16]} ({s.family}): não casou {missing}")
            except (urllib.error.URLError, RuntimeError, OSError) as e:
                print(f"ERRO {s.sha256[:16]} {s.family}: {e}")
                failures.append(f"{s.sha256[:16]}: {e}")
            finally:
                shutil.rmtree(work, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{len(samples)} amostra(s), {len(failures)} problema(s)")
    for f in failures:
        print(f"  - {f}")
    return 1 if (failures and args.strict) else 0


if __name__ == "__main__":
    sys.exit(main())

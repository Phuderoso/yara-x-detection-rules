"""Gera executáveis PE64 sintéticos, válidos o bastante para o módulo `pe` do
YARA-X parsear (`pe.is_pe`, seções, imports vazios), sem conter nada executável.

Serve para testar regras *sem* commitar malware no repositório: cada fixture
carrega só os artefatos que a regra espera (strings, stub hex), embutidos em um
container PE realista (headers + .text + .rdata + .data).
"""

from __future__ import annotations

import random
import struct
from typing import Any

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
IMAGE_BASE = 0x140000000


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def _rand_bytes(n: int, seed: int) -> bytes:
    # Fixture determinística, não é uso criptográfico.
    return random.Random(seed).randbytes(n)  # noqa: S311 # nosec B311


def build_pe(
    *,
    text: bytes = b"",
    rdata: bytes = b"",
    data: bytes = b"",
    min_size: int = 12 * 1024,
    seed: int = 1,
    extra_sections: int = 0,
) -> bytes:
    """Monta um PE64 com .text/.rdata/.data e, opcionalmente, seções vazias
    extras (para testar limites como `pe.sections.len() < N`).

    O arquivo é preenchido com bytes pseudoaleatórios determinísticos em .data
    até atingir `min_size`, para que filtros de `filesize` e entropia tenham
    algo realista para olhar.
    """
    sections: list[tuple[bytes, bytes, int]] = [
        (b".text", text or _rand_bytes(0x400, seed + 1), 0x60000020),  # CODE|EXEC|READ
        (b".rdata", rdata or b"\x00" * 0x100, 0x40000040),  # INIT_DATA|READ
    ]
    for i in range(extra_sections):
        sections.append((f".s{i}".encode().ljust(8, b"\x00")[:8], b"\x00" * 0x40, 0x40000040))

    header_size = _align(0x80 + 4 + 20 + 240 + 40 * (len(sections) + 1), FILE_ALIGN)
    used = header_size + sum(_align(len(c), FILE_ALIGN) for _, c, _ in sections)
    pad = max(len(data), min_size - used)
    data_section = data + _rand_bytes(max(0, pad - len(data)), seed + 2)
    sections.append((b".data", data_section, 0xC0000040))  # INIT_DATA|READ|WRITE

    # Layout
    raw_ptr = header_size
    rva = SECT_ALIGN
    laid: list[dict[str, Any]] = []
    for name, content, chars in sections:
        raw_size = _align(len(content), FILE_ALIGN)
        laid.append(
            {
                "name": name,
                "content": content,
                "chars": chars,
                "rva": rva,
                "vsize": len(content),
                "raw_ptr": raw_ptr,
                "raw_size": raw_size,
            }
        )
        raw_ptr += raw_size
        rva += _align(max(len(content), 1), SECT_ALIGN)
    size_of_image = rva
    text_sec = laid[0]

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<H", dos, 0x3C, 0x80)
    dos[0x40 : 0x40 + 14] = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
    dos[0x4E : 0x4E + 39] = b"This program cannot be run in DOS mode."

    coff = struct.pack(
        "<IHHIIIHH",
        0x00004550,  # "PE\0\0"
        0x8664,  # AMD64
        len(laid),
        0x66F00000,  # TimeDateStamp
        0,
        0,
        240,  # SizeOfOptionalHeader (PE32+)
        0x0022,  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    opt = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,  # PE32+
        14,
        0,  # linker version
        text_sec["raw_size"],  # SizeOfCode
        sum(s["raw_size"] for s in laid[1:]),  # SizeOfInitializedData
        0,  # SizeOfUninitializedData
        text_sec["rva"],  # AddressOfEntryPoint
        text_sec["rva"],  # BaseOfCode
        IMAGE_BASE,
        SECT_ALIGN,
        FILE_ALIGN,
        6,
        0,  # OS version
        0,
        0,  # image version
        6,
        0,  # subsystem version
        0,  # Win32VersionValue
        size_of_image,
        header_size,
        0,  # CheckSum
        2,  # SUBSYSTEM_WINDOWS_GUI
        0x8160,  # DllCharacteristics: HIGH_ENTROPY_VA|DYNAMIC_BASE|NX_COMPAT|TERMINAL_SERVER_AWARE
        0x100000,
        0x1000,  # stack reserve/commit
        0x100000,
        0x1000,  # heap reserve/commit
        0,  # LoaderFlags
        16,  # NumberOfRvaAndSizes
    )
    opt += b"\x00" * (8 * 16)  # data directories vazios
    assert len(opt) == 240

    sect_hdrs = b"".join(
        struct.pack(
            "<8sIIIIIIHHI",
            s["name"].ljust(8, b"\x00"),
            s["vsize"],
            s["rva"],
            s["raw_size"],
            s["raw_ptr"],
            0,
            0,
            0,
            0,
            s["chars"],
        )
        for s in laid
    )

    out = bytearray(bytes(dos) + coff + opt + sect_hdrs)
    out += b"\x00" * (header_size - len(out))
    for s in laid:
        assert len(out) == s["raw_ptr"]
        out += s["content"].ljust(s["raw_size"], b"\x00")
    return bytes(out)


def cstrings(*items: str | bytes) -> bytes:
    """Concatena strings como C-strings NUL-terminadas, do jeito que ficam em .rdata."""
    out = b""
    for it in items:
        out += (it.encode("ascii") if isinstance(it, str) else it) + b"\x00"
    return out

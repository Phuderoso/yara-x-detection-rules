"""Casos de teste das regras: fixtures sintéticas + regras que DEVEM e que NÃO
DEVEM casar.

Cada caso é construído em memória por `build()`; nada binário é commitado.
Os negativos são tão importantes quanto os positivos: eles provam que a regra
exige a âncora (e não dispara só com APIs genéricas, ou com a string fora de
um PE).

Para adicionar uma regra nova: crie seus casos aqui e referencie o nome dela
em `expect_match` / `expect_no_match`. O runner (scripts/test_rules.py) falha
se alguma regra em rules/ não tiver pelo menos um positivo e um negativo.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from eicar import eicar, eicar_zip
from fakepe import build_pe, cstrings

FAMILYX = "MAL_Win_Loader_FamilyX_ConfigMarker"
FAMILYX_MEM = "MAL_Win_Loader_FamilyX_InMemory"
EICAR_FILE = "TEST_Multi_EICAR_File"
EICAR_ZIP = "TEST_Multi_EICAR_InZip_Stored"
WANNACRY = "MAL_Win_Ransomware_WannaCry_Strings"
ALL_RULES = [FAMILYX, FAMILYX_MEM, EICAR_FILE, EICAR_ZIP, WANNACRY]


def _except(*names: str) -> list[str]:
    return [r for r in ALL_RULES if r not in names]


# Stub do decoder da Family X: `48 8B 0D [4] 48 85 C9 74 ?? 0F B6 01 34 ?? 88 01 48 FF C1`
# Duas "compilações" com disp32/rel8/immediate diferentes, para provar que os
# wildcards estão no lugar certo.
DECODER_BUILD_A = bytes.fromhex("48 8B 0D 10 20 00 00 48 85 C9 74 1A 0F B6 01 34 5A 88 01 48 FF C1".replace(" ", ""))
DECODER_BUILD_B = bytes.fromhex("48 8B 0D F4 3B 01 00 48 85 C9 74 0E 0F B6 01 34 C3 88 01 48 FF C1".replace(" ", ""))

INJECT_APIS = ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess")


def memory_region(*chunks: bytes, size: int = 256 * 1024, seed: int = 99) -> bytes:
    """Região de memória sintética: bytes pseudoaleatórios com os artefatos no
    meio, sem cabeçalho PE (como um VAD dump ou uma seção já mapeada)."""
    import random

    rnd = random.Random(seed)  # noqa: S311 # nosec B311
    buf = bytearray(rnd.randbytes(size))
    pos = size // 4
    for chunk in chunks:
        buf[pos : pos + len(chunk)] = chunk
        pos += len(chunk) + rnd.randrange(512, 4096)
    return bytes(buf)


@dataclass
class Case:
    name: str
    build: Callable[[], bytes]
    expect_match: list[str] = field(default_factory=list)
    expect_no_match: list[str] = field(default_factory=list)
    note: str = ""


CASES: list[Case] = [
    # ---- Positivos: uma âncora + contexto de injeção, em builds diferentes ----
    Case(
        name="familyx_marker_build1",
        build=lambda: build_pe(rdata=cstrings("CONFIG_START::mutex_id::", *INJECT_APIS), seed=11),
        expect_match=[FAMILYX],
        expect_no_match=[FAMILYX_MEM],
        note="âncora = config marker (uma string só não basta para a regra de memória)",
    ),
    Case(
        name="familyx_pdb_only",
        build=lambda: build_pe(
            rdata=cstrings("WriteProcessMemory", "CreateRemoteThread"),
            data=cstrings("C:\\build\\loader_v3\\src\\inject.c"),
            seed=12,
        ),
        expect_match=[FAMILYX],
        expect_no_match=[FAMILYX_MEM],
        note="build que dropou o marker mas manteve o PDB",
    ),
    Case(
        name="familyx_decoder_build_a",
        build=lambda: build_pe(text=b"\x90" * 64 + DECODER_BUILD_A + b"\xc3", rdata=cstrings(*INJECT_APIS), seed=13),
        expect_match=[FAMILYX, FAMILYX_MEM],
        note="sem nenhuma string única; só o hex do decoder",
    ),
    Case(
        name="familyx_decoder_build_b",
        build=lambda: build_pe(text=b"\xcc" * 300 + DECODER_BUILD_B, rdata=cstrings(*INJECT_APIS), seed=14),
        expect_match=[FAMILYX, FAMILYX_MEM],
        note="mesmo decoder, relinkado (disp32/rel8/imm diferentes)",
    ),
    Case(
        name="familyx_beacon_ua",
        build=lambda: build_pe(rdata=cstrings("X-FamilyX-Beacon: 1", "VirtualAllocEx", "CreateRemoteThread"), seed=15),
        expect_match=[FAMILYX],
        expect_no_match=[FAMILYX_MEM],
    ),
    # ---- Memória: região mapeada, sem MZ, sem filesize útil, config já decifrada ----
    Case(
        name="familyx_memory_region_decoded_config",
        build=lambda: memory_region(
            cstrings("CONFIG_START::mutex_id::", "mutex_id=Global\\FamilyX_7f3a", *INJECT_APIS), seed=51
        ),
        expect_match=[FAMILYX_MEM],
        expect_no_match=[FAMILYX],
        note="a regra de arquivo exige MZ+pe: em memória ela é cega; a de memória vê a config em claro",
    ),
    Case(
        name="familyx_memory_region_decoder_only",
        build=lambda: memory_region(DECODER_BUILD_B, seed=52),
        expect_match=[FAMILYX_MEM],
        expect_no_match=[FAMILYX],
        note="só o stub do decoder, mapeado",
    ),
    # ---- Negativos: provam que a regra não vira detector de "qualquer injector" ----
    Case(
        name="generic_injector_apis_only",
        build=lambda: build_pe(rdata=cstrings(*INJECT_APIS, "NtUnmapViewOfSection"), seed=21),
        expect_no_match=[FAMILYX, FAMILYX_MEM],
        note="APIs de injeção sem âncora: ferramenta legítima / outra família",
    ),
    Case(
        name="marker_in_text_file",
        build=lambda: b"ioc notes\nCONFIG_START::mutex_id:: WriteProcessMemory CreateRemoteThread\n" * 300,
        expect_no_match=[FAMILYX, FAMILYX_MEM],
        note="string da âncora num .txt/relatório: o gate de MZ+PE barra a de arquivo; uma string só não basta para a de memória",
    ),
    Case(
        name="marker_without_context",
        build=lambda: build_pe(rdata=cstrings("CONFIG_START::mutex_id::"), seed=22),
        expect_no_match=[FAMILYX, FAMILYX_MEM],
        note="âncora sem nenhuma API de injeção (ex.: scanner/CTI tool que embute o IOC)",
    ),
    Case(
        name="familyx_strings_in_bloated_pe",
        build=lambda: build_pe(
            rdata=cstrings("CONFIG_START::mutex_id::", *INJECT_APIS), min_size=3 * 1024 * 1024, seed=23
        ),
        expect_no_match=[FAMILYX, FAMILYX_MEM],
        note="acima de 2MB: fora do envelope da família (ajuste a regra se um build real passar disso)",
    ),
    Case(
        name="familyx_strings_many_sections",
        build=lambda: build_pe(rdata=cstrings("CONFIG_START::mutex_id::", *INJECT_APIS), extra_sections=10, seed=24),
        expect_no_match=[FAMILYX, FAMILYX_MEM],
        note="13 seções: fora do envelope estrutural",
    ),
    # ---- EICAR: o alvo publicado, gerado em memória (tests/eicar.py) ----
    Case(
        name="eicar_published_68_bytes",
        build=eicar,
        expect_match=[EICAR_FILE],
        expect_no_match=_except(EICAR_FILE),
        note="os 68 bytes publicados; sha256 conferido em tests/test_eicar.py",
    ),
    Case(
        name="eicar_with_trailing_whitespace",
        build=lambda: eicar(b"\r\n" + b" " * 40),
        expect_match=[EICAR_FILE],
        expect_no_match=_except(EICAR_FILE),
        note="a especificação permite espaço em branco depois, até 128 bytes no total",
    ),
    Case(
        name="eicar_in_zip_stored",
        build=lambda: eicar_zip(stored=True),
        expect_match=[EICAR_ZIP],
        expect_no_match=_except(EICAR_ZIP),
        note="zip sem compressão: o YARA vê os bytes",
    ),
    Case(
        name="eicar_in_zip_stored_second_member",
        build=lambda: eicar_zip(stored=True, name="samples/eicar.com", padding=3),
        expect_match=[EICAR_ZIP],
        expect_no_match=_except(EICAR_ZIP),
        note="não é o primeiro membro e tem nome com diretório",
    ),
    Case(
        name="eicar_in_zip_deflated_is_opaque",
        build=lambda: eicar_zip(stored=False),
        expect_no_match=ALL_RULES,
        note="limite documentado: zip deflatado não casa; o YARA-X não inflaciona. Precisa de unpacker antes",
    ),
    Case(
        name="eicar_string_inside_document",
        build=lambda: b"AV test notes\n" * 20 + eicar() + b"\n" + b"more notes\n" * 20,
        expect_no_match=ALL_RULES,
        note="a string no meio de um texto (relatório, .yar, dump de AV): não é o arquivo de teste",
    ),
    Case(
        name="eicar_at_zero_but_file_too_big",
        build=lambda: eicar() + b"\n" + b"x" * 200,
        expect_no_match=ALL_RULES,
        note="começa com o EICAR mas passa de 128 bytes: fora da especificação",
    ),
    # ---- WannaCry: strings de relatórios públicos em PE sintético; nenhuma amostra ----
    Case(
        name="wannacry_worm_killswitch",
        build=lambda: build_pe(
            rdata=cstrings("http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com", "mssecsvc2.0", "tasksche.exe"),
            seed=61,
        ),
        expect_match=[WANNACRY],
        expect_no_match=_except(WANNACRY),
        note="componente worm: kill switch + nome do serviço",
    ),
    Case(
        name="wannacry_dropper_zip_password",
        build=lambda: build_pe(rdata=cstrings("WNcry@2ol7"), seed=62),
        expect_match=[WANNACRY],
        expect_no_match=_except(WANNACRY),
        note="só a senha do zip embutido basta",
    ),
    Case(
        name="wannacry_components_pair",
        build=lambda: build_pe(rdata=cstrings("c.wnry", "r.wnry", "t.wnry", "u.wnry", "@WanaDecryptor@.exe"), seed=63),
        expect_match=[WANNACRY],
        expect_no_match=_except(WANNACRY),
        note="dois ou mais nomes de componente num PE",
    ),
    Case(
        name="wannacry_ioc_list_text",
        build=lambda: (
            b"WannaCry IOCs\niuqerfsodp9ifjaposdfjhgosurijfaewrwergwea\nWNcry@2ol7\nmssecsvc2.0\ntasksche.exe\nc.wnry\n"
            * 50
        ),
        expect_no_match=ALL_RULES,
        note="lista de IOC em texto: sem MZ, não casa. É o FP clássico de regra de ransomware",
    ),
    Case(
        name="wannacry_single_weak_string_in_pe",
        build=lambda: build_pe(rdata=cstrings("tasksche.exe", *INJECT_APIS), seed=64),
        expect_no_match=ALL_RULES,
        note="um nome de componente só, num PE: ferramenta de resposta/limpeza, não a família",
    ),
    Case(
        name="wannacry_strings_in_huge_pe",
        build=lambda: build_pe(rdata=cstrings("WNcry@2ol7", "c.wnry", "r.wnry"), min_size=9 * 1024 * 1024, seed=65),
        expect_no_match=ALL_RULES,
        note="acima de 8MB: fora do envelope dos componentes públicos (ex.: instalador de AV com assinaturas embutidas)",
    ),
]

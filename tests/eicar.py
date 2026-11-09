"""EICAR: o único alvo de detecção real e benigno que cabe num repo sem malware.

O arquivo de teste da EICAR (https://www.eicar.org/download-anti-malware-testfile/) é uma
string ASCII de 68 bytes que todo antivírus detecta por convenção. É um programa COM
válido e inofensivo (imprime "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"), publicado para
exatamente isto: provar que um scanner vê o que diz ver, sem precisar de malware.

Por que ele aqui: as regras deste repo eram provadas só com fixtures sintéticas da
FamilyX fictícia. O EICAR é um alvo publicado, com sha256 conhecido
(275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f), que a regra tem de
casar byte a byte. A fixture aqui É o alvo, não um substituto dele.

Por que em hex: o texto literal da string dispara antivírus em qualquer arquivo que o
contenha, inclusive um .py ou .yar no checkout do runner Windows ou no GitHub. O hex
abaixo não é o padrão que os AVs buscam (eles buscam os bytes ASCII). O arquivo em si
nunca é commitado nem escrito em disco pelos testes; `test_rules.py --dump` é a única
coisa que o escreve, e só se você pedir.
"""

from __future__ import annotations

import io
import zipfile

EICAR_HEX = (
    "58354f2150254041505b345c505a58353428505e2937434329377d"
    "2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a"
)
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_LEN = 68


def eicar(trailer: bytes = b"") -> bytes:
    """Os 68 bytes publicados, opcionalmente com o sufixo de espaço em branco que a
    especificação permite (o arquivo todo tem de caber em 128 bytes)."""
    return bytes.fromhex(EICAR_HEX) + trailer


def eicar_zip(*, stored: bool = True, name: str = "eicar.com", padding: int = 0) -> bytes:
    """EICAR dentro de um zip. `stored=True` (sem compressão) deixa os bytes visíveis
    para o YARA; `stored=False` (deflate) não, e isso é um limite real documentado na
    regra. `padding` adiciona um arquivo inerte antes, para o EICAR não ficar no
    primeiro local header."""
    buf = io.BytesIO()
    method = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(buf, "w", compression=method) as zf:
        if padding:
            zf.writestr("readme.txt", b"test archive\n" * padding, compress_type=zipfile.ZIP_STORED)
        zf.writestr(name, eicar(), compress_type=method)
    return buf.getvalue()

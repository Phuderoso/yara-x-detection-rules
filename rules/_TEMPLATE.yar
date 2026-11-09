// Template de regra. Copie para rules/<plataforma>/<NOME>.yar e preencha.
// Arquivos com prefixo "_" são ignorados pelo lint/CI (este não compila: strings vazias).
//
// Convenção de nome: <PREFIXO>_<Plataforma>_<Tipo>_<Família>_<Traço>
//   PREFIXO: MAL (família conhecida) | HUNT (hipótese, larga) | SUSP (suspeito, genérico)
//            TEST (alvo de teste publicado e benigno, ex.: EICAR)
// Meta obrigatório (scripts/lint_rules.py): id, version, author, date, modified,
//   description, hash, status, purpose, mitre_attack, scope.
// Ciclo de vida: experimental → test → stable → deprecated.
// Gate de promoção: purpose=blocking exige status=stable e confidence=high.
// Formate com `make fmt` antes de abrir o PR. Gere o id com `python -c "import uuid; print(uuid.uuid4())"`.

import "pe"

rule MAL_Win_Type_Family_Trait {
  meta:
    id           = "00000000-0000-4000-8000-000000000000"
    version      = 1
    author       = ""
    date         = "YYYY-MM-DD"
    modified     = "YYYY-MM-DD"
    description  = ""
    malware      = ""
    status       = "experimental" // experimental | test | stable | deprecated
    confidence   = "medium"       // low | medium | high
    severity     = "medium"       // low | medium | high | critical
    tlp          = "amber"        // clear | green | amber | red
    reference    = ""
    hash         = ""             // hash da sample-semente (md5/sha1/sha256)
    purpose      = "hunting"      // hunting | triage | blocking
    mitre_attack = "none"         // "T1055.002, T1027" — só se for verdade
    scope        = "file"         // file | memory | both (memory: sem uintN(0), filesize, pe.*)
    license      = "CC0-1.0"      // o repositório inteiro é CC0 (LICENSE)
    // engine    = "yara-x"       // opcional: declare se a regra usa sintaxe só do YARA-X

  strings:
    // Âncoras (únicas da família): config marker, PDB, mutex, UA interno,
    // hex de lógica (decoder) com wildcard só em offsets/immediates.
    $anchor_1 = "" ascii

    // Contexto (fraco sozinho): APIs, strings de import, etc.
    $ctx_1 = "" ascii
    $ctx_2 = "" ascii

  condition:
    // magic → filesize → PE barato → strings → regex/entropia
    uint16(0) == 0x5A4D and
    filesize < 5MB and
    pe.is_pe and
    any of ($anchor_*) and
    all of ($ctx_*)
}

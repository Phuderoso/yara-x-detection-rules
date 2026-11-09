import "pe"

rule MAL_Win_Loader_FamilyX_ConfigMarker {
  meta:
    id           = "f2522e58-c8f9-4ced-aea3-97419582c3f4"
    version      = 2
    author       = "detection-eng"
    date         = "2026-09-17"
    modified     = "2026-11-09"
    description  = "Family X loader: unique config marker + call-site stub"
    malware      = "FamilyX"
    status       = "test"
    confidence   = "high"
    severity     = "high"
    tlp          = "amber"
    reference    = "internal-ir-2026-041"
    // sample que gerou a regra (placeholder: troque pelo hash real da semente)
    hash         = "e3b0c44298fc1c149afbf4c8996fb924"
    // hunting | triage | blocking — a CI usa isso para decidir o gate de FP
    purpose      = "triage"
    mitre_attack = "T1055.002, T1027"
    // file: a condição exige MZ, filesize e pe.*; a variante de memória é outra regra
    scope        = "file"
    license      = "CC0-1.0"
    // pe.sections.len() não existe no YARA 4.x; ver scripts/compat_yara4.py
    engine       = "yara-x"

  strings:
    // Âncoras: qualquer uma sozinha já justifica o hit
    $marker = "CONFIG_START::mutex_id::" ascii
    $pdb    = "\\loader_v3\\src\\inject.c" ascii
    $ua     = "X-FamilyX-Beacon:" ascii
    // Stub do decoder: wildcards só onde o compilador/linker mexe
    // (RIP-relative disp32, rel8 do jz e o immediate do XOR)
    $decode = { 48 8B 0D [4] 48 85 C9 74 ?? 0F B6 01 34 ?? 88 01 48 FF C1 }

    // Contexto: fracas sozinhas, só reforçam a âncora
    $api_wpm = "WriteProcessMemory" ascii
    $api_crt = "CreateRemoteThread" ascii
    $api_vae = "VirtualAllocEx" ascii

  condition:
    // barato → caro, da esquerda para a direita
    uint16(0) == 0x5A4D and
    filesize > 8KB and
    filesize < 2MB and
    pe.is_pe and
    pe.sections.len() < 12 and
    (
      $marker or $pdb or $ua or $decode
    ) and
    2 of ($api_*)
}

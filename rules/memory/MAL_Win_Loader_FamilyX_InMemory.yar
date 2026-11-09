rule MAL_Win_Loader_FamilyX_InMemory {
  meta:
    id           = "3c6a1f0e-7b2d-4e8a-9c41-5d2f8a0b6e17"
    version      = 1
    author       = "detection-eng"
    date         = "2026-11-09"
    modified     = "2026-11-09"
    description  = "Family X loader mapeado em memória: decoder stub ou config decifrada + marcadores; sem MZ/filesize/pe"
    malware      = "FamilyX"
    status       = "experimental"
    confidence   = "medium"
    severity     = "high"
    tlp          = "amber"
    reference    = "internal-ir-2026-041"
    hash         = "e3b0c44298fc1c149afbf4c8996fb924"
    purpose      = "hunting"
    mitre_attack = "T1055.002, T1027"
    // memory: a condição não usa uint16(0), filesize nem pe.*; vale para VAD dump, procdump e imagem via Volatility
    scope        = "memory"
    license      = "CC0-1.0"

  strings:
    // Mesmas âncoras da regra de arquivo...
    $marker = "CONFIG_START::mutex_id::" ascii
    $pdb    = "\\loader_v3\\src\\inject.c" ascii
    $ua     = "X-FamilyX-Beacon:" ascii
    $decode = { 48 8B 0D [4] 48 85 C9 74 ?? 0F B6 01 34 ?? 88 01 48 FF C1 }
    // ...mais o que só existe depois do decoder rodar: a config em claro
    $cfg    = "mutex_id=Global\\FamilyX_" ascii

  condition:
    // O stub do decoder é código mapeado e sobrevive ao unpack; as strings
    // isoladas são fracas (podem estar num scanner, num relatório), por isso 2.
    $decode or 2 of ($marker, $pdb, $ua, $cfg)
}

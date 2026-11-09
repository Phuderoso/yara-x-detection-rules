rule TEST_Multi_EICAR_InZip_Stored {
  meta:
    id           = "0d85cd57-3805-4b9b-9905-47b9dea7c380"
    version      = 1
    author       = "detection-eng"
    date         = "2026-11-09"
    modified     = "2026-11-09"
    description  = "EICAR test file inside a ZIP archive stored without compression (deflated entries are opaque to YARA: documented limit)"
    malware      = "EICAR-Test-File"
    status       = "test"
    confidence   = "high"
    severity     = "low"
    tlp          = "clear"
    reference    = "https://www.eicar.org/download-anti-malware-testfile/"
    // sha256 do eicar.com de 68 bytes (o conteúdo); o zip em si varia com nome/timestamps
    hash         = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    purpose      = "triage"
    mitre_attack = "none"
    scope        = "file"
    license      = "CC0-1.0"
    engine       = "any"

  strings:
    // Mesma string publicada, em hex (ver TEST_Multi_EICAR_File)
    $eicar         = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A }  // allow-hex-as-text: o texto literal dispara AV
    // Local file header de um membro ARMAZENADO (method 0x0000) e logo depois o EICAR:
    // PK\x03\x04, versão (2 bytes), flags (2), método = 00 00. Depois: mtime/mdate (4),
    // crc32 (4), tamanhos (8), name_len (2), extra_len (2), nome (n), extra (m), dados.
    // [8] = mtime/mdate + crc32; [4-68] = name_len + extra_len + nome + extra (até 64 bytes).
    $stored_member = { 50 4B 03 04 ?? ?? ?? ?? 00 00 [8] 44 00 00 00 44 00 00 00 [4-68] 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A }

  condition:
    // Zip (local header no offset 0), e o EICAR aparece como dado de um membro
    // armazenado: tamanho comprimido = descomprimido = 0x44 (68). Zip deflatado não
    // casa: o YARA-X não inflaciona; isso é escopo de um unpacker antes do scan.
    uint32(0) == 0x04034B50 and
    filesize < 1MB and
    $eicar and
    $stored_member
}

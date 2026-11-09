rule TEST_Multi_EICAR_File {
  meta:
    id           = "557866dc-2447-4b56-b1ca-141721779893"
    version      = 1
    author       = "detection-eng"
    date         = "2026-11-09"
    modified     = "2026-11-09"
    description  = "EICAR standard anti-virus test file: the 68-byte published string at offset 0, whole file <= 128 bytes (spec)"
    malware      = "EICAR-Test-File"
    status       = "test"
    confidence   = "high"
    severity     = "low"
    tlp          = "clear"
    reference    = "https://www.eicar.org/download-anti-malware-testfile/"
    // sha256 do arquivo publicado de 68 bytes; tests/eicar.py gera a fixture e confere este hash
    hash         = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    purpose      = "triage"
    mitre_attack = "none"
    scope        = "file"
    license      = "CC0-1.0"
    engine       = "any"

  strings:
    // A string publicada, em hex de propósito: o texto literal dispara qualquer AV que
    // encontre este .yar (checkout no runner Windows, scanner do GitHub). Os AVs
    // buscam os bytes ASCII, não a representação hex.
    // (A string em claro não está nem neste comentário: tests/test_eicar.py falha se
    // algum arquivo versionado a contiver.)
    $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A }  // allow-hex-as-text: o texto literal dispara AV

  condition:
    // Especificação EICAR: a string é o início do arquivo; pode haver espaço em branco
    // depois; o arquivo inteiro não passa de 128 bytes. Fora disso (a string no meio de
    // um documento, de um .yar, de um dump de AV) não é o arquivo de teste e não casa.
    filesize <= 128 and
    $eicar at 0
}

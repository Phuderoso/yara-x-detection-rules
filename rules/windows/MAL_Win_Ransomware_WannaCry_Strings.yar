rule MAL_Win_Ransomware_WannaCry_Strings {
  meta:
    id           = "1ad79fe1-7886-4d78-b8b7-6c6498b99e98"
    version      = 1
    author       = "detection-eng"
    date         = "2026-11-09"
    modified     = "2026-11-09"
    description  = "WannaCry / WanaCrypt0r (May 2017 worm): kill-switch domain, embedded-zip password or 2+ component names, in a PE. Strings only from public vendor reports; no sample in the repo"
    malware      = "WannaCry"
    status       = "test"
    confidence   = "high"
    severity     = "critical"
    tlp          = "clear"
    // Fontes das strings e dos hashes (todas públicas, 2017-05):
    //   Kaspersky Securelist, "WannaCry ransomware used in widespread attacks all over the world"
    //     https://securelist.com/wannacry-ransomware-used-in-widespread-attacks-all-over-the-world/78351/
    //   Microsoft, "WannaCrypt ransomware worm targets out-of-date systems"
    //     https://www.microsoft.com/en-us/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/
    //   Cisco Talos, "Player 3 Has Entered the Game: Say Hello to 'WannaCry'"
    //     https://blog.talosintelligence.com/wannacry/
    //   MalwareTech, "How to Accidentally Stop a Global Cyber Attacks" (kill switch)
    //     https://www.malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html
    //   CISA Alert TA17-132A, "Indicators Associated With WannaCry Ransomware"
    //     https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware
    reference    = "https://securelist.com/wannacry-ransomware-used-in-widespread-attacks-all-over-the-world/78351/, https://blog.talosintelligence.com/wannacry/, https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware"
    // tasksche.exe (encryptor dropper) e mssecsvc.exe (worm), sha256 citados nos relatórios acima
    hash         = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa, 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
    purpose      = "triage"
    // T1486 Data Encrypted for Impact; T1210 Exploitation of Remote Services (EternalBlue/SMBv1); T1543.003 Windows Service
    mitre_attack = "T1486, T1210, T1543.003"
    scope        = "file"
    license      = "CC0-1.0"
    engine       = "any"

  strings:
    // Âncoras: cada uma sozinha identifica a família
    // domínio kill switch consultado pelo worm (mssecsvc.exe) antes de propagar
    $killswitch = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea" ascii
    // senha do zip embutido em tasksche.exe que carrega os componentes .wnry
    $zip_pw     = "WNcry@2ol7" ascii

    // Componentes: fracos sozinhos (aparecem em IOC lists e ferramentas), fortes em par dentro de um PE
    $svc       = "mssecsvc2.0" ascii
    $hdr       = "WANACRY!" ascii
    $decryptor = "@WanaDecryptor@" ascii
    $tasksche  = "tasksche.exe" ascii
    $wnry_c    = "c.wnry" ascii
    $wnry_r    = "r.wnry" ascii
    $wnry_t    = "t.wnry" ascii
    $wnry_u    = "u.wnry" ascii

  condition:
    // PE pequeno (os componentes públicos têm 3-4 MB; o worm, ~3.7 MB), fora disso é outra coisa
    uint16(0) == 0x5A4D and
    filesize < 8MB and
    (
      $killswitch or
      $zip_pw or
      2 of ($svc, $hdr, $decryptor, $tasksche, $wnry_*)
    )
}

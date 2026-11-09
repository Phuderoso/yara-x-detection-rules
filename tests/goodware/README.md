# Goodware pack (local)

Coloque aqui binários **limpos** para o gate de FP (`make goodware`). O conteúdo
deste diretório é ignorado pelo git; só este README é versionado.

Sugestão mínima, na ordem em que mais pegam FP:

- `C:\Windows\System32` e `SysWOW64` (Windows 10/11)
- Visual C++ Redistributables, .NET runtime
- Chrome, Edge, Firefox, Office, Adobe Reader
- Python embeddable, Node.js, Go toolchain (binários estaticamente linkados)
- Instaladores: NSIS, Inno Setup, 7-Zip SFX, MSI
- Ferramentas de admin/red team legítimas que o SOC usa (Sysinternals, Nmap)
- Amostras de documentos: PDF, DOCX, XLSX, imagens PNG/JPG (entropia alta sem ser malware)

Na CI o pack real é o `C:\Windows\System32` do runner `windows-latest`
(ver `.github/workflows/ci.yml`). Localmente, aponte para outro diretório com
`make goodware GOODWARE=/mnt/goodware`.

O corpus é descrito por um manifesto (`scripts/corpus_manifest.py build DIR -o manifest.json`,
sha256 por arquivo). Os manifestos dos runners da CI ficam em `manifests/` quando fixados;
veja `manifests/README.md`.

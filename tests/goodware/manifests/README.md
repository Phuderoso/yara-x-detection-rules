# Manifests fixados do corpus de goodware

Um arquivo por runner: `ubuntu-latest.json`, `windows-latest.json`. Gerados por
`scripts/corpus_manifest.py build` na própria CI e publicados como artifact
(`reports-linux`, `reports-windows`). Para fixar o corpus, baixe o artifact e
commite o `manifest-<os>.json` aqui com o nome `<os>.json`.

Com o manifesto fixado, cada rodada publica o drift (arquivos adicionados,
removidos, alterados) no job summary. Um FP que aparece junto com drift tem
causa conhecida; um FP sem drift é mudança de regra.

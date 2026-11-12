# yara-x-detection-rules

**Repositório de detection engineering em YARA-X: regras que sobrevivem a corpus limpo, a builds novos da família e a pipelines de hunting barulhentos. CC0.**

[![rules-ci](https://github.com/Phuderoso/yara-x-detection-rules/actions/workflows/ci.yml/badge.svg)](https://github.com/Phuderoso/yara-x-detection-rules/actions/workflows/ci.yml)
[![release](https://github.com/Phuderoso/yara-x-detection-rules/actions/workflows/release.yml/badge.svg)](https://github.com/Phuderoso/yara-x-detection-rules/actions/workflows/release.yml)
[![YARA-X](https://img.shields.io/badge/engine-YARA--X%201.23-blue)](https://virustotal.github.io/yara-x/)
[![license: CC0-1.0](https://img.shields.io/badge/license-CC0--1.0-lightgrey)](LICENSE)

[English](README.md) · Português (Brasil)

Repositório de regras YARA-X com **detection engineering** embutido na CI. Uma regra só é
promovida depois de provar três coisas: casa a família (fixtures positivas, inclusive
builds diferentes), não é um detector genérico (fixtures negativas) e não acende em software
legítimo (gate de goodware real, com diff por PR). O que sai na release são bundles por
`purpose`, assinados.

O raciocínio (o que é uma regra boa, YARA vs YARA-X, onde ela encaixa num pipeline de hunting,
por que regra de arquivo falha em memória) está em [`docs/handbook.md`](docs/handbook.md). O
checklist de contribuição está em [`CONTRIBUTING.md`](CONTRIBUTING.md). O que o repo cobre hoje,
por técnica, faixa, escopo e família, está em [`docs/coverage.md`](docs/coverage.md) (gerado).
Como ele foi construído, rodada a rodada, está em [`journal/`](journal/).

Além da CI, o repo traz duas ferramentas que normalmente ficam no notebook do analista:
[`tools/anchors`](tools/anchors/README.md) extrai âncoras de código de N amostras com
wildcards automáticos só nos operandos que variam, e [`scripts/memscan.py`](scripts/memscan.py)
roda só as regras de escopo de memória em dumps e imagens (Volatility 3).

[![fp-watch](https://github.com/Phuderoso/yara-x-detection-rules/actions/workflows/fp-watch.yml/badge.svg)](https://github.com/Phuderoso/yara-x-detection-rules/actions/workflows/fp-watch.yml) roda toda semana contra um corpus limpo reprodutível e abre uma única issue `fp-regression` quando uma regra stable/test começa a acender em goodware. A saúde das regras (FP, último match verdadeiro, candidatas a deprecated) está em [`docs/health.md`](docs/health.md) (gerado).

## Doutrina

- detecção, não armas
- mapas, não guerra
- nenhum malware vivo no repo: fixtures são sintetizadas, amostras reais são hashes
- nenhum segredo: um secret de CI, lido da plataforma, nunca escrito
- nenhum kit de ataque a host: nada aqui executa, injeta ou persiste em lugar nenhum
- todo FP é lição, não vergonha: vira fixture negativa e linha no journal
- promover devagar, aposentar com honestidade: `experimental → test → stable → deprecated`, nunca apagar
- faz o fork: um fork é uma cabeça nova

## Fluxo

```mermaid
flowchart LR
    A0[N amostras\nda família] -->|tools/anchors\ncapstone · wildcard por operando\nfiltro goodware| A
    A[CTI / IR\nâncora estável] --> B[rules/*.yar\nmeta: id, version,\nstatus, purpose, scope, mitre]
    B --> C[lint\ncompile · meta · unicidade\nstrings · formatação]
    C --> D[fixtures sintéticas\npositivos + negativos\nfakepe]
    D --> E[goodware real\nELF no Linux · PE no Windows\ndiff vs base · orçamento de tempo]
    E --> F{revisão\nPR comment}
    F -->|status: test → stable| G[promoção\nblocking exige stable + high]
    G --> H[release\nbundles por purpose · .yar/.yarc\nSHA256SUMS · cosign keyless]
    H --> I[disco\nhunt.py → JSONL/ECS → SIEM]
    H --> J[memória\nmemscan.py → raw / Volatility 3]
    I -.->|FP / bypass / telemetria| B
    J -.->|FP / bypass / telemetria| B
    W[fp-watch semanal\nrunner + corpus pip por hash\nvs baseline.json] -.->|issue única fp-regression| B
    B -.-> K[docs/coverage.md · docs/health.md\nMITRE · purpose × status · scope\nFP · último match · candidatas a deprecated]
```

## Quickstart

```bash
make setup                 # pip install yara-x
make lint                  # compila + policies de meta/ciclo de vida/unicidade/strings + formatação
make test                  # positivos e negativos de cada regra (fixtures em memória)
make goodware GOODWARE=/mnt/goodware    # gate de FP local
make fmt                   # formatter do YARA-X (yr fmt)

# varredura em disco
python scripts/hunt.py /evidence/2026 --jsonl hits.jsonl
python scripts/hunt.py /evidence/2026 --jsonl hits.ecs.jsonl --format ecs   # campos ECS para o SIEM
python scripts/hunt.py sample.bin -s                                         # strings casadas + offsets

# varredura em memória (só regras scope = memory/both)
python scripts/memscan.py proc_1234.dmp -s --jsonl mem.jsonl --format ecs    # VAD dump / procdump: bytes brutos
python scripts/memscan.py memory.raw --backend vol3                          # imagem completa via Volatility 3

# de N amostras para um rascunho de regra com o hex do decoder
python tools/anchors/extract_anchors.py samples/*.exe --goodware /mnt/goodware \
    --family FamilyX --draft rules/windows/SUSP_Win_FamilyX_CodeAnchors.yar
```

Para desenvolver tooling: `make setup-dev` (ruff, mypy, pytest, bandit, yara-python, pre-commit) e
`make quality`.

## Layout

```text
rules/                        regras, uma por arquivo
  _TEMPLATE.yar               ponto de partida (prefixo "_" = ignorado pela CI)
  windows/MAL_Win_Loader_FamilyX_ConfigMarker.yar   scope = file (MZ, cabeçalho PE, filesize); família fictícia
  windows/MAL_Win_Ransomware_WannaCry_Strings.yar   família pública, strings e hashes de relatórios citados
  memory/MAL_Win_Loader_FamilyX_InMemory.yar        scope = memory (decoder ou config decifrada)
  multi/TEST_Multi_EICAR_File.yar                   o arquivo de teste EICAR publicado (alvo real, benigno)
  multi/TEST_Multi_EICAR_InZip_Stored.yar           EICAR dentro de zip armazenado (deflate = limite documentado)
rules-ci.toml                 limites: strings mínimas, orçamento de tempo, tamanho máximo no corpus
scripts/
  yrlib.py                    compilador com policies, parse de meta, config, helpers
  lint_rules.py               lint (ver "Contrato de uma regra")
  test_rules.py               roda tests/cases.py contra todas as regras
  scan_goodware.py            gate de FP: falha conforme meta.purpose
  report.py                   hits + tempo por regra + fixtures → JSON (unidade de comparação da CI)
  diff_report.py              base vs head → Markdown (PR comment / job summary) + orçamento de performance
  corpus_manifest.py          manifesto sha256 do goodware; drift do runner vira diff
  hunt.py                     varredura operacional: sha256, strings/offsets, JSONL nativo ou ECS
  memscan.py                  memória: só regras scope memory/both; backend raw (chunks) ou Volatility 3
  coverage.py                 gera docs/coverage.md do meta; a CI falha se estiver desatualizado
  health.py                   gera docs/health.md (FP, idade, último match, candidatas a deprecated); conferido na CI
  fp_watch.py                 vigia de FP: corpus pip fixado por hash, comparação com baseline, issue única
  build_bundles.py            bundles por purpose (.yar + .yarc) + manifest + SHA256SUMS
  changelog.py                CHANGELOG a partir de commits e do diff de rules/ entre tags
  compat_yara4.py             matriz de compatibilidade com YARA 4.x (yara-python)
  fetch_samples.py            positivos reais do MalwareBazaar: baixa, escaneia, apaga (manual)
  fmt_rules.py                formatter
tools/anchors/                extrator de âncoras: capstone, superset disassembly, wildcard por operando
tests/
  fakepe.py                   gera PE64 sintéticos válidos para o módulo `pe`
  eicar.py                    monta o EICAR (e o zip) em memória a partir de hex; o literal nunca vai a disco
  cases.py                    fixtures positivas e negativas por regra (PE, memória, EICAR, WannaCry)
  test_eicar.py               sha256 da fixture == hash publicado; nenhum arquivo versionado tem o literal
  test_anchors.py             aceitação do extrator: acha o $decode da FamilyX sozinho
  test_memscan.py             dump sintético, chunks sobrepostos, ECS, parse da saída do vol3
  samples.lock                sha256 + família + fonte de amostras reais (sem binário)
  activity.json               último match verdadeiro por regra (hunt.py / memscan.py --record-activity); alimenta docs/health.md
  test_lint.py, test_tooling.py, test_fp_watch.py, test_health.py   pytest do tooling
  goodware/                   corpus limpo local (ignorado pelo git) + manifests/, baseline.json, pip-corpus.txt
journal/                      diário da construção, estilo case-files, um arquivo por dia
AGENTS.md                     guia para agentes de código (layout, CI local, armadilhas do YARA-X)
CREDITS.md                    linha de autoria (fora do README)
llms.txt                      índice curto para modelos (llmstxt.org)
.github/workflows/ci.yml      lint → fixtures → goodware ELF → diff vs base → goodware PE (windows)
.github/workflows/release.yml tag v* → bundles → cosign → GitHub Release
.github/workflows/fp-watch.yml semanal: corpus limpo reprodutível → regras stable/test → baseline → uma issue
docs/handbook.md              o ofício
docs/coverage.md              painel gerado (MITRE, purpose × status, scope, família, experimentais > 90d)
docs/health.md                painel gerado (status, idade, FP, último match, candidatas a deprecated)
```

Nenhum binário é versionado: fixtures são geradas em memória por `fakepe.py`; goodware e
samples ficam fora do repo (ou só como hash em `samples.lock` e nos manifests).

## Alvos reais sem malware

- **EICAR** (`TEST_Multi_EICAR_File`, `TEST_Multi_EICAR_InZip_Stored`). O
  [arquivo de teste da EICAR](https://www.eicar.org/download-anti-malware-testfile/) é uma string
  publicada de 68 bytes que todo antivírus detecta por convenção; inofensiva, e o único alvo de
  detecção que cabe num repo sem malware. A fixture *é* o alvo: `tests/eicar.py` monta o arquivo a
  partir de hex na hora do teste e `tests/test_eicar.py` confere o sha256 contra o publicado. O
  literal nunca é escrito, nem em comentário: qualquer arquivo versionado que o contivesse
  dispararia antivírus no checkout do runner Windows (um teste varre a árvore procurando). Regras e
  fixtures usam hex por isso; o lint aceita `// allow-hex-as-text` exatamente nessa linha. A regra
  de zip só enxerga membros **armazenados**: o YARA-X não inflaciona, então zip deflatado é
  fixture negativa e limite documentado, não escondido. O prefixo `TEST_` existe para isto: não é
  malware, não é hipótese.
- **WannaCry** (`MAL_Win_Ransomware_WannaCry_Strings`). Uma família pública e exaustivamente
  documentada. Cada string (domínio kill switch, senha do zip embutido, nomes de componentes) e os
  dois hashes vêm dos relatórios citados no `meta` da regra (Kaspersky Securelist, Microsoft, Cisco
  Talos, MalwareTech, CISA TA17-132A). A condição exige PE abaixo de 8 MB e uma âncora única ou
  dois nomes de componente, então listas de IOC e relatórios não acendem. `tests/samples.lock` leva
  os dois sha256 públicos para o job manual `real-samples`; nada é commitado.

## Contrato de uma regra

Validado por `scripts/lint_rules.py`; a CI quebra o PR se falhar.

| Requisito | Regra |
|---|---|
| Nome | `^(MAL\|HUNT\|SUSP)_<Plataforma>_<...>$`, único no repositório |
| `id` | UUID, único no repositório, nunca muda |
| `version` | inteiro ≥ 1; +1 a cada mudança de lógica |
| `meta` obrigatório | `id`, `version`, `author`, `date`, `modified`, `description`, `hash`, `status`, `purpose`, `mitre_attack`, `scope` |
| `status` | `experimental` → `test` → `stable` → `deprecated` |
| `purpose` | `hunting` \| `triage` \| `blocking` |
| Gate de promoção | `blocking` exige `status = stable` **e** `confidence = high`; `deprecated` fica fora dos bundles |
| Datas | `YYYY-MM-DD`; `modified` ≥ `date` |
| `hash` | md5/sha1/sha256 da sample-semente |
| `mitre_attack` | `"T1055.002, T1027"` ou `"none"` (meta YARA não tem lista; é string separada por vírgula) |
| `scope` | `file` \| `memory` \| `both`; `memory`/`both` não podem usar `uintN(0)`, `filesize` nem `pe.*` na condição |
| `license` | opcional; se presente, tem que ser `"CC0-1.0"` (o repo inteiro é CC0) |
| Strings de texto | ≥ 6 bytes (ou `// yara-lint: allow-short`) |
| Hex | ≥ 6 bytes fixos e menos wildcards do que fixos (ou `// yara-lint: allow-wildcards`) |
| Compilador | zero warnings (campo deprecado, pattern lento, meta ausente, nome fora do padrão) |
| Formatação | igual ao `yr fmt` |
| Testes | ≥ 1 positivo **e** ≥ 1 negativo em `tests/cases.py` |

### Gate de FP por `purpose`

| `purpose` | Largura | Hit no goodware |
|---|---|---|
| `hunting` | larga, analista investiga | aviso |
| `triage` | média, etiqueta/prioriza | **falha** (ou aviso com `--triage-warn`) |
| `blocking` | estreita, EDR mata | **falha** |

## O que a CI faz num PR

1. **código**: ruff, ruff format, mypy (strict), pytest (lint, tooling, extrator de âncoras,
   memscan), bandit, pip-audit.
2. **regras**: lint → fixtures → `docs/coverage.md` e `docs/health.md` em dia → goodware ELF do runner → `report.py` no head **e** no base
   (mesmos scripts, regras do base) → `diff_report.py` publica como comentário no PR e no job
   summary: hits novos/removidos por regra (com sha256), tempo por regra com Δ%, fixtures que
   mudaram. Falha se uma regra passar de `max_rule_seconds`, regredir mais de
   `max_regression_pct` (acima de `regression_floor_seconds`, para ignorar ruído) ou gerar hit
   novo em triage/blocking. Limites em `rules-ci.toml`.
3. **manifesto do corpus**: gera o manifesto sha256 do goodware do runner e compara com o
   fixado em `tests/goodware/manifests/<os>.json`, se existir. Drift da imagem do runner
   aparece como lista de arquivos adicionados/removidos/alterados, não como FP misterioso.
   Para fixar: baixe o artifact `reports-*` e commite `manifest-<os>.json` em
   `tests/goodware/manifests/<os>.json`.
4. **compatibilidade**: tenta compilar cada arquivo com `yara-python` (YARA 4.x) e publica a
   matriz. Regra que só compila em YARA-X precisa declarar `engine = "yara-x"`.
5. **windows**: gate de FP e tempo por regra em `System32`, `SysWOW64`, Git, Node, PowerShell e
   7-Zip (goodware PE real). Roda também toda segunda-feira.
6. **real-samples** (manual, `workflow_dispatch` com `real_samples=true`): baixa as entradas de
   `tests/samples.lock` do MalwareBazaar com o secret `MALWAREBAZAAR_API_KEY`, escaneia num
   tmpdir, confere as regras esperadas e apaga. Nada é executado nem vira artifact. Sem o
   secret, o job avisa e termina verde.

## Release

Tag `vX.Y.Z` (semver; `-rc1` etc. vira pre-release) dispara `release.yml`:

- `blocking.yar` / `triage.yar` / `hunting.yar` (fonte concatenada) e `.yarc` (compilado
  YARA-X). Cumulativo: `blocking ⊂ triage ⊂ hunting`. `deprecated` fica fora.
- `manifest.json` (regras, ids, versões, scope, sha256 do fonte), `compat-yara4.json`,
  `CHANGELOG.md` (gerado de commits + diff de `rules/` desde a tag anterior), `SHA256SUMS`.
- Tudo assinado com **Sigstore/cosign keyless** via OIDC do GitHub Actions
  (`*.sigstore.json`). Verificação:

```bash
cosign verify-blob --bundle blocking.yar.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Phuderoso/yara-x-detection-rules/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  blocking.yar
```

## Extrator de âncoras (`tools/anchors`)

Dado N amostras da família, acha sequências de instruções comuns a todas (ou a K), com `??`
automático em disp32, rel8/rel32, imediatos e RVAs (pela informação de operando do capstone,
nunca em opcodes), descarta o que acende no goodware e ranqueia por bytes fixos, raridade e
cobertura. O teste de aceitação é o decoder da FamilyX: com os dois builds sintéticos
(disp32/rel8/imm diferentes) ele devolve, sem dica,
`48 8B 0D [4] 48 85 C9 74 ?? 0F B6 01 34 ?? 88 01 48 FF C1`, o mesmo `$decode` escrito à mão,
e o rascunho `experimental` passa no lint e nas fixtures. Método, flags e limites em
[`tools/anchors/README.md`](tools/anchors/README.md).

## Memória (`scope` e `memscan.py`)

Regra de arquivo começa com `uint16(0) == 0x5A4D and filesize < 2MB and pe.is_pe`; num VAD
dump nada disso existe (sem header no offset 0, `filesize` é o tamanho da região, `pe` não
parseia seções mapeadas). Por isso `meta.scope`: o lint barra essas cláusulas em regras
`memory`/`both`, e `scripts/memscan.py` compila **só** essas regras. Backend `raw` escaneia
bytes brutos em chunks sobrepostos (procdump, VAD dump, `windows.memmap --dump`); backend
`vol3` chama o Volatility 3 (`yarascan`/`vadyarascan`, que já usa YARA-X) para imagens com OS
detectado e traz PID/processo; `auto` tenta vol3 e cai para raw. Saída JSONL nativa ou ECS
(`event.category: [malware, process]`, `yara.memory.offset`, `process.pid`). O porquê está na
seção "Memória" do handbook. `memscan.py --record-activity` registra hits de memória em
`tests/activity.json` (fonte `memscan`), como o `hunt.py` faz para arquivos.

## Vigia de FP (`fp-watch.yml`)

Regra limpa hoje pode começar a acender mês que vem: a imagem do runner mudou, uma biblioteca nova
saiu, a regra foi afrouxada. `fp-watch.yml` roda toda quarta (e por `workflow_dispatch`):

1. **Corpus limpo reprodutível**: `/usr/bin`, `/usr/sbin`, `/usr/lib/x86_64-linux-gnu`, `/usr/libexec`
   do `ubuntu-latest`, mais as wheels de `tests/goodware/pip-corpus.txt`, fixadas por versão **e**
   sha256 (`pip download --require-hashes`, descompactadas, nunca instaladas). `corpus_manifest.py`
   registra o sha256 de cada arquivo, então drift da imagem aparece como diff, não como mistério.
2. **Scan só com regras stable e test** (`--status stable,test`): `scan_goodware.py` para o gate,
   `report.py` para hits com sha256 e tempo por regra.
3. **Comparação com `tests/goodware/baseline.json`**: hit cujo sha256 não está em `known_fp` da regra
   é FP novo (regressão em `triage`/`blocking`, aviso em `hunting`); tempo acima de `max_rule_seconds`
   ou mais de `max_regression_pct` sobre a baseline (acima do piso de ruído) é regressão. FP conhecido
   que sumiu é listado como informativo.
4. **Uma issue, sem spam**: `fp_watch.py issue` procura a issue aberta com rótulo `fp-regression` e o
   marcador dele. Mesmo diff → nenhuma escrita (digest no corpo). Diff diferente → edita o corpo. Run
   limpo → um comentário e fecha. Só o `GITHUB_TOKEN` padrão, com `contents: read` e `issues: write`.

Aceitar o estado atual como baseline, depois de corrigir ou tolerar conscientemente um FP, é
decisão humana e commit; o workflow nunca escreve no repositório. Dois caminhos:

- **Do runner (recomendado):** rode o `fp-watch` à mão com `propose_baseline: true`. O job escreve
  `baseline.proposed.json`, `health.proposed.md` e um `baseline.patch` no artifact e mostra o diff
  no resumo do run, nada mais. Depois, localmente:
  `gh run download <run-id> -n fp-watch-<run-id> -D build/artifact && make fp-propose ARTIFACT=build/artifact`.
  Isso reescreve `tests/goodware/baseline.json` e `docs/health.md` no seu working tree a partir do
  report e do manifesto do runner; revise o `git diff`, commite, abra o PR.
- **Local:** `make fp-compare` e depois `make fp-baseline REPORT=build/report.json`. A baseline fica
  com o hash de corpus da *sua* máquina; o primeiro run no runner marca "corpus mudou" até ser
  re-baselinada de um artifact.

`baseline.json` guarda também `last_fp` e `fp_total` por regra, que alimentam o painel de saúde.

## Painel de saúde

`docs/health.md` é gerado por `scripts/health.py`: por regra, status, purpose, scope, idade, tempo
desde a última mudança, FP conhecidos, FP total histórico, último FP (da baseline) e último match
verdadeiro (de `tests/activity.json`, escrito por `hunt.py --record-activity`, `memscan.py
--record-activity` ou à mão depois de um IR; a fonte `published-target` marca as regras EICAR, cuja
fixture é o arquivo publicado). Regra com FP registrado e sem match verdadeiro em 12 semanas entra em **candidatas a
deprecated**; regra `test`/`stable` sem FP nem match entra em "sem prova". Idades em faixas, para o
arquivo só mudar quando uma regra cruza uma; a CI roda `--check` como faz com o coverage.

## Painel de cobertura

`docs/coverage.md` é gerado por `scripts/coverage.py` a partir do `meta`: regras por técnica
MITRE (com link), matriz purpose × status, por scope, por família, por engine, e a lista de
`experimental` há mais de 90 dias (candidatas a promoção ou descarte, em faixas > 90/180/365
para o arquivo não mudar todo dia). A CI roda `--check` e falha se o arquivo commitado não
bater com o gerado; `make coverage` regenera.

## Varredura e SIEM

`scripts/hunt.py --format ecs` emite um documento ECS por hit:

| ECS | origem |
|---|---|
| `file.hash.sha256`, `file.path`, `file.size` | arquivo escaneado |
| `rule.name`, `rule.id`, `rule.version`, `rule.author`, `rule.description`, `rule.reference`, `rule.category` | `meta` da regra (`category` = `purpose`) |
| `threat.technique.id[]`, `threat.framework` | `mitre_attack` |
| `threat.software.name` | `malware` |
| `event.severity` | `severity` (low 21, medium 47, high 73, critical 99) |
| `yara.strings[]` | id/offset/length de cada string casada |
| `yara.scope`, `yara.memory.offset`, `process.pid` | `memscan.py`: escopo da regra, offset na imagem e PID (vol3) |

`hunt.py --record-activity` marca as regras que casaram com a data de hoje em `tests/activity.json`
(fonte `hunt`); é isso que `docs/health.md` chama de "último match".

## YARA-X

Este repo é YARA-X (bindings `yara-x` ≥ 1.23). Duas coisas que o compilador já pegou na regra
de exemplo e que valem para migrações:

- string declarada e não usada na condição é **erro** (`E022`), não warning;
- `pe.number_of_sections` está deprecado → `pe.sections.len()` (que não existe no YARA 4.x);
- `import "pe"` parseia **todo** arquivo escaneado, seja qual for a ordem da condição:
  `uint16(0) == 0x5A4D` primeiro não evita o parse. No corpus PE do runner Windows isso custou
  28.14s para uma regra; desde a v3 a regra de exemplo lê o cabeçalho à mão
  (`uint32(uint32(0x3C)) == 0x00004550`, `uint16(uint32(0x3C) + 6) < 12`), o mesmo corpus leva
  0.32s, e a regra não precisa mais de `engine = "yara-x"`.

Exemplos antes/depois dos erros que modelos costumam cometer ao escrever YARA-X
(string não usada = `E022`, `pe.number_of_sections` → `pe.sections.len()`, custo do
`import "pe"`) estão em [`AGENTS.md`](AGENTS.md#common-ai-mistakes-writing-yara-x).

CLI equivalente, se preferir o binário `yr`:

```bash
yr check rules/                      # compila e avisa
yr fmt rules/                        # formata
yr scan -s rules/ sample.bin         # strings casadas
yr scan -C dist/triage.yarc corpus/  # bundle compilado
```

## Trabalhos relacionados

Este repositório não é um pacote grande de regras públicas, e várias das ideias já existem
em outros lugares. O que ele tenta ser é um pipeline único, pequeno, auto-hospedado e
[CC0](LICENSE), nativo de YARA-X.

Trabalho anterior de que aprendemos (e que não substituímos):

- [YARA Style Guide](https://github.com/Neo23x0/YARA-Style-Guide) (Florian Roth) — nomes,
  meta obrigatório, estrutura legível.
- [YARA Forge](https://github.com/YARAHQ/yara-forge) — agrega e faz QA de conjuntos
  públicos e publica pacotes prontos.
- [YARA-CI](https://yara-ci.cloud.virustotal.com/) (VirusTotal) — serviço externo no
  GitHub que valida regras e varre um corpus grande de goodware.
- [yaraQA](https://github.com/Neo23x0/yaraQA) — checagens estáticas de qualidade e
  desempenho em regras YARA.
- [mkYARA](https://github.com/fox-it/mkyara) (Fox-IT) e
  [YARA-Signator](https://github.com/fxb-cocacoding/yara-signator) — geração automática
  de regras a partir de código, inclusive com wildcard em operandos. O
  [`tools/anchors`](tools/anchors/README.md) deste repo é um primo pequeno, não um
  substituto.
- As [regras YARA da Elastic](https://github.com/elastic/protections-artifacts) usam
  `scan_context` (`file`, `memory`) no meta; o campo `scope` deste repo tem um papel
  parecido.
- O [Sigma](https://github.com/SigmaHQ/sigma) popularizou um ciclo de vida de status
  (`experimental` / `test` / `stable` / `deprecated` / `unsupported`); este repo usa
  quatro dos cinco valores do Sigma (todos menos `unsupported`) como política local,
  não como um port do Sigma.
- O [Volatility 3](https://github.com/volatilityfoundation/volatility3) já varre memória
  com YARA/YARA-X; o [`scripts/memscan.py`](scripts/memscan.py) é um wrapper fino sobre
  dumps crus e vol3, não um framework novo de forense.

O que este repo faz de diferente, de propósito:

- Tudo vive num pipeline único, pequeno e auto-hospedado: lint, fixtures sintéticas, gate
  de goodware, diff de hits e tempo por PR, fp-watch semanal, painéis de cobertura e
  saúde, e releases assinados. O YARA-CI é um serviço externo; as ferramentas acima são
  projetos separados.
- É nativo de YARA-X. Quase todo esse ferramental público nasceu para YARA 4.x.
- O [`scripts/lint_rules.py`](scripts/lint_rules.py) rejeita `filesize`, `pe.*` e
  `uintN(0)` em regras com `scope = "memory"` ou `"both"`. Não conhecemos um linter
  público que imponha exatamente isso.
- As fixtures são montadas em memória na hora do teste ([`tests/fakepe.py`](tests/fakepe.py),
  [`tests/eicar.py`](tests/eicar.py)). Nenhum malware real é commitado; o literal do EICAR
  fica só em hex para o checkout não disparar antivírus.
- Cada PR ganha um diff de hits e tempo por regra contra a branch base, um orçamento de
  tempo, e (na agenda) o fp-watch contra um corpus limpo fixado por hash, além de um
  painel de saúde com candidatas a depreciação.

Limites honestos: hoje há só cinco regras — duas do loader fictício FamilyX, duas do
arquivo de teste EICAR publicado, e uma do WannaCry montada a partir de relatórios
públicos citados. Isto é um repositório-modelo e um harness, não um pacote de cobertura.
Nomes, meta obrigatório, o gate de FP por `purpose`, os pisos de string e o orçamento em
`rules-ci.toml` são políticas deste repositório, não um padrão da comunidade. Os tempos
citados na documentação (28.14s antes da v3, 0.32s depois, no corpus PE do runner
Windows) são medições do autor naquele runner, não um benchmark publicado.

## Segurança do próprio tooling

- SAST: `bandit` nos scripts a cada PR; `pip-audit` nas dependências; Dependabot semanal para
  pip e GitHub Actions.
- Como reportar FP, bypass ou problema de CI: [`SECURITY.md`](SECURITY.md).

## Licença

Tudo neste repositório, regras e código, está dedicado ao domínio público sob
[CC0 1.0 Universal](LICENSE). Atribuição não é exigida; é bem-vinda. As regras podem carregar
`license = "CC0-1.0"` no `meta` para a dedicação viajar junto com o bundle. Créditos:
[CREDITS.md](CREDITS.md).

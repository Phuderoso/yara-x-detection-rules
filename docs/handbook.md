# Handbook: detection engineering com YARA-X

> **English note.** This handbook is written in Portuguese on purpose: it is the craft notes behind
> the repo, not its interface. The interface (rule contract, CI, tools, doctrine) is in English in
> [`README.md`](../README.md). If one section matters to you and machine translation is not enough,
> open an issue and we will translate it. Everything here is CC0, like the rest of the repository.

O próximo nível não é "mais strings". É **detection engineering**: regra que
sobrevive a corpus limpo, a um novo build da família, e a um pipeline que não
explode de FP.

Três camadas.

---

## 1. Escrever uma regra *boa*

Uma regra ruim casa um sintoma genérico. Uma regra boa casa um **artefato
estável da família** e exige contexto o bastante para não acender em software
legítimo.

### O que escolher como evidência

Ordem de qualidade, do melhor para o pior:

| Qualidade | Exemplo | Por quê |
|---|---|---|
| Código único / stack strings / config parser | `"CONFIG_START::mutex_id::"` | Quase só a família tem |
| PDB, mutex, campaign ID, user-agent interno | `"C:\\build\\loader_v3\\src\\inject.c"` | Estável entre samples |
| Hex de um trecho de lógica (não de endereço) | bytes do decoder, sem RVAs absolutos | Sobrevive a rebase |
| Combo de imports + estrutura PE | `pe.imports("kernel32.dll", "WriteProcessMemory")` + seção atípica | Fraco sozinho, forte em conjunto |
| API names isoladas | `"CreateRemoteThread"` | Todo injector, packer e muita ferramenta legítima |

Regra prática: se a string aparece em `kernel32`, em um installer da Adobe ou
em um repo GitHub público, ela **não** é a âncora. Pode ser *contexto*, nunca o
gatilho sozinho.

### Anatomia de uma regra de produção

A regra de referência deste repo é
[`rules/windows/MAL_Win_Loader_FamilyX_ConfigMarker.yar`](../rules/windows/MAL_Win_Loader_FamilyX_ConfigMarker.yar).
Em resumo:

```yara
condition:
  uint16(0) == 0x5A4D and
  filesize > 8KB and
  filesize < 2MB and
  pe.is_pe and
  pe.sections.len() < 12 and
  ( $marker or $pdb or $ua or $decode ) and
  2 of ($api_*)
```

Por que essa sobrevive melhor:

- **Magic + filesize primeiro** — short-circuit. Barato. Descarta 90% do corpus antes de regex/entropia.
- **Âncora única OU hex do decoder** — um único artefato forte já justifica o hit; APIs só reforçam.
- **Não exige todas as strings** — o próximo build pode dropar o PDB. Se você puser `all of them`, a regra morre.
- **Não usa API sozinha** — `2 of ($api_*)` sem âncora seria um detector de "qualquer coisa que injeta", inclusive ferramentas suas.

Duas correções que o compilador do YARA-X impôs sobre a versão original:
string declarada e não referenciada na condição é **erro** (não deixe `$fp_*`
"de enfeite"), e `pe.number_of_sections` virou `pe.sections.len()`. Uma
consequência da segunda: `pe.sections.len()` não existe no YARA 4.x, então a
regra declara `engine = "yara-x"` e aparece como "só YARA-X" na matriz de
compatibilidade da CI.

### Anti-FP: o checklist que importa

Teste **sempre** contra corpus limpo *antes* de ir para o SOC.

1. **Goodware**: Windows ISO, `System32`, installers comuns, Visual Studio redistributables, Chrome, Office, Python embeddable, NSIS, Inno Setup, 7-Zip SFX.
2. `yr scan -s regra.yar falso_positivo.exe` (ou `scripts/hunt.py -s`) — **qual string** casou? Essa é a que você mata ou rebaixa.
3. String `< 6 bytes` → quase sempre FP. `.js`, `http`, `cmd`, `MZ` não são âncora. (O lint bloqueia.)
4. Hex com `??` demais vira "casa com o universo". Wildcard só em immediates/offsets que o linker mexe. (O lint bloqueia mais wildcard do que byte fixo.)
5. Regex é a última opção. Hex com jumps costuma ser mais rápido e mais preciso.
6. Entropia alta **não** é malware. É packer, ou um `.pdf` comprimido, ou um `.png`. Use `math.entropy` só como filtro auxiliar depois do magic.
7. Exclusões explícitas quando o FP é uma lib conhecida:

```yara
condition:
  ... and
  not pe.version_info["CompanyName"] contains "Microsoft" and
  not $fp_vendor
```

8. Uma regra, um propósito. Hunting pode ser larga. **Blocking** tem que ser estreita. Não misture as duas no mesmo arquivo sem `meta.purpose`.

### Condição: `any` vs `all` vs grupos

| Situação | Use |
|---|---|
| Cada string é única da família | `any of ($uniq*)` |
| Strings fracas, combinação forte | `all of ($core*)` |
| Núcleo estável + variantes | `all of ($core*) and any of ($var*)` |
| Começou a dar FP | `any` → `all`, ou some uma âncora |

Ordem na condição (esquerda → direita):

```text
magic → filesize → seções/imports baratos → strings → regex/entropia/loops
```

Errado (lento):

```yara
math.entropy(0, filesize) > 7.2 and uint16(0) == 0x5A4D
```

Certo:

```yara
uint16(0) == 0x5A4D and filesize < 3MB and math.entropy(0, filesize) > 7.2
```

### O erro clássico: overfit vs underfit

- **Overfit**: copiar 40 strings de *um* sample, inclusive timestamps e endereços. Casa aquele hash. O irmão recompilado escapa.
- **Underfit**: três APIs de injeção + `MZ`. Casa meio mundo.

Alvo: 2–6 evidências **estáveis entre samples da mesma família**, não entre
*todas* as famílias. Code reuse (o "gene" que Intezer e similares extraem) é o
método moderno: assinar o trecho binário que a família reutiliza, não o wrapper
que muda toda semana.

É exatamente isso que `tests/cases.py` codifica: dois "builds" do decoder com
disp32/rel8/immediate diferentes **têm** que casar; APIs de injeção sem âncora
**não** podem.

---

## 2. YARA vs YARA-X

YARA clássico (C, 4.x) está em **manutenção**: bugfix, pouca feature nova.
YARA-X é o rewrite em Rust da VirusTotal, estável desde 1.0 (jun/2025); em
nov/2026 os bindings publicados estão na série **1.23**. No VirusTotal roda em
produção há tempo — bilhões de arquivos, dezenas de milhares de regras.

Compatibilidade de regras: ~**99%**. A maioria do seu `.yar` compila direto.

| | YARA 4.x | YARA-X |
|---|---|---|
| Linguagem | C | Rust |
| Status | maintenance | onde entra módulo e feature nova |
| Performance | ainda boa em strings simples | mais rápida na maioria dos casos |
| Regex pesada | lenta; warning "may slow down scanning" | motor novo; casos patológicos caem de segundos para sub-segundo |
| Loops `for` em filesize | caros | muito mais rápidos |
| Segurança de memória | histórico de bugs no parser | ownership do Rust; menos classe de crash/OOM |
| DX | `yara` CLI, erros secos | erros melhores, [language server](https://virustotal.github.io/yara-x/blog/introducing-the-yara-language-server/) (VS Code), formatter |
| APIs | C, Python (`yara-python`) | Rust, C/C++, Python, Go |
| Lint nativo | — | `allowed_metadata`, `allowed_rule_name`, `error_on_slow_pattern` (usados em `scripts/yrlib.py`) |
| Fast scan | — | `--fast-scan`: throughput > profundidade, bom para coleções grandes |

Incompatibilidades que pegam gente no migrate
([doc oficial](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/)):

```yara
// YARA 4.x aceitava; YARA-X exige escape
$re = /abc\{/          // não /abc{/

// base64: YARA-X exige ≥ 3 chars e não gera o FP clássico do motor antigo
$b = "ABC" base64

// indexação negativa sumiu
// $a[-1]  → não compila. Use offsets explícitos.

// string não usada na condição é ERRO (E022), não warning
// pe.number_of_sections está deprecado → pe.sections.len()
```

Ferramenta de migração: `yara2x` no projeto
[VirusTotal/yara-x](https://github.com/VirusTotal/yara-x).

CLI típica:

```bash
yr scan -s rules/family.yar sample.bin     # -s = strings que casaram
yr scan --fast-scan rules/ corpus/
```

Se você está começando um pipeline *hoje*, comece em YARA-X. Mantenha YARA 4.x
só onde um produto (EDR, sandbox antiga) ainda não engole o motor novo.

---

## 3. Encaixar num pipeline de hunting

YARA não é o SIEM. É um **filtro de artefato**. O pipeline decide o que acontece no hit.

```text
hipótese → evidência (RE/CTI) → regra
        → testar goodware + samples        (make lint test goodware / CI)
        → promover                          (merge; meta.purpose define a faixa)
        → varrer (disk / memory / VT Livehunt / object store)
        → enriquecer hit (hash, VT, sandbox, identity)   (scripts/hunt.py --jsonl)
        → caso / detecção / ignora
        → versionar e aposentar
```

### Três faixas de regra (não misture)

| Faixa | Largura | Ação no hit |
|---|---|---|
| **Hunting** | mais larga, aceita FP | analista investiga |
| **Triage** | média | etiqueta a sample, prioriza fila |
| **Blocking / prevent** | estreita, FP ≈ 0 | quarentena, EDR kill |

Uma regra de hunting jogada no prevent vira incidente político no dia em que
casar com o Chrome. Por isso `meta.purpose` é obrigatório e a CI trata as
faixas de forma diferente no gate de goodware.

### Onde ela roda

1. **Retrospectivo** — object store de dumps, disk images, coleção de malware, buckets S3 de evidência.
2. **Livehunt** — VirusTotal Livehunt / Retrohunt: a regra corre em *tudo* que chega no VT. Ótimo para "essa família apareceu onde?".
3. **Endpoint** — alguns EDRs aceitam YARA custom (LimaCharlie, Elastic, alguns modos do CrowdStrike/Defender). Cuidado com CPU: regex gorda × milhares de processos.
4. **Ingest de e-mail/sandbox** — no detonator (CAPE, Joe, etc.) a regra classifica o dropped file *depois* do unpack. Muito mais útil do que no binário packed.
5. **Memória** — `yr` em dump de processo / Volatility. Pega strings decodificadas em runtime que o arquivo em disco não tem.

### Memória: por que a regra de arquivo falha lá (e o que fazer)

A regra de arquivo da FamilyX começa com `uint16(0) == 0x5A4D and filesize < 2MB and pe.is_pe`.
Em disco isso é a melhor parte dela (barato, corta 99% antes de olhar strings).
Num dump de processo ou numa imagem de memória, cada uma dessas três cláusulas é falsa ou sem sentido:

- **Sem cabeçalho PE no offset 0.** O que você escaneia é uma região (VAD, seção mapeada,
  heap). O `MZ` do módulo está no início da *imagem*, não da região; loaders reflexivos e
  packers apagam ou nunca escrevem o header; injeção por `WriteProcessMemory` copia só o
  payload. `uint16(0) == 0x5A4D` falha e a regra inteira morre no primeiro `and`.
- **`filesize` é o tamanho do que foi dumpado,** não do binário: uma região de 4KB, um VAD de
  200MB, uma imagem de 32GB. Qualquer envelope de tamanho vira ruído.
- **`pe.*` precisa do arquivo como está no disco.** Em memória as seções estão alinhadas por
  `SectionAlignment` (0x1000), não por `FileAlignment` (0x200); os RVAs não batem com offsets
  de arquivo; a IAT já foi resolvida e tem ponteiros, não nomes. O módulo `pe` não parseia uma
  região, e mesmo num dump de imagem inteira os campos que dependem de layout de arquivo mentem.
- **O que estava cifrado está em claro.** É a razão para escanear memória: config, strings de C2,
  o payload de segundo estágio depois do unpack. Uma regra de memória pode (e deve) usar
  âncoras que *não existem* no disco: `$cfg = "mutex_id=Global\\FamilyX_"` só aparece depois
  do decoder rodar.
- **O código continua lá.** O stub do decoder (`$decode`) é a âncora que atravessa disco e
  memória: opcodes mapeados são os mesmos bytes, com os mesmos wildcards nos operandos.

Por isso o repo tem `meta.scope`:

| `scope` | Pode usar `uintN(0)`, `filesize`, `pe.*` | Onde roda |
|---|---|---|
| `file` | sim | `hunt.py`, `scan_goodware.py`, EDR em disco, VT |
| `memory` | **não** (o lint barra) | `memscan.py` sobre VAD dump / procdump / Volatility |
| `both` | **não** | os dois |

`rules/memory/MAL_Win_Loader_FamilyX_InMemory.yar` é a versão de memória da mesma família:
`$decode or 2 of ($marker, $pdb, $ua, $cfg)`, sem nenhum gate de arquivo. Ela também casa o
arquivo em disco quando o decoder está lá, e tudo bem: é `hunting`, e as fixtures listam isso.

```bash
# região/VAD/procdump (bytes brutos): YARA-X direto, em chunks com sobreposição
python scripts/memscan.py proc_1234.dmp -s --jsonl mem.jsonl --format ecs

# imagem completa: Volatility 3 (usa YARA-X por baixo quando o módulo está instalado)
python scripts/memscan.py memory.raw --backend vol3 --plugin windows.vadyarascan.VadYaraScan
```

Duas armadilhas: regra de memória é mais larga por construção (sem envelope de tamanho,
sem PE), então nasce `hunting` e sobe de faixa só com telemetria; e `2 of` em strings
isoladas é o mínimo, porque um scanner de AV, um relatório de IR ou o próprio `memscan.py`
carregam essas strings em memória também.

### Exemplo mínimo de loop de hunting

Hipótese: "loaders da família X deixam o marker de config mesmo depois do packer ruim".

```bash
# 1. validar FP
python scripts/scan_goodware.py /mnt/goodware/windows11-system32/

# 2. validar TP (corpus privado, fora do repo)
python scripts/hunt.py samples/familyx/ -s

# 3. retrospectivo interno
python scripts/hunt.py /evidence/2026 --jsonl hits-$(date +%F).jsonl

# 4. o hit não é o fim — é o começo
#    sha256 → VT/GTI → sandbox → identidade da máquina → timeline EDR
```

O analista não fecha o ticket no `match`. Fecha quando o hit virou: família,
paciente-zero, persistência, e se a regra precisa apertar.

### Operação da regra (o que times maduros fazem)

- Repo Git, PR, review. Sem `.yar` solto no desktop.
- CI: compile + scan num **goodware pack** + scan nos samples da família. Quebra o PR se FP > 0 no goodware para regras `purpose = blocking` (aqui: também `triage`).
- `meta.hash` do sample-semente. Sem isso, daqui 8 meses ninguém sabe de onde veio.
- `meta.id` (UUID) estável e `meta.version` inteiro: o nome pode mudar, o id não; o SIEM correlaciona pelo id e o CHANGELOG mostra `v2 → v3`.
- Ciclo de vida explícito em `meta.status`: `experimental → test → stable → deprecated`. Só `stable` com `confidence = high` pode virar `blocking`; `deprecated` fica no repo para histórico mas fora dos bundles.
- Versionar `date` / `modified`. Aposentar regra morta (família sumiu, ou passou a dar FP por um produto novo).
- Mapear MITRE só se for verdade. `T1055` em toda regra de injector não ajuda ninguém. `mitre_attack = "none"` é uma resposta válida.
- Diff por PR, não só pass/fail: hits novos/removidos no goodware por regra, tempo por regra vs base, fixtures que mudaram. O revisor lê o que mudou, não um check verde.
- Corpus de goodware com manifesto (sha256 por arquivo). Um FP aponta para um hash reproduzível; drift da imagem do runner aparece como diff.
- Release como produto: bundles por faixa (`blocking ⊂ triage ⊂ hunting`), checksums, assinatura keyless (Sigstore), CHANGELOG gerado. Quem consome a regra sabe de onde veio e o que mudou.
- Telemetria: quantos hits/semana, % FP confirmado, idade da regra. Regra que não hitou em 18 meses e não é canary → arquivo morto ou retire. O JSONL de `hunt.py`/`scan_goodware.py` é a matéria-prima disso.

### Onde YARA é fraca (para não cobrar dela o que ela não é)

- Packed/crypted: a string não está em claro no disco. Solução de defensor: unpack na sandbox, depois YARA no dumped image — não "escrever regra mágica no packed".
- Polymorphic / cada build muda string: assine o **decoder** (hex estável), não a config da semana.
- Comportamento puro (quem abriu o quê): isso é Sigma/EDR telemetry, não YARA.
- Prova jurídica sozinha: YARA diz "casou o padrão". A atribuição vem do resto do case.

---

## Como isso se junta

```text
CTI / IR  →  âncora estável (string rara ou hex de lógica)
          →  regra com purpose explícito
          →  CI contra goodware
          →  YARA-X no scanner
          →  hit vira caso, não alerta cego
          →  feedback: apertar, alargar, ou aposentar
```

Isso é o ofício. A linguagem é a parte fácil.

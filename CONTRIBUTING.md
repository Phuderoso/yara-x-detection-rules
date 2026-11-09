# Contribuindo

Toda regra passa pelo mesmo caminho: lint → fixtures → goodware → revisão →
promoção. Este documento é o checklist; o raciocínio está em
[`docs/handbook.md`](docs/handbook.md).

## Setup

```bash
make setup-dev     # yara-x, ruff, mypy, pytest, bandit, yara-python, pre-commit install
make ci            # tudo o que a CI roda (precisa de tests/goodware/ local para o gate de FP)
```

## Adicionando ou alterando uma regra

1. Copie `rules/_TEMPLATE.yar` para `rules/<plataforma>/<NOME>.yar`. Uma regra por arquivo
   (o orçamento de performance é medido por arquivo).
2. Gere o `id`: `python -c "import uuid; print(uuid.uuid4())"`. Ele nunca muda; o nome pode.
3. Preencha o `meta`. Obrigatórios: `id`, `version`, `author`, `date`, `modified`,
   `description`, `hash` (sample-semente), `status`, `purpose`, `mitre_attack`, `scope`.
   `scope = "memory"`/`"both"` proíbe `uintN(0)`, `filesize` e `pe.*` na condição (o lint barra);
   veja "Memória" no handbook.
4. Escolha a âncora. Artefato **estável da família**: config marker, PDB, mutex, UA interno,
   hex do decoder. API isolada é contexto, nunca gatilho. Com N amostras da família em mãos,
   `tools/anchors/extract_anchors.py` acha o hex do decoder com os wildcards certos e gera o
   rascunho `experimental` (ver `tools/anchors/README.md`).
5. Ordene a condição do barato para o caro:
   `magic → filesize → PE barato → strings → regex/entropia/loops`.
6. Adicione casos em `tests/cases.py`: positivos (variantes, builds diferentes) **e**
   negativos (APIs sem âncora, âncora fora de PE, fora do envelope de tamanho/seções).
7. `make fmt && make lint && make test && make coverage` (o painel `docs/coverage.md` é
   gerado do `meta` e a CI falha se estiver desatualizado).
8. `make goodware GOODWARE=/mnt/goodware` contra um corpus limpo de verdade.
9. Abra o PR. A CI publica o diff de hits e de tempo em relação ao base.

Ao alterar uma regra existente: incremente `version`, atualize `modified`, e explique no PR o
que mudou e por quê (FP novo? build novo da família? aperto/alargamento?).

## Checklist anti-FP (vai no PR)

- [ ] Nenhuma string isolada que apareça em `kernel32`, instaladores comuns ou repos públicos é gatilho sozinha.
- [ ] Strings de texto têm ≥ 6 bytes; hex tem ≥ 6 bytes fixos e wildcard só em offsets/immediates.
- [ ] A condição não exige `all of them` em strings que o próximo build pode dropar.
- [ ] `uint16(0)`/magic e `filesize` vêm antes de regex, entropia e loops.
- [ ] Entropia, se usada, é filtro auxiliar depois do magic, nunca o gatilho.
- [ ] Testei contra goodware: System32, redistributables, browsers, Office, Python/Node/Go, NSIS/Inno/7-Zip.
- [ ] Para cada FP encontrado, sei **qual string** casou (`yr scan -s` / `scripts/hunt.py -s`) e a rebaixei para contexto ou removi.
- [ ] Exclusões explícitas (`not pe.version_info[...]`) quando o FP é de um vendor conhecido.
- [ ] `purpose` reflete a largura real: hunting (larga), triage (média), blocking (estreita, FP ≈ 0).
- [ ] `mitre_attack` só lista técnicas que a regra de fato evidencia (ou `"none"`).
- [ ] `scope` reflete onde a regra funciona: `file` se usa MZ/filesize/pe; `memory` nasce `hunting`
      e exige ≥ 2 strings isoladas ou hex de código.
- [ ] Se a âncora veio do `tools/anchors`, o goodware usado no filtro está descrito no PR.

## Ciclo de vida (`status`)

| status | significado | pode ser `blocking`? |
|---|---|---|
| `experimental` | recém-escrita, ainda sem goodware amplo | não |
| `test` | passou lint/fixtures/goodware da CI; em observação em hunting/triage | não |
| `stable` | semanas sem FP em produção, telemetria ok | sim (com `confidence = high`) |
| `deprecated` | família sumiu ou passou a dar FP; fica no repo para histórico, fora dos bundles | não |

Promoção para `stable` é uma mudança de regra como outra qualquer: PR, `version` +1, justificativa.

## Convenções de commit

Prefixos convencionais alimentam o CHANGELOG da release:

```text
rule: add MAL_Win_Loader_FamilyX_ConfigMarker
rule: tighten MAL_Win_Loader_FamilyX_ConfigMarker (FP in NSIS stub) v2
fix: lint accepted invalid dates
ci: pin goodware manifest for windows-latest
docs: ...
```

## Código (scripts/, tests/)

- `ruff check`, `ruff format`, `mypy --strict`, `pytest`, `bandit` passam (`make quality`).
- Nada de binário real em `tests/`. Fixtures são geradas por `tests/fakepe.py`.
- Nenhum segredo no repo. A CI lê `MALWAREBAZAAR_API_KEY` dos secrets do GitHub e nada mais.

## Licença

O repositório inteiro, regras e código, é [CC0 1.0 Universal](LICENSE): domínio público, sem
exigência de atribuição. Ao contribuir, você dedica sua contribuição ao domínio público nos
mesmos termos. Se a regra tiver `license` no `meta`, o valor é `"CC0-1.0"` (o lint confere).

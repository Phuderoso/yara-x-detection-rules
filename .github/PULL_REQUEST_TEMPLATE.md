## O que muda

<!-- Regra nova? Aperto por FP? Build novo da família? Mudança de tooling/CI? -->

## Evidência

- Sample-semente (sha256 em `meta.hash`):
- Referência (IR, relatório, VT):
- Âncora(s) escolhida(s) e por que são estáveis entre builds:

## Checklist anti-FP

- [ ] `make fmt && make lint && make test` passam localmente
- [ ] Rodei `make goodware` (ou `scripts/scan_goodware.py`) contra corpus limpo; hits: 0 em triage/blocking
- [ ] Nenhuma string genérica (API, `MZ`, `http`, nomes de DLL) é gatilho sozinha
- [ ] Hex tem ≥ 6 bytes fixos e wildcard só em offsets/immediates
- [ ] Condição em ordem barato → caro (`magic → filesize → PE → strings → regex/entropia`)
- [ ] Casos positivos **e** negativos adicionados/atualizados em `tests/cases.py`
- [ ] `version` incrementado e `modified` atualizado (se regra existente)
- [ ] `mitre_attack` só com técnicas que a regra evidencia
- [ ] `purpose`/`status` coerentes com a largura real (blocking exige stable + confidence high)

## Revisão

- [ ] Li o diff de hits e de tempo publicado pela CI neste PR
- [ ] Hits novos no goodware explicados ou corrigidos

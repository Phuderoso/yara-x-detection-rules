# Saúde das regras

<!-- gerado por scripts/health.py; não edite à mão -->

2 regra(s). Referência: 2026-11-09. Regenerar: `make health`. FP vem de `tests/goodware/baseline.json` (fp-watch semanal); match verdadeiro vem de `tests/activity.json` (`hunt.py --record-activity`). Idades em faixas: o arquivo só muda ao cruzar uma.

Baseline de FP: 2026-11-09; 1 regra(s) sob vigia (stable/test); 0 FP conhecido(s) aceito(s).

## Por regra

| Regra | status | purpose | scope | idade | alterada há | FP conhecidos | FP total | último FP | último match | fonte |
|---|---|---|---|---|---|---:|---:|---|---|---|
| [`MAL_Win_Loader_FamilyX_ConfigMarker`](../rules/windows/MAL_Win_Loader_FamilyX_ConfigMarker.yar) | test | triage | file | 30–90 d | < 30 d | 0 | 0 | nunca | nunca | - |
| [`MAL_Win_Loader_FamilyX_InMemory`](../rules/memory/MAL_Win_Loader_FamilyX_InMemory.yar) | experimental | hunting | memory | < 30 d | < 30 d | 0 | 0 | nunca | nunca | - |

## Candidatas a `deprecated` (FP registrado e sem match há > 12 semanas)

Nenhuma.

## Sem prova fora das fixtures

Regras `test`/`stable` sem FP e sem match registrado em `tests/activity.json`: limpas, mas ainda não mostraram serviço. Rode `hunt.py --record-activity` num caso real ou o job `real-samples`.

- [`MAL_Win_Loader_FamilyX_ConfigMarker`](../rules/windows/MAL_Win_Loader_FamilyX_ConfigMarker.yar) (test, triage)

## Sinais

- **FP conhecidos**: hits no corpus limpo aceitos na baseline (`fp_watch.py baseline`). Zero é o alvo para `triage`/`blocking`.
- **FP total**: acumulado desde a primeira baseline, mesmo os já corrigidos. Mede quanto a regra já custou.
- **último match**: hunting real, amostra do `samples.lock` ou IR. Fixture não conta; fixture é o que a regra promete, não o que entregou.
- **candidata a deprecated**: tem custo (FP) e não tem retorno (match) há mais de N semanas. Não é automático; é pauta de revisão.

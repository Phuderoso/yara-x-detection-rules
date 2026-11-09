# Segurança

Este repositório contém regras de detecção e o tooling que as valida. Não há
serviço exposto nem código que execute conteúdo escaneado. Os riscos que
importam são: uma regra que dispara em software legítimo (falso-positivo), uma
regra que deixa passar o que diz detectar (bypass), e um pipeline de CI que
baixe ou execute algo que não deveria.

## Reportar um falso-positivo

Abra uma issue com o rótulo `false-positive` (ou envie em privado se o
arquivo for interno) contendo:

- nome da regra e `meta.id`;
- sha256 do arquivo que casou (não anexe o arquivo se ele for proprietário);
- produto/vendor e versão, se souber;
- a saída de `scripts/hunt.py -s <arquivo>` ou `yr scan -s`, para sabermos
  **qual string** casou.

FP em regra `blocking` é tratado como incidente: a regra é rebaixada para
`triage` ou `deprecated` no mesmo dia e sai do bundle `blocking` na próxima
release.

## Reportar um bypass

Um bypass é um sample da família que a regra deveria pegar e não pega. Como
isso pode ser informação útil para o adversário, **não abra issue pública**.
Envie em privado (contato abaixo) com:

- regra e `meta.id`;
- sha256 do sample (de preferência já no MalwareBazaar ou VT);
- o que mudou no sample em relação à semente (packer, string removida, decoder
  recompilado...).

Vamos responder em até 5 dias úteis e, se procedente, publicar a regra
apertada com `version` +1 e mencionar o reporte no CHANGELOG (ou não, se
preferir anonimato).

## Reportar um problema no tooling ou na CI

Qualquer caminho pelo qual conteúdo externo possa ser executado (e não só
lido) pela CI, segredo exposto em log, ou dependência vulnerável: envie em
privado. O job `real-samples` baixa binários do MalwareBazaar para um tmpdir,
só os lê como bytes e os apaga; se você achar um jeito de isso sair do trilho,
queremos saber.

## Contato

Abra uma issue marcada `security` pedindo um canal privado, ou use o e-mail do
mantenedor listado no perfil do GitHub de `@Phuderoso`.

## Escopo

Este repositório não oferece recompensa financeira. Reconhecemos reportes no
CHANGELOG quando o autor quiser.

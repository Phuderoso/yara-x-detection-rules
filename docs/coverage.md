# Cobertura das regras

<!-- gerado por scripts/coverage.py; não edite à mão -->

5 regra(s) em 5 arquivo(s). Regenerar: `make coverage`.

## Por técnica MITRE ATT&CK

| Técnica | Regras | Quais |
|---|---:|---|
| [T1027](https://attack.mitre.org/techniques/T1027/) | 2 | [`MAL_Win_Loader_FamilyX_ConfigMarker`](../rules/windows/MAL_Win_Loader_FamilyX_ConfigMarker.yar), [`MAL_Win_Loader_FamilyX_InMemory`](../rules/memory/MAL_Win_Loader_FamilyX_InMemory.yar) |
| [T1055.002](https://attack.mitre.org/techniques/T1055/002/) | 2 | [`MAL_Win_Loader_FamilyX_ConfigMarker`](../rules/windows/MAL_Win_Loader_FamilyX_ConfigMarker.yar), [`MAL_Win_Loader_FamilyX_InMemory`](../rules/memory/MAL_Win_Loader_FamilyX_InMemory.yar) |
| [T1210](https://attack.mitre.org/techniques/T1210/) | 1 | [`MAL_Win_Ransomware_WannaCry_Strings`](../rules/windows/MAL_Win_Ransomware_WannaCry_Strings.yar) |
| [T1486](https://attack.mitre.org/techniques/T1486/) | 1 | [`MAL_Win_Ransomware_WannaCry_Strings`](../rules/windows/MAL_Win_Ransomware_WannaCry_Strings.yar) |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | 1 | [`MAL_Win_Ransomware_WannaCry_Strings`](../rules/windows/MAL_Win_Ransomware_WannaCry_Strings.yar) |
| (nenhuma) | 2 | [`TEST_Multi_EICAR_File`](../rules/multi/TEST_Multi_EICAR_File.yar), [`TEST_Multi_EICAR_InZip_Stored`](../rules/multi/TEST_Multi_EICAR_InZip_Stored.yar) |

3/5 regra(s) com técnica mapeada; `mitre_attack = "none"` é válido quando não há técnica honesta.

## Por purpose × status

| purpose \ status | experimental | test | stable | deprecated | total |
|---|---:|---:|---:|---:|---:|
| hunting | 1 | 0 | 0 | 0 | 1 |
| triage | 0 | 4 | 0 | 0 | 4 |
| blocking | 0 | 0 | 0 | 0 | 0 |
| total | 1 | 4 | 0 | 0 | 5 |

Gate de promoção: `blocking` exige `stable` + `confidence = high`; `deprecated` fica fora dos bundles.

## Por scope

| scope | Regras | Quais |
|---|---:|---|
| file | 4 | [`MAL_Win_Loader_FamilyX_ConfigMarker`](../rules/windows/MAL_Win_Loader_FamilyX_ConfigMarker.yar), [`MAL_Win_Ransomware_WannaCry_Strings`](../rules/windows/MAL_Win_Ransomware_WannaCry_Strings.yar), [`TEST_Multi_EICAR_File`](../rules/multi/TEST_Multi_EICAR_File.yar), [`TEST_Multi_EICAR_InZip_Stored`](../rules/multi/TEST_Multi_EICAR_InZip_Stored.yar) |
| memory | 1 | [`MAL_Win_Loader_FamilyX_InMemory`](../rules/memory/MAL_Win_Loader_FamilyX_InMemory.yar) |
| both | 0 | - |

`memory`/`both` não podem depender de `uintN(0)`, `filesize` ou `pe.*` (lint); `scripts/memscan.py` usa só essas.

## Por família

| Família | Regras | purpose | status | scope |
|---|---:|---|---|---|
| EICAR-Test-File | 2 | triage | test | file |
| FamilyX | 2 | hunting, triage | experimental, test | file, memory |
| WannaCry | 1 | triage | test | file |

## Por engine

| engine | Regras |
|---|---:|
| any | 4 |
| yara-x | 1 |

`yara-x` = usa sintaxe/módulo que não compila em YARA 4.x (ver matriz em `scripts/compat_yara4.py`).

## Experimentais há mais de 90 dias

Referência: 2026-11-09. Candidatas a promoção (`test`) ou descarte; idade conta desde `date`.

Nenhuma (1 experimental(is) no total, todas com menos de 90 dias).

## Inventário

| Regra | id | v | status | purpose | scope | Família | MITRE | Arquivo |
|---|---|---:|---|---|---|---|---|---|
| `MAL_Win_Loader_FamilyX_ConfigMarker` | `f2522e58-c8f9-4ced-aea3-97419582c3f4` | 2 | test | triage | file | FamilyX | T1055.002, T1027 | `rules/windows/MAL_Win_Loader_FamilyX_ConfigMarker.yar` |
| `MAL_Win_Loader_FamilyX_InMemory` | `3c6a1f0e-7b2d-4e8a-9c41-5d2f8a0b6e17` | 1 | experimental | hunting | memory | FamilyX | T1055.002, T1027 | `rules/memory/MAL_Win_Loader_FamilyX_InMemory.yar` |
| `MAL_Win_Ransomware_WannaCry_Strings` | `1ad79fe1-7886-4d78-b8b7-6c6498b99e98` | 1 | test | triage | file | WannaCry | T1486, T1210, T1543.003 | `rules/windows/MAL_Win_Ransomware_WannaCry_Strings.yar` |
| `TEST_Multi_EICAR_File` | `557866dc-2447-4b56-b1ca-141721779893` | 1 | test | triage | file | EICAR-Test-File | none | `rules/multi/TEST_Multi_EICAR_File.yar` |
| `TEST_Multi_EICAR_InZip_Stored` | `0d85cd57-3805-4b9b-9905-47b9dea7c380` | 1 | test | triage | file | EICAR-Test-File | none | `rules/multi/TEST_Multi_EICAR_InZip_Stored.yar` |

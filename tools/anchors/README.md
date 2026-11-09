# tools/anchors — extrator de âncoras de código sem overfit

Recebe N amostras da mesma família e devolve sequências de instruções que todas
(ou pelo menos K) compartilham, já com `??` nos bytes que o compilador/linker
muda entre builds e **nunca** em opcodes. O que sobra depois do filtro de goodware
sai ranqueado e, se você pedir, como rascunho de regra `status = experimental`
no formato do lint.

```bash
pip install -r requirements-dev.txt          # capstone, pefile
python tools/anchors/extract_anchors.py samples/familyx_*.exe \
    --goodware /mnt/goodware --family FamilyX \
    --draft rules/windows/SUSP_Win_FamilyX_CodeAnchors.yar --json build/anchors.json
python scripts/lint_rules.py rules/windows/SUSP_Win_FamilyX_CodeAnchors.yar
```

Depois: adicione positivos e negativos em `tests/cases.py`, rode `make test` e
`make goodware`, e só então pense em `status = test`.

## Como funciona

| Etapa | O que faz | Por quê |
|---|---|---|
| Seções de código | `pefile`: seções com `MEM_EXECUTE`/`CNT_CODE` (ou `--raw` para blobs) | Strings e dados têm outro tratamento; aqui é só código |
| Superset disassembly | Toda posição da seção vira início de instrução; cadeias se fundem quando ressincronizam | Não depende de acertar o início da função; ruído das cadeias erradas não é comum entre amostras e some na interseção |
| Normalização por operando | Para cada instrução, `disp_offset/disp_size` e `imm_offset/imm_size` do capstone dizem quais bytes são disp32, rel8/rel32 (grupos JUMP/CALL/BRANCH_RELATIVE) ou imediato; esses viram `??` | Wildcard onde o linker mexe (RVAs, RIP-relative, alvos de salto, chaves) e nunca em opcode/prefixo/ModRM/SIB |
| Mineração | Janelas de `--min-insns` instruções são sementes; as comuns a >= K amostras são estendidas à direita enquanto continuarem comuns, até `--max-insns` | Dá a sequência compartilhada **máxima**, não um pedaço arbitrário |
| Limpeza | Apara filler nas bordas (`00 00`, `int3`, `nop`); descarta degenerados (< 3 mnemônicos distintos, < 4 valores de byte), `fixos < --min-fixed`, `wild > fixos`; remove sufixos e janelas sobrepostas | Zero-fill e nop sled são "comuns" a tudo; sufixos são artefato do superset |
| Goodware | Compila todos os candidatos como regras e escaneia `--goodware` | Candidato que acende em software legítimo é FP garantido |
| Score | `fixos × cobertura × raridade × bônus` — raridade = 1 / ocorrências médias por amostra; bônus 1.25 se há xor/rol/shift/imul…; ×0.5 se é só push/pop/mov/ret | Lógica de decoder vale mais que prólogo |

Política padrão de wildcard (ajuste com flags):

| Operando | Padrão | Flag |
|---|---|---|
| disp32 (RIP-relative, absoluto) | `??` | sempre |
| disp8 (`[rbp-0x20]`) | fixo | `--wild-disp8` |
| rel8/rel32 (jmp, jcc, call) | `??` | sempre |
| imm32/imm64 | `??` | sempre |
| imm8 (`xor al, 0x5a`, `shl eax, 3`) | `??` | `--keep-imm8` |

## Teste de aceitação

`tests/test_anchors.py` usa as fixtures que já existem: os dois builds sintéticos
do decoder da FamilyX (`familyx_decoder_build_a/b`, disp32/rel8/imm diferentes).
O extrator tem que achar, sem dica, exatamente

```
48 8B 0D [4] 48 85 C9 74 ?? 0F B6 01 34 ?? 88 01 48 FF C1
```

o mesmo `$decode` da regra escrita à mão, e o rascunho gerado tem que passar no
lint e casar as fixtures positivas sem casar as negativas.

## Limites (leia antes de confiar)

- É x86/x64 e código nativo. .NET, Go com tabelas, scripts e packers precisam de
  outra abordagem (desempacote antes; use `--raw` em dumps).
- Código compartilhado por biblioteca estática (CRT, zlib, OpenSSL) é "comum a
  todas as amostras" e também a meio mundo: o filtro de goodware é obrigatório,
  não opcional. Quanto maior e mais parecido com o ambiente-alvo, melhor.
- Sequências de prólogo/epílogo, PLT/IAT thunks e tabelas de salto aparecem no
  topo quando o goodware é pequeno. O score penaliza, não elimina.
- `k < N` é para famílias com builds divergentes; com `k` baixo demais você
  está extraindo "o que duas amostras têm em comum", não "a família".
- Sem Ghidra/IDA: o caminho é capstone puro. Um wrapper de Ghidra headless
  faria sentido para recuperar limites de função e cross-references (âncoras
  "chamadas pelo decoder"), mas não há Ghidra neste ambiente para validar, e um
  wrapper sem teste seria pior que nenhum.

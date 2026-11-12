# yara-x-detection-rules

**YARA-X detection-engineering repo: rules that survive clean corpora, new family builds, and noisy hunting pipelines. CC0.**

[![rules-ci](https://github.com/Phuderoso/yara-x-detection-rules/actions/workflows/ci.yml/badge.svg)](https://github.com/Phuderoso/yara-x-detection-rules/actions/workflows/ci.yml)
[![release](https://github.com/Phuderoso/yara-x-detection-rules/actions/workflows/release.yml/badge.svg)](https://github.com/Phuderoso/yara-x-detection-rules/actions/workflows/release.yml)
[![YARA-X](https://img.shields.io/badge/engine-YARA--X%201.23-blue)](https://virustotal.github.io/yara-x/)
[![license: CC0-1.0](https://img.shields.io/badge/license-CC0--1.0-lightgrey)](LICENSE)

English · [Português (Brasil)](README.pt-BR.md)

A YARA-X rules repository with **detection engineering** built into the CI. A rule is only
promoted after it proves three things: it matches the family (positive fixtures, including
different builds), it is not a generic detector (negative fixtures), and it does not fire on
legitimate software (a real goodware gate, diffed per PR). Releases ship signed bundles per
`purpose`.

The reasoning (what a good rule is, YARA vs YARA-X, where a rule sits in a hunting pipeline, why
file rules fail in memory) lives in [`docs/handbook.md`](docs/handbook.md) (Portuguese, the original)
and [`docs/handbook.en.md`](docs/handbook.en.md) (English translation). The contribution checklist is [`CONTRIBUTING.md`](CONTRIBUTING.md). What
the repo covers today, by technique, tier, scope and family, is [`docs/coverage.md`](docs/coverage.md)
(generated). How it was built, round by round, is in [`journal/`](journal/).

Beyond the CI, the repo ships two tools that usually live on an analyst's laptop:
[`tools/anchors`](tools/anchors/README.md) extracts code anchors from N samples with automatic
wildcards only on the operands that vary, and [`scripts/memscan.py`](scripts/memscan.py) runs
only the memory-scoped rules against dumps and images (Volatility 3).

[![fp-watch](https://github.com/Phuderoso/yara-x-detection-rules/actions/workflows/fp-watch.yml/badge.svg)](https://github.com/Phuderoso/yara-x-detection-rules/actions/workflows/fp-watch.yml) runs weekly against a reproducible clean corpus and opens a single `fp-regression` issue when a stable/test rule starts firing on goodware. Rule health (FPs, last true match, deprecation candidates) is in [`docs/health.md`](docs/health.md) (generated).

## Doctrine

- detection, not weapons
- maps, not war
- no live malware in the repo: fixtures are synthesized, real samples are hashes
- no secrets: one CI secret, read from the platform, never written down
- no host-attack kits: nothing here runs, injects, or persists anywhere
- every FP is a lesson, not a shame: it becomes a negative fixture and a journal line
- promote slowly, deprecate honestly: `experimental → test → stable → deprecated`, never deleted
- fork it: a fork is a new head

## Flow

```mermaid
flowchart LR
    A0[N samples\nof the family] -->|tools/anchors\ncapstone · wildcard per operand\ngoodware filter| A
    A[CTI / IR\nstable anchor] --> B[rules/*.yar\nmeta: id, version,\nstatus, purpose, scope, mitre]
    B --> C[lint\ncompile · meta · uniqueness\nstrings · formatting]
    C --> D[synthetic fixtures\npositives + negatives\nfakepe]
    D --> E[real goodware\nELF on Linux · PE on Windows\ndiff vs base · time budget]
    E --> F{review\nPR comment}
    F -->|status: test → stable| G[promotion\nblocking requires stable + high]
    G --> H[release\nbundles per purpose · .yar/.yarc\nSHA256SUMS · cosign keyless]
    H --> I[disk\nhunt.py → JSONL/ECS → SIEM]
    H --> J[memory\nmemscan.py → raw / Volatility 3]
    I -.->|FP / bypass / telemetry| B
    J -.->|FP / bypass / telemetry| B
    W[fp-watch weekly\nrunner + pip corpus by hash\nvs baseline.json] -.->|single fp-regression issue| B
    B -.-> K[docs/coverage.md · docs/health.md\nMITRE · purpose × status · scope\nFP · last match · deprecation candidates]
```

## Quickstart

```bash
make setup                 # pip install yara-x
make lint                  # compile + meta/lifecycle/uniqueness/string policies + formatting
make test                  # positives and negatives for every rule (in-memory fixtures)
make goodware GOODWARE=/mnt/goodware    # local FP gate
make fmt                   # YARA-X formatter (yr fmt)

# scanning on disk
python scripts/hunt.py /evidence/2026 --jsonl hits.jsonl
python scripts/hunt.py /evidence/2026 --jsonl hits.ecs.jsonl --format ecs   # ECS fields for the SIEM
python scripts/hunt.py sample.bin -s                                         # matched strings + offsets

# scanning memory (only rules with scope = memory/both)
python scripts/memscan.py proc_1234.dmp -s --jsonl mem.jsonl --format ecs    # VAD dump / procdump: raw bytes
python scripts/memscan.py memory.raw --backend vol3                          # full image via Volatility 3

# from N samples to a draft rule with the decoder's hex
python tools/anchors/extract_anchors.py samples/*.exe --goodware /mnt/goodware \
    --family FamilyX --draft rules/windows/SUSP_Win_FamilyX_CodeAnchors.yar
```

For tooling development: `make setup-dev` (ruff, mypy, pytest, bandit, yara-python, pre-commit)
and `make quality`.

## Layout

```text
rules/                        rules, one per file
  _TEMPLATE.yar               starting point (prefix "_" = ignored by the CI)
  windows/MAL_Win_Loader_FamilyX_ConfigMarker.yar   scope = file (MZ, PE header, filesize); fictional family
  windows/MAL_Win_Ransomware_WannaCry_Strings.yar   public family, strings and hashes from cited vendor reports
  memory/MAL_Win_Loader_FamilyX_InMemory.yar        scope = memory (decoder or decrypted config)
  multi/TEST_Multi_EICAR_File.yar                   the published EICAR test file (real, benign target)
  multi/TEST_Multi_EICAR_InZip_Stored.yar           EICAR inside a stored ZIP (deflate = documented limit)
rules-ci.toml                 limits: minimum strings, time budget, max file size in the corpus
scripts/
  yrlib.py                    compiler with policies, meta parsing, config, helpers
  lint_rules.py               lint (see "Rule contract")
  test_rules.py               runs tests/cases.py against every rule
  scan_goodware.py            FP gate: fails according to meta.purpose
  report.py                   hits + time per rule + fixtures → JSON (the CI's unit of comparison)
  diff_report.py              base vs head → Markdown (PR comment / job summary) + performance budget
  corpus_manifest.py          sha256 manifest of the goodware; runner drift becomes a diff
  hunt.py                     operational scan: sha256, strings/offsets, native JSONL or ECS
  memscan.py                  memory: only scope memory/both rules; raw backend (chunks) or Volatility 3
  coverage.py                 generates docs/coverage.md from meta; the CI fails if it is stale
  dataset_jsonl.py            generates dataset.jsonl (one JSON line per rule); the CI fails if it is stale
  health.py                   generates docs/health.md (FP, age, last match, deprecation candidates); CI-checked
  fp_watch.py                 FP watch: hash-pinned pip corpus, compare vs baseline, single fp-regression issue
  build_bundles.py            bundles per purpose (.yar + .yarc) + manifest + SHA256SUMS
  changelog.py                CHANGELOG from commits and the rules/ diff between tags
  compat_yara4.py             compatibility matrix against YARA 4.x (yara-python)
  fetch_samples.py            real positives from MalwareBazaar: download, scan, delete (manual)
  fmt_rules.py                formatter
tools/anchors/                anchor extractor: capstone, superset disassembly, wildcard per operand
tests/
  fakepe.py                   generates valid synthetic PE64 files for the `pe` module
  eicar.py                    builds the EICAR file (and zip) in memory from hex; the literal never hits disk
  cases.py                    positive and negative fixtures per rule (PE, memory regions, EICAR, WannaCry)
  test_eicar.py               sha256 of the fixture == published hash; no tracked file holds the literal
  test_anchors.py             extractor acceptance: finds FamilyX's $decode on its own
  test_memscan.py             synthetic dump, overlapping chunks, ECS, vol3 output parsing
  samples.lock                sha256 + family + source of real samples (no binaries)
  activity.json               last true match per rule (hunt.py / memscan.py --record-activity); feeds docs/health.md
  test_lint.py, test_tooling.py, test_fp_watch.py, test_health.py   pytest for the tooling
  goodware/                   local clean corpus (git-ignored) + manifests/, baseline.json, pip-corpus.txt
journal/                      build diary, case-files style, one file per day
AGENTS.md                     guidance for coding agents (layout, local CI, YARA-X pitfalls)
CREDITS.md                    authorship line (kept out of the README)
llms.txt                      short index for language models (llmstxt.org)
dataset.jsonl                 generated: one JSON line per rule (path, meta, string ids, test cases)
.github/workflows/ci.yml      lint → fixtures → goodware ELF → diff vs base → goodware PE (windows)
.github/workflows/release.yml tag v* → bundles → cosign → GitHub Release
.github/workflows/fp-watch.yml weekly: reproducible clean corpus → stable/test rules → baseline → one issue
docs/handbook.md              the craft (Portuguese, the original)
docs/handbook.en.md           the craft, English translation
docs/coverage.md              generated panel (MITRE, purpose × status, scope, family, experimental > 90d)
docs/health.md                generated panel (status, age, FPs, last match, deprecation candidates)
```

No binary is versioned: fixtures are generated in memory by `fakepe.py` and `eicar.py`; goodware
and samples stay outside the repo (or only as hashes in `samples.lock` and in the manifests).

## Real targets without malware

- **EICAR** (`TEST_Multi_EICAR_File`, `TEST_Multi_EICAR_InZip_Stored`). The
  [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) is a published 68-byte
  string every antivirus detects by convention; harmless, and the one detection target that fits a
  repo with no malware. The fixture *is* the target: `tests/eicar.py` builds it from hex at test
  time and `tests/test_eicar.py` checks its sha256 against the published one. The literal string is
  never written, not even in a comment: any tracked file containing it would trip antivirus on the
  Windows runner's checkout (a test scans the tree for it). Rules and fixtures use hex for the same
  reason; the lint accepts `// allow-hex-as-text` on exactly that line. The zip rule only sees
  **stored** members: YARA-X does not inflate, so a deflated zip is a negative fixture and a
  documented limit, not a hidden one. Rule prefix `TEST_` exists for this: not malware, not a
  hypothesis.
- **WannaCry** (`MAL_Win_Ransomware_WannaCry_Strings`). One public, exhaustively documented family.
  Every string (kill-switch domain, embedded-zip password, component names) and both hashes come
  from the vendor reports cited in the rule's `meta` (Kaspersky Securelist, Microsoft, Cisco Talos,
  MalwareTech, CISA TA17-132A). The condition requires a PE under 8 MB and either a unique anchor
  or two component names, so IOC lists and reports do not fire. `tests/samples.lock` carries the
  two public sha256s for the manual `real-samples` job; nothing is committed.

## Rule contract

Enforced by `scripts/lint_rules.py`; the CI breaks the PR if it fails.

| Requirement | Rule |
|---|---|
| Name | `^(MAL\|HUNT\|SUSP)_<Platform>_<...>$`, unique in the repository |
| `id` | UUID, unique in the repository, never changes |
| `version` | integer ≥ 1; +1 on every logic change |
| Required `meta` | `id`, `version`, `author`, `date`, `modified`, `description`, `hash`, `status`, `purpose`, `mitre_attack`, `scope` |
| `status` | `experimental` → `test` → `stable` → `deprecated` |
| `purpose` | `hunting` \| `triage` \| `blocking` |
| Promotion gate | `blocking` requires `status = stable` **and** `confidence = high`; `deprecated` stays out of the bundles |
| Dates | `YYYY-MM-DD`; `modified` ≥ `date` |
| `hash` | md5/sha1/sha256 of the seed sample |
| `mitre_attack` | `"T1055.002, T1027"` or `"none"` (YARA meta has no list type; comma-separated string) |
| `scope` | `file` \| `memory` \| `both`; `memory`/`both` may not use `uintN(0)`, `filesize` or `pe.*` in the condition |
| `license` | optional, must be `"CC0-1.0"` if present (the whole repo is CC0) |
| Text strings | ≥ 6 bytes (or `// yara-lint: allow-short`) |
| Hex | ≥ 6 fixed bytes and fewer wildcards than fixed bytes (or `// yara-lint: allow-wildcards`) |
| Compiler | zero warnings (deprecated field, slow pattern, missing meta, name off-pattern) |
| Formatting | identical to `yr fmt` |
| Tests | ≥ 1 positive **and** ≥ 1 negative in `tests/cases.py` |

### FP gate by `purpose`

| `purpose` | Width | Hit on goodware |
|---|---|---|
| `hunting` | wide, an analyst investigates | warning |
| `triage` | medium, labels/prioritizes | **fails** (or warns with `--triage-warn`) |
| `blocking` | narrow, the EDR kills | **fails** |

## What the CI does on a PR

1. **code**: ruff, ruff format, mypy (strict), pytest (lint, tooling, anchor extractor, memscan),
   bandit, pip-audit.
2. **rules**: lint → fixtures → `docs/coverage.md`, `dataset.jsonl` and `docs/health.md` up to date → runner's ELF goodware → `report.py`
   on head **and** base (same scripts, base's rules) → `diff_report.py` posts as a PR comment and
   in the job summary: new/removed hits per rule (with sha256), time per rule with Δ%, fixtures
   that changed. Fails if a rule exceeds `max_rule_seconds`, regresses more than
   `max_regression_pct` (above `regression_floor_seconds`, to ignore noise) or produces a new hit
   in triage/blocking. Limits in `rules-ci.toml`.
3. **corpus manifest**: builds the sha256 manifest of the runner's goodware and compares it with
   the pinned one in `tests/goodware/manifests/<os>.json`, if present. Runner image drift shows up
   as a list of added/removed/changed files, not as a mysterious FP. To pin: download the
   `reports-*` artifact and commit `manifest-<os>.json` as `tests/goodware/manifests/<os>.json`.
4. **compatibility**: tries to compile every file with `yara-python` (YARA 4.x) and publishes the
   matrix. A rule that only compiles on YARA-X must declare `engine = "yara-x"`.
5. **windows**: FP gate and time per rule on `System32`, `SysWOW64`, Git, Node, PowerShell and
   7-Zip (real PE goodware). Also runs every Monday.
6. **real-samples** (manual, `workflow_dispatch` with `real_samples=true`): downloads the entries
   of `tests/samples.lock` from MalwareBazaar with the `MALWAREBAZAAR_API_KEY` secret, scans in a
   tmpdir, checks the expected rules and deletes. Nothing is executed or kept as an artifact.
   Without the secret the job warns and ends green.

## Release

A `vX.Y.Z` tag (semver; `-rc1` etc. becomes a pre-release) triggers `release.yml`:

- `blocking.yar` / `triage.yar` / `hunting.yar` (concatenated source) and `.yarc` (compiled
  YARA-X). Cumulative: `blocking ⊂ triage ⊂ hunting`. `deprecated` stays out.
- `manifest.json` (rules, ids, versions, scope, source sha256), `compat-yara4.json`,
  `CHANGELOG.md` (generated from commits + `rules/` diff since the previous tag), `SHA256SUMS`.
- Everything signed with **Sigstore/cosign keyless** through GitHub Actions OIDC
  (`*.sigstore.json`). Verification:

```bash
cosign verify-blob --bundle blocking.yar.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Phuderoso/yara-x-detection-rules/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  blocking.yar
```

## Anchor extractor (`tools/anchors`)

Given N samples of a family, it finds instruction sequences common to all of them (or to K),
with automatic `??` on disp32, rel8/rel32, immediates and RVAs (from capstone's operand
information, never on opcodes), drops whatever fires on goodware and ranks by fixed bytes,
rarity and coverage. The acceptance test is FamilyX's decoder: from the two synthetic builds
(different disp32/rel8/imm) it returns, unprompted,
`48 8B 0D [4] 48 85 C9 74 ?? 0F B6 01 34 ?? 88 01 48 FF C1`, the same `$decode` written by
hand, and the `experimental` draft passes lint and fixtures. Method, flags and limits in
[`tools/anchors/README.md`](tools/anchors/README.md).

## Memory (`scope` and `memscan.py`)

A file rule starts with `uint16(0) == 0x5A4D and filesize < 2MB and pe.is_pe`; in a VAD dump
none of that exists (no header at offset 0, `filesize` is the region size, `pe` does not parse
mapped sections). Hence `meta.scope`: the lint rejects those clauses in `memory`/`both` rules and
`scripts/memscan.py` compiles **only** those rules. The `raw` backend scans raw bytes in
overlapping chunks (procdump, VAD dump, `windows.memmap --dump`); the `vol3` backend calls
Volatility 3 (`yarascan`/`vadyarascan`, which already uses YARA-X) for images with a detected OS
and brings PID/process; `auto` tries vol3 and falls back to raw. Output is native JSONL or ECS
(`event.category: [malware, process]`, `yara.memory.offset`, `process.pid`). The why is in the
handbook's "Memória" section. `memscan.py --record-activity` records memory hits in
`tests/activity.json` (source `memscan`), exactly like `hunt.py` does for files.

## FP watch (`fp-watch.yml`)

A rule that is clean today can start firing next month because the runner image changed, a new
library shipped, or the rule was loosened. `fp-watch.yml` runs every Wednesday (and on demand):

1. **Reproducible clean corpus**: `/usr/bin`, `/usr/sbin`, `/usr/lib/x86_64-linux-gnu`, `/usr/libexec`
   of `ubuntu-latest`, plus the wheels in `tests/goodware/pip-corpus.txt`, pinned by version **and**
   sha256 (`pip download --require-hashes`, unzipped, never installed). `corpus_manifest.py` records
   the sha256 of every file, so image drift shows as a diff, not as a mystery.
2. **Scan with stable and test rules only** (`--status stable,test`): `scan_goodware.py` for the gate,
   `report.py` for hits with sha256 and time per rule.
3. **Compare with `tests/goodware/baseline.json`**: a hit whose sha256 is not in the rule's `known_fp`
   is a new FP (regression for `triage`/`blocking`, warning for `hunting`); time above
   `max_rule_seconds` or more than `max_regression_pct` over the baseline (above the noise floor) is a
   regression. Known FPs that disappeared are listed as informational.
4. **One issue, no spam**: `fp_watch.py issue` finds the open issue labeled `fp-regression` that
   carries its marker. Same diff → no write at all (a digest in the body). Different diff → edits
   the body. Clean run → one comment and close. Only the default `GITHUB_TOKEN`, with
   `contents: read` and `issues: write`.

Accepting the current state as the baseline, after fixing or consciously tolerating an FP, is a
human decision and a commit; the workflow never writes to the repository. Two paths:

- **From the runner (recommended):** run `fp-watch` manually with `propose_baseline: true`. The job
  writes `baseline.proposed.json`, `health.proposed.md` and a `baseline.patch` into the artifact
  and shows the diff in the run summary, nothing else. Then locally:
  `gh run download <run-id> -n fp-watch-<run-id> -D build/artifact && make fp-propose ARTIFACT=build/artifact`.
  That rewrites `tests/goodware/baseline.json` and `docs/health.md` in your working tree from the
  runner's report and manifest; review `git diff`, commit, open the PR.
- **Locally:** `make fp-compare` then `make fp-baseline REPORT=build/report.json`. The baseline then
  carries *your* machine's corpus hash; the first runner run will flag "corpus changed" until it is
  re-based from an artifact.

`baseline.json` also keeps `last_fp` and `fp_total` per rule, which feed the health panel.

## Health panel

`docs/health.md` is generated by `scripts/health.py`: per rule, status, purpose, scope, age, time
since last change, known FPs, total FPs ever, last FP (from the baseline) and last true match (from
`tests/activity.json`, written by `hunt.py --record-activity`, `memscan.py --record-activity` or by hand
after an IR; source `published-target` marks the EICAR rules, whose fixture is the published file). Rules with FPs
on record and no true match in 12 weeks are listed as **deprecation candidates**; `test`/`stable`
rules with neither FP nor match are listed as unproven. Ages are in bands so the file only changes
when a rule crosses one; the CI runs `--check` like it does for coverage.

## Coverage panel

`docs/coverage.md` is generated by `scripts/coverage.py` from `meta`: rules per MITRE technique
(with links), purpose × status matrix, per scope, per family, per engine, and the list of
`experimental` rules older than 90 days (promotion or discard candidates, in > 90/180/365 bands
so the file does not change every day). The CI runs `--check` and fails if the committed file
does not match the generated one; `make coverage` regenerates.

## Rule dataset (`dataset.jsonl`)

`dataset.jsonl` is generated by `scripts/dataset_jsonl.py`: one JSON object per rule, sorted by
path, with `path`, `line`, `name`, `platform` (the directory under `rules/`), every `meta` field as
written in the rule (integers stay integers), the file's `imports`, the string identifiers
(names only, not the values), and `tests.positive` / `tests.negative`, the names of the cases in
`tests/cases.py` that must and must not match the rule. When `meta.hash` is a prefix of the
digest of an empty file, the row also gets `hash_note`. The FamilyX `hash` is a placeholder
(FamilyX is a fictional family), not the hash of a real sample. Nothing else is inferred; `status` is the
local lifecycle described in "Rule contract". The CI runs `--check` (every line must parse as
JSON and the file must match the generated one); `make dataset` regenerates.

## Scanning and SIEM

`scripts/hunt.py --format ecs` emits one ECS document per hit:

| ECS | source |
|---|---|
| `file.hash.sha256`, `file.path`, `file.size` | scanned file |
| `rule.name`, `rule.id`, `rule.version`, `rule.author`, `rule.description`, `rule.reference`, `rule.category` | the rule's `meta` (`category` = `purpose`) |
| `threat.technique.id[]`, `threat.framework` | `mitre_attack` |
| `threat.software.name` | `malware` |
| `event.severity` | `severity` (low 21, medium 47, high 73, critical 99) |
| `yara.strings[]` | id/offset/length of every matched string |
| `yara.scope`, `yara.memory.offset`, `process.pid` | `memscan.py`: rule scope, offset in the image and PID (vol3) |

`hunt.py --record-activity` marks the matched rules with today's date in `tests/activity.json`
(source `hunt`), which is what `docs/health.md` means by "last true match".

## YARA-X

This repo is YARA-X (`yara-x` bindings ≥ 1.23). Two things the compiler already caught in the
example rule that matter for migrations:

- a string declared and not used in the condition is an **error** (`E022`), not a warning;
- `pe.number_of_sections` is deprecated → `pe.sections.len()` (which does not exist in YARA 4.x);
- `import "pe"` parses **every** scanned file, whatever the condition order: `uint16(0) == 0x5A4D`
  first does not skip it. On the Windows runner's PE corpus that cost 28.14s for one rule; since v3
  the example rule reads the header by hand (`uint32(uint32(0x3C)) == 0x00004550`,
  `uint16(uint32(0x3C) + 6) < 12`), the same corpus takes 0.32s, and the rule no longer needs
  `engine = "yara-x"`.

Before/after examples of the mistakes models often make when writing YARA-X (unused
string = `E022`, `pe.number_of_sections` → `pe.sections.len()`, cost of `import "pe"`)
are in [`AGENTS.md`](AGENTS.md#common-ai-mistakes-writing-yara-x).

Equivalent CLI, if you prefer the `yr` binary:

```bash
yr check rules/                      # compiles and warns
yr fmt rules/                        # formats
yr scan -s rules/ sample.bin         # matched strings
yr scan -C dist/triage.yarc corpus/  # compiled bundle
```

## Related work

This repository is not a large public rule pack, and several of its ideas already exist
elsewhere. What it tries to be is one small, self-hosted, [CC0](LICENSE) pipeline that is
native to YARA-X.

Prior art we learned from (and do not replace):

- [YARA Style Guide](https://github.com/Neo23x0/YARA-Style-Guide) (Florian Roth) — naming,
  required meta, readable structure.
- [YARA Forge](https://github.com/YARAHQ/yara-forge) — aggregates and quality-checks public
  rule sets into ready-made packages.
- [YARA-CI](https://yara-ci.cloud.virustotal.com/) (VirusTotal) — an external GitHub service
  that validates rules and scans a large goodware corpus.
- [yaraQA](https://github.com/Neo23x0/yaraQA) — static quality and performance checks on
  YARA rules.
- [mkYARA](https://github.com/fox-it/mkyara) (Fox-IT) and
  [YARA-Signator](https://github.com/fxb-cocacoding/yara-signator) — automatic rule generation
  from code, including operand wildcards. This repo's [`tools/anchors`](tools/anchors/README.md)
  is a small cousin, not a replacement.
- [Elastic YARA rules](https://github.com/elastic/protections-artifacts) use `scan_context`
  (`file`, `memory`) in meta; this repo's `scope` field plays a similar role.
- [Sigma](https://github.com/SigmaHQ/sigma) popularized a status lifecycle (`experimental` /
  `test` / `stable` / `deprecated` / `unsupported`); this repo uses four of Sigma's five
  values (all but `unsupported`) as a local policy, not as a Sigma port.
- [Volatility 3](https://github.com/volatilityfoundation/volatility3) already scans memory
  with YARA/YARA-X; [`scripts/memscan.py`](scripts/memscan.py) is a thin wrapper around raw
  dumps and vol3, not a new memory-forensics framework.

What this repo does differently, on purpose:

- Everything lives in one small self-hosted pipeline: lint, synthetic fixtures, a goodware
  gate, a per-PR hit and time diff, weekly fp-watch, coverage and health panels, and signed
  releases. YARA-CI is an external service; the tools above are separate projects.
- It is written for YARA-X first. Most of the public tooling grew up on YARA 4.x.
- [`scripts/lint_rules.py`](scripts/lint_rules.py) rejects `filesize`, `pe.*` and `uintN(0)`
  in rules with `scope = "memory"` or `"both"`. We are not aware of a public linter that
  enforces that specifically.
- Fixtures are built at runtime in memory ([`tests/fakepe.py`](tests/fakepe.py),
  [`tests/eicar.py`](tests/eicar.py)). No real malware is committed; the EICAR literal is
  stored only as hex so checkouts do not trip antivirus.
- Every PR gets a diff of hits and time per rule against the base branch, a time budget,
  and (on a schedule) fp-watch against a pinned clean corpus, plus a health panel with
  deprecation candidates.

Honest limits: there are only five rules today — two for the fictional FamilyX loader, two
for the published EICAR test file, and one for WannaCry built from cited public reports.
This is a repository-model and a harness, not a coverage pack. Naming, required meta, the
`purpose` FP gate, string floors and the time budget in `rules-ci.toml` are this
repository's policies, not a community standard. Scan times quoted in the docs (28.14s
before v3, 0.32s after, on the Windows runner's PE corpus) are the author's own
measurements on that runner, not a published benchmark.

## Security of the tooling itself

- SAST: `bandit` on the scripts on every PR; `pip-audit` on the dependencies; weekly Dependabot
  for pip and GitHub Actions.
- How to report an FP, a bypass or a CI problem: [`SECURITY.md`](SECURITY.md).

## License

Everything in this repository, rules and code alike, is dedicated to the public domain under
[CC0 1.0 Universal](LICENSE). No attribution required; it is appreciated. Rules may carry
`license = "CC0-1.0"` in `meta` so the dedication travels with the bundle. Credits:
[CREDITS.md](CREDITS.md).

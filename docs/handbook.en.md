# Handbook: detection engineering with YARA-X

> **Translation note.** This is the English translation of [`handbook.md`](handbook.md), which is
> written in Portuguese and remains the original: if the two disagree, the Portuguese file wins and
> this one has a bug (open an issue). Code blocks, rule excerpts and commands are copied unchanged;
> comments inside them are translated. Everything here is CC0, like the rest of the repository.

The next level is not "more strings". It is **detection engineering**: a rule
that survives a clean corpus, a new build of the family, and a pipeline that
does not blow up with FPs.

Three layers.

---

## 1. Writing a *good* rule

A bad rule matches a generic symptom. A good rule matches a **stable artifact
of the family** and demands enough context not to fire on legitimate
software.

### What to pick as evidence

Quality order, best to worst:

| Quality | Example | Why |
|---|---|---|
| Unique code / stack strings / config parser | `"CONFIG_START::mutex_id::"` | Almost only the family has it |
| PDB, mutex, campaign ID, internal user-agent | `"C:\\build\\loader_v3\\src\\inject.c"` | Stable across samples |
| Hex of a piece of logic (not of an address) | decoder bytes, without absolute RVAs | Survives rebasing |
| Combination of imports + PE structure | `pe.imports("kernel32.dll", "WriteProcessMemory")` + atypical section | Weak alone, strong together |
| Isolated API names | `"CreateRemoteThread"` | Every injector, packer and a lot of legitimate tooling |

Rule of thumb: if the string shows up in `kernel32`, in an Adobe installer or
in a public GitHub repo, it is **not** the anchor. It can be *context*, never
the trigger on its own.

### Anatomy of a production rule

This repo's reference rule is
[`rules/windows/MAL_Win_Loader_FamilyX_ConfigMarker.yar`](../rules/windows/MAL_Win_Loader_FamilyX_ConfigMarker.yar).
In short:

```yara
condition:
  uint16(0) == 0x5A4D and
  filesize > 8KB and
  filesize < 2MB and
  uint32(uint32(0x3C)) == 0x00004550 and   // "PE\0\0" at e_lfanew
  uint16(uint32(0x3C) + 6) < 12 and        // NumberOfSections
  ( $marker or $pdb or $ua or $decode ) and
  2 of ($api_*)
```

Why this one survives better:

- **Magic + filesize first** — short-circuit. Cheap. Discards 90% of the corpus before regex/entropy.
- **No `import "pe"`** — the short-circuit applies to the condition, not to modules: an imported module
  parses **every** scanned file before the condition runs. With `pe.is_pe` and `pe.sections.len()`
  this rule took 28.14s on the Windows runner's PE corpus (budget: 20s); reading the header by hand,
  0.32s. Use `pe.*` when you need imports, version_info or the rich header, not to check "is it a PE".
- **Unique anchor OR decoder hex** — a single strong artifact already justifies the hit; APIs only reinforce.
- **Does not require every string** — the next build may drop the PDB. If you write `all of them`, the rule dies.
- **Does not use APIs alone** — `2 of ($api_*)` without an anchor would be a detector of "anything that injects", your own tools included.

Two fixes the YARA-X compiler imposed on the original version: a string that is
declared and not referenced in the condition is an **error** (do not leave
`$fp_*` "for decoration"), and `pe.number_of_sections` became
`pe.sections.len()`. One consequence of the second: `pe.sections.len()` does not
exist in YARA 4.x, so the rule declared `engine = "yara-x"`. Since v3 it does not
import `pe` (see above), compiles on YARA 4.x and shows up as portable in the CI
compatibility matrix.

### Anti-FP: the checklist that matters

**Always** test against a clean corpus *before* it goes to the SOC.

1. **Goodware**: Windows ISO, `System32`, common installers, Visual Studio redistributables, Chrome, Office, Python embeddable, NSIS, Inno Setup, 7-Zip SFX.
2. `yr scan -s rule.yar false_positive.exe` (or `scripts/hunt.py -s`) — **which string** matched? That is the one you kill or demote.
3. String `< 6 bytes` → almost always an FP. `.js`, `http`, `cmd`, `MZ` are not anchors. (The lint blocks it.)
4. Hex with too many `??` becomes "matches the universe". Wildcards only on immediates/offsets the linker moves. (The lint blocks more wildcards than fixed bytes.)
5. Regex is the last option. Hex with jumps is usually faster and more precise.
6. High entropy is **not** malware. It is a packer, or a compressed `.pdf`, or a `.png`. Use `math.entropy` only as an auxiliary filter after the magic.
7. Explicit exclusions when the FP is a known library:

```yara
condition:
  ... and
  not pe.version_info["CompanyName"] contains "Microsoft" and
  not $fp_vendor
```

8. One rule, one purpose. Hunting can be broad. **Blocking** has to be narrow. Do not mix the two in the same file without `meta.purpose`.

### Condition: `any` vs `all` vs groups

| Situation | Use |
|---|---|
| Each string is unique to the family | `any of ($uniq*)` |
| Weak strings, strong combination | `all of ($core*)` |
| Stable core + variants | `all of ($core*) and any of ($var*)` |
| Started producing FPs | `any` → `all`, or add an anchor |

Order in the condition (left → right):

```text
magic → filesize → cheap sections/imports → strings → regex/entropy/loops
```

Wrong (slow):

```yara
math.entropy(0, filesize) > 7.2 and uint16(0) == 0x5A4D
```

Right:

```yara
uint16(0) == 0x5A4D and filesize < 3MB and math.entropy(0, filesize) > 7.2
```

### The classic mistake: overfit vs underfit

- **Overfit**: copying 40 strings from *one* sample, timestamps and addresses included. It matches that hash. The recompiled sibling escapes.
- **Underfit**: three injection APIs + `MZ`. Matches half the world.

Target: 2–6 pieces of evidence that are **stable across samples of the same
family**, not across *all* families. Code reuse (the "gene" that Intezer and
similar tools extract) is the modern method: sign the binary snippet the family
reuses, not the wrapper that changes every week.

That is exactly what `tests/cases.py` encodes: two decoder "builds" with
different disp32/rel8/immediate **must** match; injection APIs without an anchor
**must not**.

---

## 2. YARA vs YARA-X

Classic YARA (C, 4.x) is in **maintenance**: bug fixes, few new features.
YARA-X is VirusTotal's Rust rewrite, stable since 1.0 (Jun 2025); as of
Nov 2026 the published bindings are in the **1.23** series. At VirusTotal it has
run in production for a while — billions of files, tens of thousands of rules.

Rule compatibility: ~**99%**. Most of your `.yar` compiles as is.

| | YARA 4.x | YARA-X |
|---|---|---|
| Language | C | Rust |
| Status | maintenance | where new modules and features land |
| Performance | still good on simple strings | faster in most cases |
| Heavy regex | slow; warning "may slow down scanning" | new engine; pathological cases drop from seconds to sub-second |
| `for` loops over filesize | expensive | much faster |
| Memory safety | history of parser bugs | Rust ownership; fewer crash/OOM bug classes |
| DX | `yara` CLI, terse errors | better errors, [language server](https://virustotal.github.io/yara-x/blog/introducing-the-yara-language-server/) (VS Code), formatter |
| APIs | C, Python (`yara-python`) | Rust, C/C++, Python, Go |
| Native lint | — | `allowed_metadata`, `allowed_rule_name`, `error_on_slow_pattern` (used in `scripts/yrlib.py`) |
| Fast scan | — | `--fast-scan`: throughput > depth, good for large collections |

Incompatibilities that catch people during migration
([official doc](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/)):

```yara
// YARA 4.x accepted it; YARA-X requires the escape
$re = /abc\{/          // not /abc{/

// base64: YARA-X requires ≥ 3 chars and does not produce the old engine's classic FP
$b = "ABC" base64

// negative indexing is gone
// $a[-1]  → does not compile. Use explicit offsets.

// a string not used in the condition is an ERROR (E022), not a warning
// pe.number_of_sections is deprecated → pe.sections.len()
```

Migration tool: `yara2x` in the
[VirusTotal/yara-x](https://github.com/VirusTotal/yara-x) project.

Typical CLI:

```bash
yr scan -s rules/family.yar sample.bin     # -s = strings that matched
yr scan --fast-scan rules/ corpus/
```

If you are starting a pipeline *today*, start on YARA-X. Keep YARA 4.x only
where a product (EDR, old sandbox) still cannot take the new engine.

---

## 3. Fitting into a hunting pipeline

YARA is not the SIEM. It is an **artifact filter**. The pipeline decides what happens on a hit.

```text
hypothesis → evidence (RE/CTI) → rule
        → test goodware + samples           (make lint test goodware / CI)
        → promote                           (merge; meta.purpose sets the tier)
        → sweep (disk / memory / VT Livehunt / object store)
        → enrich the hit (hash, VT, sandbox, identity)   (scripts/hunt.py --jsonl)
        → case / detection / ignore
        → version and retire
```

### Three rule tiers (do not mix them)

| Tier | Breadth | Action on hit |
|---|---|---|
| **Hunting** | broadest, accepts FPs | an analyst investigates |
| **Triage** | medium | tags the sample, prioritizes the queue |
| **Blocking / prevent** | narrow, FP ≈ 0 | quarantine, EDR kill |

A hunting rule thrown into prevent becomes a political incident the day it
matches Chrome. That is why `meta.purpose` is mandatory and the CI treats the
tiers differently in the goodware gate.

### Where it runs

1. **Retrospective** — object store of dumps, disk images, malware collection, S3 evidence buckets.
2. **Livehunt** — VirusTotal Livehunt / Retrohunt: the rule runs on *everything* that reaches VT. Great for "where did this family show up?".
3. **Endpoint** — some EDRs accept custom YARA (LimaCharlie, Elastic, some CrowdStrike/Defender modes). Watch the CPU: fat regex × thousands of processes.
4. **Email/sandbox ingest** — in the detonator (CAPE, Joe, etc.) the rule classifies the dropped file *after* unpacking. Much more useful than on the packed binary.
5. **Memory** — `yr` on a process dump / Volatility. Catches strings decoded at runtime that the file on disk does not have.

### Memory: why the file rule fails there (and what to do)

The FamilyX file rule starts with `uint16(0) == 0x5A4D and filesize < 2MB and pe.is_pe`.
On disk that is its best part (cheap, cuts 99% before looking at strings).
In a process dump or a memory image, each of those three clauses is false or meaningless:

- **No PE header at offset 0.** What you scan is a region (VAD, mapped section,
  heap). The module's `MZ` is at the start of the *image*, not of the region; reflective
  loaders and packers wipe the header or never write it; injection via `WriteProcessMemory`
  copies only the payload. `uint16(0) == 0x5A4D` fails and the whole rule dies at the first `and`.
- **`filesize` is the size of what was dumped,** not of the binary: a 4KB region, a 200MB
  VAD, a 32GB image. Any size envelope becomes noise.
- **`pe.*` needs the file as it is on disk.** In memory the sections are aligned by
  `SectionAlignment` (0x1000), not by `FileAlignment` (0x200); RVAs do not match file
  offsets; the IAT has already been resolved and holds pointers, not names. The `pe` module
  does not parse a region, and even on a full image dump the fields that depend on file layout lie.
- **What was encrypted is in the clear.** That is the reason to scan memory: config, C2
  strings, the second-stage payload after unpacking. A memory rule can (and should) use
  anchors that *do not exist* on disk: `$cfg = "mutex_id=Global\\FamilyX_"` only appears after
  the decoder runs.
- **The code is still there.** The decoder stub (`$decode`) is the anchor that crosses disk and
  memory: mapped opcodes are the same bytes, with the same wildcards on the operands.

That is why the repo has `meta.scope`:

| `scope` | May use `uintN(0)`, `filesize`, `pe.*` | Where it runs |
|---|---|---|
| `file` | yes | `hunt.py`, `scan_goodware.py`, on-disk EDR, VT |
| `memory` | **no** (the lint blocks it) | `memscan.py` over VAD dump / procdump / Volatility |
| `both` | **no** | both |

`rules/memory/MAL_Win_Loader_FamilyX_InMemory.yar` is the memory version of the same family:
`$decode or 2 of ($marker, $pdb, $ua, $cfg)`, with no file gate at all. It also matches the
file on disk when the decoder is there, and that is fine: it is `hunting`, and the fixtures list it.

```bash
# region/VAD/procdump (raw bytes): YARA-X directly, in overlapping chunks
python scripts/memscan.py proc_1234.dmp -s --jsonl mem.jsonl --format ecs

# full image: Volatility 3 (uses YARA-X underneath when the module is installed)
python scripts/memscan.py memory.raw --backend vol3 --plugin windows.vadyarascan.VadYaraScan
```

Two traps: a memory rule is broader by construction (no size envelope, no PE), so it is
born `hunting` and moves up a tier only with telemetry; and `2 of` over isolated strings
is the minimum, because an AV scanner, an IR report or `memscan.py` itself carry those
strings in memory too.

### Minimal hunting loop example

Hypothesis: "family X loaders leave the config marker even after the bad packer".

```bash
# 1. validate FP
python scripts/scan_goodware.py /mnt/goodware/windows11-system32/

# 2. validate TP (private corpus, outside the repo)
python scripts/hunt.py samples/familyx/ -s

# 3. internal retrospective
python scripts/hunt.py /evidence/2026 --jsonl hits-$(date +%F).jsonl

# 4. the hit is not the end — it is the beginning
#    sha256 → VT/GTI → sandbox → machine identity → EDR timeline
```

The analyst does not close the ticket at the `match`. They close it when the
hit has become: family, patient zero, persistence, and whether the rule needs
tightening.

### Operating the rule (what mature teams do)

- Git repo, PR, review. No loose `.yar` on the desktop.
- CI: compile + scan over a **goodware pack** + scan over the family's samples. Break the PR if FP > 0 on goodware for `purpose = blocking` rules (here: `triage` too).
- `meta.hash` of the seed sample. Without it, 8 months from now nobody knows where it came from.
- Stable `meta.id` (UUID) and integer `meta.version`: the name may change, the id does not; the SIEM correlates by id and the CHANGELOG shows `v2 → v3`.
- Explicit lifecycle in `meta.status`: `experimental → test → stable → deprecated`. Only `stable` with `confidence = high` may become `blocking`; `deprecated` stays in the repo for history but out of the bundles.
- Version `date` / `modified`. Retire dead rules (the family is gone, or it started producing FPs on a new product).
- Map MITRE only if it is true. `T1055` on every injector rule helps nobody. `mitre_attack = "none"` is a valid answer.
- Diff per PR, not just pass/fail: new/removed goodware hits per rule, time per rule vs base, fixtures that changed. The reviewer reads what changed, not a green check.
- Goodware corpus with a manifest (sha256 per file). An FP points to a reproducible hash; runner image drift shows up as a diff.
- Release as a product: bundles per tier (`blocking ⊂ triage ⊂ hunting`), checksums, keyless signing (Sigstore), generated CHANGELOG. Whoever consumes the rule knows where it came from and what changed.
- Telemetry: hits per week, % confirmed FP, rule age. A rule that has not hit in 18 months and is not a canary → archive or retire it. The JSONL from `hunt.py`/`scan_goodware.py` is the raw material for this.

### Where YARA is weak (so you do not ask of it what it is not)

- Packed/crypted: the string is not in the clear on disk. The defender's answer: unpack in the sandbox, then YARA on the dumped image — not "write a magic rule for the packed file".
- Polymorphic / every build changes the strings: sign the **decoder** (stable hex), not this week's config.
- Pure behavior (who opened what): that is Sigma/EDR telemetry, not YARA.
- Legal proof on its own: YARA says "the pattern matched". Attribution comes from the rest of the case.

---

## How it fits together

```text
CTI / IR  →  stable anchor (rare string or logic hex)
          →  rule with an explicit purpose
          →  CI against goodware
          →  YARA-X in the scanner
          →  a hit becomes a case, not a blind alert
          →  feedback: tighten, broaden, or retire
```

That is the craft. The language is the easy part.

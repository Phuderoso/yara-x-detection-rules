# AGENTS.md

Guidance for coding agents working in this repository. Human contributors should start from
[`CONTRIBUTING.md`](CONTRIBUTING.md) and [`docs/handbook.md`](docs/handbook.md).

## Layout

- `rules/` — one rule per file (performance is measured per file). Platforms: `windows/`,
  `memory/`, `multi/`. New rules start from `rules/_TEMPLATE.yar`.
- `scripts/` — lint, fixtures, goodware scan, report/diff, bundles, coverage/health panels,
  hunt and memscan.
- `tests/` — pytest for the tooling, `cases.py` fixtures, `fakepe.py`, `samples.lock`. No real
  binaries in git. A local FP corpus lives under `tests/goodware/` (see that directory's README).
- `docs/` — `handbook.md` is the writing guide; `coverage.md` and `health.md` are generated, and
  CI fails if they are stale.
- `tools/anchors/` — extract decoder hex from samples into an `experimental` draft.
- `journal/` — historical build logs, not runbooks.
- `.github/workflows/` — `ci.yml` (PRs), `fp-watch.yml` (weekly), `release.yml` (semver tags,
  Sigstore/cosign keyless).
- `rules-ci.toml` — lint string floors and the time budget.

## Lint, tests, and CI locally

```bash
make setup-dev     # yara-x, ruff, mypy, pytest, bandit, yara-python, pre-commit
make lint          # compile + meta/lifecycle/uniqueness/string policies + yr fmt
make test          # synthetic positives and negatives
make quality       # ruff, ruff format, mypy, pytest, bandit
make ci            # lint + test + coverage-check + health-check + goodware + quality
```

`make ci` needs a local `tests/goodware/` tree for the FP gate. After changing a rule, increment
`version` and `modified`, then run `make fmt && make lint && make test && make coverage && make health`
so the generated panels stay in sync.

Other useful targets: `make fmt`, `make goodware GOODWARE=...`, `make report`, `make compat`,
`make bundles`, `make memscan IMAGE=...`, `make anchors SAMPLES='...' FAMILY=...`.

## Scope lint

`meta.scope` must be `file`, `memory`, or `both`. For `memory` or `both`, `scripts/lint_rules.py`
rejects condition clauses that only make sense on disk: `uintN(0)` (magic at offset 0),
`filesize`, and `pe.*`. `scripts/memscan.py` compiles only `memory`/`both` rules. A file rule
that checks MZ, filesize, or PE belongs in `scope = "file"`.

## Time budget

Set in `rules-ci.toml` and enforced by the CI report against the runner corpus:

- `max_rule_seconds = 20` — one rule scanning the whole corpus
- `max_regression_pct = 50` — versus the base branch, ignored below
  `regression_floor_seconds = 1.0` (runner noise)

Put cheap predicates first: magic, then filesize, then PE checks, then strings, then
regex/entropy.

## Do not `import "pe"` in hot rules

A YARA-X module parses every scanned file, before and independently of the condition.
`uint16(0) == 0x5A4D` written first short-circuits the condition, not the module. On the
Windows runner's PE corpus, `MAL_Win_Loader_FamilyX_ConfigMarker` with `import "pe"` took
28.14s (budget 20s). Since v3 the rule reads the two header facts by hand (`"PE\0\0"` at
`e_lfanew`, `NumberOfSections`) and the same corpus takes 0.32s. Use `pe.*` when you need
imports, version_info, or the rich header — not to ask "is this a PE?". See
`journal/2026-11-11-pe-budget.md` and `docs/handbook.md`.

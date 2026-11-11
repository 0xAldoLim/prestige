# Executed validation — 2026-11-10

This records local evidence. The full specification remains incomplete; no model
benchmark superiority is claimed.

## Current record

| Check | Actual result |
| --- | --- |
| Default suite (offline) | **151 passed, 3 skipped**; 11.3 s |
| With `PRESTIGE_TEST_IMAGE` pinned to `python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39` | **153 passed, 1 skipped** |
| With `PRESTIGE_TEST_GHIDRA=1` and the same image | **154 passed**; 39.7 s |
| Ruff | All checks passed |
| Wheel build | Built successfully (`python -m build --wheel`) |
| GitHub Actions `offline-validation` | Green on Ubuntu/Windows, Python 3.11 and 3.14 |
| IBoH / Celestial Gatekeeper | Solved; forward decoder reconstruction matched all 136 target bytes |
| VENOM | Flag supplied by an operator writeup; activation-phrase branch proven to be a decoy |
| Real Codex / B0 / B1 / P1 / P2 / P3 comparisons | **Not run**; no paid model comparison or performance claim |
| Remote challenge / endpoint broker / live renewal | **Disabled, not tested live** |
| Persistent debugger / Gray Swan / AgentLSD / AgentDojo | **Not implemented** |

The fixture worker is deterministic. Tokens are unknown for fixture runs, usage coverage
is 0, efficiency is null and the composite is `not_comparable`. Repeating small synthetic
fixtures does not estimate real CTF solve accuracy. Time excludes setup.

## Reproduce

```text
python -m pip install -e ".[dev,codex]"
python -m pytest -q
PRESTIGE_TEST_IMAGE=python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39 python -m pytest -q
PRESTIGE_TEST_GHIDRA=1 PRESTIGE_TEST_IMAGE=python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39 python -m pytest -q
ruff check .
python -m build
python -m prestige --help
python -m prestige --home ./private/smoke doctor
python -m prestige --home ./private/bench benchmark run --suite benchmarks/synthetic/suite.json --repetitions 3 --output ./private/results.json
git diff --check
```

Container tests are opt-in using `PRESTIGE_TEST_IMAGE`, pointing to an existing
reviewed immutable image containing python3. No automatic image download occurs.
Tests cover TCP, DNS, child egress, root writes, credential/socket absence, bounded
output and timed cancellation. Docker is not treated as a hardened VM guarantee.

## Historical record

Earlier baselines (2026-10-28, 83 tests, Codex-first wording) are superseded by the
current OpenCode-native record above. One historical paid Codex smoke turn used
11,563 input / 29 output tokens including 11,392 cached input; it is not a
current-workflow requirement and is not counted toward the current suite. Unknown
usage from earlier exploratory calls stays unknown.

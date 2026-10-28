# Executed validation — 2026-10-28

This records local evidence. The full specification and P0 remain incomplete.

| Check | Actual result |
| --- | --- |
| Windows host, Python 3.14.3; pytest 9.2.0; installed SDK 0.163.0 | **64 passed**, including explicitly enabled Docker isolation/cancellation tests; 5.87 s |
| Kali Linux container, Python 3.14.7, network disabled | **62 passed, 2 skipped**; 1.37 s. Skips: SDK types absent in that image; nested Docker unavailable |
| Ruff | All checks passed |
| Wheel and sdist | Built successfully using `python -m build --no-isolation` |
| Fresh Windows venv wheel install | Imported from installed site-packages; CLI fixture suite **4/4 verified** |
| Distribution audit | Wheel includes learning schema and exact MIT notice; sdist includes tests/conftest.py; schema bytes match pinned upstream |
| CLI smoke | Entry-point help, module entry point, doctor, configuration, benchmark, reports and unit-tested solve path passed |
| Owner skills integration | Real pinned read-only checkout search returned 3 cited matches; checkout unmodified |
| Synthetic Windows fixture benchmark, seed 2026, 3 repetitions | **12/12 verified**, 1,200 synthetic points; summed investigation wall time 0.243 s |
| Synthetic Kali fixture benchmark, 1 repetition | **4/4 verified**, 400 synthetic points; summed investigation wall time 0.024 s |
| Real Codex / B0 / B1 / P1 / P2 / P3 / real Ollama | **Not run**; no paid model usage or performance claim |
| Remote challenge / endpoint broker / live renewal | **Disabled, not tested live** |
| GitHub Actions | Configured; local checks do not establish remote CI success |

The fixture worker is deterministic. Tokens are unknown, usage coverage is 0,
efficiency is null and the composite is `not_comparable`. Repeating four small
synthetic fixtures does not estimate real CTF solve accuracy. Time excludes setup.

## Reproduce

```text
python -m pip install -e ".[dev,codex]"
python -m pytest -q
ruff check .
python -m build
python -m prestige --help
python -m prestige --home ./private/smoke doctor
python -m prestige --home ./private/bench benchmark run --suite benchmarks/synthetic/suite.json --repetitions 3 --output ./private/results.json
git diff --check
```

Container tests are opt-in using `PRESTIGE_TEST_IMAGE`, pointing to an existing
reviewed immutable image containing python3. The tested local Kali image was
`sha256:8ebf73b0ac7b5e706244ab5dff1d6fe80dc3ca0cc59585fd7053819ce001c8b6`.
No automatic image download occurs. Tests covered TCP, DNS, child egress, root
writes, credential/socket absence, bounded output and timed cancellation.

The portable Kali run mounted source and test wheels read-only, disabled networking
and used disposable storage. Reviewed native test dependencies needed a separate
executable dependency mount; the shipped runner retains a non-executable temporary
filesystem. No auth or private host directories were mounted. This does not certify
containment of arbitrary native malware or a scoped remote broker.

The initial Windows sandbox run could not use pytest's default temporary directory
and stalled during asyncio startup. Validation passed in the permitted normal process
context with workspace-local temporary directories, without relaxing application policy.

# Continuation / migration checkpoint — 2026-11-10

PRESTIGE is an **OpenCode-native** autonomous offline CTF investigation system.
OpenCode owns the generic agent runtime; the Python engine owns investigation strategy,
trusted tool authorization, evidence persistence, verification and isolation.
Codex and OpenAI API credentials are **optional legacy integrations**, not core
requirements.

## Current HEAD

- Actual HEAD: `5bd0df8` (local)
- Latest pushed commit: `5bd0df8` (`origin/main`)
- GitHub account: `0xAldoLim`
- CI: `offline-validation` passing on Ubuntu/Windows, Python 3.11 and 3.14
  (latest run to be confirmed after this push).

## What works now

- **OpenCode-native MCP broker**
  - `src/prestige/mcp_server.py` exposes PRESTIGE tools over stdio MCP.
  - Tools: `prestige_create_investigation`, `prestige_get_status`,
    `prestige_run_experiment`, `prestige_verify_candidate`,
    `prestige_start_analysis`, `prestige_get_analysis`, `prestige_cancel_analysis`.
  - Model-driven investigations default to and are locked to `backend=fake`; no
    provider credentials are requested or persisted.
  - Operator-controlled scope: source paths restricted to `PRESTIGE_ALLOWED_DIRS`
    / `config.allowed_source_dirs`, runner image loaded from operator config,
    model cannot supply rules files, runner images, or provider secrets.
- **Security boundaries**
  - Trusted artifact resolver (`Artifacts.resolve_path`) used by all path-taking
    tools; rejects absolute paths, traversal, unknown digests, symlinks and
    cross-investigation access.
  - MCP budgets enforce `max_turns`, `max_seconds`, per-tool deadline caps,
    terminal-state checks and persistent attempt accounting.
  - OpenCode `prestige` agent permissions deny shell/read/write/browser/skill and
    allow only `prestige_*` MCP tools.
- **Durable analysis jobs**
  - `JobManager` persists long-running Ghidra/radare2/python work outside the
    model conversation.
  - Cache by artifact digest + tool + normalized args within a run.
  - Failure classification (`tool_timeout`, `policy_denied`, `prestige_error`, …).
- **Isolated execution**
  - Reviewed Docker worker pinned by immutable digest:
    `python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39`.
  - Non-root, no network, no Docker socket, restricted mounts, CPU/memory/pids/time
    limits, bounded output.
  - `WorkspaceRunner` output directory made writable for the containerized user.
- **Tests**
  - Default suite: **120 passed, 3 skipped**.
  - With `PRESTIGE_TEST_IMAGE`: **122 passed, 1 skipped**.
  - With `PRESTIGE_TEST_GHIDRA=1 PRESTIGE_TEST_IMAGE=...`: **123 passed**.
  - Ruff clean; wheel builds.

## Latest executed checks

```bash
PRESTIGE_TEST_GHIDRA=1 PRESTIGE_TEST_IMAGE=python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39 \
  python -m pytest -q
# 123 passed in ~45 s
```

## Real challenge status

### IBoH / Celestial Gatekeeper — solved and independently verified

- Archive: `/home/kali/Prestige/gate.7z`
- Source: `/tmp/opencode/iboh/gate.exe` (PE32 i386 console)
- Solving run: `1646ef39be614ef7` via OpenCode `prestige` agent,
  model `opencode-go/kimi-k3.1-pro`.
- Result: a unique 34-byte flag candidate matching `BOH25{...}` was derived and
  independently verified by a forward reconstruction that matched all 136 encoded
  target bytes at VA `0x41f008`.
- Verification: `prestige_verify_candidate` returned
  `{verified: false, expected_available: false}` because no expected digest was
  configured; the derivation was instead checked by replaying the recovered
  decoder in isolated Python and confirming byte-for-byte equality with the
  dumped target. The binary was never executed.
- Decoder summary (preserved for reproducibility, flag value omitted from repo):
  1. `FUN_00401130`: 34 little-endian dwords XORed with repeating key
     `[0xdeadbeef, 0xcafebabe, 0x13371337]`.
  2. `FUN_004010a0`: 32-bit nonlinear byte mixer; inverted by exhaustive
     256-entry lookup (unique preimages).
  3. 64-bit LFSR seed `0x7f3a1c9e5b2d4f61` at `0x41f090`; reversed the shuffle
     swaps `i = 33..0` with `j = lfsr() % (i+1)`.
  4. Main input-byte transform `t(x)` inverted by enumeration (unique inverses).
  5. Forward reconstruction of the recovered candidate reproduced the 136 target
     bytes exactly.

### VENOM — in progress

- Path: `/home/kali/Prestige/venom_6acc0b13b97020e8cd0e3d02276b9626.zip`
- SHA-256: `d1a14ca7dc3044a97210c9d336237029b834bc64265633d1f127c3ca30bea28f`
- Prior runs: `62b1e633895444b8`, `f46789e7f71c461e`, `b1d67678d32642c2`,
  `ac3465420fc24566`.
- Recovered evidence: `venom.paper`, `FlagApp.exe`, PE32+ x86-64 GUI,
  OpenSSL/CRYPTOGAMS RC4, `TOILPAPE` marker, DER-like signature,
  `VENOM_ACTIVATION_PHRASE`, activation-phrase hint.
- Status: no verified candidate yet. The activation-phrase path remains the most
  promising next target.

## Completed milestones

1. OpenCode-native migration: no mandatory API keys or Codex default.
2. MCP trust-boundary hardening: artifact resolver, source policy, budgets,
   agent permissions.
3. Durable, cached, resumable analysis jobs.
4. Reviewed Docker worker and isolated Python execution.
5. Ghidra/radare2 integration validated.
6. First real autonomous CTF solve (IBoH) with reproducible verification.

## Next executable milestone

1. Resume VENOM using the now-validated durable analysis jobs and isolated Python
   worker. Target the `VENOM_ACTIVATION_PHRASE` check with bounded decompilation
   and decoder replay.
2. Preserve VENOM evidence and derivation; do not fabricate a flag.
3. Update public documentation to reflect the OpenCode-native architecture.
4. Continue adversarial-resilience and capability roadmap items as resources allow.

## Installed toolchain

- Python 3.13.12, pytest 9.2.0, pytest-asyncio 1.4.1.post1, ruff 0.17.4, build 1.6.1
- `mcp>=2,<3` Python SDK
- httpx 0.28.1 (for optional standalone OpenAI-compatible backend)
- `openai-codex` 0.163.0 (optional legacy extra)
- git 2.53.0, Docker 28.5.2+dfsg3
- `file`, `objdump`, `readelf`, `gdb`, `r2`/`radare2`
- Ghidra headless: `/usr/share/ghidra/support/analyzeHeadless`
- OpenCode v2.2.6

## Configured providers

- OpenCode Go models are the default and only required runtime.
- Verified models: `opencode-go/beam-free`, `opencode-go/kimi-k2.7-code`,
  `opencode-go/kimi-k3.1-pro`.
- Standalone OpenAI/Codex providers remain optional and unconfigured.

## Exact reproduction commands

```bash
cd /home/kali/projects/prestige
source .venv/bin/activate
python -m pytest -q
PRESTIGE_TEST_IMAGE=python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39 python -m pytest -q
PRESTIGE_TEST_GHIDRA=1 PRESTIGE_TEST_IMAGE=python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39 python -m pytest -q
ruff check .
python -m build --wheel
python -m prestige --home ./.prestige config set sandbox.image python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39
python -m prestige agent
```

## Known limitations

- No official challenge checker is integrated; verification is independent
  derivation/replay only.
- VENOM remains unsolved.
- Adversarial-resilience benchmarks (Gray Swan, AgentLSD, AgentDojo) are not yet
  integrated.
- Persistent GDB / `/exhaust` / future Claude adapter are roadmap items, not
  shipped features.

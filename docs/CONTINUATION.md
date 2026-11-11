# Continuation / migration checkpoint — 2026-11-10

PRESTIGE is an **OpenCode-native** autonomous offline CTF investigation system.
OpenCode owns the generic agent runtime; the Python engine owns investigation strategy,
trusted tool authorization, evidence persistence, verification and isolation.
Codex and OpenAI API credentials are **optional legacy integrations**, not core
requirements.

## Current HEAD

- Validated code HEAD: `84601b4` (this docs-only refresh is the commit containing this line).
- Latest pushed commit: see the latest `git log` on `origin/main`.
- GitHub account: `0xAldoLim`
- CI: `offline-validation` passing on Ubuntu/Windows, Python 3.11 and 3.14.

## What works now

- **OpenCode-native MCP broker**
  - `src/prestige/mcp_server.py` exposes PRESTIGE tools over stdio MCP.
  - Tools: `prestige_create_investigation`, `prestige_get_status`,
    `prestige_run_experiment`, `prestige_verify_candidate`,
    `prestige_start_analysis`, `prestige_get_analysis`, `prestige_cancel_analysis`,
    `prestige_request_operator`, `prestige_answer_operator`,
    `prestige_resume_investigation`, `prestige_skills_discover`,
    `prestige_skills_route`, `prestige_skills_search`, `prestige_skills_read`,
    `prestige_skills_pivots`, `prestige_skills_apply`.
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
  - Candidate verification reports an explicit `stage`
    (`discovered`, `derived`, `reproduced`, `independently_verified`) plus
    `checker: unavailable`; a digest match never implies official checker acceptance.
  - Human escalation: `prestige_request_operator` records a durable question and
    pauses the run; `prestige_answer_operator` relays an answer as
    `operator_relayed`, while `prestige answer RUN_ID ...` records an
    operator-direct answer without the model. Answers are evidence, not verification.
- **Owner skills integration**
  - `SkillsBridge` discovers all nine categories plus `solve-challenge`,
    `ctf-writeup` and `find-skills`; routes observed evidence to a primary skill
    and supporting categories; returns bounded excerpts with path, line and
    SHA-256 provenance; reads bounded sections; returns cross-category pivots.
  - Live MCP tools: `prestige_skills_discover`, `prestige_skills_route`,
    `prestige_skills_search`, `prestige_skills_read`, `prestige_skills_pivots`,
    `prestige_skills_apply`. `apply` records a `skill_route` event so the
    strategy choice is durable.
  - The external checkout stays read-only; `skills.path` is operator-configured.
- **Durable analysis jobs**
  - `JobManager` persists long-running Ghidra/radare2/python work outside the
    model conversation.
  - Cache by artifact digest + tool + normalized args within a run.
  - Identical requests reuse queued, running or completed jobs (no duplicate Ghidra).
  - Deterministic experiment tools (`inspect`, `strings`, `read`, `file`, `zip`,
    `base64`, `hex`, `xor`) reuse prior observations unless `force=true`.
  - New MCP sessions recover the same durable run state from SQLite (tested by
    reconnecting mid-investigation).
  - Failure classification (`tool_timeout`, `policy_denied`, `prestige_error`, …).
- **Isolated execution**
  - Reviewed Docker worker pinned by immutable digest:
    `python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39`.
  - Non-root, no network, no Docker socket, restricted mounts, CPU/memory/pids/time
    limits, bounded output.
  - `WorkspaceRunner` output directory made writable for the containerized user.
- **Tests**
  - Default suite: **171 passed, 3 skipped**.
  - With `PRESTIGE_TEST_IMAGE`: **172 passed, 1 skipped**.
  - With `PRESTIGE_TEST_GHIDRA=1 PRESTIGE_TEST_IMAGE=...`: **174 passed**.
- **Operator known-answer helper**
  - `prestige verify-candidate --expected-sha256 <digest> [--candidate-file PATH]`
    reads a candidate from stdin/file, reports only digests + `match`, and never
    persists or echoes the candidate value.
  - Ruff clean; wheel builds.

## Latest executed checks

```bash
PRESTIGE_TEST_GHIDRA=1 PRESTIGE_TEST_IMAGE=python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39 \
  python -m pytest -q
# 174 passed in ~39 s
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

### VENOM — flag obtained from an operator-supplied writeup (not autonomously derived)

- Path: `/home/kali/Prestige/venom_6acc0b13b97020e8cd0e3d02276b9626.zip`
- SHA-256: `d1a14ca7dc3044a97210c9d336237029b834bc64265633d1f127c3ca30bea28f`
- Prior runs: `62b1e633895444b8`, `f46789e7f71c461e`, `b1d67678d32642c2`,
  `ac3465420fc24566`, `dc8a90b9038343af`.
- Recovered evidence: `venom.paper`, `FlagApp.exe`, PE32+ x86-64 GUI,
  OpenSSL/CRYPTOGAMS RC4, `TOILPAPE` marker, DER-like signature,
  `VENOM_ACTIVATION_PHRASE`, activation-phrase hint.
- **Outcome:** the operator supplied a public writeup plus the challenge flag in chat.
  The literal flag is deliberately not stored in this repository. PRESTIGE did **not**
  solve VENOM autonomously; this is an operator-provided answer.

#### Independent checks performed against the binary

- The `VENOM_ACTIVATION_PHRASE` environment-variable path is a **decoy**:
  - The check is at `0x1409e4f1a`; it reads up to `0x26` bytes, requires `SAS{` and `}`,
    hashes the buffer with SHA-256 (initial hash words `6a09e667 0bb67ae85 3c6ef372
    a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19` confirmed at `0x140ceeda0`), and
    compares 32 bytes against `0x141172048`.
  - The writeup flag's SHA-256 does **not** equal the 32-byte target at `0x141172048`.
    Therefore the activation-phrase branch is not the real success path.
- Writeup-consistent structural evidence:
  - Skibidi/rizz themed strings at file offset `0x226ac18` onward
    (`venom level 10 sigma gyatt baby gronk ...`).
  - A ChaCha20 `expand 32-byte k` constant is present once in the binary.
  - A fake-gzip resource starts at file offset `0x11c108c`
    (`1f8b0808 0dd4c769 0203 76656e6f6d2e` -> `venom.`), matching the writeup's
    "SKIB blob with a fake gzip header".
- Writeup's real path (recorded for future verification work, not claimed as reproduced
  by PRESTIGE): GUI requests a licence file; a second Venom process is a debugger;
  real logic hides in `INVALID_INSTRUCTION` / `ACCESS_VIOLATION` handlers; a `ud2`
  redirects to the real `WinMain`; the protected flag app is encrypted with modified
  ChaCha20 keyed from the licence context; `DUMB` / `VAR` / `HWID` licence entities
  validate the context; the flag app requests `SKIBIDI-ID` over a pipe protocol.

## Completed milestones

1. OpenCode-native migration: no mandatory API keys or Codex default.
2. MCP trust-boundary hardening: artifact resolver, source policy, budgets,
   agent permissions.
3. Durable, cached, resumable analysis jobs.
4. Reviewed Docker worker and isolated Python execution.
5. Ghidra/radare2 integration validated.
6. First real autonomous CTF solve (IBoH) with reproducible verification.
7. VENOM flag obtained from an operator-supplied writeup; the binary's
   activation-phrase branch was independently shown to be a decoy.
8. Adversarial-resilience regression suite added (`tests/test_adversarial.py`):
   artifact text is treated as data, fake flags are not self-verified, candidate
   values are not echoed, radare2 shell injection is denied, strings output is
   bounded, MCP tool/scope escalation fields fail closed, and the expected digest
   remains operator-controlled.
9. Local known-answer verification exercised with an operator-supplied expected
   digest; the literal VENOM flag is not stored in the report or the repository.

## Next executable milestone

1. Extend adversarial coverage toward Gray Swan IPI Arena, AgentLSD and AgentDojo
   scenarios (tool-output injection, fake system instructions, decoy
   vulnerabilities, context flooding, cross-model handoff contamination).
2. Add a small operator-facing known-answer verification helper that accepts an
   expected digest without persisting the flag value.
3. Preserve VENOM evidence; do not claim PRESTIGE autonomously derived the
   writeup flag.

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
# operator known-answer check (candidate read from stdin; nothing persisted)
python -m prestige verify-candidate --expected-sha256 <64-hex-digest> < candidate.txt
```

## Known limitations

- No official challenge checker is integrated; verification is independent
  derivation/replay only.
- VENOM's flag came from an operator-supplied writeup, not from PRESTIGE's own
  autonomous path; the activation-phrase branch is a confirmed decoy.
- Adversarial-resilience benchmarks (Gray Swan, AgentLSD, AgentDojo) are not yet
  integrated.
- Persistent GDB / `/exhaust` / future Claude adapter are roadmap items, not
  shipped features.

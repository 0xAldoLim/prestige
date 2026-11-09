# Continuation / migration checkpoint — 2026-11-09

Read `docs/OPENCODE_HANDOFF.md`, `docs/DEVELOPMENT_MISSION.md`, `docs/roadmap.json` and
the current Git status. The user requested a status report and preparation to move
development to OpenCode. This does not change PRESTIGE's primary product backend.

The historical pushed baseline is `7a32b4557840d0a49b3590346d843e2a0b6426c1` (main).
The migration increment preserves subsequent local work. `git log -1` gives its exact
current revision; no self-referential future commit hash is embedded here.

## Current increment

- Strict, canonical SSE frame parser in `InferenceGate`:
  - Accepts only `data`, `event`, `id`, `retry` fields; rejects unknown fields.
  - Joins multiline `data:` per the SSE spec and reserializes accepted frames.
  - Enforces event/data type agreement and discards `response.metadata` frames.
  - `data: [DONE]` is tolerated but not forwarded.
- Active upstream provider socket cancellation:
  - `InferenceGate` tracks sockets opened by the official transport.
  - `cancel_sockets()` shuts them down; `close()` invokes it before server shutdown.
  - `CodexBackend.interrupt()` propagates cancellation to the gate.
- Local malicious-provider regression tests added:
  - Unknown SSE event names, event/data disagreement, unexpected fields.
  - Malformed JSON, missing completion, comments, carriage returns, metadata discard.
  - Request budget exhaustion and active upstream read cancellation timing.
- Public CLI controls for live solving:
  - `--live` enables real Codex inference (still requires authenticated SDK).
  - `--runner-image` accepts an immutable Docker digest for isolated tools.
  - `--max-artifact-mib` configures per-file inventory limits (1-256).
- Provider-independent OpenAI-compatible backend (`prestige solve --backend openai`):
  - Uses `httpx` to call any `/chat/completions` endpoint.
  - Supports explicit base URL, model and API key (key also via env).
  - Parses JSON proposals; enforces the same action schema as Codex.
  - No Codex SDK or CLI binary required.
- Engine/ToolRegistry integration:
  - `WorkspaceRunner` is constructed from run settings and passed to `ToolRegistry`.
  - Tool execution is offloaded to a thread and cancels owned containers on interruption.
  - Artifact previews use bounded `view()` instead of loading entire large files.
- Failed-attempt usage accounting:
  - New `attempts` run column counts every `backend.propose()` call, including failures.
  - `progress` events now record turns, attempts, tokens, elapsed and recovery signal.
- Local static reverse-engineering tools `file` and `radare2` added to the trusted
  tool surface. radare2 commands are allowlisted to prevent shell execution or file
  sourcing.
- Ghidra headless adapter added as a trusted `ghidra` tool. It runs a Java export
  script via `analyzeHeadless`, supports functions/strings/imports/exports/decompile
  modes, uses a temporary project and returns bounded JSON. Slow tests are opt-in
  via `PRESTIGE_TEST_GHIDRA=1`.
- End-to-end CLI integration test exercises the OpenAI backend against a local mock
  `/chat/completions` endpoint and verifies autonomous tool selection solves a base64
  challenge.
- Codex SDK `openai-codex==0.163.0` installed successfully after a slow background
  wheel download.
- Ghidra discovered at `/usr/share/ghidra/ghidraRun` with headless analyzer at
  `/usr/share/ghidra/support/analyzeHeadless`.
- Normal CLI remains gated (`live=False`). No paid inference was triggered.
- Internal per-run artifact-size policy, bounded byte views and adjusted ZIP limits.
  Default remains 1 MiB unless explicitly raised.
- Internal WorkspaceRunner: exact readonly blob/writable output mounts, offline Docker,
  command allowlist, file persistence, output collection and owned-container cancellation.
  Files persist; debugger processes do not.
- OpenCode project AGENTS.md, resume command, mission, handoff and machine-readable roadmap.
  OpenCode is running this Build session; PRESTIGE's own provider setup is separate.

## Latest executed checks

Kali Linux VM, Python 3.13.12:
**98 passed in 3.13 seconds**, 3 skipped (container tests require `PRESTIGE_TEST_IMAGE`).
Ruff clean. These are offline regressions, not an autonomous challenge or comparative benchmark.
No paid model call was made during this increment.

## Repository state

- Actual HEAD: `04d68d0a77ff0651d9b2f33fff90290a43029b20` plus local commits
- Branch: `main`
- Latest pushed commit: `04d68d0a77ff0651d9b2f33fff90290a43029b20` (identical to `origin/main`)
- Local commits since origin/main:
  - `6d36df9` strict SSE parsing and active upstream socket cancellation
  - `fae3a01` live CLI controls, runner wiring and failed-attempt accounting
  - `20c9816` provider-independent OpenAI-compatible backend
  - `003ca2e` local file tool and end-to-end OpenAI backend CLI integration test
  - `b6ecb10` allowlisted radare2 static analysis tool
- Recovered historical commits: none
- Missing historical commits:
  - `976fc33`
  - `4e778f1`
  - `22e7a3d`
  - `b07e5ed`
  - `651d987`
  - `9e4f4db`
  These unpushed objects were not found in the local repository or remote.

## Real challenge

VENOM:
- Path: `/home/kali/Prestige/venom_6acc0b13b97020e8cd0e3d02276b9626.zip`
- SHA-256: `d1a14ca7dc3044a97210c9d336237029b834bc64265633d1f127c3ca30bea28f`
- ZIP contents: `venom.paper` 1214 bytes; `FlagApp.exe` 36089344 bytes.
- Static inspection: PE32+ x86-64 GUI executable; strings indicate OpenSSL/CRYPTOGAMS
  RC4, SHA1, Camellia, Poly1305, X25519 and other primitives. No model-driven
  investigation, candidate or recovered flag yet.

IBoH / Celestial Gatekeeper:
- Archive: `/home/kali/Prestige/gate.7z` (538112 bytes extracted `gate.exe`)
- Archive SHA-256: `d3459995cd7543175f758cf7738bab8ec3bc04767102bfd18b715361faf656bc`
- Description image: `/home/kali/Prestige/Screenshot (11).png`
- Title: Celestial Gatekeeper; category: Reverse Engineering; points: 500.
- Flag format: `BOH25{flag}`; archive password: `ba5ada3d6169866673a5480745744cc4`.
- Status: description transcribed; no extraction, execution or investigation yet.

## Current phase

Phase 1: actual autonomous harness — inference boundary, live CLI controls, provider-
independent backend and local static RE tools complete. Codex SDK is installed; Ghidra
is present. Blocked on an authenticated model endpoint and a reviewed local runner image
before the first real VENOM investigation.

## Completed milestones

- Kali environment validated; repository up to date with `origin/main`.
- Python 3.13.12 virtual environment and offline dev dependencies installed.
- `InferenceGate` strict SSE parsing and active upstream socket cancellation.
- `CodexBackend.interrupt()` propagates cancellation.
- Malicious-provider regression tests passing.
- Explicit `--live`, `--runner-image`, `--max-artifact-mib` CLI controls.
- `WorkspaceRunner` wired into `ToolRegistry`; cancellable offloaded execution.
- Bounded artifact previews, failed-attempt accounting and progress events.
- Provider-independent OpenAI-compatible backend with tests.
- Local `file` and allowlisted `radare2` static analysis tools.
- Ghidra headless adapter and opt-in integration test.
- End-to-end mock-provider CLI solve regression.
- Codex SDK installed and Ghidra located.

## Next executable milestone

1. Authenticate Codex through `codex login` or configure an OpenAI-compatible endpoint.
2. Run the actual VENOM investigation through `prestige solve --backend openai` or `--live`.
3. Iterate on model-driven observations using `file`, `strings`, `radare2`, `ghidra` and
   the runner image once available.
4. Obtain or build a reviewed, immutable local Docker runner image for `python`/`command`.

## Installed toolchain

- Python 3.13.12, pytest 9.2.0, pytest-asyncio 1.4.1.post1, ruff 0.17.4, build 1.6.1
- httpx 0.28.1 (for the OpenAI backend)
- openai-codex 0.163.0 and openai-codex-cli-bin 0.163.0
- git 2.53.0, Docker 28.5.2+dfsg3
- `file`, `objdump`, `readelf`, `gdb`, `r2`/`radare2` present
- Ghidra: `/usr/share/ghidra/ghidraRun`, headless analyzer `/usr/share/ghidra/support/analyzeHeadless`
- Missing: `gdb-multiarch`

## Configured model providers

PRESTIGE runtime providers are not configured. OpenCode's development provider powers
this session only; it is not copied into PRESTIGE state.

## Real inference tested

No paid PRESTIGE runtime inference in this increment. All gate tests use mock
transports or fake sockets; the CLI integration test uses a local mock endpoint.

## Exact reproduction commands

```bash
cd /home/kali/projects/prestige
source .venv/bin/activate
python -m pytest -q
ruff check .
python -m build --wheel
python -m prestige --help
python -m prestige doctor
```

## External blockers

1. No authenticated model endpoint (Codex or OpenAI-compatible) is configured for
   PRESTIGE's runtime.
2. No reviewed, immutable local Docker runner image is available for isolated
   `python`/`command` tool execution.

No external authentication blocker was found for the Codex SDK on this machine historically.
OpenCode provider setup is separate; never read/copy Codex auth to migrate it.
Full roadmap/P0 remain incomplete.

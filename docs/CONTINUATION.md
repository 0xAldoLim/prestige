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
**88 passed in 2.83 seconds**, 3 skipped (container tests require `PRESTIGE_TEST_IMAGE`).
Ruff clean. These are offline regressions, not an autonomous challenge or comparative benchmark.
No paid model call was made during this increment.

## Repository state

- Actual HEAD: `04d68d0a77ff0651d9b2f33fff90290a43029b20` plus local commits
- Branch: `main`
- Latest pushed commit: `04d68d0a77ff0651d9b2f33fff90290a43029b20` (identical to `origin/main`)
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
- Status: inventoried only; no binary execution, model-driven investigation, candidate or flag.

IBoH / Celestial Gatekeeper:
- Archive: `/home/kali/Prestige/gate.7z` (538112 bytes extracted `gate.exe`)
- Archive SHA-256: `d3459995cd7543175f758cf7738bab8ec3bc04767102bfd18b715361faf656bc`
- Description image: `/home/kali/Prestige/Screenshot (11).png`
- Title: Celestial Gatekeeper; category: Reverse Engineering; points: 500.
- Flag format: `BOH25{flag}`; archive password: `ba5ada3d6169866673a5480745744cc4`.
- Status: description transcribed; no extraction, execution or investigation yet.

## Current phase

Phase 1: actual autonomous harness — inference boundary and live CLI controls complete;
blocked on authenticated Codex SDK and a reviewed local runner image before the first
real VENOM investigation.

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

## Next executable milestone

1. Complete installation of `openai-codex==0.163.0` (CLI binary wheel download in progress).
2. Optionally test the openai backend against a local model or small endpoint.
3. Obtain or build a reviewed, immutable local Docker runner image.
4. Authenticate Codex through `codex login` if not already authenticated.
5. Run the actual VENOM investigation through `prestige solve --backend openai` or `--live`.
6. Iterate on model-driven observations and isolated tool results.

## Installed toolchain

- Python 3.13.12, pytest 9.2.0, pytest-asyncio 1.4.1.post1, ruff 0.17.4, build 1.6.1
- git 2.53.0, Docker 28.5.2+dfsg3
- `file`, `objdump`, `readelf`, `gdb` present
- Missing: `gdb-multiarch`, Ghidra / `analyzeHeadless`

## Configured model providers

PRESTIGE runtime providers are not configured. OpenCode's development provider powers
this session only; it is not copied into PRESTIGE state.

## Real inference tested

No paid PRESTIGE runtime inference in this increment. All gate tests use mock
transports or fake sockets.

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

No external authentication blocker was found for the Codex SDK on this machine historically.
The current blockers are: (1) the `openai-codex-cli-bin` wheel download is still in progress,
and (2) a reviewed local runner image is not yet available. OpenCode provider setup is
separate; never read/copy Codex auth to migrate it. Full roadmap/P0 remain incomplete.

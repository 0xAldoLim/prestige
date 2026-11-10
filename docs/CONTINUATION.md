# Continuation / migration checkpoint — 2026-11-10

Read `docs/OPENCODE_HANDOFF.md`, `docs/DEVELOPMENT_MISSION.md`, `docs/roadmap.json` and
the current Git status. PRESTIGE is now an OpenCode-native project: OpenCode provides
the generic agent runtime, and the Python engine retains investigation strategy,
trusted tool authorization, evidence persistence and verification. Codex and Daybreak
are no longer required dependencies or default backends.

## Current increment

- OpenCode-native MCP bridge:
  - `src/prestige/mcp_server.py` exposes PRESTIGE tools over stdio MCP.
  - Tools: `prestige_create_investigation`, `prestige_get_status`,
    `prestige_run_experiment`, `prestige_verify_candidate`.
  - Handler return types conform to `mcp>=1,<2` (`ListToolsResult`, `CallToolResult`).
  - Evidence and action metadata are JSON-serializable and redacted before return.
- `prestige agent` CLI subcommand starts the MCP server.
- `.opencode/plugins/prestige/` registers the PRESTIGE MCP server and a dedicated
  `prestige` agent via `opencode.jsonc`.
- `pyproject.toml` adds `mcp>=1,<2` as an optional dependency group (`pip install -e ".[dev,codex,mcp]"`).
- Legacy Codex adapter remains isolated and optional; `openai-codex` is still in the
  `codex` extra but is not required for core workflows.
- Tests:
  - In-process MCP client tests verify tool listing, investigation creation, status
    roundtrip, experiment execution and observation recording, and candidate digest
    verification.
  - A stdio smoke test verifies `python -m prestige agent` answers an `initialize`
    JSON-RPC request.
  - Additional tests cover a complete create/inspect/transform/read/verify loop and
    fail-closed behavior for unknown tools and invalid investigation IDs.
  - Full suite: **106 passed, 3 skipped**.

## Latest executed checks

Kali Linux VM, Python 3.13.12:
**106 passed in 5.64 seconds**, 3 skipped (container tests require `PRESTIGE_TEST_IMAGE`,
ghidra test requires `PRESTIGE_TEST_GHIDRA=1`).
Ruff clean. `python -m build --wheel` succeeds.
No paid model call was made during this increment.

## Repository state

- Actual HEAD: `afd59df` (local)
- Branch: `main`
- Latest pushed commit: `afd59df` (`origin/main`)
- GitHub authentication: authenticated as `0xAldoLim` via `gh auth login --web`.
- Push status: all local commits pushed successfully.
- CI: `offline-validation` passed on Ubuntu/Windows, Python 3.11 and 3.14
  (latest run `42737614805`).

## Real challenge

VENOM:
- Path: `/home/kali/Prestige/venom_6acc0b13b97020e8cd0e3d02276b9626.zip`
- SHA-256: `d1a14ca7dc3044a97210c9d336237029b834bc64265633d1f127c3ca30bea28f`
- ZIP contents: `venom.paper` 1214 bytes; `FlagApp.exe` 36089344 bytes.
- Initial offline PRESTIGE investigation created through the MCP bridge:
  run `62b1e633895444b8`. The broker inventoried the ZIP, extracted the two members,
  identified `FlagApp.exe` as PE32+ x86-64 GUI, recorded radare2 section/entry-point
  output, and captured venom.paper strings. No candidate solution has been submitted
  or verified.
- Static inspection: PE32+ x86-64 GUI executable; strings indicate OpenSSL/CRYPTOGAMS
  RC4, SHA1, Camellia, Poly1305, X25519 and other primitives.
- No model-driven investigation, candidate or recovered flag yet.

IBoH / Celestial Gatekeeper:
- Archive: `/home/kali/Prestige/gate.7z` (538112 bytes extracted `gate.exe`)
- Archive SHA-256: `d3459995cd7543175f758cf7738bab8ec3bc04767102bfd18b715361faf656bc`
- Description image: `/home/kali/Prestige/Screenshot (11).png`
- Title: Celestial Gatekeeper; category: Reverse Engineering; points: 500.
- Flag format: `BOH25{flag}`; archive password: `ba5ada3d6169866673a5480745744cc4`.
- Status: description transcribed; no extraction, execution or investigation yet.

## Current phase

Phase 1 (OpenCode-native foundation) complete: MCP bridge, plugin, dedicated agent and
Python engine integration are validated offline. Phase 4 (real challenge investigation)
is blocked on a configured, authorized model endpoint and a reviewed local runner image.

## Completed milestones

- OpenCode-native MCP server and `prestige agent` CLI command.
- `.opencode/plugins/prestige/` plugin and `opencode.jsonc` registration.
- In-process and stdio MCP tests passing.
- Codex dependency decoupled from required/default backend.
- All prior milestones from 2026-11-09 remain intact (SSE gate, CLI controls, OpenAI
  backend, local RE tools, Ghidra adapter, mock end-to-end solve).

## Next executable milestone

1. Configure an authorized PRESTIGE runtime model endpoint (OpenAI-compatible or
   officially supported OpenCode provider) after verifying provider terms.
2. Obtain or build a reviewed, immutable local Docker runner image for isolated
   `python`/`command` tool execution.
3. Run the first real model-driven PRESTIGE investigation on VENOM through the
   OpenCode `prestige` agent, using only PRESTIGE tools and recording evidence.
4. Preserve the VENOM checkpoint and, only if VENOM stalls, investigate IBoH.

## Installed toolchain

- Python 3.13.12, pytest 9.2.0, pytest-asyncio 1.4.1.post1, ruff 0.17.4, build 1.6.1
- `mcp>=1,<2` Python SDK
- httpx 0.28.1 (for the OpenAI backend)
- openai-codex 0.163.0 and openai-codex-cli-bin 0.163.0 (optional)
- git 2.53.0, Docker 28.5.2+dfsg3
- `file`, `objdump`, `readelf`, `gdb`, `r2`/`radare2` present
- Ghidra: `/usr/share/ghidra/ghidraRun`, headless analyzer `/usr/share/ghidra/support/analyzeHeadless`
- OpenCode v2.2.6

## Configured model providers

PRESTIGE runtime providers are not configured. The OpenCode session can see the
`prestige` MCP tools, but no paid inference has been triggered. Any real model-driven
investigation requires explicit provider authorization and must be recorded separately.

## Real inference tested

No paid PRESTIGE runtime inference in this increment. All tests are offline mock or
in-process.

## Exact reproduction commands

```bash
cd /home/kali/projects/prestige
source .venv/bin/activate
python -m pytest -q
ruff check .
python -m build --wheel
python -m prestige --help
python -m prestige doctor
# Start MCP server manually:
python -m prestige agent
```

## External blockers

1. No authenticated PRESTIGE runtime model endpoint configured.
2. No reviewed, immutable local Docker runner image available for isolated
   `python`/`command` tool execution.

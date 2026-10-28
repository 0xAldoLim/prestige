# Continuation / migration checkpoint — 2026-10-28

Read `docs/OPENCODE_HANDOFF.md`, `docs/DEVELOPMENT_MISSION.md`, `docs/roadmap.json` and
the current Git status. The user requested a status report and preparation to move
development to OpenCode. This does not change PRESTIGE's primary product backend.

The historical pushed baseline is `7a32b4557840d0a49b3590346d843e2a0b6426c1` (main).
The migration increment preserves subsequent local work. `git log -1` gives its exact
current revision; no self-referential future commit hash is embedded here.

## Current increment

- Experimental text-only inference gateway and explicit internal `live=True` SDK path.
- Actual SDK/runtime mock-provider smoke and one successful real model smoke executed.
  Successful-turn usage: input 11563, output 29, cached input 11392, reasoning 0.
  Earlier compatibility-attempt usage is unknown. Do not repeat paid smokes needlessly.
- Internal per-run artifact-size policy, bounded byte views and adjusted ZIP limits.
  Default remains 1 MiB; CLI exposure and streaming hashes are unfinished.
- Internal WorkspaceRunner: exact readonly blob/writable output mounts, offline Docker,
  command allowlist, file persistence, output collection and owned-container cancellation.
  Files persist; debugger processes do not. The engine does not construct this runner.
- OpenCode project AGENTS.md, resume command, mission, handoff and machine-readable roadmap.
  OpenCode not found on PATH; installation/login/startup have not been validated.

## Latest executed checks

Windows host with explicit immutable local Kali Docker test image:
**75 passed in 19.95 seconds**, including the real workspace-runner isolation,
readonly-input and cross-call file-persistence test. Ruff and Python compilation passed.
These are offline regressions, not an autonomous challenge or comparative benchmark.
No paid model call was made during migration preparation. Baseline CI passed four
Ubuntu/Windows Python 3.11/3.14 jobs; check current CI after pushing the new increment.

## Real challenge

VENOM original SHA256:
`d1a14ca7dc3044a97210c9d336237029b834bc64265633d1f127c3ca30bea28f`.
ZIP metadata: venom.paper 1214 bytes; FlagApp.exe 36089344 bytes. Source untouched;
no binary execution, model-driven investigation, candidate or recovered flag exists.
Exact local source path and private probe references are in ignored
`private/migration/LOCAL_CONTEXT.md`, not a remote-repo dependency.

## Exact next action

Add active upstream-socket cancellation and canonical, strict SSE-frame handling to
InferenceGate, with local malicious-provider real SDK/runtime tests. Keep normal CLI
gated. Then integrate explicit live/image/large-artifact CLI controls, cancellable
offloaded tool execution, complete failed-attempt usage accounting and useful progress
signals. Only after those checks run the actual VENOM investigation through PRESTIGE.

No external authentication blocker was found for the Codex SDK on this machine. The
current blockers are unfinished engineering/integration. OpenCode provider setup is
separate; never read/copy Codex auth to migrate it. Full roadmap/P0 remain incomplete.

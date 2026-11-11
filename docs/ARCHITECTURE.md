# Architecture

PRESTIGE is split into two cooperating layers:

1. **OpenCode agent runtime** — owns the generic agent loop, model transport, model
   selection and provider authentication. It is not reimplemented in Python.
2. **Trusted Python engine** — owns investigation identity and scope, challenge
   strategy, tool authorization, evidence persistence, progress evaluation, candidate
   verification and isolated execution.

OpenCode talks to the engine through a stdio MCP server (`src/prestige/mcp_server.py`,
started by `prestige agent`). The project `opencode.jsonc` registers that server and a
restricted `prestige` agent whose permissions allow only `prestige_*` tools.

## Investigation flow

`prestige_create_investigation` validates an operator-controlled source path, snapshots
the artifact into content-addressed storage, and returns a `run_id`.
`prestige_get_status` returns bounded state: artifact previews, recent observations,
hypotheses, progress and candidates. `prestige_run_experiment` executes one authorized
tool and records an observation. `prestige_verify_candidate` records a candidate and
reports an explicit stage (`discovered`, `derived`, `reproduced`,
`independently_verified`). `prestige_start_analysis` / `prestige_get_analysis` /
`prestige_cancel_analysis` provide durable, cached jobs for expensive tools.
`prestige_request_operator` / `prestige_answer_operator` provide durable human
escalation; `prestige answer` records an operator-direct answer from the CLI.

SQLite WAL is the canonical state. An `RLock` and immediate transactions serialize
writes within one process; SQLite's lock and busy timeout serialize separate processes.
A run lease excludes concurrent solvers. Append-only event keys are idempotent.

## Trust boundary

Proposals carry testable hypotheses, never facts. Tools accept content-hash artifact IDs,
not arbitrary paths. The trusted resolver (`Artifacts.resolve_path`) rejects absolute
paths, traversal, unknown digests, symlinks and cross-investigation access. Byte
transforms produce child artifacts with replayable parent records.

The verifier needs a separately supplied trusted digest. Absent one, candidates stay
unverified and `expected_available` is false. `reproduced` means a referenced derivation
artifact contains the candidate bytes; it is not an official checker.

The model cannot expand scope through tool arguments: source paths, rules files, runner
images and provider credentials are operator-controlled. MCP budgets persist across
sessions and cap tool attempts, wall time and per-tool deadlines. Artifact contents and
tool output are untrusted data.

## Lanes and duplicate suppression

AUTO keeps the same canonical artifact/evidence store when moving from FAST to EXPERT.
Duplicate fingerprints include content hash, tool and normalized JSON arguments. A
deterministic stagnation rule stops or escalates after two actions without new artifacts.
Durable jobs reuse queued, running or completed results; deterministic experiment tools
reuse prior observations unless `force=true`. This is a simple heuristic, not calibrated
expected information gain or semantic equivalence of arbitrary code.

## Skills and learning

SkillsBridge returns small lexical reference chunks with paths, lines and content hashes.
Knowledge first searches accepted local records, then the configured skill corpus. New local
decoding records pass replay, schema and static sanitization gates; related skills require
review.

## Isolated execution

The optional Docker worker is a separate offline data plane. It uses an immutable image
digest, a non-root user, no network, no host Docker socket, restricted capabilities,
narrow mounts, CPU/memory/pids/time limits and bounded output. It is not a substitute for
isolating every provider built-in tool, and Docker is not a hardened VM guarantee.
Persistent debugger sessions are not yet implemented.

## Scheduling and remote scope

Competition scheduling uses transparent user priority, deadline and points order; no
model probability estimates. No endpoint broker is shipped and remote challenge
networking remains disabled. `--instance` fails closed.

## Optional legacy backends

The standalone Codex SDK and OpenAI-compatible adapters remain available for explicitly
configured use. They are not required by the OpenCode-native workflow and never persist
provider secrets in investigation settings.

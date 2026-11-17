# Architecture

PRESTIGE is split into two cooperating layers:

1. **OpenCode agent runtime** — owns the generic agent loop, model transport, model
   selection and provider authentication. It is not reimplemented in Python.
2. **Trusted Python engine** — owns investigation identity and scope, challenge
   strategy, tool authorization, evidence persistence, progress evaluation, candidate
   verification and isolated execution.

OpenCode talks to the engine through a stdio MCP server (`src/prestige/mcp_server.py`,
started by `prestige agent`). The project `opencode.jsonc` registers that server and
three project agents: a delegation-only `orchestrator` (Kimi K3.1 Pro), an autonomous
`executor` (free DeepSeek V4.1 Flash) and the restricted `prestige` CTF agent (free
DeepSeek V4.1 Flash), whose permissions allow only `prestige_*` tools.

## Model routing

Routing is deliberately asymmetric:

- `orchestrator` is `primary` on `opencode-go/kimi-k3.1-pro`. It may read/glob/grep,
  but shell/edit/write/browser/web/skill are denied and its only subagents are
  `executor` and `prestige`. It decomposes work, gives each subagent a self-contained
  task with acceptance criteria, and reviews recorded evidence. It is instructed to
  intervene only for initial planning, meaningful failures, strategy changes, major
  decisions and final evaluation.
- `executor` is a `subagent` on `opencode/deepseek-v4.1-flash-free`. It executes
  implementation, commands, debugging, tests and research end to end without asking
  the orchestrator to approve individual tool calls, and cannot spawn further
  subagents.
- `prestige` is mode `all` on `opencode/deepseek-v4.1-flash-free`. It is the direct CTF
  path and keeps the existing host-tool denials: only `prestige_*` MCP tools are
  allowed.

`default_agent` is `orchestrator`; the root fallback model and the
`compaction`/`title`/`summary` helpers use
`opencode/deepseek-v4.1-flash-free`. The built-in `build`, `plan`, `general` and
`explore` agents are disabled. Provider policy allows only `opencode-go` and
`opencode`, and checked-in disable lists leave exactly the Kimi and free-DeepSeek
routes selectable. Paid `opencode-go/deepseek-v4.1-flash` (Flash 1017), GPT-6 Luna
and other fallbacks are disabled; a free-route failure is reported rather than
substituted. Configuration and model choice are not a security sandbox: the Python
broker still enforces operator-controlled source paths, target registrations, budgets,
image policy and verification commitments. Real routing evidence is recorded in
[MODEL_ROUTING.md](MODEL_ROUTING.md).

## Investigation flow

`prestige_create_investigation` validates an operator-controlled source path, snapshots
the artifact into content-addressed storage, and returns a `run_id`.
`prestige_get_status` returns bounded state: artifact previews, recent observations,
hypotheses, progress and candidates. `prestige_run_experiment` executes one authorized
tool and records an observation. V3 adds `prestige_exec`, which runs bounded argv inside
the isolated worker without a host shell, and `prestige_target_bind`, which lets the
model bind an already operator-registered target but never register or widen scope. `prestige_verify_candidate` records a candidate and
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

## Adversarial resilience

`src/prestige/deception.py` deterministically classifies untrusted text for instruction
overrides, authority/verification claims, scope probes, credential or exfiltration
requests, tool-output conflicts, cross-model handoffs, hidden/encoded instructions and
decoys. Findings carry `policy_effect: "none"`; they are evidence about data, not
authority. `src/prestige/trust.py` centralizes the rule that only operator-controlled
origins may authorize policy or verification.

MCP creation, experiments, skills, research and verification attach bounded deception
summaries. `prestige_deception_scan` can re-scan an artifact or recorded event. The
evaluator refuses to treat an observation containing instruction/verification claims as
supporting or falsifying evidence and cross-checks hypotheses that share support.
`Knowledge.propose` stores actionable model proposals as `quarantined`; operators can
release or quarantine records, and a contaminated run can quarantine its inbox. Cached
research can be quarantined and is then excluded from search.

`src/prestige/adversarial_adapters.py` parses native AgentDojo suite YAML and static
`GOAL` literals, Gray Swan behavior JSON/attack YAML, and AgentLSD-style pairs without
executing upstream code. `run_corpus`/`run_pairs` report attack success, detection,
clean-side false positives, added tool calls, legitimate completion and recovery.
`src/prestige/opencode_harness.py` optionally runs the real OpenCode loop and reads
outcomes from PRESTIGE state; no solve is inferred from model text.

## Lanes, budgets and duplicate suppression

V3 raises the AUTO/EXPERT attempt ceiling to 30 so an investigation is not exhausted
merely because it used more than twelve evidence actions. FAST remains the lightweight
direct path; EXPERT is jumped to only on observed stagnation or task complexity.
Duplicate fingerprints include content hash, tool and normalized JSON arguments. A
deterministic stagnation rule stops or escalates after two actions without new artifacts.
Durable jobs reuse queued, running or completed results; deterministic experiment tools
reuse prior observations unless `force=true`. This is a simple heuristic, not calibrated
expected information gain or semantic equivalence of arbitrary code.

Budget handling is explicit: a request is capped by an operator ceiling and then by the
selected lane, and creation/resume return the requested and effective values with an
adjustment note. The wall clock starts at the first tool attempt in both enforcement and
resume, so an idle investigation does not appear to have spent its budget.
`progress.assess` is a deterministic, advisory signal over durable observations: it
classifies recent repeated action/result signatures as `no_progress` or `loop_suspected`,
keeps distinct new outputs `productive`, and only recommends `escalate` when there is
stagnation plus enough remaining attempts/time. It never changes lane, model, provider or
scope. The independent hypothesis evaluator uses the same signal to avoid escalating a
pending or merely difficult test.

## Skills and learning

Web research supports DuckDuckGo HTML, Tavily (API key from the environment) and an
operator-hosted SearXNG endpoint. Search results are metadata; fetched pages remain
allowlisted and cached with provenance. Blind benchmarks disable research or restrict
it so challenge solutions cannot be retrieved.

SkillsBridge returns small lexical reference chunks with paths, lines and content hashes.
Knowledge first searches accepted local records, then the configured skill corpus. New local
decoding records pass replay, schema and static sanitization gates; related skills require
review.

## Isolated execution

The optional Docker worker is a separate offline data plane. It uses an immutable image
digest, a non-root user, no network, no host Docker socket, restricted capabilities,
narrow mounts, CPU/memory/pids/time limits and bounded output. It is not a substitute for
isolating every provider built-in tool, and Docker is not a hardened VM guarantee.
Persistent sessions can run any executable or argv string available in the reviewed
worker, including interpreters, shells, GDB and radare2. The container, not an executable
name allowlist, is the isolation boundary. `prestige_exec` likewise permits arbitrary
argv inside the worker while retaining no network, dropped capabilities, narrow mounts
and resource limits.

## Scheduling and remote scope

Competition scheduling uses transparent user priority, deadline and points order; no
model probability estimates. No endpoint broker is shipped and remote challenge
networking remains disabled. `--instance` fails closed.

## Optional legacy backends

The standalone Codex SDK and OpenAI-compatible adapters remain available for explicitly
configured use. They are not required by the OpenCode-native workflow and never persist
provider secrets in investigation settings.

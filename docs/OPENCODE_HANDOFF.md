# OpenCode development handoff

Prepared 2026-10-28. This migrates **development context**, not product-provider
support, credentials, private challenge files or a running agent session.

## Start

Open a terminal in this repository, run `opencode`, choose/authenticate a provider
through OpenCode's supported UI if required, and issue `/prestige-resume`.
No model or provider has been forced by this repository. No global OpenCode settings
have been changed. OpenCode was not found on the current development PATH, so its
installation, login and runtime command discovery remain unverified.

If this OpenCode version does not discover the custom command, paste:

> Continue PRESTIGE development. Read AGENTS.md, docs/CONTINUATION.md,
> docs/DEVELOPMENT_MISSION.md and docs/roadmap.json. Read
> private/migration/LOCAL_CONTEXT.md if present. Preserve Git history and local work.
> Complete the next unmet acceptance criteria with tests, then continue. Keep the
> Codex-first product architecture and all isolation/scope restrictions.

The project `AGENTS.md` and `.opencode/commands/prestige-resume.md` follow official
[rules](https://opencode.ai/docs/rules/) and
[custom-command](https://opencode.ai/docs/commands/) documentation checked on
2026-10-28. Version-specific startup behavior must still be checked in the installed
OpenCode version. No OpenCode-for-CTF plugin or OpenCode 1.x version lock is required.

OpenCode's permissions and external-directory approvals belong to the development
environment. They do not enforce PRESTIGE's runtime sandbox. Honor any enforced
approval; never bypass it with another identity, command wrapper or endpoint.

## Honest status

The pushed baseline is commit `7a32b4557840d0a49b3590346d843e2a0b6426c1` on `main`.
Its four Windows/Ubuntu Python 3.11/3.14 CI jobs passed. Local work after that commit
adds the experimental gateway and unfinished artifact/workspace-tool extensions.
Check `git log` and `git status` for the latest migration checkpoint; this baseline
identifier is historical, not a claim that later local work has been pushed.

- Working baseline: installable Python CLI, SQLite state/leases, bounded byte tools,
  fixture worker, lane handoff, digest+replay verifier, lexical skills retrieval,
  narrow local learning, advisory Ollama, queue and synthetic benchmark harness.
- One real SDK/model turn succeeded through the text-only gateway. The normal CLI
  still constructs `CodexBackend` with live=False and is deliberately gated.
- `WorkspaceRunner` now exists as an internal extension with exact run-blob/output
  mounts, network disabled, limits and file persistence. The engine does not yet
  construct/pass it into ToolRegistry. It is not a persistent debugger session.
- Artifact policy has internal stored-limit and bounded-read support. `new_run` and
  CLI do not yet expose the larger limit. Hashing/inventory still load complete
  files into memory; streaming large-file snapshots remain unfinished.
- VENOM has only been hashed/inventoried. No model-driven challenge investigation,
  recovered flag, independent real-challenge verification or B0/B1 comparison exists.

## First implementation target

Finish the inference boundary before connecting it to useful tools. Current gaps:

1. `InferenceGate.close()` shuts down its listening server but does not explicitly
   cancel each active upstream TLS socket. `CodexBackend.interrupt()` only interrupts
   the SDK turn. Add cancellation propagation and tests for active upstream reads.
2. SSE validation currently parses data lines separately. Normalize complete frames,
   reject malformed/multiline ambiguity and event/data disagreement, reserialize only
   accepted events, and test that native calls cannot slip through any representation.
3. Add opt-in actual SDK/runtime tests against a local malicious mock transport. A
   local mock-provider runtime test spends no model quota. Existing runtime smoke is
   a private scratch script rather than a committed repeatable integration test.
4. Bound startup/retry/request counts, record failed attempts/unknown usage, and make
   error/context recovery preserve evidence. Current accounting misses some failed turns.
5. Tool execution is synchronous in the async engine; add bounded offloading and
   cancellation that actually removes owned containers without orphaning writer threads.

Then expose explicit live/image/large-artifact options, pass a validated runner,
record meaningful observations as progress, and run VENOM through the public CLI.
Do not simply set live=True in the current engine or bypass a gate to get a solve.

## Local/private continuity

`private/migration/LOCAL_CONTEXT.md` is intentionally ignored. On the existing
machine it identifies the repository, workspace, existing venv, skills checkout,
VENOM path, previous scratch probes and full original continuation request.
It contains no credentials and is not part of the public repository or distribution.
On a fresh clone it will be absent; set local paths explicitly and ask only for
genuinely missing inputs. Do not copy provider auth or private transcripts to migrate.

The source tree is authoritative. Older README/status claims describe the shipped
baseline; docs/CONTINUATION.md and roadmap distinguish local experiments from release
capabilities. Update product claims only when public-interface acceptance tests pass.

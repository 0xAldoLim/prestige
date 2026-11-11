# OpenCode development handoff

Prepared 2026-11-10. PRESTIGE is an **OpenCode-native** autonomous offline CTF
investigation system. OpenCode owns the generic agent runtime and model transport;
PRESTIGE's Python engine owns investigation strategy, trusted tool authorization,
evidence persistence, progress evaluation and candidate verification.

## Start

Open a terminal in this repository. If OpenCode is installed and authenticated,
run the restricted `prestige` agent directly:

```bash
opencode run --standalone --agent prestige --model opencode-go/kimi-k2.7-code \
  "Resume the existing authorized offline investigation."
```

Or invoke the registered custom command:

```text
/prestige-resume
```

No model or provider has been forced by this repository. No global OpenCode settings
have been changed. The repository's `opencode.jsonc` registers the `prestige` MCP server
and a restricted `prestige` agent that can call only `prestige_*` MCP tools. See
[PROVIDERS.md](PROVIDERS.md) for model-family and Claude guidance; a Claude subscription
is not assumed to grant API credits and Claude is never mandatory.

If OpenCode is not on PATH, install it through its official mechanism and authenticate
a provider if required. Then paste:

> Continue PRESTIGE development. Read AGENTS.md, docs/CONTINUATION.md,
> docs/DEVELOPMENT_MISSION.md and docs/roadmap.json. Read
> private/migration/LOCAL_CONTEXT.md if present. Preserve Git history and local work.
> Complete the next unmet acceptance criteria with tests, then continue. PRESTIGE is
> OpenCode-native; keep Codex/OpenAI adapters optional and preserve isolation/scope
> restrictions.

The project `AGENTS.md`, `.opencode/commands/prestige-resume.md` and `opencode.jsonc`
follow official [rules](https://opencode.ai/docs/rules/) and
[custom-command](https://opencode.ai/docs/commands/) documentation.
No OpenCode-for-CTF plugin or OpenCode 1.x version lock is required.

OpenCode's permissions and external-directory approvals belong to the development
environment. They do not enforce PRESTIGE's runtime sandbox. Honor any enforced
approval; never bypass it with another identity, command wrapper or endpoint.

## Honest status

The pushed baseline is commit `82f7bb3` on `main`. Its CI jobs validate offline tests,
packaging and Ruff on Ubuntu/Windows with Python 3.11 and 3.14. Check `git log` and
`git status` for the latest migration checkpoint; this baseline identifier is historical,
not a claim that later local work has been pushed.

- Working baseline: installable Python CLI, SQLite state/leases, bounded byte tools,
  fixture worker, lane handoff, digest+replay verifier, lexical skills retrieval,
  narrow local learning, advisory Ollama, queue and synthetic benchmark harness.
- OpenCode-native MCP broker (`src/prestige/mcp_server.py`) exposes trusted tools over
  stdio and is registered by `.opencode/plugins/prestige/index.ts`.
- Restricted `prestige` agent in `opencode.jsonc` can call only `prestige_*` tools;
  shell/read/write/browser/skill are denied.
- Durable analysis jobs (`src/prestige/jobs.py`) cache Ghidra/radare2/python work by
  artifact digest and normalized arguments, persisting state outside the conversation.
- `WorkspaceRunner` is wired into MCP investigations via operator-controlled config
  (`sandbox.image`); it uses a pinned immutable Docker image, no network, restricted
  mounts and resource limits.
- Artifact policy uses a trusted resolver (`Artifacts.resolve_path`) that rejects
  absolute paths, traversal, unknown digests, symlinks and cross-investigation access.
- IBoH / Celestial Gatekeeper was solved and independently verified by forward decoder
  reconstruction matching all 136 encoded target bytes. VENOM has been inventoried and
  partially analyzed; no verified candidate exists yet.

## First implementation target

Resume the VENOM investigation using durable jobs and the isolated Python worker:

1. Create a new MCP investigation for `/tmp/opencode/venom/` (or the authorized VENOM path).
2. Use `prestige_run_experiment` for file/strings/inspect and ZIP expansion.
3. Use `prestige_start_analysis` with radare2/Ghidra for targeted static analysis of
   `FlagApp.exe` and the `VENOM_ACTIVATION_PHRASE` path.
4. Use `prestige_run_experiment` with the `python` tool in isolation to reconstruct any
   decoder and derive a candidate.
5. Record candidates with `prestige_verify_candidate` only when derivation supports them.

Do not execute the binary on the host. Do not fabricate a candidate. Do not claim
official checker acceptance without a real authorized checker.

## MCP tools available to the prestige agent

- `prestige_create_investigation` — start a bounded offline investigation.
- `prestige_get_status` — current state, artifacts, observations and budget.
- `prestige_run_experiment` — execute one authorized tool and record evidence.
- `prestige_verify_candidate` — record and digest-check a candidate.
- `prestige_start_analysis` — start a durable cached analysis job.
- `prestige_get_analysis` — poll job status and result.
- `prestige_cancel_analysis` — cancel a queued or running job.
- `prestige_request_operator` — record a durable human question and pause.
- `prestige_answer_operator` — relay an operator answer as `operator_relayed`.
- `prestige_resume_investigation` — compact context reconstruction without resetting budgets.

Allowed experiment tools include: `inspect`, `strings`, `file`, `zip`, `read`, `base64`,
`hex`, `xor`, `radare2`, `ghidra`, `python` (isolated Docker worker), and `command`.

## Local/private continuity

`private/migration/LOCAL_CONTEXT.md` is intentionally ignored. On the existing
machine it identifies the repository, workspace, existing venv, skills checkout,
VENOM path, previous scratch probes and full original continuation request.
It contains no credentials and is not part of the public repository or distribution.
On a fresh clone it will be absent; set local paths explicitly and ask only for
genuinely missing inputs. Do not copy provider auth or private transcripts to migrate.

The source tree is authoritative. Older README/status claims describe earlier
baselines; docs/CONTINUATION.md and roadmap distinguish local experiments from release
capabilities. Update product claims only when public-interface acceptance tests pass.

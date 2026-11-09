# Implementation status — experimental 0.1.0

Date: 2026-11-09. **The full requested roadmap is not complete. P0 is incomplete and this
is not a production-ready release.** No model benchmark superiority is claimed.

| Milestone | Status | Evidence and missing work |
| --- | --- | --- |
| A: installable spine | Working, tested | Python CLI, configuration, truthful doctor, immutable inventory, SQLite WAL, synthetic fixture worker |
| B: Codex/OpenAI actual solving | Inference boundary complete; live CLI controls and OpenAI-compatible backend implemented; solving still gated on SDK auth/runner image | Real SDK 0.163.0 account/model discovery and a text-only transport completed one paid smoke historically. Strict SSE parsing, active upstream socket cancellation, malicious-provider tests, `--live`/`--runner-image` CLI, cancellable offloaded execution and an `httpx`-based OpenAI backend now pass. Real challenge solve remains |
| C: lanes, verifier, recovery | Working for bounded offline tools | FAST/EXPERT/AUTO, one-way handoff, duplicate suppression, digest+replay verification, pause/resume; progress events added. General CTF reasoning requires the live backend |
| D: scope, isolation, leases | Partial, fail closed | Strict offline tool surface; Docker egress/child/DNS/root-write probes; endpoint parser and lease unit tests. WorkspaceRunner is wired but requires a reviewed local image. Remote broker and actual instance renewal remain disabled |
| E: skills, research, learning | Partial | Read-only lexical retrieval, local-first accepted knowledge, exact upstream schema, static decoding generalizers, related-technique inbox. No helper-script execution, general exploit learning or live research broker |
| F: competition and comparisons | Partial | Local queue with bounded concurrency; deterministic priority/deadline/points policy; fixture harness and equality gates. B0/B1/P1/P2/P3 live comparisons and calibrated marginal value unimplemented |
| G: advanced tools and portability | Partial | Internal WorkspaceRunner wired into engine; local `file` and allowlisted `radare2` static tools added. Persistent GDB/PTY, Ghidra headless, OpenCode runtime adapter and remote worker remain |
| H: local models and attribution | Partial | User-declared pinned registry, loopback advisory adapter, hardware diagnostics, mocked tests, attribution/license audit. No downloaded weights, real inference benchmark, paired-model experiments or autonomous local worker |

## Validated boundaries

Unknown challenge binaries and scripts never execute through the host solve loop. The only
implemented solver tools are bounded byte transforms/readers. Proposed shell/network tools
are denied before any subprocess/socket transport is reached. ZIP members are never written
to attacker-chosen paths. A fake flag without an independent digest cannot become a solve.
Source data and local candidates remain in private local state, not reusable knowledge.

The inference gateway now rejects unknown SSE fields, event/data disagreements, non-text
content types and executable model output before it reaches the authenticated runtime.
Active upstream sockets can be cancelled on interrupt/close to avoid waiting for a dead
provider read.

An explicit Docker audit passed on a local Kali Linux image:
`sha256:8ebf73b0ac7b5e706244ab5dff1d6fe80dc3ca0cc59585fd7053819ce001c8b6`.
It checks loopback-only interfaces, TCP, DNS, subprocess egress and read-only root. These are
offline isolation checks; they do not validate a scoped remote broker or provider built-in tools.

## Validation record

Current Kali checkpoint: **83 passed, 3 skipped in 2.88 seconds**, Ruff clean.
The skipped tests are opt-in Docker container checks requiring `PRESTIGE_TEST_IMAGE`.
OpenCode development handoff files are prepared; OpenCode is running this Build session.
See [handoff](OPENCODE_HANDOFF.md), [continuation](CONTINUATION.md) and
[machine-readable roadmap](roadmap.json) for current uncompleted acceptance items.

See [VALIDATION.md](VALIDATION.md) for the final executed commands, exact outcomes and benchmark
totals. GitHub CI is configured but a green remote CI result is not assumed merely from the
workflow file. Windows-host sandbox restrictions required running async tests in the normal
permitted execution context with workspace-local temporary directories.

## Highest-value next work

1. Install the inspected Codex SDK and expose explicit `--live`/image/large-artifact CLI controls.
2. Wire `WorkspaceRunner` into `ToolRegistry` for cancellable offloaded execution and complete
   failed-attempt usage accounting.
3. Run the user-supplied VENOM archive through PRESTIGE's public CLI using real model inference.
4. Implement a DNS-pinned endpoint broker and validate direct socket/DNS/redirect/subprocess
   bypass prevention end-to-end before enabling any remote instance activity.
5. Add independent executable challenge oracles and a broader held-out corpus, then run B0/B1
   and PRESTIGE conditions with identical permissions, artifacts, models, budgets and accounting.
6. Add persistent debugger execution and only then evaluate whether more workers or local
   models increase verified value. Do not relax hard boundaries to complete a milestone.

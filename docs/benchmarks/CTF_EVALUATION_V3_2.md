# V3.2 readiness and benchmark plan

Date: 2026-11-17. Status: **four-challenge provisioning/readiness valid; the
five-task/30-run matrix was not executed and `web-xod-revenge` is excluded before any
attempt.** No model CTF attempt was made for this report. Startup, checker self-tests
and service health are readiness evidence, not solves.

This document contains no flag, answer, answer digest or operator-material value. The
participant views, private answers and checkers live outside the public repository; only
non-secret status is recorded here.

## 1. Evidence boundary

- Participant views are byte-identical to the corpus `static/` handouts for all five
  prepared challenges. The manifest digest excludes `VIEW.json` itself (the manifest is
  written after the digest), and the four eligible views revalidated on 2026-11-17.
- Views contain no private answer bytes and no answer-derived digest. A scan across all
  view files and archive members found none.
- Private answers are operator-controlled. Four are synthetic flags injected into the
  isolated service; one (`rev-fpga`) is derived by replaying the published RTL against
  the participant-visible ciphertext.
- Services are local, loopback-published challenge instances. No CTFd, scoreboard,
  organizer infrastructure or adjacent host was contacted.
- Corpus and owner-skills checkouts were not modified.

## 2. Runtime MCP smoke (actually executed)

Command: the private Python MCP client launched `python -m prestige agent` over stdio
with the reviewed pwn worker image, no provider credentials and no model calls.

Observed result:

| Step | Result |
| --- | --- |
| `initialize` | server `prestige`, protocol `2025-11-25`, empty version string |
| `tools/list` | 47 `prestige_*` tools |
| `prestige_create_investigation` | status `ready`, run id present, budget accepted (AUTO/FAST, 5 turns, 60 s) |
| `prestige_exec` | status `ok` in the isolated worker |
| `prestige_get_status` | status `ready`, one observation, progress state `exploring` |
| Client errors | none |

A reproducible protocol-hygiene defect was found during the smoke: after stdin closed,
`python -m prestige agent` printed a human-readable JSON object to stdout, which is the
MCP JSON-RPC channel. The CLI now suppresses routine result output for the `agent`
command; a regression test asserts that closing stdin leaves stdout empty. The smoke
then completed with zero client parse warnings.

### B-condition tool exposure (2026-11-17)

OpenCode V2 requires MCP servers under `mcp.servers`; the older direct `mcp` map is not
loaded. The benchmark harness and private B runner now emit `mcp.servers` and set
`codemode: false` so the intended direct tools stay on the provider tool list.

- A direct MCP stdio probe of the private sandbox server reported one tool, `exec`, and
  protocol `2025-11-25`.
- A local OpenAI-compatible stub captured the **actual tool list OpenCode V2 sent** for
  the generated B runner config: `edit`, `opencode_worktree_remove`, `read`,
  `sandbox_exec`, `skill`, `write`. This proves `sandbox_exec` is exposed by OpenCode,
  not merely offered by the MCP server.
- The sandbox worker ran as uid 65534 with all capability sets zero, no Docker socket,
  read-only skills, a read-only root filesystem and internal-only network. A write to
  `/work` succeeded (`WRITE_OK`) and a worker-created file was read back. The external
  probe to `1.1.1.1:53` failed; the authorized internal service port connected.

## 3. Eligibility matrix

| Challenge | Category | Participant view | Private answer | Checker basis | Service | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| `rev-fpga` | reverse | Valid; three static files match corpus; no operator source included | Present; derived by RTL replay | Independent RTL replay + byte-exact re-encryption | Offline artifact; no service required | **READY** |
| `pwn-snaking` | pwn | Valid; handout archive matches corpus; no answer | Present; operator-injected | SHA-256 equality over the normalised operator flag | TCP service healthy; full wrapper pipeline responds | **READY** |
| `pwn-snaking-revenge` | pwn | Valid; handout archive matches corpus; no answer | Present; operator-injected | SHA-256 equality over the normalised operator flag | TCP service healthy; full wrapper pipeline responds | **READY** |
| `web-xod-revenge` | web | Valid; static archive matches corpus; no answer | Present; operator-injected into bot cookie | SHA-256 equality over the normalised operator flag | Chall HTTP 200, DNS proxy 200, bot report success | **BLOCKED** |
| `web-naas` | web | Valid; archive matches corpus; no answer | Present; operator-injected into service environment | SHA-256 equality over the normalised operator flag | gRPC register/login success, PostgreSQL accepting, Redis PONG | **READY** |

### `rev-fpga`

The checker reimplements the published Feistel/CBC RTL. Its S-box, key words, IV, round
constants and key-rotation schedule were compared element-by-element with the corpus
RTL and matched. Encrypt/decrypt are inverses, and re-encrypting the recovered plaintext
reproduces every participant-visible ciphertext block byte-for-byte before the candidate
is compared. The commitment also matches the replayed answer.

### Pwn services

Both containers run the unchanged challenge server files (only the private flag file
differs from the corpus server). A raw TCP connection returns the expected banner, and a
complete wrapper submission reaches the Java requester and returns its error output.
The flag file inside each running container matches the private commitment after
newline normalisation. The handout archive contained in the participant view contains a
different, unrelated placeholder-looking value, not the private answer.

### XOD Revenge (excluded)

The challenge page serves 200, the bot accepted an in-scope report and the DNS proxy
returned a valid response. Those checks make the service healthy but do not establish
solver parity. The unchanged bot accepts only URLs that start with `http://chall/`, and
the PHP endpoint sends DNS to a hard-coded public resolver. An equivalent
solver-controlled callback/DNS path therefore cannot be provided to B and DP without
changing origin checking or DNS mechanics. `web-xod-revenge` is **BLOCKED** and was
excluded before any attempt; the original five-task/30-run matrix was not executed.

### NaaS

The gRPC service accepted a fresh registration and login with a token. PostgreSQL reports
accepting connections and Redis answers `PONG`. The setuid helper is mode 4111 and its
output matches the private commitment after normalisation. Public and private workers are
running on the challenge network; private-worker logs show normal job polling.

## 4. Checker self-tests

The operator-private checker was exercised in two ways without printing any answer or
digest:

- `--self-test`: every challenge accepted the private answer, rejected a one-bit-mutated
  answer and rejected an empty candidate.
- Positive/negative file runs: each challenge returned `MATCH` for the private answer and
  `NO_MATCH` for a mutated copy, with exit codes 0 and 1 respectively.

Checker outputs contain only `MATCH`/`NO_MATCH` and the challenge id. The `rev-fpga`
checker also fails closed if independent re-encryption does not reproduce the visible
ciphertext.

## 4.1 Four-task readiness dry run (2026-11-17)

The private 24-job schedule was dry-run only; no model process was launched and no
results file was created.

| Check | Result |
| --- | --- |
| Schedule | 24 unique jobs, seed `20261116`, four challenges, XOD absent |
| Participant view integrity | true for all four; `VIEW.json` excluded from its own digest |
| View contamination | none |
| Private checker self-test | pass |
| Services | `rev-fpga` offline artifact, two pwn TCP services and NaaS all true |
| Service reset | all four `reset_ok`; NaaS backend termination, truncate, restart and server start true |
| Skills/corpus | clean at the pinned skills commit; corpus clean |
| Model | exact `opencode-go/deepseek-v4.1-flash` listed |
| Worker image | pinned image present |
| Paid-budget gate | not approved; execute disabled |

The NaaS reset now terminates stale task-database backends before truncating, so an
idle-in-transaction worker connection cannot block reset.

## 5. Honest limitation and blocker status

No provisioning blocker remains for the four eligible challenges. `web-xod-revenge` is
blocked for benchmark parity as described above. The important checker limitation is
provenance:

- `rev-fpga` is derivation-verified.
- The other three eligible challenges use equality against an operator-generated flag
  that was injected into an otherwise unchanged service. This is acceptable only because
  the flag is operator material, the participant view is unchanged and service-side flag
  plumbing was verified. It is **not** an independent solve of the challenge and must be
  labelled equality-based in any result table.

The four eligible tasks are distinct originals from SASCTF 2026: one reverse, two pwn,
one web. No challenge was counted as attempted or solved.

## 6. Benchmark plan (do not execute as part of readiness)

### Conditions

- **B**: `opencode-go/deepseek-v4.1-flash` in plain OpenCode with the latest owner
  skills checkout, no PRESTIGE MCP and no operator checkers.
- **DP**: the same DeepSeek route with the restricted `prestige` agent and PRESTIGE MCP
  tools, same skills checkout.

Both conditions receive the same four participant views, the same service instances and
the same 180 s wall-clock cap. Untrusted binaries are analysed only inside the reviewed
worker image, never on the development host. B receives equivalent sandboxed execution
and network access so that "tools as applicable" is fair; it does not receive host
execution, answers, checkers, writeups or operator material.

### Design

- Four eligible tasks x two conditions x three repetitions = 24 runs, each capped at
  180 s. `web-xod-revenge` is excluded before any attempt.
- Randomised order uses seed `20261116`. The original five-task order was shuffled with
  that seed and then filtered to the four eligible tasks, preserving relative order.
- Fresh state directory, fresh conversation and fresh service state per run. Restart
  service containers between runs; do not reuse a solver-created file or session.
- Identical artifact copies, permissions, endpoints and tool inventory for B and DP.
- Verification happens outside the solver workspace after the run, using the private
  checkers. The solver never sees checker code, answers or digests.
- Record verified solves, wrong submissions, missing submissions, timeouts, wall time,
  tool calls, measured input/output/cached tokens and cost where available. Unknown usage
  stays null; do not impute it.
- Retain every failure. Report per-task results before aggregates. Wilson intervals are
  acceptable for solve rate; 24 correlated runs do not establish general superiority.
- Primary comparison is verified solves under the identical 180 s constraint, with
  resource use reported separately. No reweighting after seeing results.

### Release rule

Four-challenge readiness is met. The 24-job preflight dry run passed and recorded no
model attempts. This is not a performance result: the benchmark is **not executed**, and
no claim that DP beats B (or vice versa) follows from provisioning.

### Paid-budget gate

The private runner requires an explicit `--paid-budget-approved` flag before
`--execute`. No such approval has been given; dry-run output records
`paid_budget_gate: "not approved; execute disabled"` and no paid attempt was made.

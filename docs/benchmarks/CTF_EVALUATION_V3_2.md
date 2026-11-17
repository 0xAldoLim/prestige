# V3.2 readiness and benchmark plan

Date: 2026-11-16. Status: **five-challenge provisioning/readiness validated; the
benchmark has not been executed.** No model CTF attempt was made for this report.
Startup, checker self-tests and service health are readiness evidence, not solves.

This document contains no flag, answer, answer digest or operator-material value. The
participant views, private answers and checkers live outside the public repository; only
non-secret status is recorded here.

## 1. Evidence boundary

- Participant views are byte-identical to the corpus `static/` handouts for all five
  challenges. Each view manifest's integrity value was recomputed from the view file
  names and bytes and matched.
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

## 3. Eligibility matrix

| Challenge | Category | Participant view | Private answer | Checker basis | Service | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| `rev-fpga` | reverse | Valid; three static files match corpus; no operator source included | Present; derived by RTL replay | Independent RTL replay + byte-exact re-encryption | Offline artifact; no service required | **READY** |
| `pwn-snaking` | pwn | Valid; handout archive matches corpus; no answer | Present; operator-injected | SHA-256 equality over the normalised operator flag | TCP service healthy; full wrapper pipeline responds | **READY** |
| `pwn-snaking-revenge` | pwn | Valid; handout archive matches corpus; no answer | Present; operator-injected | SHA-256 equality over the normalised operator flag | TCP service healthy; full wrapper pipeline responds | **READY** |
| `web-xod-revenge` | web | Valid; static archive matches corpus; no answer | Present; operator-injected into bot cookie | SHA-256 equality over the normalised operator flag | Chall HTTP 200, DNS proxy 200, bot report success | **READY** |
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

### XOD Revenge

The challenge page serves 200. The bot accepted a report for the in-scope challenge URL
and returned success (about 8.6 s, including browser startup). The DNS proxy returned a
valid 61-byte DNS response for a known-good query. The bot process environment carries
the same normalised flag as the private commitment. The bot rate limit is two reports per
minute; benchmarks must pace submissions or restart the service.

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

## 5. Honest limitation and blocker status

No provisioning blocker remains for the five challenges above. The important limitation
is checker provenance:

- `rev-fpga` is derivation-verified.
- The other four use equality against an operator-generated flag that was injected into
  an otherwise unchanged service. This is acceptable only because the flag is operator
  material, the participant view is unchanged and service-side flag plumbing was
  verified. It is **not** an independent solve of the challenge and must be labelled
  equality-based in any result table.

The five tasks are distinct originals from SASCTF 2026: one reverse, two pwn, two web.
No challenge was counted as attempted or solved.

## 6. Benchmark plan (do not execute as part of readiness)

### Conditions

- **B**: `opencode/deepseek-v4.1-flash-free` in plain OpenCode with the latest owner
  skills checkout, no PRESTIGE MCP and no operator checkers.
- **DP**: the same free DeepSeek route with the restricted `prestige` agent and PRESTIGE
  MCP tools, same skills checkout.

Both conditions receive the same five participant views, the same service instances and
the same 180 s wall-clock cap. Untrusted binaries are analysed only inside the reviewed
worker image, never on the development host. B receives equivalent sandboxed execution
and network access so that "tools as applicable" is fair; it does not receive host
execution, answers, checkers, writeups or operator material.

### Design

- Five tasks x two conditions x three repetitions = 30 runs, each capped at 180 s.
- Randomised block order with a seed fixed and recorded before the first run.
- Fresh state directory, fresh conversation and fresh service state per run. Restart
  service containers between runs; do not reuse a solver-created file or session.
- Identical artifact copies, permissions, endpoints and tool inventory for B and DP.
- Verification happens outside the solver workspace after the run, using the private
  checkers. The solver never sees checker code, answers or digests.
- Record verified solves, wrong submissions, missing submissions, timeouts, wall time,
  tool calls, measured input/output/cached tokens and cost where available. Unknown usage
  stays null; do not impute it.
- Retain every failure. Report per-task results before aggregates. Wilson intervals are
  acceptable for solve rate; 30 correlated runs do not establish general superiority.
- Primary comparison is verified solves under the identical 180 s constraint, with
  resource use reported separately. No reweighting after seeing results.

### Release rule

Five-challenge readiness is met. This is not a performance result: the benchmark is
**not executed**, and no claim that DP beats B (or vice versa) follows from provisioning.

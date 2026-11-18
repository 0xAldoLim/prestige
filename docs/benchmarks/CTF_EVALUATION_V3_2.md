# V3.2 four-challenge benchmark: readiness and executed results

Date: 2026-11-17. Status: **the frozen 24-job schedule completed with 24 durable job
records: 19 paid model attempts, 5 pre-model infrastructure failures and 0
independently verified solves.** The two pwn pairs are not comparable: the five
infrastructure records removed two B repetitions on `pwn-snaking` and all three DP
repetitions on `pwn-snaking-revenge`. `web-xod-revenge` remains excluded before any
attempt. No superiority claim is made.

This document contains no flag, answer, answer digest or operator-material value. The
participant views, private answers, raw traces and checkers live outside the public
repository; only sanitized, non-secret status and aggregate metrics are recorded here.
The companion `benchmark-results/v3_2.json` is likewise sanitized.

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

## 5. Execution status and honest limitations

The four-challenge matrix was executed on 2026-11-17 under the explicit paid-budget
approval. The five-task/30-run matrix was never executed; `web-xod-revenge` stays
excluded for benchmark parity as described above.

The important checker limitation is provenance:

- `rev-fpga` is derivation-verified.
- The other three eligible challenges use equality against an operator-generated flag
  that was injected into an otherwise unchanged service. This is acceptable only because
  the flag is operator material, the participant view is unchanged and service-side flag
  plumbing was verified. It is **not** an independent solve of the challenge and is
  labelled equality-based in the result tables.

No challenge was counted as solved. The executed matrix produced zero verified solves,
two independently rejected submissions and seventeen missing submissions across 19 paid
model attempts. Five additional schedule jobs stopped at a pre-model service-reset
readiness check; they are infrastructure records, not solver failures. See sections 6-8.

## 6. Frozen design and paid-budget gate

### Conditions

- **B**: `opencode-go/deepseek-v4.1-flash` in plain OpenCode with the latest owner
  skills checkout, no PRESTIGE MCP and no operator checkers.
- **DP**: the same DeepSeek route with the restricted `prestige` agent and PRESTIGE MCP
  tools, same skills checkout.

Both conditions received the same four participant views, the same service instances and
the same 180 s wall-clock cap. Untrusted binaries were analysed only inside the reviewed
worker image, never on the development host. B received equivalent sandboxed execution
and network access so that "tools as applicable" is fair; it did not receive host
execution, answers, checkers, writeups or operator material.

### Design

- Four eligible tasks x two conditions x three repetitions = 24 jobs, each capped at
  180 s. `web-xod-revenge` was excluded before any attempt.
- Randomised order used seed `20261116`. The original five-task order was shuffled with
  that seed and then filtered to the four eligible tasks, preserving relative order.
- Fresh state directory, fresh conversation and fresh service state per job. Service
  containers were restarted between jobs; solver-created files and sessions were not
  reused.
- Identical artifact copies, permissions, endpoints and tool inventory for B and DP.
- Verification happened outside the solver workspace after the run, using the private
  checkers. The solver never saw checker code, answers or digests.
- Every failure was retained. Per-task results are reported before aggregates.
- Primary comparison is verified solves under the identical 180 s constraint, with
  resource use reported separately. No reweighting after seeing results.

### Paid-budget gate

The operator explicitly approved exactly 24 paid attempts on
`opencode-go/deepseek-v4.1-flash`. The runner was invoked with `--execute
--paid-budget-approved` against the pre-registered 24-job schedule. It launched 19 paid
model processes. The other five jobs stopped at the pre-model service-reset check and
launched no model process. No retry, replacement, model substitution or budget expansion
was performed. Five paid-attempt slots therefore remained unused; they were not executed
because the frozen schedule had no remaining jobs. A replacement cohort would require a
new operator approval and a new pre-registered schedule.

## 7. Executed results

### 7.1 Per challenge and condition

`Records` counts durable jobs. `Model` counts paid model attempts. `Infra` counts
pre-model infrastructure records. `Verified`, `Wrong`, `Missing`, `Invalid`, `Timeout`
and `Completed` are counted among model attempts only. `Median s` is wall-clock
execution time. `Tools` is the total tool-call count. Token columns are totals over model
attempts; `Uncached in`, `Output` and `Cache read` are raw OpenCode usage fields. Cost is
provider-reported.

| Challenge | Cond | Records | Model | Infra | Verified | Wrong | Missing | Invalid | Timeout | Completed | Median s | Tools | Uncached in | Output | Cache read | Cost rep. |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `rev-fpga` | B | 3 | 3 | 0 | 0 | 0 | 3 | 0 | 3 | 0 | 180.028 | 72 | 68,246 | 7,325 | 487,808 | 0.0 |
| `rev-fpga` | DP | 3 | 3 | 0 | 0 | 0 | 3 | 0 | 3 | 0 | 180.088 | 62 | 87,926 | 9,383 | 648,192 | 0.0 |
| `pwn-snaking` | B | 3 | 1 | 2 | 0 | 0 | 1 | 0 | 1 | 0 | 180.023 | 14 | 14,888 | 1,071 | 58,112 | 0.0 |
| `pwn-snaking` | DP | 3 | 3 | 0 | 0 | 0 | 3 | 0 | 2 | 1 | 180.016 | 27 | 39,654 | 3,198 | 148,352 | 0.0 |
| `pwn-snaking-revenge` | B | 3 | 3 | 0 | 0 | 0 | 3 | 0 | 3 | 0 | 180.033 | 31 | 54,989 | 5,995 | 230,400 | 0.0 |
| `pwn-snaking-revenge` | DP | 3 | 0 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | — | 0 | 0 | 0 | 0 | 0.0 |
| `web-naas` | B | 3 | 3 | 0 | 0 | 0 | 3 | 0 | 3 | 0 | 180.046 | 55 | 137,128 | 4,632 | 770,176 | 0.0 |
| `web-naas` | DP | 3 | 3 | 0 | 0 | 2 | 1 | 0 | 1 | 2 | 178.855 | 58 | 210,659 | 8,846 | 1,158,400 | 0.0 |

### 7.2 Overall totals

- **Durable records:** 24/24 schedule jobs; 19 paid model attempts; 5 pre-model
  infrastructure records; 0 remaining schedule jobs.
- **Outcomes among 19 model attempts:** 0 verified, 2 wrong, 17 missing, 0 invalid;
  16 timed out, 3 completed, 0 failed at the process level.
- **Execution time:** median 180.028 s across model attempts. No solve-time median exists
  because no attempt was verified.
- **Tool use:** 319 tool calls (median 17 per model attempt), 20 failed tool calls, 0
  duplicate tool calls.
- **Tokens (raw fields):** 613,490 uncached input; 3,501,440 cache read; 0 cache write;
  40,450 output; 87,996 reasoning. Combined prompt input including cache read is
  4,114,930. `total_tokens` in the per-run records is uncached input + output and excludes
  cache read.
- **Provider-reported cost:** 0.0 for all 254 `step_finish` records. Actual billing was
  not independently confirmed; this is not a verified charge.
- **By condition:** B had 10 model attempts (0 verified, 0 wrong, 10 missing, 10
  timeouts, median 180.034 s, 172 tool calls, 294,274 uncached+output tokens and
  1,546,496 cache-read tokens). DP had 9 model attempts (0 verified, 2 wrong, 7 missing,
  6 timeouts, 3 completed, median 180.026 s, 147 tool calls, 359,666 uncached+output
  tokens and 1,954,944 cache-read tokens).

### 7.3 Independent verification

Verification ran outside the solver views after each run, using the operator-private
checker. The checker self-test passed positive, negative and empty cases for all five
prepared challenges.

- Only two submission artifacts were produced, both in `web-naas` DP repetitions 2 and 3.
- Both were independently rejected with `NO_MATCH`. One was an 8-character non-flag
  placeholder; the other was a 13-character string in the published flag format but did
  not match the private commitment.
- No valid submission existed, so no candidate was accepted. No exact answer bytes were
  found in model output, final text or solver workspaces for any attempt.
- Under the benchmark contract, model text and intermediate output are not solves. The
  verified-solve count is therefore **0/19 model attempts** and **0/24 durable records**.

### 7.4 Actual model routing

Routing was captured for all 19 model attempts through the OpenCode session API.

- Every captured assistant message used `opencode-go/deepseek-v4.1-flash`; no fallback,
  substitution or second model appeared.
- B attempts used agent `bench`; DP attempts used agent `prestige`.
- 254 `step_finish` events carried token usage. The five infrastructure records launched
  no model process and have no routing or usage, which is recorded as absent rather than
  imputed.

### 7.5 Infrastructure blocker and comparability

Five pwn jobs failed the pre-model service-reset readiness check:

| Job | Challenge | Condition | Repetition | Result |
| --- | --- | --- | ---: | --- |
| 1 | `pwn-snaking` | B | 2 | `port_open=false`; flag match true |
| 5 | `pwn-snaking-revenge` | DP | 3 | `port_open=false`; flag match true |
| 9 | `pwn-snaking-revenge` | DP | 1 | `port_open=false`; flag match true |
| 13 | `pwn-snaking` | B | 3 | `port_open=false`; flag match true |
| 20 | `pwn-snaking-revenge` | DP | 2 | `port_open=false`; flag match true |

In each case the container restart completed and the injected flag still matched, but the
TCP readiness probe returned false before any model process was launched. These are
**pre-model infrastructure records, not solver failures**. No retry or replacement was
made. The runner preserves and resumes them, so they remain distinct from ordinary
wrong, missing or timeout outcomes.

Consequences:

- `pwn-snaking`: B has 1/3 valid model attempts; DP has 3/3. The pair is incomplete.
- `pwn-snaking-revenge`: B has 3/3 valid model attempts; DP has 0/3 because all three
  resets failed. The pair is invalid for comparison.
- `rev-fpga` and `web-naas`: 3/3 valid attempts in both conditions, but zero verified
  solves.

The failure is systemic for pwn reset readiness and voids pwn condition comparisons. It
does not invalidate the `rev-fpga` or `web-naas` cells. The frozen schedule nevertheless
completed; no additional cohort, retry or substitution was started.

### 7.6 Paired observations

These are descriptive observations from sanitized tool names, statuses and traces. They
are not evidence of superiority.

- **`rev-fpga`:** both conditions went 0/3 and exhausted the cap. B used more tool calls
  (72 versus 62) but fewer tokens (75,571 versus 97,309 uncached+output); DP used
  `prestige_exec`/`run_experiment` and had four failed skill-name lookups. No outcome
  difference was observed.
- **`pwn-snaking`:** DP exercised `target_bind` and `remote_tcp` against the assigned
  endpoint and produced three valid attempts, but two timed out and one stopped after
  five failed `skill` calls without creating an investigation. B's single valid attempt
  timed out after sandbox analysis and produced no submission. The pair is incomplete.
- **`pwn-snaking-revenge`:** B used `sandbox_exec` to reach the service, unpack the
  handout and build/send a protocol payload, but all three attempts timed out. DP never
  ran a model process because all three resets failed. No comparison is possible.
- **`web-naas`:** B produced no submissions while reverse-engineering the client in the
  sandbox. DP produced two submissions near the end of its runs; both were independently
  `NO_MATCH`. DP recovered from four failed artifact-size `create_investigation` calls
  across the three runs before proceeding. This is a submission-behaviour difference, not
  a solve advantage.
- **Resource pattern:** among valid attempts DP reported more tokens and more failed tool
  calls, mostly from skill-name misuse and artifact-limit errors. B had fewer failed tool
  calls but two infrastructure resets versus DP's three.

### 7.7 Limitations and claim

- Zero verified solves in either condition. The matrix measures behaviour and resource
  use under a 180 s cap, not comparative solving ability.
- Three repetitions per cell are correlated and too few for a statistical claim. No
  confidence interval is used to imply superiority.
- Five pre-model infrastructure failures leave both pwn pairs incomplete; pwn
  comparisons are void.
- `rev-fpga` verification is derivation-based; the other three checkers are
  equality-based against operator-injected flags.
- Provider-reported cost is 0.0 on every step; actual billing is unknown.
- Service access was available and observed in at least one attempt per condition: B
  connected to the `pwn-snaking-revenge` service from the sandbox; DP completed
  `target_bind`/`remote_tcp` calls to `pwn-snaking` and `naas-api`. No host execution,
  answer access or checker access was given to either condition.

**Claim:** descriptive only. The executed data do not establish that DP beats B or that B
beats DP.

## 8. Release rule after execution

The 24-job schedule was executed under explicit approval and is durably recorded. This
document and `benchmark-results/v3_2.json` are the sanitized Phase 1 record. No expanded
cohort was started. A future cohort requires a new operator approval, a new pre-registered
schedule and, for the pwn challenges, a corrected pre-model reset readiness check that
does not turn a completed restart into a false-negative infrastructure record.

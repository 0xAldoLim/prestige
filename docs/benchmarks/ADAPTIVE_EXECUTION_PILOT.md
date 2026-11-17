# Adaptive execution and pilot

This document records the offline engineering increment, the challenge preflight,
and the bounded adaptive pilot. Sunk_Cost initially failed independent-answer
preflight; a later operator-supplied answer was independently verified against
all 16 samples and used only for private verification of the fresh cohort. The
earlier JSculator cohort is preserved as aborted infrastructure evidence.
No combined cross-challenge claim is made.

Historical reports remain authoritative for their own data:
[V1](CTF_EVALUATION.md), [V2](CTF_EVALUATION_V2.md),
[V3](CTF_EVALUATION_V3.md), [V3.1](CTF_EVALUATION_V3_1.md).

## 1. What the surviving traces actually show

Only the V3 and V3.1 run artifacts under the private local
private local trace store survived. V2 raw traces no longer exist, so V2
statements about repeated investigations or status polling cannot be re-audited
from surviving data and are not used as a basis for new runtime complexity.

| Observation | Surviving evidence | Implication |
| --- | --- | --- |
| Investigation creation | Exactly one `prestige_create_investigation` per surviving D run (n=3) | Do **not** add creation deduplication |
| Status calls | Exactly one `prestige_get_status` per surviving D run | Do **not** add a status-delta protocol |
| Analysis jobs | Zero `prestige_start_analysis` / `prestige_get_analysis` calls | Duplicate analysis was not a measured V3/V3.1 problem |
| Duplicate calls | One exact duplicate `remote_tcp` in one D run; one duplicate native `skill ctf-pwn` in one C run | Minor; not the dominant overhead |
| Outcomes | D 1 verified (57.1 s) and 2 missing submissions at the outer 180 s cutoff; failed runs were still `ready` with attempts left | Missing submissions were outer-budget/orchestration, not wrong answers or PRESTIGE exhaustion |
| Budget request | One solved D run asked for `mode=fast, max_turns=30, max_seconds=150` but received 8 attempts/120 s and exhausted attempts at 30 s | The reduction was silent; report requested vs effective explicitly |
| Timing | Traces do not separate reasoning, tool startup and state updates | No per-phase timing claim |

## 2. Offline changes and rationale

| Change | Why retained pending evaluation | Measured effect |
| --- | --- | --- |
| Explicit `budget.requested` / `budget.effective` / `budget.adjusted` / note in create and resume | Removes a concrete silent-clamp defect observed in a surviving trace; operator ceilings and lane caps are unchanged | Overhead not measured; response payload grows by a few small fields |
| `progress.remaining_budget` using `runs.started` | Resume and enforcement previously used different clocks; idle time was wrongly charged | Correctness fix, not a performance claim |
| `progress.assess` over durable observations | Detects repeated identical action/result signatures while preserving productive novel output; advisory only | Classification thresholds are heuristic; no solve-rate claim |
| Evaluator escalation gating | A pending test is not stagnation; escalation now needs `no_progress`/`loop_suspected` plus remaining attempts/time | No evidence yet that it changes solve rate |
| `JobManager.find_cached` for `prestige_start_analysis` | Answers an identical durable job without consuming another attempt; small reuse of the existing cache | Not a measured V3 problem; retained as a bounded defensive improvement |
| `progress_signal` in status; `progress` in resume | Makes durable evidence visible where the model already looks | Unknown token effect; bounded summary only |

Deliberately **not** added: investigation-creation deduplication, status-delta
protocols, broad caching, new planner layers, model/provider switching, or any
automatic scope expansion. The surviving traces do not justify them.

## 3. `iboh26` candidate inventory (read-only)

Source tree: the user-authorized read-only `iboh26` workspace. It
also contains operator solve files, notes and a writeup. Those are **not**
participant material and must never enter a solver view or the repository.

| Archive | Participant-visible content | Category | Provisioning / verification status |
| --- | --- | --- | --- |
| `Sunk_Cost.tar.gz` | A self-contained mission brief with 16 modular-reciprocal high-bit blocks | crypto / number theory | **Used for the fresh cohort.** The operator-supplied answer was independently verified against all 16 original samples privately. The answer, hash and solve path remain outside the repository and solver views. |
| `Conservation.tar.gz` | `Conservation.sol`, `IPolicy.sol`, `ISetup.sol` | smart contract | Missing deployment/Setup contract and chain context; no local `isSolved` path from participant files alone. Blocked. |
| `Margins.tar.gz` | `Setup.sol`, `Margins.huff` | smart contract / Huff | `Setup` expects workspace and processor code blobs that are not in the archive; not locally deployable as-is. Blocked. |
| `Relay_Cascade.tar.gz` | `relay_cascade` ELF, `libduktape.so.207`, short README | pwn / JS engine | No service descriptor, prompt or answer format; execution only in the reviewed worker. Blocked for a verification pilot. |
| `DEAD_DROP.tar.gz` | `dead_drop` ELF | pwn / reverse | No README, service or answer format; execution only in the worker. Blocked. |
| `BLACK_LANTERN.tar.gz` | `bzImage`, `rootfs.cpio.gz` | kernel pwn | Requires a VM/QEMU environment and a private instance answer; not safely provisioned here. Blocked. |
| `Allowance_Day.tar.gz` | `allowance-notice.eml` | forensics / phishing | No challenge prompt or answer format; a solver could inspect it, but independent verification is undefined. Blocked. |
| `Oversimplified_Crackme.zip` | AES-encrypted ZIP containing `2EZ4AI.exe` | reverse | Password/prompt absent; archive cannot be extracted without the missing participant password. Blocked. |
| `You_Find_Lor.tar.gz` | `dist-You Find Lor.png` | stego / forensics | No prompt or operator commitment; extraction may be possible but the exact answer is not established. Blocked until an operator commitment exists. |

`Sunk_Cost` initially failed independent-answer preflight. A later operator-supplied
answer was independently verified against all 16 original samples using the
mission brief data, and only the resulting private commitment was used for blind
verification. The earlier JSculator cohort was a fallback that was aborted for
infrastructure reasons. The operator's solve path and writeup material remain
excluded from every view.

## 4. Bounded Sunk_Cost comparison

### 4.1 The single question

> Under equal budgets and fresh workspaces, does **Kimi orchestrator + DeepSeek
> executor** or **DeepSeek PRESTIGE MCP** change verified solve reliability or
> measured overhead relative to **DeepSeek direct execution** on the same
> independently verifiable offline challenge?

"Reliability" includes verified solve rate and missing-submission/timeout rate.
"Overhead" includes wall time, tool calls, input/output tokens, cache-read/write
tokens, provider-reported cost and duplicate/unproductive calls. Five
repetitions on one challenge describe this pilot only; they do not establish
superiority or population effects.

### 4.2 Configurations

| ID | Configuration | Model routing | Tools |
| --- | --- | --- | --- |
| `DD` | DeepSeek direct execution | `opencode-go/deepseek-v4.1-flash` primary agent | Standard OpenCode read/glob/grep/shell/write plus read-only owner skills; no PRESTIGE MCP |
| `KE` | Kimi orchestrator + DeepSeek executor | `opencode-go/kimi-k3.1-pro` primary delegating to `opencode-go/deepseek-v4.1-flash` executor | Standard executor tools plus read-only owner skills; no PRESTIGE MCP |
| `DP` | DeepSeek PRESTIGE MCP | `opencode-go/deepseek-v4.1-flash` `prestige` agent | Only `prestige_*` MCP tools; reviewed worker; same submission protocol |

**Historical provenance.** This table records the routes used by the completed
cohorts on 2026-11-15: the then-configured paid
`opencode-go/deepseek-v4.1-flash` route. The results below are preserved unchanged
and are **not** evidence about the current free route. Future adaptive runs pin
`opencode/deepseek-v4.1-flash-free` for `DD`, and `KE`/`DP` derive the free
executor/prestige models from the checked-in config. No CTF benchmark was rerun
for this provider change.

The checked-in routing is not changed by the pilot. `DD` and `KE` use separate
benchmark agent configurations so the comparison does not alter the production
`orchestrator`/`executor` agents.

### 4.3 Equal conditions

- Same challenge view, same participant files, same submission path shape.
- Per attempt: 180 s wall clock, `max_turns=30`, `max_seconds=150` for the
  PRESTIGE create call (auto lane), same outer timeout for all configurations.
  If the outer timeout fires, the attempt is a missing submission, never a solve.
- Fresh workspace, fresh `PRESTIGE_HOME`, fresh OpenCode session and fresh state
  directory per attempt; parent `OPENCODE_*`, `AI_AGENT` and `PWD` sanitized.
- Exactly one final submission per attempt, operator-graded.
- Randomized configuration order with a recorded seed, multiple repetitions.
- No internet challenge lookup; network access only to an explicitly registered
  local service if a secondary task provides one.

### 4.4 Repetitions and fixed schedule

Sunk_Cost is the cohort task. The executed schedule was:

- **5 repetitions × 3 configurations = 15 paid runs**;
- 180 s outer budget per attempt, `max_turns=30`, no retries;
- seed **611**, randomized order recorded privately;
- fresh workspace, state, submission path and OpenCode session per attempt;
- no secondary challenge and no replacement attempts.

### 4.5 Metrics to record per run

- submission status (valid / wrong / missing / invalid), verified by the operator;
- wall time, outer-timeout flag and submission timestamp;
- tool calls by name, failed/denied calls and exact duplicate signatures;
- input, output, reasoning, cache-read and cache-write tokens from JSONL
  `step_finish`/usage events;
- provider-reported cost, or **unknown** when the provider reports none; never
  infer a dollar cost from a list price;
- PRESTIGE investigation count, status/create/analysis counts, attempts consumed,
  lane changes, progress states and escalation events;
- per-message agent/model IDs captured privately through the OpenCode API.

### 4.6 Independent verification and contamination controls

For Sunk_Cost:

1. The participant view contains only the original mission brief, copied once as
   `README.md` and once under `challenge/`. The operator's answer file, solve path,
   scripts, writeups, notes, other archives and state are excluded.
2. The private answer is compared only outside the solver workspace. The solver
   never receives an answer, answer-derived hash or preloaded commitment in blind
   mode.
3. Each attempt must write exactly one explicit submission; intermediate text and
   tool output are never solves. Missing, wrong, invalid and timed-out submissions
   are counted separately.
4. The operator verifies the submitted SHA-256 against the private answer after the
   run. Raw traces, routing captures and submissions remain private.
5. Sunk_Cost is offline; no local service or remote target is used. No internet
   challenge lookup is used.
6. Public output uses the harness redaction functions: no submitted hashes,
   candidate digests, private paths, configs or transcripts.

### 4.7 Expected usage limits

From surviving V3 D traces, a run used roughly 25–40k input+output tokens and
80–175k cache-read tokens at a 180 s cap. Set per-run guardrails of **200k
input+output tokens and 2M cache-read tokens**, and a pilot total cap of **30
runs / 60M cache-read tokens**. These are safety ceilings, not predictions.
Provider cost is recorded as reported; opencode-go has reported 0 in prior runs,
so dollar cost may remain unknown and must not be fabricated.

## 5. Aborted JSculator cohort (separate, not a benchmark)

This cohort was stopped when a later instruction required stopping after any paid
attempt had begun. It is **ABORTED / INFRASTRUCTURE-INVALID**, not a comparative
benchmark and not a solve-rate claim. Its two missing runs were not resumed.

| Cond | Completed | Verified | Wrong | Missing | Timeouts | Total sec | Tools | Input+output |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| DD | 5 | 0 | 1 | 4 | 5 | 900.1 | 65 | 129,984 |
| KE | 3 | 0 | 0 | 3 | 3 | 540.2 | 0 | 0 |
| DP | 5 | 0 | 0 | 5 | 5 | 900.1 | 93 | 162,678 |

One additional KE workspace was created without a recorded result; one KE attempt
never started. The KE runs showed only one Kimi orchestrator message and no child
executor session. Raw JSculator state remains private and separate from the
Sunk_Cost cohort.

## 6. Sunk_Cost results (fresh cohort)

All 15 authorized attempts completed and were recorded. Every attempt hit the
180 s outer cutoff without a final submission. There were **0 verified solves**,
0 wrong submissions, 0 invalid submissions and 15 missing submissions.

| Cond | Attempt | Status | Seconds | Submission | Verified | Tools |
|---|---|---:|---|---:|---|---:|
| DD | 1 | timed_out | 180.010 | missing | no | 5 |
| DD | 2 | timed_out | 180.011 | missing | no | 4 |
| DD | 3 | timed_out | 180.010 | missing | no | 4 |
| DD | 4 | timed_out | 180.010 | missing | no | 1 |
| DD | 5 | timed_out | 180.010 | missing | no | 1 |
| KE | 1 | timed_out | 180.010 | missing | no | 0 |
| KE | 2 | timed_out | 180.011 | missing | no | 0 |
| KE | 3 | timed_out | 180.011 | missing | no | 0 |
| KE | 4 | timed_out | 180.011 | missing | no | 0 |
| KE | 5 | timed_out | 180.010 | missing | no | 0 |
| DP | 1 | timed_out | 180.010 | missing | no | 6 |
| DP | 2 | timed_out | 180.010 | missing | no | 7 |
| DP | 3 | timed_out | 180.011 | missing | no | 8 |
| DP | 4 | timed_out | 180.010 | missing | no | 8 |
| DP | 5 | timed_out | 180.010 | missing | no | 6 |

### Aggregate usage

| Cond | n | Verified | Wrong | Missing | Timeouts | Total sec | Median sec | Tools | Failed tools | Input | Output | Reasoning | Cache read | Cost |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| DD | 5 | 0 | 0 | 5 | 5 | 900.1 | 180.010 | 15 | 0 | 50,362 | 1,279 | 21,029 | 65,408 | 0.0 |
| KE | 5 | 0 | 0 | 5 | 5 | 900.1 | 180.011 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 |
| DP | 5 | 0 | 0 | 5 | 5 | 900.1 | 180.010 | 35 | 2 | 82,392 | 4,091 | 47,875 | 208,128 | 0.0 |

Provider-reported cost was `0.0` for every run; this is not a genuine dollar-cost
measurement and should be treated as unknown/not informative. No exact duplicate
tool signatures were observed. Cache-write tokens were zero throughout.

### Routing and DP behavior

- **DD:** all 5 runs show agent `bench` and model
  `opencode-go/deepseek-v4.1-flash`.
- **DP:** all 5 runs show agent `prestige` and model
  `opencode-go/deepseek-v4.1-flash`.
- **KE:** all 5 runs show only agent `orchestrator` on
  `opencode-go/kimi-k3.1-pro`, one assistant message, no `subagent` tool call,
  no child executor session, zero tool calls and zero tokens. The parent Kimi
  routing is observed; the child DeepSeek handoff is **absent**. This reproduces
  the JSculator KE anomaly and is reported as an unresolved orchestration/provider
  stall, not as a successful two-model run.
- DP used one `create_investigation` per attempt, 3–6 `exec` calls, 4–5 recorded
  observations, no `start_analysis`/`get_analysis`, no escalation events, and one
  `get_status` in one attempt. No progress/escalation-driven change was observed.
- Private per-message routing metadata is retained; raw traces and state remain
  outside the repository.

### Verification

Each attempt had at most one explicit submission path. The private checker
compared the submitted SHA-256 against the independently verified private answer
and checked all 16 original high-bit modular-inverse samples. With no submissions,
the verified count is zero. No answer, answer hash or solve path appears in this
document or the public JSON.

## 7. What this pilot will not establish

- It will not establish general model or architecture superiority.
- Five to seven repetitions per configuration cannot support significance
  claims; report descriptive counts and intervals with that limitation stated.
- One challenge (plus one optional secondary) is not a corpus estimate.
- It does not settle whether owner skills, deception detection or the
  hypothesis evaluator improve solving.

## 8. Status

**Sunk_Cost cohort complete: 0/15 verified, all 15 outer timeouts, no submissions.**
The operator-supplied answer was independently verified against all 16 original
high-bit samples before execution; it is not a PRESTIGE solve. The aborted
JSculator cohort is preserved separately as **ABORTED / INFRASTRUCTURE-INVALID**
evidence (13 completed attempts, 0 verified, 1 wrong, 12 missing, 13 timeouts)
and is not combined with Sunk_Cost for any solve-rate claim.

The KE condition did not exercise the child executor in either cohort; its
deepseek handoff remains unproven. This single-challenge, five-repetition result
is descriptive only and does not establish model or architecture superiority.
Raw traces, private routing captures, answers and submissions remain outside the
repository.

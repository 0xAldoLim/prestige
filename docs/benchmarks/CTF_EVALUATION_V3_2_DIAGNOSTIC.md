# V3.2 offline diagnostic: attribution, readiness and next experiment

Date: 2026-11-17. Scope: offline analysis of the frozen V3.2 four-Task matrix only.
No model inference, paid benchmark, new CTF attempt, challenge-source change or model
routing change was made for this diagnostic. `benchmark-results/v3_2.json` is unchanged;
the unexecuted 12-job expanded cohort is unchanged. The frozen V3.2 records remain the
authoritative outcome data; this document adds diagnosis, not retroactive scoring.

This document contains no flag, candidate value, answer digest, raw trace, private
checkpoint path or operator-material value. Run labels use challenge, condition and
repetition. Timing, token, status and tool-category fields are sanitized measurements.

## 1. Evidence boundary and method

- Inputs: the 24 durable V3.2 records, their private event streams, routing captures,
  submission status, checker outcomes and the private final texts. Raw traces and final
  texts were read only to classify behaviour; no raw content is reproduced here.
- A run is a **timeout** only when the process was killed at the 180 s cap. `span` is the
  interval between the first and last recorded event. `tail` is `180 s - span`; a large
  tail with a last event of `step_start` means the model/provider had not returned another
  action while no tool was in flight. It does not by itself distinguish model reasoning
  from provider/transport latency.
- `max latency` is the largest observed interval from `step_start` to the next text or
  tool event. It is a lower-bound indicator of model/provider latency, not a clean
  inference-time measurement.
- Failed-tool counts come from tool state `error`. Duplicate calls are exact
  `(tool, input)` repeats.
- Static and private facts were checked against the frozen files; no job was rerun.

## 2. Per-run attribution (all 24 durable records)

Attribution categories:

- `infra_reset`: pre-model TCP readiness false negative; no model process launched.
- `model_stall_timeout`: timeout with a large unresolved tail after `step_start` and no
  tool in flight (model/provider stall dominant; cause not separable offline).
- `wall_timeout_active`: timeout while tool work was still progressing near the cap.
- `wall_timeout_wrong_submission`: the same wall-clock exhaustion, with one wrong
  submission written near the cap.
- `completed_no_submission`: process completed without a submission.
- `completed_wrong_submission`: process completed after writing one wrong submission.

| Challenge | Cond | Rep | Status | Category | s | Tools | Failed | Steps | Uncached in | Output | Cache read | Submission | Tail s | Max latency s |
| --- | --- | ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: |
| `pwn-snaking` | B | 1 | timed_out | model_stall_timeout | 180.023 | 14 | 0 | 9 | 14,888 | 1,071 | 58,112 | missing | 92.1 | 36.3 |
| `pwn-snaking` | B | 2 | infrastructure_failed | infra_reset | 0 | 0 | 0 | 0 | 0 | 0 | 0 | missing | — | — |
| `pwn-snaking` | B | 3 | infrastructure_failed | infra_reset | 0 | 0 | 0 | 0 | 0 | 0 | 0 | missing | — | — |
| `pwn-snaking` | DP | 1 | timed_out | model_stall_timeout | 180.086 | 12 | 1 | 10 | 18,641 | 1,361 | 81,024 | missing | 137.5 | 4.7 |
| `pwn-snaking` | DP | 2 | timed_out | model_stall_timeout | 180.016 | 10 | 0 | 7 | 13,437 | 1,149 | 46,720 | missing | 84.2 | 62.1 |
| `pwn-snaking` | DP | 3 | completed | completed_no_submission | 36.619 | 5 | 5 | 6 | 7,576 | 688 | 20,608 | missing | 12.4 | 7.7 |
| `pwn-snaking-revenge` | B | 1 | timed_out | wall_timeout_active | 180.026 | 11 | 1 | 10 | 18,154 | 1,608 | 82,688 | missing | 13.5 | 94.9 |
| `pwn-snaking-revenge` | B | 2 | timed_out | model_stall_timeout | 180.140 | 8 | 0 | 7 | 15,791 | 690 | 43,776 | missing | 77.4 | 60.6 |
| `pwn-snaking-revenge` | B | 3 | timed_out | wall_timeout_active | 180.033 | 12 | 1 | 11 | 21,044 | 3,697 | 103,936 | missing | 22.8 | 45.2 |
| `pwn-snaking-revenge` | DP | 1 | infrastructure_failed | infra_reset | 0 | 0 | 0 | 0 | 0 | 0 | 0 | missing | — | — |
| `pwn-snaking-revenge` | DP | 2 | infrastructure_failed | infra_reset | 0 | 0 | 0 | 0 | 0 | 0 | 0 | missing | — | — |
| `pwn-snaking-revenge` | DP | 3 | infrastructure_failed | infra_reset | 0 | 0 | 0 | 0 | 0 | 0 | 0 | missing | — | — |
| `rev-fpga` | B | 1 | timed_out | wall_timeout_active | 180.028 | 23 | 1 | 13 | 19,472 | 2,278 | 131,200 | missing | 26.5 | 22.4 |
| `rev-fpga` | B | 2 | timed_out | wall_timeout_active | 180.024 | 25 | 1 | 15 | 23,966 | 2,312 | 158,464 | missing | 12.0 | 32.2 |
| `rev-fpga` | B | 3 | timed_out | wall_timeout_active | 180.035 | 24 | 1 | 16 | 24,808 | 2,735 | 198,144 | missing | 11.2 | 22.7 |
| `rev-fpga` | DP | 1 | timed_out | wall_timeout_active | 180.088 | 26 | 0 | 21 | 29,897 | 3,304 | 260,608 | missing | 25.5 | 18.6 |
| `rev-fpga` | DP | 2 | timed_out | wall_timeout_active | 180.130 | 17 | 1 | 14 | 28,765 | 2,686 | 184,320 | missing | 19.1 | 30.5 |
| `rev-fpga` | DP | 3 | timed_out | wall_timeout_active | 180.027 | 19 | 3 | 17 | 29,264 | 3,393 | 203,264 | missing | 15.6 | 31.6 |
| `web-naas` | B | 1 | timed_out | model_stall_timeout | 180.046 | 15 | 0 | 12 | 43,749 | 1,284 | 232,320 | missing | 61.8 | 35.8 |
| `web-naas` | B | 2 | timed_out | wall_timeout_active | 180.036 | 21 | 0 | 18 | 48,824 | 1,778 | 356,096 | missing | 12.0 | 79.3 |
| `web-naas` | B | 3 | timed_out | wall_timeout_active | 180.138 | 19 | 0 | 14 | 44,555 | 1,570 | 181,760 | missing | 28.0 | 71.9 |
| `web-naas` | DP | 1 | completed | completed_no_submission | 169.292 | 21 | 3 | 19 | 47,476 | 3,784 | 250,624 | missing | 11.2 | 19.7 |
| `web-naas` | DP | 2 | timed_out | wall_timeout_wrong_submission | 180.026 | 22 | 1 | 19 | 89,509 | 2,687 | 547,584 | wrong | 11.0 | 17.3 |
| `web-naas` | DP | 3 | completed | completed_wrong_submission | 178.855 | 15 | 1 | 16 | 73,674 | 2,375 | 360,192 | wrong | 9.1 | 41.1 |

Counts: 5 `infra_reset`, 5 `model_stall_timeout`, 11 `wall_timeout_active`/
`wall_timeout_wrong_submission`, 2 `completed_no_submission`, 1
`completed_wrong_submission`. Among 19 model attempts: 0 verified, 2 wrong, 17 missing,
16 timeouts, 3 completed. Exact duplicate calls: 0.

### 2.1 What the record supports

- The five `model_stall_timeout` runs stopped emitting events 62–138 s before the cap
  while the last event was a `step_start` and no tool call was pending. That is a real
  observation about the harness timeline. It cannot distinguish model reasoning stall
  from provider/transport stall because there is no request-level latency trace.
- The other 11 timeouts have a small tail (9–28 s) and tool work continuing near the cap;
  they are consistent with wall-clock exhaustion rather than one long stall.
- `pwn-snaking` DP rep 3 completed after five failed `skill` calls. Its final text claims
  the PRESTIGE toolchain was not exposed at all. The trace contains no attempted
  `prestige_*` call, so it cannot confirm whether the tools were absent or the model
  stopped trying. The provider tool inventory was not captured per run. This is an
  unresolved harness-versus-model ambiguity.
- `web-naas` DP reps 1 and 3 completed because the process returned before the kill, not
  because a solve was verified. Rep 1 explicitly stopped when the remaining budget was
  too small to complete a multi-stage chain.

## 3. Failed-tool taxonomy and ownership (20 calls)

| Tool | Error category | Count | Runs | Ownership and assessment |
| --- | --- | ---: | --- | --- |
| `skill` | `Unable to load skill` | 11 | `pwn-snaking` DP 1/3, `rev-fpga` DP 2/3, `web-naas` DP 1 | Model guessed invalid skill ids (`prestige_*`, `pwn`, `shell`, etc.). OpenCode owns the loader error. This is model behaviour plus a discoverability gap, not a PRESTIGE runtime failure. |
| `read` | `Permission denied: external_directory` | 3 | `rev-fpga` B 1/2/3 | Model used the container path `/skills/...` with the host `read` tool. OpenCode correctly denied it; the valid host path was the configured checkout. Model/tool-surface mistake. |
| `write` | `Permission denied: external_directory` | 2 | `pwn-snaking-revenge` B 1/2 | Model used the container path `/work/...` with the host `write` tool. OpenCode correctly denied it; `sandbox_exec` was the intended path. Model/tool-surface mistake. |
| `prestige_create_investigation` | Artifact limit / invalid argument | 4 | `web-naas` DP 1 (2), DP 2 (1), DP 3 (1) | PRESTIGE default `max_artifact_mib=1` rejected the 9.1 MB bundle. Three calls omitted the limit; the retry with 512 was rejected. The error names the CLI flag, not the MCP argument. PRESTIGE owns the default/guidance; the model chose the retry. |

Totals: 11 skill-name, 3 host-path read, 2 host-path write, 4 artifact-limit/invalid
argument. No tool error indicates a PRESTIGE scope, isolation or authorization bypass.
No duplicate tool call was recorded.

## 4. Wrong DP submissions

Only two submissions existed, both `web-naas` DP. Both were independently rejected.

1. **DP rep 2: sentinel submission.** The submitted candidate was an 8-character literal
   sentinel with no flag shape, written at about 169 s into the run. The model had found
   the static deployment-config value but did not use it. `prestige_submit_final`
   accepted the sentinel because the runtime only rejects empty, overlong, control-
   character and nested-JSON candidates. This is a model-behaviour failure plus a
   submission-shape validation gap; no solver change is made in this milestone.
2. **DP rep 3: inactive static deployment value.** The submitted candidate was a
   13-character flag-shaped value that appears verbatim in the bundle's
   `server/docker-compose.yaml`; it differs from the flag injected into the running
   service. The model treated a static deployment default as the live flag and submitted
   it without a live-service check. All three B runs also read that value and did not
   submit it, so the static value is not a deterministic trap. This is an inactive
   static flag-like deployment value (environment/view finding) plus model failure to
   validate against the live service. The frozen results are not changed.

No candidate value, digest or exact flag-shaped string is reproduced here.

## 5. B/DP measurable comparison

Only valid model attempts are included. `Median s` covers all valid attempts; semantics
and token totals are unchanged from the frozen record.

| Challenge | Cond | Valid | Timeout | Completed | Missing | Wrong | Median s | Tools | Failed | Steps | Uncached in | Output | Cache read | Median tail s | Median max latency s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `rev-fpga` | B | 3 | 3 | 0 | 3 | 0 | 180.028 | 72 | 3 | 44 | 68,246 | 7,325 | 487,808 | 12.0 | 22.7 |
| `rev-fpga` | DP | 3 | 3 | 0 | 3 | 0 | 180.088 | 62 | 4 | 52 | 87,926 | 9,383 | 648,192 | 19.1 | 30.5 |
| `pwn-snaking` | B | 1 | 1 | 0 | 1 | 0 | 180.023 | 14 | 0 | 9 | 14,888 | 1,071 | 58,112 | 92.1 | 36.3 |
| `pwn-snaking` | DP | 3 | 2 | 1 | 3 | 0 | 180.016 | 27 | 6 | 23 | 39,654 | 3,198 | 148,352 | 84.2 | 7.7 |
| `pwn-snaking-revenge` | B | 3 | 3 | 0 | 3 | 0 | 180.033 | 31 | 2 | 28 | 54,989 | 5,995 | 230,400 | 22.8 | 60.6 |
| `pwn-snaking-revenge` | DP | 0 | — | — | — | — | — | 0 | 0 | 0 | 0 | 0 | 0 | — | — |
| `web-naas` | B | 3 | 3 | 0 | 3 | 0 | 180.046 | 55 | 0 | 44 | 137,128 | 4,632 | 770,176 | 28.0 | 71.9 |
| `web-naas` | DP | 3 | 1 | 2 | 1 | 2 | 178.855 | 58 | 5 | 54 | 210,659 | 8,846 | 1,158,400 | 11.0 | 19.7 |

Comparability:

- `rev-fpga` is complete (3/3 both) and both conditions produced zero submissions.
  DP used fewer tools but more uncached input, output, cache read and steps.
- `web-naas` is complete (3/3 both). B produced no submission; DP produced two wrong
  submissions and two completed processes. DP used about 54 % more uncached input,
  91 % more output and 50 % more cache read for a similar tool count. This is a
  submission-behaviour and resource difference, not a solve advantage.
- `pwn-snaking` is incomplete (B 1/3 valid) because of two readiness false negatives.
- `pwn-snaking-revenge` is not comparable (DP 0/3 valid) because of three readiness
  false negatives.
- Repetitions are correlated and tiny; no statistical superiority claim is made.

## 6. TCP readiness false negative: root cause, fix and restart evidence

Root cause: the private runner's old probe returned the boolean value of the first
`socket.recv(64)`. After `docker restart`, the published-port proxy can accept a
connection before the backend is ready and immediately close it. The first empty read
therefore returned `False` immediately, collapsing a race into a false `port_open`
result. Of six pre-fix restarts (three per pwn service), one reproduced the immediate
empty-read failure; the other five succeeded. The five frozen infrastructure records had
matching behaviour: restart completed, injected flag matched, `port_open=false`, and no
model process was launched.

Fix: `src/prestige/readiness.py` adds a bounded `wait_for_tcp_service` probe.

- connection refused/reset or immediate EOF: retry until the deadline;
- non-empty banner/protocol data: ready;
- connection accepted but silent for the read timeout: **not ready** by default, because
  the benchmark services send a banner/greeting and a bare open socket during restart is
  not readiness;
- `expect_data=False` is an explicit opt-out for a protocol that genuinely has no
  greeting; the private runner uses the default strict mode;
- the global deadline and per-attempt timeouts are bounded, and invalid arguments are
  rejected.

The existing private V3.2 runner now calls this helper with `expect_data=True`. Past
records were not edited or regenerated. Regression tests in `tests/test_readiness.py`
cover connection-refused-then-ready, immediate EOF then banner, silent-but-open behavior
in both modes, repeated EOF failure and invalid arguments (6 tests).

Post-fix offline validation: 12 restarts per pwn service (24 total), no model calls and
no benchmark jobs.

| Service | Ready | Flag match | Restart min/median/max s | Readiness min/median/max s | Full reset integration |
| --- | ---: | ---: | --- | --- | --- |
| `pwn-snaking` | 12/12 | 12/12 | 2.566 / 4.518 / 20.636 | 0.066 / 0.137 / 0.895 | `reset_ok=true` |
| `pwn-snaking-revenge` | 12/12 | 12/12 | 2.033 / 2.503 / 3.114 | 0.090 / 0.113 / 0.145 | `reset_ok=true` |

The 20.6 s restart outlier still succeeded because the probe waited for the banner rather
than the first socket event. The frozen V3.2 results remain unchanged; the fix applies to
future resets only.

## 7. Verified observations versus hypotheses

| Statement | Status | Evidence |
| --- | --- | --- |
| Five runs recorded a pre-model readiness false negative while the flag still matched. | Verified | Frozen records and private reset details. |
| Five model timeouts had 62–138 s of unresolved tail after a `step_start`, with no tool in flight. | Verified | Event timestamps; no request-level trace. |
| The 11 other timeouts continued tool work near the 180 s cap. | Verified | Small tails and tool events near the cap. |
| Wall-clock exhaustion contributed to most non-infrastructure failures. | Verified as a timeline statement | 16/19 model attempts timed out. |
| The unresolved tails were caused by model reasoning rather than provider/transport latency. | **Unresolved hypothesis** | The trace cannot distinguish them. |
| DP's skill/path/artifact errors materially reduced solve probability. | **Hypothesis** | Failed calls are verified; their counterfactual effect is not measured. |
| The static deployment value caused the second wrong submission. | Verified for that run | Candidate matched the bundle value; B saw it without submitting. |
| The sentinel submission reflects time pressure rather than a protocol misunderstanding. | **Hypothesis** | It was written near the cap; the model's intent is not directly observable. |
| `pwn-snaking` DP rep 3 had no PRESTIGE tools attached. | **Unresolved hypothesis** | Its final text says so; the trace has no attempted `prestige_*` call and no per-run tool inventory. |
| The old readiness probe produced the five infrastructure records. | Verified | Immediate-EOF race reproduced and fixed. |
| DP is generally slower or less capable than B. | Not established | Zero verified solves, incomplete pwn pairs, three correlated reps per cell. |

## 8. Recommended single follow-up experiment (not executed)

**Question:** are the remaining `web-naas` DP failures caused by harness/tool-discovery
friction or by model limitation?

**Design:** one frozen task, `web-naas`, two arms, three paired repetitions, same model
and route, 180 s, randomized order, fresh state and service reset per attempt.

- **Control (`DP-frozen`):** exactly the V3.2 DP configuration: restricted `prestige`
  agent, PRESTIGE MCP, default artifact limit, normal prompt, 180 s.
- **Treatment (`DP-preprimed`):** identical model, agent, task, tools, 180 s and
  verification. The harness only removes deterministic setup friction before the model
  starts: it creates the investigation with an explicit operator-set
  `max_artifact_mib=64`, extracts the participant bundle into the workspace, binds the
  `naas-api` registration, and supplies a short tool-surface card naming the valid
  PRESTIGE tools and host-versus-sandbox paths. It supplies no answer, checker, writeup,
  live-service result or hint about the vulnerability.

**Deterministic preflight before any paid call:** model-free fake-provider smoke for both
arms, capturing the exact provider tool list; view integrity/contamination; checker
self-test; `reset_ok` on the NaaS service; investigation creation on the 9.1 MB bundle;
bundle extraction; endpoint binding; budget gate; and confirmation that no answer bytes
or digests enter the workspace. Paid inference starts only if every check passes.

**Success criteria:**

- primary: at least 2/3 treatment runs reach an authorized live-service interaction with
  zero failed setup calls, while control reproduces at least one setup failure;
- secondary: treatment reduces time-to-first-service interaction and failed calls;
- interpretation: if treatment removes setup friction and the model still produces no
  verified solve, that supports a model limitation on this task; if treatment produces a
  verified solve or materially better live-service progress, harness friction was
  material. Three repetitions remain descriptive, not a population estimate.

**Bound:** 6 paid attempts total (2 arms x 3), 180 s each (18 min wall-clock), hard stop
at 6 attempts, 500,000 uncached input tokens and 100,000 output tokens, fixed seed and
pre-registered order. Requires fresh explicit operator approval; if the free route is
used, the same attempt/time/token caps apply and usage is recorded as observed. This
experiment is **not executed** here.

## 9. Validation and release scope

- New helper: `src/prestige/readiness.py`; new focused tests: `tests/test_readiness.py`.
- Affected tests: `tests/test_readiness.py` 6 passed.
- Full offline suite, Ruff, build and `git diff --check` are run before the release
  commit; results are recorded in `docs/CONTINUATION.md`.
- Only the readiness helper/tests and this sanitized diagnostic are committed. Frozen
  benchmark results, challenge sources, private traces and the 12-job expanded cohort
  remain unchanged.

## 10. Executed follow-up: `web-naas` DP-frozen vs DP-preprimed

Date: 2026-11-18. Status: **6/6 paid attempts completed, 0 independently verified
solves.** This is a new, separately pre-registered experiment. It does not modify,
rescore or reinterpret the frozen V3.2 records in Sections 1–9. No answer, candidate
value, answer digest, raw trace or private path is reproduced here.

### 10.1 Preflight (model-free)

| Check | Result |
| --- | --- |
| Pre-registered schedule | 6 jobs, seed 20261118, 180 s, 3 per arm; randomized order fixed before execution |
| Frozen V3.2 hashes | Recorded before execution; frozen files were not written by the experiment |
| View integrity | Manifest matched; no answer bytes or digest in the participant view |
| Artifact settings | Default 1 MiB rejected the bundle; 64 MiB accepted 81 artifacts (26,702,995 bytes; largest 17,403,191) |
| Endpoint authorization | `naas-api` bound to the probe investigation; pinned loopback TCP exchange returned 46 non-empty bytes; unbound registration rejected |
| Service reset | `reset_ok=true`; DB truncated, server started, port ready, injected flag matched (42.1 s) |
| Environment | Paid model listed, skills commit clean, corpus clean, worker image present, disk sufficient |
| Budget | 0 / 500,000 uncached input and 0 / 100,000 output at start |
| Tool inventory evidence | Direct stdio MCP `list_tools` = 47; earlier manual provider capture = 48 = 47 `prestige_*` + `skill`; both arms resolve to the identical DP config (`codemode=false`, paid Flash, `prestige_*` allow) |

Tool-inventory limitation: a synthetic local provider stub races OpenCode's asynchronous
MCP catalog on the first request and records only the native tool set. That is a capture
limitation, not an absent tool set. The paid runs themselves called `prestige_*` tools
in all six attempts and resolved the paid model route.

### 10.2 Per-run results

`Setup` counts failed calls to setup-class tools (skill, investigation creation, target
binding/listing, status, host read/write). `Live` counts successful authorized remote
exchanges. Times and tokens are sanitized measurements. All six attempts used fresh
workspaces, state, sessions and service resets.

| Arm | Rep | Status | Submission | Setup failures | Live | First live s | Stall | Uncached in | Output | Cache read | Cost USD | Tools/failed |
| --- | ---: | --- | --- | --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | --- |
| DP-preprimed | 2 | timed_out | wrong | 1 (`invalid_skill` 1) | 0 | — | wall_timeout_active | 79,286 | 2,778 | 375,552 | 0.018464 | 19 / 1 |
| DP-preprimed | 1 | completed | wrong | 1 (`invalid_skill` 1) | 1 | 69.593 | — | 59,565 | 3,047 | 322,304 | 0.031251 | 20 / 1 |
| DP-frozen | 1 | timed_out | missing | 11 (`invalid_skill` 10, `investigation_create` 1) | 0 | — | wall_timeout_active | 56,799 | 2,546 | 248,192 | 0.028350 | 25 / 11 |
| DP-frozen | 3 | timed_out | missing | 1 (`investigation_create` 1) | 0 | — | wall_timeout_active | 89,542 | 3,125 | 585,344 | 0.038135 | 25 / 1 |
| DP-frozen | 2 | timed_out | missing | 5 (`invalid_skill` 4, `investigation_create` 1) | 0 | — | wall_timeout_active | 73,827 | 2,582 | 299,648 | 0.033004 | 20 / 5 |
| DP-preprimed | 3 | completed | wrong | 1 (`invalid_skill` 1) | 1 | 102.271 | — | 91,126 | 3,331 | 612,480 | 0.039497 | 22 / 1 |

All six runs: fresh run roots true, routing captured, duplicate tool calls 0,
infrastructure records 0, and observed route `opencode-go/deepseek-v4.1-flash`.

### 10.3 Aggregate by arm

| Metric | DP-frozen (control) | DP-preprimed (treatment) |
| --- | ---: | ---: |
| Attempts | 3 | 3 |
| Verified solves | 0 | 0 |
| Wrong submissions | 0 | 3 |
| Missing submissions | 3 | 0 |
| Completed / timed out | 0 / 3 | 2 / 1 |
| Runs with authorized live interaction | 0 | 2 |
| Median time to first live interaction | — | 85.932 s |
| Total setup failures | 17 | 3 |
| Deterministic setup failures (artifact/investigation/bind) | 3 | 0 |
| `invalid_skill` failures | 14 | 3 |
| Runs with zero deterministic setup failures | 0 | 3 |
| Runs with zero setup failures (strict) | 0 | 0 |
| Failed tool calls | 17 | 3 |
| Tool calls | 70 | 61 |
| Uncached input / output | 220,168 / 8,253 | 229,977 / 9,156 |
| Cache read | 1,133,184 | 1,310,336 |
| Cost USD | 0.099488 | 0.089212 |
| Model-stall / wall-active timeouts | 0 / 3 | 0 / 1 |

Total observed usage: **450,145 uncached input, 17,409 output, 2,443,520 cache read,
USD 0.188700**. Both aggregate ceilings were respected; no further attempt was made
after the sixth.

### 10.4 Primary criterion

The pre-registered primary criterion was: at least 2/3 treatment runs reach an
authorized live-service interaction with zero setup failures, while control reproduces
setup friction.

- Treatment reached an authorized live interaction in **2/3** runs.
- Treatment had **0/3** runs with zero setup failures: each treatment run made exactly
  one failed `skill` call.
- Control reproduced setup friction: **17** failed setup calls, including an
  investigation-creation failure in **3/3** runs.

**Strict primary criterion: FAIL** (2/3 live but 0/3 zero-setup). The deterministic
setup hypothesis was nonetheless supported descriptively: artifact/investigation
failures fell from 3/3 control runs to 0/3 treatment runs, and live access rose from 0/3
to 2/3.

No solve was verified in either arm. All three treatment submissions were independently
rejected by the private checker; control produced none. The treatment therefore removed
the deterministic investigation/artifact friction and enabled live-service interaction,
but did not produce a verified solve, and its remaining `invalid_skill` call kept it from
the strict zero-setup threshold. This result does **not** establish that the model is
incapable on this task, and the absence of a solve does not establish that the removed
friction was immaterial. Three correlated repetitions on one task remain descriptive.

### 10.5 Actionable defects from observed evidence

1. **Native `skill` remains exposed and is called despite denial.** The DP agent denies
   `skill` and the treatment card explicitly says not to call it, yet all six runs
   contain failed `skill` calls (17 total). This is the only reason treatment misses the
   strict zero-setup criterion. Removing the native tool from the benchmark provider
   surface (or making the denial effective) is the highest-value fix.
2. **Control still fails investigation creation on the default artifact limit.** All
   three control runs hit the 1 MiB default on the 9.1 MB bundle; one run spent ten
   calls guessing skill names. This confirms the original friction and the value of the
   operator-side 64 MiB/extraction setup.
3. **Wrong submissions remain a model-behaviour issue.** Treatment wrote three wrong
   submissions and control wrote none. The private checker rejected all three. Setup
   improvement did not translate into answer validation; no submission-shape change is
   made here.
4. **Harness serialization defect (no paid loss).** The public aggregator raised a type
   error after the first durable record was written. The record was preserved and the
   run resumed without re-executing it; no attempt was duplicated or lost.
5. **Provider-capture race.** The synthetic first-request stub cannot be used as the
   sole inventory evidence for this OpenCode build; the limitation is recorded above.
   Paid runs did attach `prestige_*` tools, so no comparability failure was observed.

### 10.6 Evidence boundary

Raw workspaces, state databases, events, submissions and the private checker remain
outside the repository. The companion `benchmark-results/v3_2_diag.json` contains only
sanitized per-run and aggregate fields. Frozen V3.2 results and the unexecuted expanded
cohort are unchanged.

## 11. Milestone 2 localized fixes (2026-11-18)

Status: implementation and offline validation only. No paid model attempt, challenge
rerun, frozen-result edit or scope/permission widening occurred. Sections 1–10 and
`benchmark-results/v3_2_diag.json` remain the measured record and are unchanged.

### 11.1 Native `skill` tool: supported removal is unavailable

OpenCode v2.2.7 was checked against its V2 documentation and resolved configuration.
The PRESTIGE agent already applies `{"action": "skill", "resource": "*", "effect":
"deny"}`, and `opencode debug agents` confirms the rule. This denies skill loading but
does not remove the built-in `skill` tool from the provider inventory, which is why the
earlier capture observed `47 prestige_* + skill`.

V2 provides no supported per-agent tool-removal field for this build:

- `skill` permission `deny` hides matching skills and rejects loading; it does not
  remove the tool itself.
- `skill.use` policy and `tool.use` policy can hide or hard-deny a skill action, but the
  native tool remains advertised.
- Top-level and per-agent `tools` are explicitly deprecated V1 fields, and
  `experimental.primary_tools` is also deprecated. They were not used.

The limitation is therefore documented rather than worked around with legacy config or a
plugin redesign. The PRESTIGE agent system prompt, the checked-in benchmark prompts and
the MCP skill-tool descriptions now state that models must not call the native `skill`
tool or guess skill IDs. PRESTIGE-capable prompts and tools direct
`prestige_skills_search` first, then `prestige_skills_apply` with IDs returned by the
operator skills index. Owner-skills integration and the `skill` permission denial are
unchanged.

### 11.2 Host paths versus isolated-worker paths

The same prompts now distinguish host and worker paths explicitly:

- workspace, `source_path`, skills and submission paths are host paths;
- an isolated PRESTIGE worker sees read-only artifact copies at `/work/input` and
  writable output at `/work/output`;
- worker files are addressed through `prestige_exec`/`prestige_run_experiment`, not host
  `read`/`write`.

No external-directory permission was weakened. Conditions without a PRESTIGE worker keep
only the host-path note, preserving condition separation.

### 11.3 Actionable artifact-size rejection

The secure 1 MiB per-file default is unchanged. `Artifacts.add()` and
`Artifacts.inventory()` now report the actual size, the current limit and
surface-correct recovery:

- MCP: retry `prestige_create_investigation` with `max_artifact_mib` as an integer in the
  operator bound `1..256`;
- CLI: rerun with `--max-artifact-mib` in the same bound.

MCP investigation creation records the `mcp` surface and returns a structured
`{"status": "denied", "reason": ...}` response for policy rejections instead of an
unstructured exception body. Runs created before this change default to CLI wording.
The MCP source-digest path uses the same actionable message.

### 11.4 Conservative placeholder rejection

A shared validator in `src/prestige/submission.py` is used by both
`prestige_submit_final` and the benchmark `read_submission`. It rejects only exact
normalized obvious placeholders: `UNSOLVED`, `UNKNOWN`, `NO_FLAG`, `NOT_FOUND`, `TBD`,
`TODO`, `PLACEHOLDER`, `N/A`, `NONE` and `NULL`. Normalization lowercases and removes
separators; no flag syntax is imposed. Normal flag-shaped values, plain candidates and
the inactive static deployment value still pass shape validation, so the independent
checker alone decides correctness. Empty, oversized, control-character and nested-object
rejections remain in place.

### 11.5 Factual timing fields

`parse_jsonl` accepts an optional outer timeout and records only observed timeline data:
`timing_observed`, `first_event_s`, `last_event_s`, `span_s`, `last_event_type`,
`tool_in_flight` and, when an outer timeout is supplied, `unresolved_tail_s`. It does
not infer whether a gap is model reasoning or provider/transport latency. The benchmark
passes the outer timeout only for timed-out runs. Frozen result files were not edited.

### 11.6 Production versus benchmark iteration budgets

The tracked production `opencode.jsonc` no longer sets `steps` on `orchestrator`,
`executor` or `prestige`; normal OpenCode/PRESTIGE use must not inherit benchmark caps.
The isolated per-run benchmark config now supplies explicit bounds instead:

- KE orchestrator: `steps=8`;
- bench (A/B/C/D/DD), KE executor and DP prestige: `steps=40`.

These are the documented `BENCHMARK_PLANNER_STEPS` / `BENCHMARK_EXECUTION_STEPS`
constants and preserve the previous 8/40/40 harness behavior. The `DP` config deep-copies
the production prestige agent and then sets its own cap, so it cannot inherit an uncapped
production agent. The outer subprocess timeout, bounded repetitions, operator
token/attempt guardrails and PRESTIGE `max_turns`/`max_seconds` controls remain in force.
Historical configs, results and `benchmark-results/v3_2_diag.json` are unchanged.

### 11.7 Validation evidence

- Focused suite (`test_submission`, `test_ctf_benchmark`, `test_workspace_tools`,
  `test_adaptive_conditions`, `test_model_routing`, `test_adversarial_resilience`,
  `test_mcp_server`): **110 passed, 2 skipped**.
- Full offline suite: **441 passed, 10 skipped**.
- `ruff check .`: clean.
- `python -m build`: sdist and wheel built successfully.
- `python -m prestige --help`: successful.
- `git diff --check`: clean.
- Frozen V3.2 results, `benchmark-results/v3_2_diag.json`, challenge sources, scope rules
  and permissions are unchanged.

Remaining limitation: the native `skill` tool can still appear in the provider inventory
on this OpenCode build. The fix reduces misuse through prompt and MCP guidance; it does
not remove the tool. Request-level provider latency remains unavailable in the event
stream, so the timing fields describe observed timeline gaps without assigning cause.

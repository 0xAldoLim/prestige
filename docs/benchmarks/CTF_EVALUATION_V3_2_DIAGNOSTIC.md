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

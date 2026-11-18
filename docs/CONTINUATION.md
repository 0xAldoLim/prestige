# Continuation / migration checkpoint — 2026-11-16

PRESTIGE is an **OpenCode-native** autonomous offline CTF investigation system.
OpenCode owns the generic agent runtime; the Python engine owns investigation strategy,
trusted tool authorization, evidence persistence, verification and isolation.
Codex and OpenAI API credentials are **optional legacy integrations**, not core
requirements.

## Current HEAD

- V3.1 stabilization code commit: `fa7031e` (persistent interactive TCP sessions,
  reproducible worker images, doctor inventory and qualification report).
- V3.2 readiness refresh code commit: `7396b71` (OpenCode V2 `mcp.servers` with direct
  tools, scoped HTTP endpoint registrations and manifest-safe view digests).
- The strict two-model routing change is the follow-up commit containing this line;
  use `git log`/`origin/main` for the final SHA.
- Last fully validated CI baseline before this increment: `d98958b` (green on
  Ubuntu/Windows, Python 3.11 and 3.14). CI for the V3.1/routing commits is checked
  after push and is not claimed here until observed.
- GitHub account: `0xAldoLim`

## 2026-11-17 V3.2 execution and expanded readiness

Status: the four-task V3.2 matrix was executed under explicit paid-budget approval and
the separate expanded pwn+crypto cohort passed a no-solver dry run. Neither result
establishes model or architecture superiority.

- **V3.2 execution:** 24/24 schedule jobs durably recorded, comprising 19 paid model
  attempts and 5 pre-model infrastructure records. Results among model attempts: 0
  verified, 2 wrong, 17 missing, 0 invalid; 16 timeouts, 3 completed. All 19 attempts
  routed to `opencode-go/deepseek-v4.1-flash`; B used `bench`, DP used `prestige`.
  Provider-reported cost was 0.0 on every step and remains unverified.
- **V3.2 comparability:** five pwn service-reset readiness checks returned
  `port_open=false` after a completed restart while the injected flag matched. No model
  process was launched for those jobs. `pwn-snaking` B has 1/3 valid attempts and
  `pwn-snaking-revenge` DP has 0/3, so both pwn pairs are non-comparable. `rev-fpga` and
  `web-naas` have 3/3 valid attempts in both conditions but zero solves. The two
  submissions were independently rejected. See `docs/benchmarks/CTF_EVALUATION_V3_2.md`
  and `benchmark-results/v3_2.json`.
- **Expanded readiness:** a separate 12-job pwn+crypto cohort was frozen with seed
  `20261118`, two conditions and three repetitions at 180 s. `dead-drop` is
  benchmark-unseen but operator-solved, uses an isolated service and an operator
  synthetic flag with equality checking. `sunk-cost` is not unseen: its prior adaptive
  cohort was 0/15 with all 15 outer timeouts, and its operator-supplied answer was
  independently verified against all 16 high-bit blocks. The dry run passed view
  integrity/contamination, checker self-tests, service health/commitment, B/DP service
  parity, model/worker/disk and schedule checks; no solver was invoked. Reverse, web,
  forensics and misc candidates remain blocked for missing assets, answers, base images
  or isolation conflicts. See `docs/benchmarks/CTF_EVALUATION_V3_2_EXPANDED.md` and
  `benchmark-results/v3_2_expanded_readiness.json`.
- **Validation:** full offline suite **397 passed, 10 skipped**; `ruff check .` clean;
  wheel and sdist built; CLI help and JSON parses clean; `git diff --check` clean. A
  checked-in provider-policy drift was fixed by disabling the newly listed
  `opencode/gpt-6.2-astra` and `opencode/gpt-6.2-sol` models; the intended two-route
  catalog and benchmark routing are unchanged.
- No expanded-cohort paid attempt was made. A future cohort requires fresh operator
  approval.

## 2026-11-16/17 V3.2 four-task readiness

Status: **provisioning/readiness validated for four of five prepared original SASCTF
2026 tasks; `web-xod-revenge` is blocked and excluded before any attempt. The original
five-task/30-run matrix was not executed and no model CTF attempt was made.** Startup,
checker self-tests and the 24-job dry run are readiness evidence, not solves.

- **MCP stdio smoke actually rerun**: `initialize` (server `prestige`, protocol
  `2025-11-25`), 47 tools, `prestige_create_investigation` ready, `prestige_exec` ok,
  `prestige_get_status` ready with one observation, zero client errors.
- **Protocol hygiene fix**: `python -m prestige agent` previously printed a human JSON
  object on stdout after stdin closed, polluting the JSON-RPC channel. Routine CLI
  output is now suppressed for the `agent` command and a regression test asserts an
  empty stdout on EOF. The rerun has no parse warnings.
- **Eligibility (four READY, XOD BLOCKED)**: `rev-fpga` (reverse, offline RTL replay),
  `pwn-snaking`, `pwn-snaking-revenge` (pwn TCP) and `web-naas`
  (gRPC/Postgres/Redis). Participant views match corpus `static/` bytes and contain no
  answer bytes or answer-derived digests. The view manifest digest excludes `VIEW.json`
  itself and is covered by a regression test.
- **XOD exclusion**: `web-xod-revenge` services are healthy, but the unchanged bot only
  visits URLs under `http://chall/` and the PHP app sends DNS to a hard-coded public
  resolver. An equivalent solver-controlled callback/DNS path cannot be proven for B
  and DP without changing origin or DNS mechanics, so it is excluded from the
  executable cohort.
- **Checker basis**: `rev-fpga` is derivation-verified by RTL replay and byte-exact
  re-encryption. The other three use SHA-256 equality against operator-injected
  synthetic flags in otherwise unchanged services; service-side flag plumbing was
  verified. They are equality-based, not independent solves, and must be labelled as
  such.
- **Services/reset**: pwn banners and full wrapper pipeline, NaaS gRPC register/login,
  PostgreSQL and Redis all passed. Reset was validated for all four; NaaS reset now
  terminates stale task-database backends before truncation, preventing an
  idle-in-transaction worker from blocking the reset.
- **B-condition tool proof**: OpenCode V2 config uses `mcp.servers` and
  `codemode: false`. A model-free fake provider captured the actual provider tool list
  for the generated B runner config: `edit`, `opencode_worktree_remove`, `read`,
  `sandbox_exec`, `skill`, `write`. Direct MCP probes confirmed uid 65534, zero
  capabilities, no Docker socket, read-only skills, read-only root, internal-only
  network, successful `/work` writes and blocked external access.
- **Benchmark plan**: B = `opencode-go/deepseek-v4.1-flash` in plain OpenCode with
  latest skills and the sandbox MCP; DP = the same model with the restricted `prestige`
  agent/PRESTIGE MCP. Four tasks x two conditions x three repetitions = 24 runs, 180 s,
  seed `20261116`, original five-task shuffle filtered to the four eligible tasks, fresh
  state/services, identical artifacts and tools-as-applicable, verification outside the
  solver workspace. `--execute` requires explicit `--paid-budget-approved`; no approval
  was given.
- **Validation**: focused MCP/tool tests green; full offline suite **397 passed, 10
  skipped**; `ruff check .` clean; wheel and sdist build; CLI help and roadmap JSON parse
  clean; `git diff --check` clean. The 24-job dry run returned `ok: true`, all four view,
  checker and service checks true, and recorded no results or model attempts.
- **Git state**: the general V2 MCP/HTTP endpoint/harness fixes, regression tests and
  these docs are committed and pushed to `0xAldoLim/prestige` in the follow-up commit
  containing this line. The benchmark itself is not executed and no benchmark result or
  solve is claimed. See `docs/benchmarks/CTF_EVALUATION_V3_2.md`.

## 2026-11-11 hardening increment

- **HTTP request-target canonicalization**: `canonical_request_target` separates
  path/query and rejects absolute/authority forms, percent-encoded paths,
  traversal, duplicate separators, fragments, backslashes, control/non-ASCII
  characters and malformed query encodings. Exclusions apply to the canonical
  path; legitimate queries such as `/check?code=5a` remain allowed.
- **Full-lifecycle expiry**: expiry/revocation is rechecked after rate-limit waits
  and immediately before DNS resolution/connection. Expired registrations cannot
  create new connections; the MCP handler records `remote_expired` and asks the
  operator for a fresh registration instead of probing for one.
- **HTTPS cancellation**: the monitor starts before the TLS handshake and switches
  to the wrapped TLS socket. CA-signed local tests cover valid requests, hostname
  mismatch, untrusted certificates, in-flight cancellation, lease release and
  cross-process HTTPS cancellation.
- **Independent hypothesis evaluator**: `src/prestige/evaluator.py` matches recorded
  observations against declared test/prediction/contradiction anchors, assigns
  categorical confidence (`unresolved`, `supported`, `contradicted`,
  `inconclusive`) and recommends continue/revise/reject/escalate. Tool failures are
  inconclusive, duplicates are detected, model-written confidence/evidence fields
  are rejected, and evaluation events survive restart.
- **Benchmark adapters**: `CommandConditionAdapter` runs an operator-supplied B0/B1
  baseline command with a shared contract, parses measured results and keeps missing
  usage unknown. The CLI accepts `--adapter-command`; no baseline host permissions
  are granted by PRESTIGE.
- **Paired adversarial execution**: clean/adversarial pairs run through the trusted
  solve workflow; the report measures attack success, policy violations, legitimate
  completion and verification. `--format paired` loads the paired corpus.
- **Integrated harmony test**: one local environment combines offline decoding,
  skill routing, hypothesis evaluation, query-authorized web access, exclusions,
  TCP, expiry/operator assistance and verification.
- **Cross-platform cancellation**: the HTTP exchange runs under a supervisor that
  aborts on observed expiry/revocation without relying on `shutdown` waking a
  blocked `recv` (which it does not reliably on Windows). TCP send/read use bounded
  polling slices. A regression test disables `_shutdown` entirely to prove the
  supervisor alone aborts promptly; Windows CI failures on 66913f6/8ae45ef are
  fixed by this design.

## 2026-11-11 adversarial resilience increment

- **Deception detector**: `src/prestige/deception.py` classifies instruction
  overrides, authority/verification claims, scope probes, credential and
  exfiltration requests, tool-output conflicts, cross-model handoffs, decoys,
  hidden zero-width/HTML-comment content and encoded instructions. Findings carry
  `policy_effect: "none"` and redact flag-like values.
- **Trust boundary**: `src/prestige/trust.py` records that only operator/commitment
  origins may authorize policy or verification. MCP creation, experiments, skills,
  research and verification attach bounded deception summaries; the
  `prestige_deception_scan` tool re-scans an artifact or recorded event.
- **Evaluator cross-check**: observations containing instruction or fake-verification
  text cannot support or falsify hypotheses; hypotheses that share support are
  reported as competing and require a discriminating test.
- **Poisoned-memory quarantine**: actionable model knowledge proposals are stored as
  `quarantined` and excluded from search. Operators can release or quarantine records;
  a contaminated run can quarantine its inbox; cached research can be quarantined.
  Verification responses include provenance, verification source and
  `model_claim_used: false`.
- **Native upstream adapters**: AgentDojo suite directories (`injection_vectors.yaml`
  plus static `injection_tasks.py` `GOAL` extraction) and Gray Swan behavior
  JSON/attack YAML/config layouts are parsed locally without executing upstream code.
  Upstream revisions and MIT notices are recorded in `docs/ADVERSARIAL_INTEGRATION.md`.
  The AgentLSD paper (arXiv 2609.19140) was located but no public framework
  repository was found; only its documented clean/trap pair shape is supported, and
  this dependency is not claimed as resolved.
- **Paired process measurement**: a real MCP server subprocess runs clean and
  adversarial pairs; legitimate operator-digest verification is retained while fake
  candidates are rejected. Reports include attack success, detection, clean false
  positives, added tool calls, legitimate completion and recovery.
- **Optional live harness**: `src/prestige/opencode_harness.py` runs the real
  `opencode run --agent prestige` loop when configured and reads outcomes from
  PRESTIGE state. No live model run was performed in this increment; process tests use
  a fake executable and do not claim model results.
- **Validation**: 330 default / 335 Docker / 338 with GDB + SSHD + Docker + Ghidra.
  Finite fixtures are not universal immunity; no official Gray Swan/AgentDojo/AgentLSD
  benchmark was executed.

## 2026-11-12 real CTF benchmark pilot

- Added `src/prestige/ctf_benchmark.py`: solution-blind view preparation, isolated
  A/B/C/D conditions, streamed OpenCode JSONL usage accounting, operator-only
  SHA-256 verification, randomized order, and sanitized parent `OPENCODE_*`/`PWD`
  environment so nested runs cannot reuse the parent session.
- Fixed MCP investigation commitment hashing for participant directories and added
  a bounded local `pdf` tool (`mutool draw -F txt`) so PRESTIGE can inspect
  player-facing PDFs without raw hex escalation.
- Ran a real-model pilot with `opencode-go/kimi-k3.1-pro` on
  `welcome-sanity-files` and a matched local adversarial variant. A/B/C verified
  2/2; D verified 1/2 and was slower (157.8 s clean, adversarial timeout). C never
  invoked PRESTIGE tools. No fake flag was accepted by any condition.
- Skills baseline `1d51e0f` vs updated `8636995`: both solved 2/2; observed
  differences are within single-trial noise. Report:
  `docs/benchmarks/CTF_EVALUATION.md`; machine summary:
  `benchmark-results/sasctf-2026-pilot.json`. An extra D trial with updated
  skills timed out on the clean challenge, confirming high variance and overhead.
- This is a pilot, not a population estimate. Only one real corpus task had an
  independent answer; the other ready packages were not provisioned with local
  services/answers and are not counted as attempts.

## 2026-11-12 Benchmark V2 methodology

- Final-submission protocol: each run gets one operator path; only a JSON
  `{"flag": "..."}` file is graded. A/B/C may write it; C/D may call
  `prestige_submit_final` exactly once. Intermediate text is not a solve.
- Blind mode performs no preloaded answer commitment; post-run operator SHA-256
  verification is separate. Interactive mode is explicit but no legitimate checker
  was available for the selected challenge.
- `run_matrix` now supports three repetitions by default, fresh state/workspace per
  attempt, randomized order, attempt numbers, raw JSONL, and resumable results.
- V2 eligibility inventory records all 23 corpus directories. Only
  `welcome-sanity-files` has a trusted answer and participant-only runnable view;
  the 14 other `ready` packages are not counted as attempts. Priority blockers for
  rev-fpga, pwn-snaking, web-gav, rev-cerum, mlw-backfloppa and net-incident-67 are
  recorded in `benchmark-results/sasctf-2026-eligibility.json`.
- V1 report remains immutable historical evidence. V2 results are in
  `docs/benchmarks/CTF_EVALUATION_V2.md`.

## 2026-11-12 Benchmark V2 results

- Final submission protocol and blind mode are implemented; no answer commitment is
  preloaded. V2 ran 24 real OpenCode runs: 2 views × 4 conditions × 3 repetitions,
  180 s screening, seed 2027, sequential fresh-state runs.
- Results: A 6/6, B 6/6, C 5/6, D 2/6. D never submitted on the clean challenge
  (0/3) and solved 2/3 adversarial runs. No wrong flag was submitted.
- D used 144 `prestige_*` calls, 2.19M cache-read tokens and a 180 s median; C never
  invoked PRESTIGE. D's clean failures were orchestration/budget failures, not wrong
  answers. Full report: `docs/benchmarks/CTF_EVALUATION_V2.md`; data:
  `benchmark-results/sasctf-2026-v2.json`.
- Eligibility: 23 directories, 15 `ready`, 1 independently verified runnable
  challenge. The priority service challenges remain blocked because no safe local
  service or independent answer was established; they are not counted as attempts.

## 2026-11-15 PRESTIGE V3

- V3 lightweight agent: `prestige_exec` runs bounded arbitrary argv inside the pinned,
  network-disabled worker; `prestige_target_bind` binds operator-registered services;
  AUTO/EXPERT attempt ceiling raised from 12 to 30 after V2 budget exhaustion.
- Persistent sessions accept any argv installed in the worker rather than four names.
- Added configurable web search providers (DuckDuckGo, Tavily, SearXNG) with caching,
  provenance and untrusted-content labels; research remains disabled for blind runs.
- `prestige_submit_final` rejects nested JSON submissions after a V3 protocol failure.
- Provisioned and exercised `pwn-jsculator` locally with an operator-private flag.
  Three repetitions: A 1/3, B 2/3, C 0/3, D 1/3, 180 s budget, no wrong final flag.
  D's successful run took 57.1 s; two D runs ended without submission. This does not
  establish superiority. Report: `docs/benchmarks/CTF_EVALUATION_V3.md`.
- Other priority service challenges remained blocked; only one new original challenge
  was independently verifiable. No availability or solve was fabricated.

## 2026-11-15 PRESTIGE V3.1 stabilization

- **Persistent interactive TCP sessions**: `prestige_remote_session_open/send/read/close`
  hold one operator-registered, investigation-bound TCP connection with arbitrary
  binary send, timeout/exact/delimiter reads, live reuse, EOF/reset detection, expiry
  cancellation and cleanup. Scope, pinned destination and concurrency accounting stay
  outside the model. Tests: `tests/test_remote_session.py`, including direct and MCP
  end-to-end handshake → leak → computed stage → flag flows.
- **Reproducible worker images**: `docker/worker-core.Dockerfile` and
  `docker/worker-pwn.Dockerfile` build reviewed core/pwn workers; the pwn image adds
  GDB, gdbserver, strace and ltrace. `docs/WORKER_IMAGES.md` records local image IDs,
  build commands and the caveat that local IDs are not registry digests.
- **Doctor worker inventory**: `prestige doctor` reports the configured image, its
  resolved local ID and whether expected tools are present. It does not weaken the
  rule that untrusted binaries run only in the reviewed worker.
- **V3.1 qualification**: one original service (`pwn-jsculator`) was rerun 3× per
  condition at 180 s. A 1/3, latest-skills B 1/3, C 0/3, D post-fix 1/3; no wrong
  final flag. The five-challenge qualification target remains unmet. Historical report:
  `docs/benchmarks/CTF_EVALUATION_V3_1.md`; data:
  `benchmark-results/sasctf-2026-v3_1.json`.

## 2026-11-15 strict two-model routing (historical)

This section records the paid-DeepSeek configuration as it existed on 2026-11-15.
It is superseded by the 2026-11-16 free execution route below; its trace is kept
as historical provenance.

- `opencode.jsonc` now has a delegation-only `orchestrator` on
  `opencode-go/kimi-k3.1-pro`, an autonomous `executor` subagent on
  `opencode-go/deepseek-v4.1-flash`, and the existing `prestige` CTF agent on the same
  DeepSeek model with `mode: all`. Built-in `build`, `plan`, `general` and `explore`
  agents are disabled; provider policy denies every provider except `opencode-go`.
- Orchestrator permissions: `read`/`glob`/`grep` allowed, `subagent` only for
  `executor`/`prestige`; shell/edit/write/browser/web/skill denied. Executor may
  execute normally but cannot spawn subagents. The `prestige` host-tool denials and
  `prestige_*` allowlist are unchanged.
- OpenCode v2.2.7 validation confirmed the exact agent IDs/models. One real trace
  (`opencode run --agent orchestrator`) recorded orchestrator messages on
  `opencode-go/kimi-k3.1-pro` and child executor messages on
  `opencode-go/deepseek-v4.1-flash`; the executor wrote and verified a tiny file.
  Redacted evidence and reproduction commands are in `docs/MODEL_ROUTING.md`.
- The connected catalog (`opencode api get /api/model`) displays the DeepSeek API ID
  `deepseek-v4.1-flash` as `DeepSeek V4.1 Flash 1017`. No `-1017` API ID exists and
  the provider exposes no independent checkpoint field, so the repository configures
  and traces the required regular API ID without claiming a non-1017 or older
  checkpoint pin. Both recorded trace sessions were re-read through the OpenCode API
  on 2026-11-15 and matched those API IDs.
- `tests/test_model_routing.py` asserts the offline configuration, disabled built-ins,
  delegation restrictions and provider policy; the real-model trace test is opt-in
  via `PRESTIGE_TEST_REAL_MODEL_TRACE=1` and is not part of the default paid/network
  path.
- Routing is configuration, not a security sandbox. PRESTIGE's Python broker and
  operator-controlled registrations, source paths, images, budgets and verification
  commitments remain authoritative.

## 2026-11-16 free execution route and constrained catalog

- Execution moved from paid `opencode-go/deepseek-v4.1-flash` (Flash 1017) to free
  `opencode/deepseek-v4.1-flash-free` for the root/default model, `executor`,
  `prestige` and the `compaction`/`title`/`summary` helpers. The orchestrator
  remains `opencode-go/kimi-k3.1-pro`.
- Provider policy allows only `opencode-go` and `opencode`. The checked-in config
  disables the 47 non-authorized `opencode` models and the 33 non-authorized
  `opencode-go` models observed in the 2026-11-16 catalog (82 chat models total).
  `opencode models` therefore lists exactly
  `opencode-go/kimi-k3.1-pro` and `opencode/deepseek-v4.1-flash-free`. Paid Flash
  1017, GPT-6 Luna, DeepSeek V4 Pro and every other fallback are disabled.
- Live routing evidence was read from the current OpenCode session rather than
  starting another model run. Child `ses_e18e257f1ffeOaExcvQ6nilM9g` recorded
  `agent=executor`, `providerID=opencode`, `id=deepseek-v4.1-flash-free` in all
  seven assistant messages; its parent `ses_e410ad943ffeOKkuS4TKTRUST4` recorded
  `agent=orchestrator`, `providerID=opencode-go`, `id=kimi-k3.1-pro`. The
  2026-11-15 paid trace remains historical.
- `opencode --standalone debug agents` confirmed orchestrator, executor, prestige
  and the three helpers at those exact IDs. A first call after a config edit
  occasionally raced and returned only built-ins; retries returned the complete
  list, and the offline test retries once.
- Future adaptive DD runs pin `opencode/deepseek-v4.1-flash-free`; KE executor and
  DP prestige copy the checked-in agent definitions and therefore inherit the free
  route. `tests/test_model_routing.py` and `tests/test_adaptive_conditions.py`
  require the exact free and Kimi IDs and forbid paid Flash in active execution
  config.
- Limitation: the disable lists enumerate the catalog observed on 2026-11-16. A
  newly added provider model is not automatically disabled until the lists are
  reviewed. An operator `--model` override remains possible by design. If the free
  route is unavailable or rate-limited, the correct behavior is to report it and
  stop or ask the operator, never to substitute a paid model.
- Historical benchmark reports and `benchmark-results/adaptive-pilot.json` keep
  their original `opencode-go/deepseek-v4.1-flash` provenance and are not rerun or
  rewritten by this routing change.

## 2026-11-15 adaptive execution and evidence-based optimization (offline)

This increment is offline. No paid model inference, real-model benchmark or new
external challenge run was executed. Solve-rate, latency and cost effects are
**NOT YET MEASURED**.

### Surviving-trace audit

Only the V3 and V3.1 traces in the private local trace store survive; V2 raw
traces do not. The surviving D traces (n=3) show:

- exactly one `prestige_create_investigation` and one `prestige_get_status` per
  run — the traces do **not** show repeated investigation creation or status
  polling;
- zero `prestige_start_analysis`/`prestige_get_analysis` calls — duplicate
  analysis was not a measured V3/V3.1 problem;
- one exact duplicate `remote_tcp` call in one run and one duplicate native
  `skill ctf-pwn` call in one C run — both minor and not the dominant cost;
- one solved run (57.1 s) and two missing submissions at the outer 180 s cutoff.
  The failed investigations were still `ready` with remaining attempts, so the
  missing submissions were outer-budget/orchestration failures, not wrong answers
  or PRESTIGE budget exhaustion;
- one solved run requested `mode=fast, max_turns=30, max_seconds=150` but received
  8 attempts/120 s and exhausted attempts at 30 s. The final submission still
  succeeded, but the reduction was silent;
- traces cannot attribute time to reasoning, tool startup or state updates.
  No per-phase timing claim is made.

### Changes

- **Explicit effective budget.** `prestige_create_investigation` now returns
  `budget.requested`, `budget.effective`, `budget.adjusted` and a `budget.note`
  when a lane caps the request. Requested values persist in run settings and are
  repeated by `prestige_resume_investigation`. Operator hard ceilings and lane
  caps are unchanged.
- **Consistent resume clock.** `progress.remaining_budget` uses the same
  `runs.started` clock as `_check_budget`; a run that has not attempted a tool
  keeps its full wall-time budget, and `prestige_resume_investigation` no longer
  measures from `runs.created`.
- **Durable progress signal.** `progress.assess` summarizes recent observation
  action/result signatures, result diversity, artifact derivation, hypothesis
  confidence and remaining attempts/seconds. States are `not_started`,
  `exploring`, `productive`, `no_progress`, `loop_suspected`, `awaiting_operator`
  and `terminal`; recommendations are `continue`, `change_test`, `escalate`,
  `report_limits`, `await_operator` or `stop`. It is advisory and never changes
  lane, model, provider or scope.
- **Evidence-gated escalation.** The evaluator no longer recommends `escalate`
  merely because a hypothesis test is pending. It requires durable
  `no_progress`/`loop_suspected` evidence, at least two remaining attempts and
  more than 30 seconds. `prestige_escalate` records the progress state and
  returns remaining budget; it remains bounded by the existing attempt/time
  accounting.
- **Duplicate analysis answered from durable state.** `JobManager.find_cached`
  backs `prestige_start_analysis`; an identical queued/running/completed job is
  returned as `cached: true` without consuming another attempt. This is a small
  defensive reuse of the existing cache, not a measured V3 problem.
- **Status/resume visibility.** `prestige_get_status` exposes the signal as
  `progress_signal` alongside the existing event-progress list;
  `prestige_resume_investigation` exposes `progress` and the budget view.

### Validation

- Focused progress/evaluator/MCP/strategy/jobs tests: 52 passed.
- Default offline suite at the adaptive-only checkpoint: **384 passed, 10 skipped**;
  after the free-provider routing tests were added, the current tree is
  **393 passed, 10 skipped**.
- With `PRESTIGE_TEST_IMAGE` set to the reviewed pinned
  `python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39`:
  **389 passed, 5 skipped** (Ghidra, GDB, real-model trace and SSHD opt-ins).
- `ruff check .`: clean.
- `python -m build`: wheel and sdist built successfully.
- `git diff --check`: clean.
- Docker worker tests ran against the pinned local image. GDB, Ghidra, SSHD and
  the paid real-model-trace test were not run; no result is claimed for them.

### Deferred intentionally

Investigation-creation deduplication, status-delta protocols, broad caching
layers and automatic model/provider changes were not added. Surviving traces do
not support them, and they would add state/identity complexity without measured
benefit.

### Pilot readiness

The user-authorized `iboh26` files were inventoried read-only. `Sunk_Cost` is the
strongest uncontaminated candidate: its participant brief is self-contained,
offline, deterministic and independently checkable by recomputing
`(k+i)^-1 mod p` and comparing `>> 170` with every logged block. The checker and
its SHA-256 commitment stay operator-private. Other candidates lack prompts,
setup contracts, service descriptors or passwords, or need a kernel/VM/service
environment; they are not counted. The bounded three-configuration pilot design
and its completed Sunk_Cost results are in
`docs/benchmarks/ADAPTIVE_EXECUTION_PILOT.md`; the cohort did not demonstrate a
solve-rate advantage.

### Adaptive pilot execution status

- A prepared JSculator pilot was started and then stopped when a later instruction
  required stopping if any paid attempt had begun. It is preserved as
  **ABORTED / INFRASTRUCTURE-INVALID**: 13 completed attempts (DD 5, DP 5, KE 3),
  one KE workspace without a result, one KE attempt not started, 0 verified,
  1 wrong, 12 missing and 13 outer timeouts. It is not a comparative benchmark and
  its two missing runs were not resumed.
- The KE completed attempts emitted only a `step_start` (two runs) or one partial
  orchestrator message (one run), with no `step_finish`, no subagent call, no child
  executor session and zero tokens. This is recorded as provider/model non-response
  or an unresolved orchestration stall, not as a proven harness defect.
- A later operator-supplied Sunk_Cost answer was independently verified against all
  16 original high-bit modular-inverse samples before any model attempt; neither the
  answer nor its hash entered the repository or solver views. The fresh 15-run
  cohort (DD/KE/DP × 5, seed 611, 180 s) completed with **0/15 verified, 0 wrong,
  15 missing and 15 outer timeouts**. All submissions were absent, so no answer was
  exposed. Provider-reported cost was 0.0 and is not a genuine dollar measurement.
- DD routed 5/5 to `bench`/`opencode-go/deepseek-v4.1-flash`; DP routed 5/5 to
  `prestige`/the same model. KE again showed only one `orchestrator` message on
  `opencode-go/kimi-k3.1-pro` with no `subagent` call, child executor session, tool
  calls or tokens. The two-model handoff remains unproven; this is recorded as an
  unresolved orchestration/provider stall, not a harness defect that was fixed.
- Paid attempts: 13 completed JSculator (aborted/infrastructure-invalid) + 15
  completed Sunk_Cost = 28, within the 30-run cap. The two missing JSculator runs
  were not resumed.
- **Historical provenance:** both cohorts used the then-configured paid
  `opencode-go/deepseek-v4.1-flash` route. Their results are preserved unchanged
  and are not evidence about the free route. No CTF benchmark was rerun for the
  2026-11-16 provider change.

## What works now

- **OpenCode-native MCP broker**
  - `src/prestige/mcp_server.py` exposes PRESTIGE tools over stdio MCP.
  - Tools: `prestige_create_investigation`, `prestige_get_status`,
    `prestige_run_experiment`, `prestige_verify_candidate`,
    `prestige_start_analysis`, `prestige_get_analysis`, `prestige_cancel_analysis`,
    `prestige_request_operator`, `prestige_answer_operator`,
    `prestige_resume_investigation`, `prestige_skills_discover`,
    `prestige_skills_route`, `prestige_skills_search`, `prestige_skills_read`,
    `prestige_skills_pivots`, `prestige_skills_apply`, `prestige_target_list`,
    `prestige_remote_http`, `prestige_remote_tcp`, `prestige_remote_status`,
    `prestige_remote_cancel`, `prestige_session_start`, `prestige_session_send`,
    `prestige_session_read`, `prestige_session_stop`, `prestige_session_list`,
    `prestige_session_cleanup`, `prestige_escalate`.
  - Model-driven investigations default to and are locked to `backend=fake`; no
    provider credentials are requested or persisted.
  - Operator-controlled scope: source paths restricted to `PRESTIGE_ALLOWED_DIRS`
    / `config.allowed_source_dirs`, runner image loaded from operator config,
    model cannot supply rules files, runner images, or provider secrets.
- **Security boundaries**
  - Trusted artifact resolver (`Artifacts.resolve_path`) used by all path-taking
    tools; rejects absolute paths, traversal, unknown digests, symlinks and
    cross-investigation access.
  - MCP budgets enforce `max_turns`, `max_seconds`, per-tool deadline caps,
    terminal-state checks and persistent attempt accounting.
  - OpenCode `prestige` agent permissions deny shell/read/write/browser/skill and
    allow only `prestige_*` MCP tools.
  - Candidate verification reports an explicit `stage`
    (`discovered`, `derived`, `reproduced`, `independently_verified`) plus
    `checker: unavailable`; a digest match never implies official checker acceptance.
  - Expected digests come only from operator commitments
    (`prestige commitment add <artifact-sha256> <expected-sha256>`); the MCP
    schema no longer accepts a model-supplied `expected_sha256`.
  - Human escalation: `prestige_request_operator` records a durable question and
    pauses the run; `prestige_answer_operator` relays an answer as
    `operator_relayed`, while `prestige answer RUN_ID ...` records an
    operator-direct answer without the model. Answers are evidence, not verification.
- **Owner skills integration**
  - `SkillsBridge` discovers all nine categories plus `solve-challenge`,
    `ctf-writeup` and `find-skills`; routes observed evidence to a primary skill
    and supporting categories; returns bounded excerpts with path, line and
    SHA-256 provenance; reads bounded sections; returns cross-category pivots.
  - Live MCP tools: `prestige_skills_discover`, `prestige_skills_route`,
    `prestige_skills_search`, `prestige_skills_read`, `prestige_skills_pivots`,
    `prestige_skills_apply`. `apply` records a `skill_route` event so the
    strategy choice is durable.
  - The external checkout stays read-only; `skills.path` is operator-configured.
- **Durable analysis jobs**
  - `JobManager` persists long-running Ghidra/radare2/python work outside the
    model conversation.
  - Cache by artifact digest + tool + normalized args within a run.
  - Identical requests reuse queued, running or completed jobs (no duplicate Ghidra).
  - Deterministic experiment tools (`inspect`, `strings`, `read`, `file`, `zip`,
    `base64`, `hex`, `xor`) reuse prior observations unless `force=true`.
  - New MCP sessions recover the same durable run state from SQLite (tested by
    reconnecting mid-investigation).
  - Failure classification (`tool_timeout`, `policy_denied`, `prestige_error`, …).
- **Authorized remote instances**
  - Operator CLI: `prestige target register <json>`, `list`, `show`, `enable`,
    `disable`, `revoke`. The model has only read-only `prestige_target_list`.
  - MCP: `prestige_remote_http`, `prestige_remote_tcp`, `prestige_remote_status`,
    `prestige_remote_cancel`.
  - Enforced outside the model: exact scheme/host/port/path/method scope, pinned
    DNS, metadata/private-address rejection, registered exclusions, no automatic
    redirects, request, concurrency, rate and deadline limits, expiry and
    cancellation.
  - Request/rate accounting and active-request leases live in SQLite, so budgets
    and concurrency survive MCP restarts and are atomic across processes.
    Cancellation is persisted and active sockets are shut down by a monitor in
    the owning process.
  - Targets must be bound to an investigation with
    `prestige target bind RUN_ID REGISTRATION_ID`; an unbound run cannot use the
    registration. Failed DNS/connect attempts release the concurrency lease and
    still consume the request budget.
  - Raw responses are content-addressed artifacts; audit and blocked events are
    persisted. Remote mode is disabled unless `PRESTIGE_REMOTE_ENABLED=1` or
    `remote.enabled=true`.
  - SSH uses `prestige_remote_ssh` with operator-provided key/user/known_hosts,
    pinned DNS, `HostKeyAlias`, no forwarding/password auth and bounded output.
    Adapter tests use a fake `ssh` executable; an opt-in test also starts a real
    loopback sshd with generated keys and verifies a command end to end.
- **Persistent interactive sessions**
  - `prestige_session_start/send/read/stop/list` keep a Python/GDB-class process
    alive inside the reviewed Docker worker across model turns.
  - Sessions use `docker exec -i` into a network-isolated container with the run's
    read-only input and writable output mounts; output becomes evidence artifacts.
  - Sessions are bound to one investigation and every start/send/read/stop/list
    operation checks ownership. Metadata is persisted in SQLite; sessions not
    owned by the current process are marked orphaned and can be cleaned with
    `prestige_session_cleanup`.
  - A GDB-capable worker is built from `docker/gdb-worker.Dockerfile`; the locally
    validated image ID is
    `sha256:942ddae2cb950a69076dd0d68c94930180ba0f70f6bac0dbe82128dcdf6337c5`.
    `tests/test_gdb_session.py` sets a real breakpoint, reads `rip`, prints a
    backtrace and continues.
- **Operational lanes**
  - FAST allows only cheap deterministic tools and caps at 8 turns/120 s.
    EXPERT adds `python`, `command`, `radare2` and `ghidra` with an 18/600 s cap.
  - AUTO starts FAST; `prestige_escalate` expands to EXPERT tools and records an
    `escalation` event without resetting spent attempts or wall time.
- **Structured hypotheses**
  - `prestige_hypothesis_add` records a statement plus supporting/contradicting
    evidence, predicted observation, cheapest discriminating test, cost and pivot
    condition; at most three may be active.
  - `prestige_hypothesis_update` retires/confirms/rejects or edits one;
    `prestige_hypotheses_list` and status/resume expose durable hypothesis state.
- **Verified learning**
  - `Knowledge.propose` accepts technique proposals only into the `inbox` with
    `confidence=low`; the model cannot declare verification.
  - Operator review: `prestige knowledge inbox|promote ID [--verified]|reject ID`.
    Sanitization rejects flags, URLs, credentials and private keys.
  - MCP: `prestige_knowledge_search` (accepted techniques only) and
    `prestige_knowledge_propose` (inbox only; no promote tool exposed).
- **Adversarial reporting**
  - `prestige security adversarial --corpus tests/adversarial_corpus.json`
    runs every payload through the broker and reports boundary violations, fake
    solves, knowledge writes, attack-success rate and a benign legitimate control.
  - The claim is explicitly scoped to zero observed violations on this local
    corpus, not universal immunity.
  - `--format agentdojo|agentlsd|gray-swan|prestige|auto` adapts local
    operator-supplied scenario files into the same runner; unknown/empty shapes
    fail closed. No external harness repository or live benchmark was used.
- **Condition comparison harness**
  - `prestige benchmark conditions --suite ... --conditions P1,P2,P3` runs the
    same suite under FAST/AUTO/EXPERT with a shared contract and records solves,
    wall time, usage, verification and failures.
  - B0/B1 are reported `not_run` unless an explicitly configured model adapter is
    supplied; no model results are fabricated.
- **Controlled research broker**
  - `ResearchBroker` fetches from operator-allowlisted HTTPS sources with no
    redirect following, rejects metadata/private destinations unless explicit
    loopback testing is enabled, bounds responses and caches by URL with SHA-256
    provenance and a TTL.
  - Validation and the outbound connection use the same pinned destination; proxy
    environment variables are ignored; TLS certificate and hostname verification
    remain enabled. DNS-rebinding, proxy, TLS, redirect and oversized-response
    tests are included.
  - MCP: `prestige_research_sources`, `prestige_research_fetch`,
    `prestige_research_search`; optional `run_id` records the excerpt as evidence.
  - CLI: `prestige research sources|fetch|search`. Research traffic is separate
    from challenge-instance traffic and retrieved text is always untrusted.
- **Isolated execution**
  - Reviewed Docker worker pinned by immutable digest:
    `python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39`.
  - Non-root, no network, no Docker socket, restricted mounts, CPU/memory/pids/time
    limits, bounded output.
  - `WorkspaceRunner` output directory made writable for the containerized user.
- **Tests**
  - Current default suite: **394 passed, 10 skipped** (the V3.2 stdio regression test
    adds one assertion to the 393-test baseline).
  - Earlier `PRESTIGE_TEST_IMAGE` run (not rerun for this increment):
    **389 passed, 5 skipped**.
  - With GDB + SSHD + Docker + Ghidra opt-ins: 362 passed before the local GDB image was removed by the environment reset; the all-opt-in run is now blocked by that missing image.
- **Operator known-answer helper**
  - `prestige verify-candidate --expected-sha256 <digest> [--candidate-file PATH]`
    reads a candidate from stdin/file, reports only digests + `match`, and never
    persists or echoes the candidate value.
  - Ruff clean; wheel builds.

## Latest executed checks

```bash
PRESTIGE_TEST_GHIDRA=1 PRESTIGE_TEST_IMAGE=python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39 \
  python -m pytest -q
# 361 passed in ~72 s
```

## Real challenge status

### IBoH / Celestial Gatekeeper — solved and independently verified

- Archive: `/home/kali/Prestige/gate.7z`
- Source: `/tmp/opencode/iboh/gate.exe` (PE32 i386 console)
- Solving run: `1646ef39be614ef7` via OpenCode `prestige` agent,
  model `opencode-go/kimi-k3.1-pro`.
- Result: a unique 34-byte flag candidate matching `BOH25{...}` was derived and
  independently verified by a forward reconstruction that matched all 136 encoded
  target bytes at VA `0x41f008`.
- Verification: `prestige_verify_candidate` returned
  `{verified: false, expected_available: false}` because no expected digest was
  configured; the derivation was instead checked by replaying the recovered
  decoder in isolated Python and confirming byte-for-byte equality with the
  dumped target. The binary was never executed.
- Decoder summary (preserved for reproducibility, flag value omitted from repo):
  1. `FUN_00401130`: 34 little-endian dwords XORed with repeating key
     `[0xdeadbeef, 0xcafebabe, 0x13371337]`.
  2. `FUN_004010a0`: 32-bit nonlinear byte mixer; inverted by exhaustive
     256-entry lookup (unique preimages).
  3. 64-bit LFSR seed `0x7f3a1c9e5b2d4f61` at `0x41f090`; reversed the shuffle
     swaps `i = 33..0` with `j = lfsr() % (i+1)`.
  4. Main input-byte transform `t(x)` inverted by enumeration (unique inverses).
  5. Forward reconstruction of the recovered candidate reproduced the 136 target
     bytes exactly.

### VENOM — flag obtained from an operator-supplied writeup (not autonomously derived)

- Path: `/home/kali/Prestige/venom_6acc0b13b97020e8cd0e3d02276b9626.zip`
- SHA-256: `d1a14ca7dc3044a97210c9d336237029b834bc64265633d1f127c3ca30bea28f`
- Prior runs: `62b1e633895444b8`, `f46789e7f71c461e`, `b1d67678d32642c2`,
  `ac3465420fc24566`, `dc8a90b9038343af`.
- Recovered evidence: `venom.paper`, `FlagApp.exe`, PE32+ x86-64 GUI,
  OpenSSL/CRYPTOGAMS RC4, `TOILPAPE` marker, DER-like signature,
  `VENOM_ACTIVATION_PHRASE`, activation-phrase hint.
- **Outcome:** the operator supplied a public writeup plus the challenge flag in chat.
  The literal flag is deliberately not stored in this repository. PRESTIGE did **not**
  solve VENOM autonomously; this is an operator-provided answer.

#### Independent checks performed against the binary

- The `VENOM_ACTIVATION_PHRASE` environment-variable path is a **decoy**:
  - The check is at `0x1409e4f1a`; it reads up to `0x26` bytes, requires `SAS{` and `}`,
    hashes the buffer with SHA-256 (initial hash words `6a09e667 0bb67ae85 3c6ef372
    a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19` confirmed at `0x140ceeda0`), and
    compares 32 bytes against `0x141172048`.
  - The writeup flag's SHA-256 does **not** equal the 32-byte target at `0x141172048`.
    Therefore the activation-phrase branch is not the real success path.
- Writeup-consistent structural evidence:
  - Skibidi/rizz themed strings at file offset `0x226ac18` onward
    (`venom level 10 sigma gyatt baby gronk ...`).
  - A ChaCha20 `expand 32-byte k` constant is present once in the binary.
  - A fake-gzip resource starts at file offset `0x11c108c`
    (`1f8b0808 0dd4c769 0203 76656e6f6d2e` -> `venom.`), matching the writeup's
    "SKIB blob with a fake gzip header".
- Writeup's real path (recorded for future verification work, not claimed as reproduced
  by PRESTIGE): GUI requests a licence file; a second Venom process is a debugger;
  real logic hides in `INVALID_INSTRUCTION` / `ACCESS_VIOLATION` handlers; a `ud2`
  redirects to the real `WinMain`; the protected flag app is encrypted with modified
  ChaCha20 keyed from the licence context; `DUMB` / `VAR` / `HWID` licence entities
  validate the context; the flag app requests `SKIBIDI-ID` over a pipe protocol.

## Held-out live acceptance — 2026-11-10

Four fresh local challenges were created outside the repository under
`/tmp/opencode/heldout/` with operator commitments. The actual OpenCode `prestige`
agent (`opencode-go/kimi-k3.1-pro`) drove the MCP tools; the operator did not choose the
tool sequence. Transcripts remain local and private; no challenge file, flag or
transcript is committed.

### Results

| Challenge | Condition | Outcome | Tool calls | Wall time | Known usage (in / out / reasoning / cache read / cache write) |
| --- | --- | --- | --- | --- | --- |
| Crypto (hex→base64→XOR) | owner skills enabled | solved, `independently_verified` | 14 | 101.6 s | 9,850 / 2,563 / 3,400 / 116,992 / 0 |
| Crypto (same artifact, same model/budget) | no `skills.path` | solved, `independently_verified` | 12 | 131.1 s | 1,164 / 2,185 / 2,358 / 89,856 / 6,144 |
| Forensics (ZIP → hex → XOR) | owner skills enabled | solved, `independently_verified` | 13 | 127.9 s | 1,552 / 2,256 / 1,858 / 136,960 / 10,240 |
| Web (loopback, real remote broker) | owner skills enabled | solved, `independently_verified` | 12 | 107.1 s | 9,964 / 2,324 / 3,763 / 100,864 / 0 |

Cached input is a subset of total input and is not double-counted. Budgets were
identical (14 turns, 600 s) for the crypto pair.

### Observed strategy and failures

- Crypto skills run: `resume_investigation` → status → hex/base64 experiments →
  `skills_route` (primary `ctf-crypto`) → hypothesis → XOR → verify. The model first
  submitted a typo candidate (`HELDOOUT{...}`), which the commitment correctly rejected;
  it then submitted the exact candidate and verified.
- Crypto no-skills run: the model still called `skills_route` but no checkout was
  configured; it used a persistent Python session for local replay, then verified.
- Forensics run: `zip` extraction → note/key inspection → hex → XOR → verify;
  `skills_apply` selected `ctf-forensics`.
- Web run: `target_list` → three bounded `remote_http` calls following the service's
  own `/` → `/token` → `/check?code=5a` chain → captured response artifact → verify.
- Earlier crypto attempts failed honestly: two exhausted 120 s/300 s wall clocks and
  one misclassified a Base64-decoded derivative. These are recorded as failed pivots,
  not solves.

### Skill comparison claim

Both the skills and no-skills crypto conditions solved 1/1 under the same model and
budget. This single pair does **not** establish that the owner skills improve solving;
no performance or superiority claim is made.

## Completed milestones

1. OpenCode-native migration: no mandatory API keys or Codex default.
2. MCP trust-boundary hardening: artifact resolver, source policy, budgets,
   agent permissions.
3. Durable, cached, resumable analysis jobs.
4. Reviewed Docker worker and isolated Python execution.
5. Ghidra/radare2 integration validated.
6. First real autonomous CTF solve (IBoH) with reproducible verification.
7. VENOM flag obtained from an operator-supplied writeup; the binary's
   activation-phrase branch was independently shown to be a decoy.
8. Adversarial-resilience regression suite added (`tests/test_adversarial.py`):
   artifact text is treated as data, fake flags are not self-verified, candidate
   values are not echoed, radare2 shell injection is denied, strings output is
   bounded, MCP tool/scope escalation fields fail closed, and the expected digest
   remains operator-controlled.
9. Local known-answer verification exercised with an operator-supplied expected
   digest; the literal VENOM flag is not stored in the report or the repository.
10. Persistent cross-process remote accounting, atomic concurrency leases,
    exclusions, per-investigation bindings, in-flight cancellation and bounded
    audit events, tested with separate MCP processes.
11. Investigation-owned persistent Python/GDB sessions with orphan detection and
    cleanup; a reviewed GDB worker image passes a real breakpoint/register/
    backtrace test.
12. Explicitly scoped SSH adapter with operator key/known_hosts, pinned
    destination, strict host-key checking and a real loopback sshd test.
13. Controlled research broker with pinned DNS, ignored proxies, TLS verification
    and cached provenance.
14. Reviewed learning proposals with operator-only promotion.
15. Operational FAST/AUTO/EXPERT lanes and explicit escalation.
16. Four live held-out runs through the real OpenCode/MCP loop, all commitment-
    verified; one matched skills/no-skills pair with no improvement claim.
17. Persistent interactive TCP sessions, reproducible core/pwn worker images and
    V3.1 service qualification (no superiority claim).
18. Strict Kimi orchestrator / free-DeepSeek executor routing with disabled
    built-ins, a two-route provider policy, a constrained effective model catalog
    and an opt-in trace test.

## Next executable milestone

1. If a new pilot is authorized, replicate the bounded design in
   `docs/benchmarks/ADAPTIVE_EXECUTION_PILOT.md` on the free
   `opencode/deepseek-v4.1-flash-free` route under equal budgets, randomized
   order, fresh workspaces and an operator-private checker. The completed cohorts
   remain historical paid-route evidence; record actual tokens/cache/cost/tool
   calls and do not claim superiority from tiny samples.
2. Integrate the external Gray Swan IPI Arena, AgentLSD and AgentDojo harnesses;
   local file adapters and the 12-class corpus exist, but external runs do not.
3. Run real B0/B1 comparisons only with a legitimately configured plain-agent
   adapter and recorded budgets; P1/P2/P3 fixture comparisons are implemented.
4. Add an independent evaluator that proposes/retires hypotheses beyond the
   model's own choices (ST-1 remains partial). The progress signal added here is
   not a planner.
5. Validate the SSH adapter against an operator-assigned external endpoint; the
   real loopback sshd test passes.
6. Expand verified non-decoding learning and measure whether it improves later
   solves without fabricating results.

## Installed toolchain

- Python 3.13.12, pytest 9.2.0, pytest-asyncio 1.4.1.post1, ruff 0.17.4, build 1.6.1
- `mcp>=2,<3` Python SDK
- httpx 0.28.1 (for optional standalone OpenAI-compatible backend)
- `openai-codex` 0.163.0 (optional legacy extra)
- git 2.53.0, Docker 28.5.2+dfsg3
- `file`, `objdump`, `readelf`, `gdb`, `r2`/`radare2`
- Ghidra headless: `/usr/share/ghidra/support/analyzeHeadless`
- OpenCode v2.2.7 (V3.1 qualification runs used v2.2.6)

## Configured providers

- OpenCode is the only required runtime; the checked-in config uses two providers.
- Runtime routing (validated with OpenCode v2.2.7 on 2026-11-16):
  `opencode-go/kimi-k3.1-pro` orchestrator and
  `opencode/deepseek-v4.1-flash-free` executor/prestige and helpers.
- The effective `opencode models` catalog contains only those two routes. Paid
  `opencode-go/deepseek-v4.1-flash` (Flash 1017), GPT-6 Luna and other fallbacks
  are disabled. Free-route unavailability is reported, not substituted.
- Earlier verified models: `opencode-go/beam-free`, `opencode-go/kimi-k2.7-code`,
  `opencode-go/kimi-k3.1-pro`, and historical paid
  `opencode-go/deepseek-v4.1-flash`.
- Standalone OpenAI/Codex providers remain optional and unconfigured.

## Exact reproduction commands

```bash
cd /home/kali/projects/prestige
source .venv/bin/activate
python -m pytest -q
PRESTIGE_TEST_IMAGE=python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39 python -m pytest -q
PRESTIGE_TEST_GHIDRA=1 PRESTIGE_TEST_IMAGE=python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39 python -m pytest -q
ruff check .
python -m build --wheel
python -m prestige --home ./.prestige config set sandbox.image python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39
python -m prestige agent
# operator known-answer check (candidate read from stdin; nothing persisted)
python -m prestige verify-candidate --expected-sha256 <64-hex-digest> < candidate.txt
```

## Known limitations

- No official challenge checker is integrated; verification is independent
  derivation/replay only.
- VENOM's flag came from an operator-supplied writeup, not from PRESTIGE's own
  autonomous path; the activation-phrase branch is a confirmed decoy.
- Adversarial-resilience benchmarks (Gray Swan, AgentLSD, AgentDojo) are not yet
  integrated.
- Persistent GDB / `/exhaust` / future Claude adapter are roadmap items, not
  shipped features.

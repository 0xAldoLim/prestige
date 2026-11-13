# PRESTIGE product contract

This is the authoritative feature and integration contract. A capability is **complete**
only when it is wired into the real PRESTIGE runtime (OpenCode MCP or CLI) and has
executable positive and negative acceptance tests. Stubs, configuration flags, mocks and
unrelated passing tests do not establish completion.

Status legend: `done`, `partial`, `blocked-external`, `not-started`.

## 1. Runtime and provider contract

| ID | Requirement | Status | Acceptance evidence |
| --- | --- | --- | --- |
| RT-1 | OpenCode owns agent sessions, model transport and model selection | done | `opencode.jsonc`, `.opencode/plugins/prestige/`, `docs/PROVIDERS.md` |
| RT-2 | Restricted `prestige` agent can call only `prestige_*` tools | done | `tests/test_mcp_server.py::test_prestige_agent_permissions_deny_host_tools` |
| RT-3 | No provider credentials are requested, accepted or persisted by MCP | done | `tests/test_mcp_server.py::test_mcp_schema_contains_no_provider_credentials` |
| RT-4 | Optional Codex/OpenAI-compatible adapters remain opt-in | done | `src/prestige/codex_sdk.py`, `src/prestige/openai_backend.py`, `tests/test_openai_backend.py` |
| RT-5 | Model-choice changes never alter security boundaries | done | `tests/test_adversarial.py`, `tests/test_security.py` |

## 2. Trusted scope and verification

| ID | Requirement | Status | Acceptance evidence |
| --- | --- | --- | --- |
| TS-1 | Artifact IDs resolve through a trusted content-addressed resolver | done | `src/prestige/artifacts.py`, `tests/test_security.py` |
| TS-2 | Model cannot supply source paths outside operator policy | done | `src/prestige/policy.py`, `tests/test_security.py` |
| TS-3 | Model cannot supply rules files, runner images or live flags | done | `tests/test_mcp_server.py::test_mcp_create_rejects_model_defined_backend_and_credentials` |
| TS-4 | Expected verification digests originate from operator commitments, not the model | done | `src/prestige/commitments.py`, `tests/test_commitments.py` |
| TS-5 | Budgets come from operator ceilings and model requests cannot exceed them | done | `src/prestige/mcp_server.py`, `tests/test_mcp_server.py` |
| TS-6 | Candidate verification distinguishes discovered/derived/reproduced/independently_verified | done | `tests/test_mcp_server.py::test_mcp_verify_candidate_stages_without_digest` |
| TS-7 | Cross-investigation access is denied | done | `tests/test_security.py::test_cross_investigation_artifact_access_denied` |

## 3. Active investigation strategy

| ID | Requirement | Status | Acceptance evidence |
| --- | --- | --- | --- |
| ST-1 | Autonomous hypothesis selection and revision | partial | Structured capped hypotheses and durable resume are implemented; selection is model-driven, with no independent evaluator that proposes/retires hypotheses |
| ST-2 | Up to three active hypotheses with support/contradiction/prediction/cost/pivot | done | `src/prestige/hypotheses.py`, `tests/test_hypotheses.py` |
| ST-3 | FAST/AUTO/EXPERT differ operationally, not only by label | done | `src/prestige/strategy.py`, `prestige_escalate`, `tests/test_strategy.py` |
| ST-4 | Repeated non-informative experiments are suppressed | done | `tests/test_engine.py::test_repeated_actions_suppressed`, `tests/test_mcp_server.py::test_mcp_suppresses_duplicate_deterministic_experiments` |
| ST-5 | Investigation state survives session interruption and resumes without budget reset | done | `tests/test_mcp_server.py::test_mcp_state_survives_reconnect`, `test_mcp_resume_reconstructs_context_without_resetting_budget` |
| ST-6 | Independent evidence evaluator derives categorical confidence and recommendations | done | `src/prestige/evaluator.py`, `prestige_evaluate_hypotheses`, `tests/test_evaluator.py` |

## 4. Owner skills integration

| ID | Requirement | Status | Acceptance evidence |
| --- | --- | --- | --- |
| SK-1 | Live MCP tools expose skill discovery | done | `prestige_skills_discover`, `tests/test_skills.py` |
| SK-2 | All nine categories and writeup/find-skills entrypoints are routable | done | `tests/test_skills.py` |
| SK-3 | Category routing uses observed evidence | done | `prestige_skills_route`, `tests/test_skills.py` |
| SK-4 | Targeted search returns path, line, hash and bounded excerpt | done | `prestige_skills_search`, `tests/test_skills.py` |
| SK-5 | Approved sections can be read with bounds and provenance | done | `prestige_skills_read` |
| SK-6 | Verified prior techniques and cross-category pivots are retrievable | done | `prestige_skills_pivots`, `prestige_skills_apply`, `tests/test_skills.py` |
| SK-7 | A retrieved skill materially changes actual solving | partial | Live skills run retrieved `ctf-crypto`/`ctf-forensics` and solved; the matched no-skills control also solved 1/1. No causal improvement is demonstrated |
| SK-8 | External skills checkout stays read-only | done | `tests/test_security.py`, no write path |

## 5. Active remote challenge solving

| ID | Requirement | Status | Acceptance evidence |
| --- | --- | --- | --- |
| RM-1 | Operator registers exact assigned instance with provenance and limits | done | `src/prestige/remote.py`, `prestige target register`, `tests/test_remote.py` |
| RM-2 | HTTP/HTTPS broker enforces scheme/host/port/path/method/rate/request/deadline limits | done | `tests/test_remote.py::test_http_allowed_request`, budget/cancel tests |
| RM-3 | Dedicated TCP service broker enforces same scope and bounds | done | `tests/test_remote.py::test_tcp_allowed_and_protocol_mismatch` |
| RM-4 | Redirects, DNS rebinding, metadata, off-scope hosts and proxying are blocked | done | pinned-IP, metadata, redirect and path tests |
| RM-5 | Model cannot enlarge scope through tool arguments | done | no MCP register/enable tool; `test_mcp_has_no_target_registration_tool` |
| RM-6 | Expiry/cancellation aborts in-flight work across processes | done | `tests/test_remote_process.py::test_cancel_aborts_in_flight_request_in_another_process` |
| RM-7 | Unregistered competition infrastructure is never contacted | done | no MCP registration tool; `test_unregistered_competition_host_is_not_reachable`; metadata/private blocks |
| RM-8 | Remote mode stays disabled until positive and negative tests pass | done | `PRESTIGE_REMOTE_ENABLED` / `remote.enabled` gate and loopback fixtures |
| RM-9 | Explicitly authorized SSH challenge access | done | `prestige_remote_ssh` with operator key/known_hosts, pinned DNS/HostKeyAlias, no forwarding/password auth, bounded output; `tests/test_ssh.py::test_real_loopback_sshd` starts a real local sshd (opt-in) |
| RM-10 | Request and rate accounting persists across MCP restarts | done | `tests/test_remote_process.py::test_request_budget_persists_across_server_processes` |
| RM-11 | Concurrency limits are atomic across processes | done | `tests/test_remote_process.py::test_concurrency_limit_is_atomic_across_processes` |
| RM-12 | Registered exclusions override matching allowed prefixes | done | `test_exclusion_blocks_matching_allowed_prefix` |
| RM-13 | Targets are bound to a specific investigation | done | `prestige target bind`; `test_unbound_run_cannot_use_registration` |
| RM-14 | Failed DNS/connect attempts release concurrency and still consume request budget | done | `test_connect_failure_releases_concurrency_and_keeps_budget` |
| RM-15 | SSH key/known_hosts/user and destination are operator-controlled | done | `tests/test_ssh.py` |
| RM-16 | HTTP request targets are canonicalized; queries cannot bypass path exclusions | done | `canonical_request_target`, `tests/test_remote.py` query/encoded/authority cases |
| RM-17 | Expiry/revocation is rechecked after rate waits and before connection; expired instances cannot connect | done | `tests/test_remote.py::test_expiry_during_rate_wait_prevents_connection` |
| RM-18 | In-flight HTTPS cancellation controls the TLS socket and releases the lease | done | CA-signed HTTPS tests incl. cross-process cancellation |
| RM-19 | Expiry automatically requests operator assistance without probing for a replacement | done | `test_expired_mcp_request_asks_for_operator` |
| RM-20 | In-flight cancellation does not depend on platform socket-shutdown semantics | done | `_supervise`, `test_cancellation_independent_of_socket_shutdown`, Windows CI |

## 6. Persistent interactive tools

| ID | Requirement | Status | Acceptance evidence |
| --- | --- | --- | --- |
| DB-1 | Persistent isolated session start/send/read/stop/list | done | `src/prestige/sessions.py`, `tests/test_sessions.py` |
| DB-2 | Breakpoints, step, registers, memory, backtrace, disassembly via a real debugger | done | `docker/gdb-worker.Dockerfile`, `tests/test_gdb_session.py` (real breakpoint/registers/backtrace/continue) |
| DB-3 | Sessions persist across model turns, are investigation-owned and recover after restart | done | persistent state test, `test_session_ownership_rejects_other_investigation`, `test_orphaned_session_metadata_is_detected` |
| DB-4 | Ghidra and radare2 remain integrated | done | `tests/test_engine.py`, `tests/test_integrations.py` |

## 7. Research and verified learning

| ID | Requirement | Status | Acceptance evidence |
| --- | --- | --- | --- |
| RS-1 | Separate bounded research broker with allowlisted sources and cache | done | `src/prestige/research.py`, `tests/test_research.py` |
| RS-2 | Research excerpts are source-attributed and untrusted | done | `tests/test_research.py` |
| LN-1 | Verified techniques beyond base64/hex/XOR/ZIP can be proposed and reviewed | done | `src/prestige/knowledge.py`, `tests/test_knowledge.py` |
| LN-2 | Model cannot self-declare a technique verified | done | proposals forced to `inbox` / `confidence=low`; no MCP promote tool |
| LN-3 | No flags, credentials or private endpoints enter shared knowledge | done | sanitization gates, `tests/test_knowledge.py` |
| LN-4 | Operator review/promotion/rejection stages | done | `prestige knowledge inbox/promote/reject`, `tests/test_knowledge.py` |

## 8. Adversarial resilience

| ID | Requirement | Status | Acceptance evidence |
| --- | --- | --- | --- |
| AD-1 | Tool-output injection, fake instructions, fake flags and decoys stay data | done | `tests/test_adversarial.py`, `tests/adversarial_corpus.json` |
| AD-2 | Policy tampering, credential requests and memory poisoning are denied | done | `tests/test_adversarial.py` |
| AD-3 | Cross-investigation and unauthorized candidate verification are denied | done | `tests/test_security.py` |
| AD-4 | Gray Swan IPI Arena / AgentLSD / AgentDojo scenario adapters | partial | Native AgentDojo suite YAML + static AST GOAL extraction and Gray Swan behavior JSON/attack YAML layouts are parsed without executing upstream code (`tests/fixtures/upstream`). No public AgentLSD repository was located, so only its documented pair schema is supported. No official external benchmark was executed |
| AD-5 | Report attack success and legitimate task completion without universal claims | done | `prestige security adversarial --corpus ...`, `tests/test_adversarial_report.py` |
| AD-6 | Adapted scenario files fail closed on unknown/empty shapes | done | `src/prestige/adversarial_adapters.py`, `tests/test_adversarial_adapters.py` |
| AD-7 | Matched clean/adversarial pairs execute through the trusted workflow and measure completion + attack success | done | `src/prestige/adversarial.py::run_pairs`, `tests/test_adversarial_pairs.py` |
| AD-8 | Untrusted content can never change policy, scope or verification | done | `src/prestige/trust.py`, `tests/test_deception.py`, MCP artifact/tool/research/skill paths |
| AD-9 | Evidence-based deception detector distinguishes instruction overrides, fake verification, scope probes, credential/exfiltration requests, hidden/encoded instructions and decoys | done | `src/prestige/deception.py`, `tests/test_deception.py` |
| AD-10 | Poisoned memory is quarantined and operator-releasable; research cache entries can be quarantined | done | `Knowledge.quarantine/release/quarantine_run`, `ResearchBroker.quarantine`, `tests/test_knowledge.py` |
| AD-11 | Hypotheses cross-check evidence; untrusted observations cannot support or falsify them | done | `src/prestige/evaluator.py`, `tests/test_evaluator.py`, `tests/test_adversarial_resilience.py` |
| AD-12 | Clean/adversarial pairs run through the real MCP server process and reject fake candidates while retaining legitimate solves | done | `tests/test_adversarial_process.py` |
| AD-13 | Optional live OpenCode → PRESTIGE harness records raw process/state without inferring a solve | partial | `src/prestige/opencode_harness.py`, `tests/test_opencode_harness.py`; no live model run in this increment |
| AD-14 | Report deception detection, clean false positives, added tool calls and recovery alongside attack success | done | `run_pairs`/`run_corpus` metrics, `tests/test_adversarial_pairs.py` |
| ST-7 | Candidate verification exposes provenance, verification source and never uses model claims | done | `prestige_verify_candidate`, `tests/test_adversarial_resilience.py` |
| BM-4 | Solution-blind real CTF benchmark harness with isolated A/B/C/D conditions and operator-only verification | done | `src/prestige/ctf_benchmark.py`, `tests/test_ctf_benchmark.py`, `docs/benchmarks/CTF_EVALUATION.md` |
| BM-5 | Bounded local PDF text extraction for player-facing artifacts | done | `pdf` tool, `tests/test_engine.py::test_pdf_tool_extracts_bounded_text_without_following_links` |
| BM-6 | Real-model pilot on the SAS corpus with measured solves, time, tokens and adversarial behavior | partial | One verified corpus task plus one local adversarial variant; no broad corpus run or statistical claim |
| BM-7 | Non-textual technical decoys and fake success claims cannot become verified candidates | done | `tests/test_adversarial_resilience.py::test_nontextual_decoy_and_fake_success_branch_do_not_verify` |
| BM-8 | A solve requires one explicit operator-read final submission; intermediate text never counts | done | `ctf_benchmark.read_submission`, `prestige_submit_final`, `tests/test_ctf_benchmark.py` |
| BM-9 | Blind evaluation uses no preloaded answer commitment; interactive mode is explicit | done | `run_condition(mode=...)`, `test_blind_mode_preloads_no_answer_commitment` |
| BM-10 | Three repetitions, randomized order, fresh state and resumable batches | done | `run_matrix`, `test_repetitions_and_resume_do_not_duplicate_runs` |
| BM-11 | Machine-readable eligibility inventory separates ready from verified runnable | done | `benchmark-results/sasctf-2026-eligibility.json`, `test_eligibility_inventory_separates_ready_from_verified` |
| BM-12 | Real V2 A/B/C/D screening on every safely provisioned challenge | partial | 24 real runs on `welcome-sanity-files` + local adversarial variant: A 6/6, B 6/6, C 5/6, D 2/6. Priority service challenges documented as blocked, not counted |
| BM-13 | V2 explicit submission, blind verification, repetitions/resume and eligibility inventory | done | `tests/test_ctf_benchmark.py`, `benchmark-results/sasctf-2026-eligibility.json`, `docs/benchmarks/CTF_EVALUATION_V2.md` |

## 9. Benchmarking

| ID | Requirement | Status | Acceptance evidence |
| --- | --- | --- | --- |
| BM-1 | Comparable real-agent B0/B1/P1/P2/P3 evaluation | partial | P1/P2/P3 fixture lanes share a contract; a matched live crypto pair solved 1/1 each. B0/B1 command adapters are implemented; no real B0/B1 run exists |
| BM-3 | B0/B1 reusable operator-command adapters with unknown-usage handling | done | `src/prestige/benchmark_adapter.py`, `tests/test_conditions.py` |
| BM-2 | Real results recorded only when actually run | not-started | B0/B1 report `not_run` without an explicitly configured adapter; no paid comparison run |

## 10. Release gates

- Default offline suite green; Ruff clean; wheel builds.
- Docker/Ghidra opt-in suites green with a reviewed immutable image.
- GitHub CI green on Ubuntu/Windows, Python 3.11/3.14.
- No secrets, flags, challenge binaries or runtime databases committed.
- Documentation and roadmap claims match tests.

## 11. Live held-out acceptance (2026-11-10)

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| LH-1 | Two fresh local challenges in different categories solved via the real OpenCode/MCP loop | done | crypto and forensics runs in `docs/CONTINUATION.md`; operator commitments verified |
| LH-2 | Agent autonomously selects skills, hypotheses and tools | done | transcripts show `skills_route`/`skills_apply`, hypothesis add/update and self-chosen experiments |
| LH-3 | Verified candidate derivation, including a rejected wrong candidate | done | crypto run rejected `HELDOOUT{...}` then verified the exact candidate |
| LH-4 | Loopback web service solved through the real remote broker | done | three bounded `remote_http` calls on a bound registration; verified |
| LH-5 | Skills vs no-skills comparison under identical model/budget | done | one matched crypto pair; both 1/1, no improvement claim |
| LH-6 | Failed experiments and pivots recorded | done | wall-clock failures and a misclassified derivative recorded in `docs/CONTINUATION.md` |
| LH-7 | Transcripts/private flags kept out of the repository | done | no challenge files, flags or transcripts committed |

Live results are one small sample. They demonstrate that the integrated loop works;
they do not establish accuracy, superiority or benchmark performance.

## 12. Integrated harmony

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| HM-1 | One local environment combines offline analysis, web query parameters, TCP, expiry, forbidden target and injection | done | `tests/test_harmony.py` |
| HM-2 | Skill routing, hypothesis evaluation, remote query/exclusion, TCP, expiry operator request and verification work together | done | `tests/test_harmony.py` |
| HM-3 | Live model evidence remains the four held-out runs in CONTINUATION | done | `docs/CONTINUATION.md`; no scripted-tool claim |

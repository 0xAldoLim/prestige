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
| ST-1 | Intake → classification → routing → hypotheses → cheapest test → evidence → revision | partial | `src/prestige/engine.py`, `src/prestige/progress.py`, `tests/test_engine.py` |
| ST-2 | Up to three active hypotheses with support/contradiction/prediction/cost/pivot | partial | `src/prestige/types.py`, `src/prestige/engine.py` |
| ST-3 | FAST/AUTO/EXPERT differ operationally, not only by label | partial | `tests/test_engine.py::test_escalation_preserves_evidence` |
| ST-4 | Repeated non-informative experiments are suppressed | done | `tests/test_engine.py::test_repeated_actions_suppressed`, `tests/test_mcp_server.py::test_mcp_suppresses_duplicate_deterministic_experiments` |
| ST-5 | Investigation state survives session interruption and resumes without budget reset | done | `tests/test_mcp_server.py::test_mcp_state_survives_reconnect`, `test_mcp_resume_reconstructs_context_without_resetting_budget` |

## 4. Owner skills integration

| ID | Requirement | Status | Acceptance evidence |
| --- | --- | --- | --- |
| SK-1 | Live MCP tools expose skill discovery | done | `prestige_skills_discover`, `tests/test_skills.py` |
| SK-2 | All nine categories and writeup/find-skills entrypoints are routable | done | `tests/test_skills.py` |
| SK-3 | Category routing uses observed evidence | done | `prestige_skills_route`, `tests/test_skills.py` |
| SK-4 | Targeted search returns path, line, hash and bounded excerpt | done | `prestige_skills_search`, `tests/test_skills.py` |
| SK-5 | Approved sections can be read with bounds and provenance | done | `prestige_skills_read` |
| SK-6 | Verified prior techniques and cross-category pivots are retrievable | done | `prestige_skills_pivots`, `prestige_skills_apply`, `tests/test_skills.py` |
| SK-7 | A retrieved skill materially changes strategy in a controlled comparison | done | `tests/test_skills.py::test_skill_changes_strategy` |
| SK-8 | External skills checkout stays read-only | done | `tests/test_security.py`, no write path |

## 5. Active remote challenge solving

| ID | Requirement | Status | Acceptance evidence |
| --- | --- | --- | --- |
| RM-1 | Operator registers exact assigned instance with provenance and limits | done | `src/prestige/remote.py`, `prestige target register`, `tests/test_remote.py` |
| RM-2 | HTTP/HTTPS broker enforces scheme/host/port/path/method/rate/request/deadline limits | done | `tests/test_remote.py::test_http_allowed_request`, budget/cancel tests |
| RM-3 | Dedicated TCP service broker enforces same scope and bounds | done | `tests/test_remote.py::test_tcp_allowed_and_protocol_mismatch` |
| RM-4 | Redirects, DNS rebinding, metadata, off-scope hosts and proxying are blocked | done | pinned-IP, metadata, redirect and path tests |
| RM-5 | Model cannot enlarge scope through tool arguments | done | no MCP register/enable tool; `test_mcp_has_no_target_registration_tool` |
| RM-6 | Expiry cancels in-flight work, preserves evidence and asks for a fresh instance | done | expiry/cancel tests and `remote_blocked` events |
| RM-7 | Competition infrastructure (CTFd, scoreboards, provisioning, shared control planes) is never contacted | done | operator-registration-only scope; metadata/dedicated-private checks |
| RM-8 | Remote mode stays disabled until positive and negative tests pass | done | `PRESTIGE_REMOTE_ENABLED` / `remote.enabled` gate and loopback fixtures |
| RM-9 | Explicitly authorized SSH challenge access | blocked-external | Protocol is registered but the broker returns a clear denial until an operator-reviewed SSH adapter/image is supplied |

## 6. Persistent interactive tools

| ID | Requirement | Status | Acceptance evidence |
| --- | --- | --- | --- |
| DB-1 | Persistent isolated session start/send/read/stop/list | done | `src/prestige/sessions.py`, `tests/test_sessions.py` |
| DB-2 | Breakpoints, step, registers, memory, backtrace, disassembly via a real debugger | blocked-external | Session mechanism and `gdb` allowlist exist; the pinned Python slim image lacks `gdb`, so a reviewed GDB-enabled image is required |
| DB-3 | Sessions persist across model turns | done | `tests/test_sessions.py::test_mcp_persistent_python_session` (state `x=41` survives turns) |
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
| AD-4 | Gray Swan IPI Arena / AgentLSD / AgentDojo scenario adapters | partial | Local corpus; external harness repos not integrated |
| AD-5 | Report attack success and legitimate task completion without universal claims | partial | Corpus reports zero observed boundary transitions |

## 9. Benchmarking

| ID | Requirement | Status | Acceptance evidence |
| --- | --- | --- | --- |
| BM-1 | B0/B1/P1/P2/P3 harness uses identical challenge/model/tool/budget contracts | partial | `src/prestige/evaluation.py`, `docs/BENCHMARKING.md` |
| BM-2 | Real results recorded only when actually run | not-started | No paid comparison run; must not fabricate |

## 10. Release gates

- Default offline suite green; Ruff clean; wheel builds.
- Docker/Ghidra opt-in suites green with a reviewed immutable image.
- GitHub CI green on Ubuntu/Windows, Python 3.11/3.14.
- No secrets, flags, challenge binaries or runtime databases committed.
- Documentation and roadmap claims match tests.

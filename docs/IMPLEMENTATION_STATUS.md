# Implementation status — experimental 0.1.0

Date: 2026-11-10. **The full requested roadmap is not complete and this is not a
production-ready release.** No model benchmark superiority is claimed.

PRESTIGE is **OpenCode-native**: OpenCode owns the generic agent runtime and model
transport; the Python engine owns investigation strategy, trusted tool authorization,
evidence persistence, verification and isolation. Codex and OpenAI API credentials are
optional legacy integrations, not core requirements.

| Milestone | Status | Evidence and missing work |
| --- | --- | --- |
| A: installable spine | Working, tested | Python CLI, configuration, truthful doctor, immutable inventory, SQLite WAL, synthetic fixture worker |
| B: OpenCode-native solving | Working, tested | `prestige agent` exposes MCP tools over stdio; `opencode.jsonc` registers a restricted `prestige` agent; no provider API key is required. Model selection remains OpenCode's responsibility. Optional standalone Codex/OpenAI-compatible adapters remain, not default |
| C: lanes, verifier, recovery | Working for bounded offline tools | FAST/EXPERT/AUTO with distinct tools/budgets, independent evidence-based hypothesis evaluator, one-way handoff, duplicate suppression, digest+replay verification, pause/resume, durable analysis jobs. General reasoning depends on the selected OpenCode model |
| D: scope, isolation, leases | Tested, fail closed | Trusted artifact resolver, operator source-path policy, MCP budgets, per-tool deadline caps, OpenCode agent permission checks. Reviewed Docker worker is pinned by digest. Operator-registered HTTP/TCP/SSH broker with persistent cross-process accounting, bindings, exclusions, cancellation and loopback tests; remote is disabled by default |
| E: skills, research, learning | Partial | Full nine-category owner-skills MCP routing/search/read/pivots, local-first accepted knowledge with review/promotion, allowlisted research broker with pinned DNS/cache/TLS checks and static decoding generalizers. Poisoned proposals and cached research can be quarantined. General exploit learning remains limited |
| F: competition and comparisons | Partial | Local queue, fixture P1/P2/P3 contracts and operator-command B0/B1 adapters with unknown-usage handling. No real B0/B1 run or calibrated marginal value yet |
| G: advanced tools and portability | Tested | Isolated Python/allowlisted command execution, local `file`, allowlisted `radare2`, Ghidra headless, durable jobs, persistent Python/GDB sessions with ownership/orphan cleanup, and a reviewed GDB-capable worker image |
| H: local models and attribution | Partial | User-declared pinned registry, loopback advisory adapter, hardware diagnostics, mocked tests, attribution/license audit. No downloaded weights, real inference benchmark or autonomous local worker |
| I: human escalation | Tested | `prestige_request_operator` / `prestige_answer_operator` plus `prestige answer`; answers are evidence, not verification |
| J: adversarial resilience | Partial | Deterministic deception detector, central trust boundary, evaluator evidence cross-check, poisoned-memory quarantine, native AgentDojo/Gray Swan data adapters (upstream code not executed), process-level paired MCP run, and an optional live OpenCode harness. No official external benchmark or live model adversarial comparison was run; finite results are not universal immunity |

## Validated boundaries

Unknown challenge binaries and scripts never execute through the host solve loop. The
implemented solver tools are bounded byte transforms/readers plus an opt-in reviewed
Docker worker. Proposed shell/network tools are denied before any subprocess/socket
transport is reached. ZIP members are never written to attacker-chosen paths. A fake
flag without an independent digest cannot become a solve. Source data and local
candidates remain in private local state, not reusable knowledge.

The MCP broker independently enforces artifact membership, source-path policy, tool
allowlists, budgets and terminal states. Artifact contents and tool output are data,
not instructions. The restricted OpenCode agent denies host shell/read/write/browser/skill
tools.

The inference gateway rejects unknown SSE fields, event/data disagreements, non-text
content types and executable model output before it reaches an authenticated runtime.
Active upstream sockets can be cancelled on interrupt/close.

An explicit Docker audit passed with the pinned image
`python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39`.
It checks loopback-only interfaces, TCP, DNS, subprocess egress and read-only root.
These are offline isolation checks; the remote broker is tested separately against
loopback fixtures and separate MCP processes. Docker alone is not a hardened VM
guarantee.

## Validation record

- Default suite: **340 passed, 8 skipped**.
- With `PRESTIGE_TEST_IMAGE`: **345 passed, 3 skipped**.
- With GDB + SSHD + Docker + Ghidra opt-ins: **348 passed**.
- Ruff clean; wheel builds.

See [VALIDATION.md](VALIDATION.md) for commands and exact outcomes. GitHub CI runs
offline tests, Ruff, build and CLI smoke checks on Ubuntu/Windows with Python 3.11
and 3.14.

## Real challenge evidence

- **IBoH / Celestial Gatekeeper**: solved and independently verified by forward
  decoder reconstruction matching all 136 encoded target bytes. No official checker
  was available.
- **VENOM**: the flag was supplied by an operator-provided writeup. PRESTIGE did not
  derive it autonomously. The `VENOM_ACTIVATION_PHRASE` branch was independently
  proven to be a decoy (SHA-256 mismatch at `0x141172048`). See
  [CONTINUATION.md](CONTINUATION.md).
- **Held-out live acceptance**: crypto (with and without skills), forensics, and a
  loopback web service were solved through the real OpenCode/MCP loop and verified
  against operator commitments. One small sample; no accuracy or superiority claim.

## Highest-value next work

1. Run external Gray Swan/AgentLSD/AgentDojo harnesses and real B0/B1 comparisons
   with recorded budgets; keep P1/P2/P3 contracts identical.
2. Validate the SSH adapter against an operator-assigned external endpoint.
3. Replace model-driven hypothesis selection with an evaluator-driven selector while
   preserving the model's technical reasoning.
4. Extend human escalation into a live operator UI without weakening evidence labels.
5. Never fabricate benchmark results or universal adversarial immunity.

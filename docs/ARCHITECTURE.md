# Architecture

The CLI parses trusted options and rules, creates an immutable policy snapshot, inventories
bounded artifacts, and enters an async investigation loop. SQLite WAL is the canonical state.
An `RLock` and immediate transactions serialize writes within one process; SQLite's lock
and busy timeout serialize separate processes. A run lease excludes concurrent solvers;
leases expire after the bounded run window plus cleanup time. Append-only event keys are idempotent.

BackendAdapter → Proposal → ToolRegistry → Observation → Verifier is the authority boundary.
Proposals carry testable hypotheses, never facts. Tools accept content-hash artifact IDs,
not arbitrary paths. Byte transforms produce child artifacts with replayable parent records.
The verifier needs a separately supplied trusted digest; absent one, candidates stay unverified.

The fake worker implements a deterministic encoding heuristic. CodexSDK uses the installed
0.163.0 SDK contract in tests, including ExternalMessage, thread resume, turn interruption
and last-turn usage. Runtime inference remains gated. No unsupported CLI fallback is claimed.

AUTO keeps the same canonical artifact/evidence store when moving from FAST to EXPERT.
Duplicate fingerprints include content hash, tool and normalized JSON arguments. A deterministic
stagnation rule stops or escalates after two actions without new artifacts. This is a simple
heuristic, not calibrated expected information gain or semantic equivalence of arbitrary code.

SkillsBridge returns small lexical reference chunks with paths, lines and content hashes.
Knowledge first searches accepted local records, then the configured skill corpus. New local
decoding records pass replay, schema and static sanitization gates; related skills require review.

The optional Docker runner is a separate offline data-plane utility. It is not a substitute
for isolating every provider built-in tool. No endpoint broker is shipped. Competition scheduling
uses transparent user priority, deadline and points order; no model probability estimates.

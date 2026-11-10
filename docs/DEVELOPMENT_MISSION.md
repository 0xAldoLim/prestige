# Continuing PRESTIGE development

This document summarizes the user's standing continuation request. When the full
request is available in `private/migration/REQUEST.md`, read it for details. Newer
human instructions and enforced environment restrictions take precedence.

## Intended outcome

Complete a useful autonomous CTF solver that is **OpenCode-native by default**,
targeting Kali Linux first and supporting Windows. OpenCode owns the generic
agent runtime and model transport; PRESTIGE's Python engine owns investigation
strategy, trusted tool authorization, evidence persistence, progress evaluation
and candidate verification. Continue meaningful implementation, adversarial
verification, documentation, commits, pushes and CI checks without stopping after
a plan, a small test pass, a smoke response or an intermediate commit. Do not
rewrite the repository or confuse a fake fixture worker with an AI solver.

The next core milestone is an actual public agent flow:

Observe → Hypothesize → Retrieve → Request validated tool → Execute inside audited
isolation → Record real evidence → Evaluate progress → Pivot/escalate → Verify.

## Dependency order

1. Maintain the OpenCode-native inference boundary. OpenCode selects and
   authenticates the model; PRESTIGE exposes trusted MCP tools and never requests
   or persists provider API keys in investigation state.
2. Keep artifact and tool integration conservative: configurable limits, streaming
   hashes, bounded range views, narrow mounts, output provenance, cancellable
   execution, tool/resource allowlists and persistence. File persistence is not a
   persistent GDB process.
3. Maintain an explicit real-inference configuration through the OpenCode agent.
   Account for every attempted request, including failures and unknown usage.
   Enforce time, turn, token and concurrency limits and prevent recursive
   development workers.
4. Attempt the user-supplied VENOM archive through PRESTIGE itself. Investigate from
   observed evidence; never hardcode its filename, hash, decoder or answer. Keep all
   private artifacts and transcripts outside tracked source. Do not execute the EXE
   on the host. Separate a candidate from accepted/independently derived evidence.
5. Improve FAST/EXPERT with real progress signals, competing hypotheses, dynamic
   specialist retrieval and evidence-preserving handoff. Stop equivalent repeated work.
6. Complete local-first research, sanitized schema-validated learning, isolated debugger
   persistence, exact-scope remote/expiry handling, calibrated scheduling and bounded
   independent workers. Remote challenge networking remains disabled until proven safe.
7. Compare real B0 plain model, B1 model+skills, and P1/P2/P3 FAST/AUTO/EXPERT under
   identical challenge/tool/model/budget contracts. Never claim an advantage from fixtures.
8. Preserve optional standalone OpenAI/Codex adapters for explicitly configured use.
   Changing the development agent does not change the OpenCode-native default.

## Budget and scope

Use deterministic offline checks before paid calls. Existing successful real smoke:
IBoH solved via OpenCode `prestige` agent with model `opencode-go/kimi-k3.1-pro`.
Earlier unsuccessful compatibility calls have unknown usage. Do not claim complete
cumulative accounting for them.

Before another paid test establish a recorded cap. Conservative development defaults:
one active worker, at most 12 turns, 240 seconds and 50,000 reported input+output tokens
per investigation. A reported-token limit can overshoot by the last turn; document that
and use supported provider output limits where available. If a budget ends, continue
offline engineering instead of silently starting another identical paid run.

Only explicitly assigned challenge endpoints may ever be contacted. The supplied local
ZIP has no authorized remote endpoint. Research requires a separate approved broker.
URLs, redirects and recovered credentials do not add scope. Event AI/tool restrictions
are hard constraints. Instance expiry requires stopping probes and user-supplied refresh.

## Release evidence

Require real model inference, controlled useful tool execution, public agent integration,
state recovery, meaningful lane behavior, actual VENOM investigation, independently
supported verification, measured usage, negative security tests, packaging and Windows/
Kali validation. Passing mocks or connecting an SDK alone is not a completed release.

Maintain README, SECURITY, continuation, roadmap and research acknowledgments. Credit
OpenCode-for-CTF, D-CIPHER, EnIGMA, CTFAgent, PentestGPT, CTFusion, AgentLSD, owner skills
and relevant runtime/model/security research; distinguish inspiration from copied code.

Report exact external blockers. Never bypass provider/account/OS restrictions or imply
that an ended development session continues in the background.

# Benchmark V3 — real service challenge

V3 implementation: `646e48a`; target-binding test/validation: `d98958b`; CI green on Ubuntu/Windows Python 3.11/3.14.

V3 is a separate cohort from the V1/V2 Sanity Files pilot. `welcome-sanity-files`,
`welcome-adversarial` and `rev-venom` are regression-only and are excluded from the
primary V3 discovery results.

## Provisioned challenge

| Item | Value |
| --- | --- |
| Challenge | `pwn-jsculator` (SAS CTF 2026 Quals, pwn/0day) |
| Corpus commit | `d17d17c63d23460e30c3f0402510dbd5b6bd2f5e` |
| Participant view | `README.md` + `static/jsculator.tar.gz` only |
| Service | Local `pwn.red/jail` QuickJS listener on `127.0.0.1:31337` |
| Worker image | Local build `prestige-jsculator:local`, image ID `2f8b91f49258d82cb93a3f17a5942c6a99bdec6f033ed7184e7726883f0891f3` |
| Answer | Operator-private flag, sealed outside the solver workspace |
| Health check | `help` command returned the documented JSculator prompt |
| Source visibility | Server deployment material remained operator-only |

The service was rebuilt locally from the participant/server package. The answer was
set by the operator so a successful exploit could be independently verified; it was
not disclosed to any condition. This is a legitimate local test flag, not a claim
about the original competition scoreboard.

Other priority challenges could not be safely provisioned in this environment:
`rev-fpga` (no independent answer/omitted simulator), `pwn-snaking` (JVM jail),
`web-gav` (Patroni/Postgres stack), `rev-cerum` (VST3 license/checker), `mlw-backfloppa`
(malware/eBPF), `net-incident-67` (containerlab topology). They are not counted as
attempts.

## Protocol

- Model: `opencode-go/kimi-k3.1-pro`; OpenCode 2.2.6; 180 s per attempt.
- Conditions A/B/C/D as defined in V2.
- Three fresh repetitions per condition; randomized order; fresh workspace and state.
- Blind mode: no answer commitment preloaded.
- Final answer only counts through the operator submission file.
- D received the operator-registered target and had to bind it with
  `prestige_target_bind`; C could optionally use the same MCP path.
- Research and Internet challenge lookup disabled.

## Results

A/B/C were run with seed `407`; the final D protocol-fix run used seed `406`.
No wrong flag was submitted in the final runs. Detailed times/tokens are in
`benchmark-results/sasctf-2026-v3.json`.

| Condition | Verified | Attempts | Timeouts | Missing submission | Total time | Median | Tool calls | Tokens | Known cost |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A | 1/3 | 3 | 2 | 2 | 486.2 s | 180.0 s | 48 | 75,715 | $0.000 |
| B | 2/3 | 3 | 1 | 1 | 477.9 s | 150.7 s | 54 | 70,041 | $0.000 |
| C | 0/3 | 3 | 3 | 3 | 540.0 s | 180.0 s | 67 | 89,152 | $0.000 |
| D | 1/3 | 3 | 2 | 2 | 417.1 s | 180.0 s | 61 | 89,697 | $0.000 |

D's successful attempt took 57.1 s; its two failures ended at the 180 s budget with
no submission. A's solve took 126.1 s; B's two solves took 147.1 s and 150.7 s.
C produced no valid final submission in the post-reset rerun.

The earlier D protocol run submitted a nested JSON object (`{"flag":"..."}`) and was
recorded as wrong. `prestige_submit_final` now rejects nested submissions; the final D
table above reflects the post-fix rerun.

## Interpretation

- On this one original service challenge, **B solved 2/3**, A and D solved **1/3**, C
  solved **0/3** under the fixed 180 s budget.
- The post-reset C rerun produced no valid final submission; an earlier pre-reset C
  run had two valid submissions at the 180 s boundary, which were counted as timeouts
  under the fixed-budget rule and are not included in this table.
- D's successful attempt took 57.1 s; its failures were budget/orchestration
  timeouts with no submission. This is consistent with V2: D can solve when the
  workflow stays focused, but its overhead makes completion unreliable.
- No condition submitted a wrong final flag in the final matrix.
- The sample is one challenge and three repetitions. It cannot establish a
  population-level advantage. The V2 negative conclusion remains the stronger
  evidence because it includes more runs.

## V3 changes evidenced by the failures

- AUTO/EXPERT attempt ceiling raised from 12 to 30 so a normal multi-stage attempt
  is not killed solely by the previous fixed cap.
- `prestige_exec` added for arbitrary bounded argv in the worker, preserving the
  no-host-execution boundary while removing the tiny executable allowlist.
- Persistent session commands can now be any argv installed in the worker, not only
  four names.
- `prestige_target_bind` added for operator-registered local services.
- Nested JSON final submissions are rejected; the raw flag value is required.
- `prestige_research_web_search` and configurable DuckDuckGo/Tavily/SearXNG providers
  implemented; research remains disabled for blind runs.
- README rewritten for V3 installation, worker configuration, tools, research,
  security and limitations.

## Remaining blockers

- Only one original challenge was safely provisioned and independently verified in
  this environment. The release acceptance target of five distinct new challenges is
  **not met**; the exact blockers are listed above and in the eligibility inventory.
- No browser automation provider was required for this service challenge.
- Full interactive multi-step service exploitation remains a gap for D's one-shot
  `prestige_remote_tcp` interface; jsculator happened to fit a request/response shape.
- The V3 results do not justify claiming superiority over B.

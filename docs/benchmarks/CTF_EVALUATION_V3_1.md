# V3.1 stabilization and qualification

Starting HEAD: `3f5299f`. Latest skills HEAD used: `ea6cc678459a7adca2132b4d4cd3cd2c32444938`.
V1/V2/V3 reports remain separate historical evidence.

## 1. Failure diagnosis

V3 JSculator traces (post-fix D run) showed:

- One successful D attempt completed in 57.1 s.
- Two failed D attempts produced no final submission and ended at the 180 s budget.
- D used 61 PRESTIGE tool calls; the successful and failed traces differed in how
  quickly a target-bound session/command reached the challenge protocol, not in
  final-answer correctness.
- Before the protocol fix, one D run submitted a nested JSON object instead of the
  raw flag. The submission tool now rejects that shape.
- V3 D clean/Sanity failures were not wrong answers; they were missing submissions
  after repeated investigation/status/session operations and budget exhaustion.
- V2 A/B/C solved 6/6 each; D solved 2/6. The evidence supports low-overhead direct
  execution, not forced planning.

The traces do not provide a reliable per-phase timing breakdown for reasoning vs tool
startup vs state updates. No such attribution is claimed.

## 2. Persistent interactive TCP sessions

Implemented in `src/prestige/remote.py` and exposed through MCP:

- `prestige_remote_session_open`
- `prestige_remote_session_send` (base64 binary)
- `prestige_remote_session_read` (timeout, exact bytes, base64 delimiter)
- `prestige_remote_session_close`

A session holds one operator-registered, bound TCP connection, its concurrency lease
and cancellation monitor. It supports banners, binary payloads, leaks, computed
follow-up payloads, EOF/reset detection, delayed reads, expiry cancellation and cleanup.
Scope, pinned destination, expiry and request/concurrency accounting remain enforced
outside the model.

Tests: `tests/test_remote_session.py` covers a handshake → binary stage → leak →
computed stage → flag flow directly and through MCP, plus EOF, delayed reads, expiry,
protocol mismatch and unbound-run denial.

## 3. Worker images

Reproducible Dockerfiles:

- `docker/worker-core.Dockerfile`
- `docker/worker-pwn.Dockerfile`

Local pinned image IDs:

| Image | ID | Contains |
| --- | --- | --- |
| core | `sha256:04b96abcade5b2ebd36a39daa41e734e75a298e52247e8fee5573b0de85b1a14` | Python, Bash, GCC/G++, binutils, file, xxd, archives, curl, git, netcat, socat, pwntools, Z3 |
| pwn | `sha256:987cc389afc23e21fce00011bd094249e66c7d1a36f9d0c6e318fddfc63a65f1` | core + GDB, gdbserver, strace, ltrace |

`prestige doctor` reports whether the configured image exists, its resolved image ID,
and tool availability. The pwn image passed GDB, pwntools, Z3, GCC, file/strings and
workspace/GDB tests in this environment. Radare2/rizin was not packaged in the base
distribution image; it remains an optional reviewed addition.

## 4. Low-overhead changes

- `prestige_exec` runs arbitrary bounded argv inside the worker; no host shell.
- Persistent worker sessions can run any installed argv, not four names.
- AUTO/EXPERT attempt ceiling raised from 12 to 30 after V3 evidence.
- V3 agent prompt uses one investigation and avoids repeated status/create calls.
- Submission protocol rejects nested JSON.

No additional planner or multi-agent layer was added during these qualification runs.
A later, separate change introduced strict Kimi-orchestrator/DeepSeek-executor routing;
it was not part of this benchmark and has no benchmark result.

## 5. Research and model integration

Existing DuckDuckGo/Tavily/SearXNG provider code and option handling were tested with
injected provider responses and unit tests. No broad live internet research run was
performed, so live provider reliability is not claimed. OpenCode remains the model
transport; all real runs used `opencode-go/kimi-k3.1-pro`.

## 6. Latest skills baseline

The latest owner skills checkout is `ea6cc678459a7adca2132b4d4cd3cd2c32444938`.
A latest-skills B run was executed separately on the same JSculator service and budget;
see the machine-readable V3.1 result. Previous V3 B results used an older skills commit
and are not mixed into the V3.1 table.

## 7. Challenge cohort

Only `pwn-jsculator` was provisioned again for V3.1. The following priority challenges
remained blocked by environment, service or independent-answer constraints:

- `pwn-snaking` / `pwn-snaking-revenge`: JVM jnius jail; not provisioned.
- `web-gav`: Patroni/Postgres/web stack; not provisioned.
- `web-xod-revenge`: PHP plus browser bot; not provisioned.
- `web-sentinel`: Redis/Salt cluster; not provisioned.
- `rev-fpga`: no independent answer/checker; simulator files unavailable.
- `rev-cerum`: VST3 license flow and excluded resource.
- `net-incident-67`: containerlab network topology.
- `mlw-backfloppa`: malware/eBPF carrier; not safely provisioned.

The V3.1 requirement of at least five new independently verified original challenges
is **not met**. No unavailable challenge is counted as attempted or solved.

## 8. Results

V3.1 JSculator service matrix (180 s, three repetitions):

| Condition | Verified | Timeouts | Tool calls | Tokens |
| --- | ---: | ---: | ---: | ---: |
| A plain OpenCode | 1/3 | 2 | 48 | 75,715 |
| B latest owner skills `ea6cc67` | 1/3 | 2 | 42 | 75,181 |
| C optional PRESTIGE MCP | 0/3 | 3 | 67 | 89,152 |
| D PRESTIGE (post-fix) | 1/3 | 2 | 61 | 89,697 |

No wrong final flag was submitted. The latest-skills B run replaced the older V3 B
result; older results remain in the V3 historical report but are not mixed into this
table. The latest-skills baseline solved one run in 59.3 s and produced no submission
in two.

## 9. Release decision

Evidence supports **Outcome B/C**, not Outcome A:

- PRESTIGE has useful isolated execution, operator-scoped target binding, persistent
  interactive sessions and independent verification.
- On the available real challenge, A, B and D each solved 1/3; C solved 0/3. No
  configuration demonstrated an advantage. B's latest-skills run was not more reliable
  than the earlier skills run and did not beat PRESTIGE.
- PRESTIGE is not shown to solve more challenges or to be more reliable overall.
- The five-challenge qualification target is unmet.

PRESTIGE V3.1 should remain a **release candidate / specialist tool**, not a claim of
general superiority over OpenCode + skills. The same isolated worker, remote session,
verification and research components are worth preserving.

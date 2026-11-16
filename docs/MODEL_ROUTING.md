# OpenCode model routing and delegation

Validated against OpenCode **v2.2.7** on 2026-11-15 with the checked-in
`opencode.jsonc`.

The repository uses a strict two-model split. Kimi plans and reviews; DeepSeek
executes. PRESTIGE's Python broker remains the security authority; this routing is a
cost/latency and instruction-following arrangement, **not** a security sandbox.

## Roles

| Agent | Mode | Model | Responsibility | Restrictions |
| --- | --- | --- | --- | --- |
| `orchestrator` | primary | `opencode-go/kimi-k3.1-pro` | decompose work, choose strategy, review executor evidence, make final decisions | no shell/edit/write/patch/browser/web/skill; may `read`/`glob`/`grep`; may delegate only to `executor` and `prestige` |
| `executor` | subagent | `opencode-go/deepseek-v4.1-flash` | implement, run commands, debug, test, research and report evidence autonomously | cannot spawn further subagents |
| `prestige` | all | `opencode-go/deepseek-v4.1-flash` | direct CTF solving through the trusted Python broker | host shell/read/write/browser/skill denied; only `prestige_*` MCP tools allowed |

`default_agent` is `orchestrator`; the root `model` fallback is
`opencode-go/deepseek-v4.1-flash`. The built-in `build`, `plan`, `general` and
`explore` agents are disabled so they cannot be selected accidentally.

`policies` deny every `provider.use` resource except `opencode-go`. This keeps the
OpenCode model catalog and agent selection on the assigned provider; it does not
replace PRESTIGE's operator-controlled source paths, target registrations, verification
commitments, budgets or isolated worker.

## Model identity, display name and checkpoint

`opencode models` lists selection IDs only. The connected provider catalog
(`opencode api get /api/model`, OpenCode v2.2.7, inspected 2026-11-15) exposes these
fields:

| Field | Orchestrator | Executor / PRESTIGE |
| --- | --- | --- |
| API ID (`id`/`modelID`, used by config and traces) | `kimi-k3.1-pro` | `deepseek-v4.1-flash` |
| Provider display name (`name`) | `Kimi K3.1 Pro` | `DeepSeek V4.1 Flash 1017` |
| Provider family | `kimi-k3` | `deepseek-flash` |
| Independent checkpoint/version field | not exposed | not exposed |

The catalog has no `deepseek-v4.1-flash-1017` model ID. `1017` appears only in the
provider display name `DeepSeek V4.1 Flash 1017`. Two nearby catalog entries are
different API IDs and are deliberately not configured: `deepseek-v4.1-flash-free`
and `deepseek-v4-pro`. The regular API ID `deepseek-v4.1-flash` is the required,
configured selector and is what OpenCode traces report. The provider exposes no
independent checkpoint pin, so PRESTIGE cannot claim that a non-1017 or older
checkpoint is pinned. This is the provider's ordinary display label for the required
API ID, not a substitution or a misconfiguration. If the provider changes what an
alias resolves to, the same API ID can select different underlying weights, which
PRESTIGE does not independently verify. Model identity is routing metadata, not a
security boundary.

## Minimal-intervention policy

The orchestrator is instructed to intervene only for initial planning, meaningful
failures, strategy changes, major decisions and final evaluation. It gives each
executor or PRESTIGE subagent a complete task with acceptance criteria, lets it work
autonomously, and reviews recorded evidence. It must not ask the executor to request
approval for individual tool calls, and it must not fabricate results, flags, tests,
usage or verification.

The executor is the sole execution agent for development work. It must complete the
assigned task end to end, verify its own work with commands, and never delegate
further.

## Running

Interactive development starts the orchestrator by default:

```bash
opencode
```

A scripted delegated task can name the orchestrator explicitly:

```bash
opencode run --standalone --agent orchestrator \
  "Run the offline test suite with the executor and report exact failures."
```

Direct CTF work can select the DeepSeek PRESTIGE agent without the two-model layer:

```bash
opencode run --standalone --agent prestige \
  "Solve the operator-authorized challenge in this workspace."
```

Do not add `--model` for normal use; the checked-in configuration pins the assigned
models. A model override is an operator action, not a solver decision.

## Validation evidence

### Agent resolution

`opencode --standalone debug agents` returned exactly these project agents (plus
OpenCode's internal hidden `compaction`, `summary` and `title` helpers):

```text
orchestrator  mode=primary   model=opencode-go/kimi-k3.1-pro       steps=8
executor      mode=subagent  model=opencode-go/deepseek-v4.1-flash steps=40
prestige      mode=all       model=opencode-go/deepseek-v4.1-flash steps=40
```

`build`, `plan`, `general` and `explore` were absent. `opencode models` listed only
`opencode-go/*` models. Selecting an unlisted provider model failed closed with
`provider.no-route` before any trace was recorded. This is observed catalog/policy
behavior, not a claim that configuration alone isolates providers at runtime.

The effective permission output also showed the executor with normal shell/edit/write
access and `subagent *` denied, and the orchestrator with those execution tools denied
while retaining read/glob/grep and the two allowed subagents.

### Real end-to-end trace

One small paid trace was run and is not repeated by the default test suite:

```bash
opencode run --standalone --agent orchestrator --format json \
  --title orchestrator-executor-trace \
  "Delegate to the executor subagent: create and verify a tiny file ..."
```

Recorded evidence:

- Top-level session `ses_e1d900b07ffeN521f0f6S8aViN`: `agent=orchestrator`,
  model `providerID=opencode-go`, `id=kimi-k3.1-pro`; its only tool call was
  `subagent` with `agent=executor`.
- Child session `ses_e1d8ff006ffewqS8BgcoiHFV1p`: assistant messages show
  `agent=executor`, model `providerID=opencode-go`, `id=deepseek-v4.1-flash`.
- The executor wrote `/tmp/opencode/orchestrator-trace.txt` with exactly 11 bytes
  `executor-ok` (SHA-256
  `3cfc2e599c44c5d5127916d342f406d47ef901ee8fddd2ce743ac046a4c31149`). The
  orchestrator reported the executor's evidence rather than performing the write.
- At validation time the active development session
  `ses_e1d90e4c1ffegopXkWNsc4ncHV` was a child (`parentID
  ses_e410ad943ffeOKkuS4TKTRUST4`) with `agent=executor` and model
  `opencode-go/deepseek-v4.1-flash`; its parent session metadata was
  `agent=orchestrator` and model `opencode-go/kimi-k3.1-pro`. The current-session
  message list contained only executor/DeepSeek assistant messages.

The two recorded sessions were re-read on 2026-11-15 with
`opencode api get /api/session/<session>/message`. The top-level assistant messages
carry `agent=orchestrator` and `model={"id":"kimi-k3.1-pro","providerID":"opencode-go"}`;
one contains a completed `subagent` tool call with `agent=executor` and the child
session ID. The child session metadata has `parentID=ses_e1d900b07ffeN521f0f6S8aViN`,
`agent=executor`, `model={"id":"deepseek-v4.1-flash","providerID":"opencode-go"}`,
and all four assistant messages repeat that model. The trace file re-hashed to the
same 11-byte SHA-256. This verifies the API IDs actually recorded by OpenCode; it does
not expose or independently verify hidden checkpoint internals.

No raw transcripts, prompts, credentials, flags or private challenge content are
committed here.

## Reproduce the checks

Offline configuration and CLI-resolution tests are in
`tests/test_model_routing.py` and run with the default suite:

```bash
python -m pytest -q tests/test_model_routing.py
```

The real-model trace test is opt-in and may incur a provider charge:

```bash
PRESTIGE_TEST_REAL_MODEL_TRACE=1 python -m pytest -q tests/test_model_routing.py
```

Treat all model output and retrieved content as untrusted data. The operator remains
responsible for assigning challenge scope.

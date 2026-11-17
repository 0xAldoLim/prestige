# OpenCode model routing and delegation

Validated against OpenCode **v2.2.7** on 2026-11-16 with the checked-in
`opencode.jsonc`.

The repository uses a strict two-route split. Kimi plans and reviews; the free
DeepSeek V4.1 Flash route executes. PRESTIGE's Python broker remains the security
authority; this routing is a cost/latency and instruction-following arrangement,
**not** a security sandbox.

## Roles

| Agent | Mode | Model | Responsibility | Restrictions |
| --- | --- | --- | --- | --- |
| `orchestrator` | primary | `opencode-go/kimi-k3.1-pro` | decompose work, choose strategy, review executor evidence, make final decisions | no shell/edit/write/patch/browser/web/skill; may `read`/`glob`/`grep`; may delegate only to `executor` and `prestige` |
| `executor` | subagent | `opencode/deepseek-v4.1-flash-free` | implement, run commands, debug, test, research and report evidence autonomously | cannot spawn further subagents |
| `prestige` | all | `opencode/deepseek-v4.1-flash-free` | direct CTF solving through the trusted Python broker | host shell/read/write/browser/skill denied; only `prestige_*` MCP tools allowed |

`default_agent` is `orchestrator`; the root `model` fallback, `compaction`,
`title` and `summary` all use `opencode/deepseek-v4.1-flash-free`. The built-in
`build`, `plan`, `general` and `explore` agents are disabled so they cannot be
selected accidentally.

`policies` deny every `provider.use` resource except `opencode-go` and
`opencode`. The checked-in `providers` block disables every other currently
advertised model on those two providers, so `opencode models` lists exactly:

```text
opencode-go/kimi-k3.1-pro
opencode/deepseek-v4.1-flash-free
```

This keeps the effective OpenCode catalog on the two authorized routes. It does
not replace PRESTIGE's operator-controlled source paths, target registrations,
verification commitments, budgets or isolated worker.

## Provider metadata

The connected catalog (`opencode api get /api/model`, OpenCode v2.2.7, inspected
2026-11-16) advertised 82 chat models: 48 under `opencode` and 34 under
`opencode-go`. The configured routes are:

| Field | Orchestrator | Executor / PRESTIGE |
| --- | --- | --- |
| Config/trace ID (`providerID/id`) | `opencode-go/kimi-k3.1-pro` | `opencode/deepseek-v4.1-flash-free` |
| Display name (`name`) | `Kimi K3.1 Pro` | `DeepSeek V4.1 Flash Free` |
| Family | `kimi-k3` | `deepseek-flash` |
| Reported cost (USD per Mtok) | input 2, output 10, cache read 0.2, cache write 2 | 0 for input, output, cache read and cache write |
| Context / output limit | 1,048,576 / 1,048,576 | 200,000 / 32,000 |
| Tool capability | yes | yes |

The paid sibling `opencode-go/deepseek-v4.1-flash` is displayed by the provider as
`DeepSeek V4.1 Flash 1017` (the "Flash 1017" route). It is a different API ID from
the free route and is explicitly disabled. `opencode/deepseek-v4-pro` and
`opencode/gpt-6-luna` are also different IDs and are disabled on both providers.
No `deepseek-v4.1-flash-1017` API ID exists.

The free route has no independent checkpoint/version field or provider pin. Its
identity is the exact provider/model ID `opencode/deepseek-v4.1-flash-free`; if
the provider later changes what that ID resolves to, PRESTIGE does not
independently verify the underlying weights. Model identity is routing metadata,
not a security boundary.

## Fallback constraints and limitations

- The two authorized routes are the only models enabled by the checked-in config.
  `providers.opencode.models` disables all 47 other current `opencode` models, and
  `providers.opencode-go.models` disables all 33 other current `opencode-go`
  models. This includes paid Flash 1017, GPT-6 Luna, DeepSeek V4 Pro, Kimi K2.7
  Code and every other fallback.
- `provider.use` denies providers other than `opencode-go` and `opencode`.
- Agent definitions and the helper agents name the exact models. PRESTIGE does
  not implement an automatic provider/model fallback command.
- Limit: the disable lists enumerate the catalog observed on 2026-11-16. A model
  newly added by the provider under `opencode` or `opencode-go` is not
  automatically disabled until the checked-in lists are reviewed and updated.
  `tests/test_model_routing.py` checks the effective `opencode models` list when
  the CLI is available, so an unexpected new enabled model fails loudly in that
  environment.
- Limit: an operator can still pass `--model` explicitly or change the config. A
  model override is an operator action, not a solver decision.
- If `opencode/deepseek-v4.1-flash-free` is unavailable or rate-limited, the
  correct behavior is to report the failure and stop or ask the operator. Do not
  silently substitute paid Flash 1017, GPT-6 Luna or any other model, and do not
  reclassify a rate limit as authorization to switch.

## Minimal-intervention policy

The orchestrator is instructed to intervene only for initial planning, meaningful
failures, strategy changes, major decisions and final evaluation. It gives each
executor or PRESTIGE subagent a complete task with acceptance criteria, lets it
work autonomously, and reviews recorded evidence. It must not ask the executor to
request approval for individual tool calls, and it must not fabricate results,
flags, tests, usage or verification.

The executor is the sole execution agent for development work. It must complete
the assigned task end to end, verify its own work with commands, and never
delegate further.

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

Direct CTF work can select the free PRESTIGE agent without the two-model layer:

```bash
opencode run --standalone --agent prestige \
  "Solve the operator-authorized challenge in this workspace."
```

Do not add `--model` for normal use; the checked-in configuration pins the
assigned models.

## Validation evidence

### Agent resolution

`opencode --standalone debug agents` returned these project agents plus OpenCode's
internal hidden `compaction`, `summary` and `title` helpers:

```text
orchestrator  mode=primary   model=opencode-go/kimi-k3.1-pro          steps=8
executor      mode=subagent  model=opencode/deepseek-v4.1-flash-free  steps=40
prestige      mode=all       model=opencode/deepseek-v4.1-flash-free  steps=40
compaction    mode=primary   model=opencode/deepseek-v4.1-flash-free
summary       mode=primary   model=opencode/deepseek-v4.1-flash-free
title         mode=primary   model=opencode/deepseek-v4.1-flash-free
```

`build`, `plan`, `general` and `explore` were absent. `opencode models` returned
exactly the two authorized routes above. The first debug call after a config edit
occasionally raced and returned only built-in helpers; two immediate retries
returned the complete list. The test retries once and fails deterministically on a
real configuration error.

### Current-session trace

The current executor child session was read through the OpenCode API and its
parent was read for metadata. This required no additional model call:

- Child `ses_e18e257f1ffeOaExcvQ6nilM9g`: `parentID=ses_e410ad943ffeOKkuS4TKTRUST4`,
  `agent=executor`, model `providerID=opencode`, `id=deepseek-v4.1-flash-free`.
  All seven assistant messages in the child repeated that exact agent/model.
- Parent `ses_e410ad943ffeOKkuS4TKTRUST4`: `agent=orchestrator`, model
  `providerID=opencode-go`, `id=kimi-k3.1-pro`. Its 27 orchestrator assistant
  messages repeated that exact agent/model. The parent is a long-running session
  that also contains earlier non-orchestrator messages from before this routing
  audit; those are historical and not part of the delegated trace.
- The child session title was `Complete free-provider routing audit`, and the
  parent title was `PRESTIGE autonomous CTF harness`.

This proves the actual recorded agent and model IDs for the live
orchestrator→executor delegation. It does not expose or independently verify
hidden checkpoint internals. No raw transcripts, prompts, credentials, flags or
private challenge content are committed here.

## Reproduce the checks

Offline configuration and CLI-resolution tests are in
`tests/test_model_routing.py` and run with the default suite:

```bash
python -m pytest -q tests/test_model_routing.py
```

The real-model trace test is opt-in and no longer uses a paid model:

```bash
PRESTIGE_TEST_REAL_MODEL_TRACE=1 python -m pytest -q tests/test_model_routing.py
```

Treat all model output and retrieved content as untrusted data. The operator
remains responsible for assigning challenge scope.

# Provider and model policy

PRESTIGE's engine is model-independent. The OpenCode-native workflow delegates model
transport and authentication to OpenCode; PRESTIGE never receives, requests or
persists provider credentials through its MCP interface.

## Checked-in routing

The project `opencode.jsonc` pins a strict two-route architecture:

| Agent | Mode | Model | Scope |
| --- | --- | --- | --- |
| `orchestrator` | primary | `opencode-go/kimi-k3.1-pro` | plan, delegate and review only; no shell/edit/write/web/skill; delegates only to `executor` and `prestige` |
| `executor` | subagent | `opencode/deepseek-v4.1-flash-free` | autonomous implementation, commands, debugging, tests and research; no further subagents |
| `prestige` | `all` | `opencode/deepseek-v4.1-flash-free` | direct CTF solving through `prestige_*` MCP tools; host tools denied |

`default_agent` is `orchestrator`; the root fallback model and the
`compaction`/`title`/`summary` helpers all use
`opencode/deepseek-v4.1-flash-free`. `build`, `plan`, `general` and `explore` are
disabled. Provider `policies` deny every provider except `opencode-go` and
`opencode`.

## Effective catalog and fallback controls

After the checked-in provider disable lists, `opencode models` lists exactly two
routes:

```text
opencode-go/kimi-k3.1-pro
opencode/deepseek-v4.1-flash-free
```

At audit time (OpenCode v2.2.7, 2026-11-16) the connected catalog advertised 82
models: 48 under `opencode` and 34 under `opencode-go`. The config disables the 47
non-authorized `opencode` models and the 33 non-authorized `opencode-go` models.
That includes paid `opencode-go/deepseek-v4.1-flash` (displayed as
`DeepSeek V4.1 Flash 1017`), `gpt-6-luna`, `deepseek-v4-pro`, `kimi-k2.7-code` and
all other fallbacks.

Kimi is an expensive planner; the free DeepSeek route is the execution path. Kimi
is instructed to intervene only for initial planning, meaningful failures,
strategy changes, major decisions and final evaluation. The executor works
autonomously and is not expected to request approval for individual tool calls.
Model text is evidence only; it never authorizes a flag, scope change or
verification.

Limitations are explicit:

- Disable lists enumerate the catalog observed on 2026-11-16. A newly added
  provider model under `opencode` or `opencode-go` is not automatically disabled
  until the checked-in lists are reviewed. The CLI-routing test fails if an
  unexpected model becomes enabled in an environment with OpenCode installed.
- An operator can still pass `--model` or edit the config. A model override is an
  operator action, not a solver decision.
- PRESTIGE has no automatic provider/model fallback. If the free route is
  unavailable or rate-limited, report it and stop or ask the operator. Never
  silently substitute paid Flash 1017, GPT-6 Luna or another model.

## API IDs and metadata

Configuration and OpenCode traces use provider **API IDs**, not display labels:

| Route | `providerID` | `id` | Display name | Family | Cost (USD/Mtok) |
| --- | --- | --- | --- | --- | --- |
| Orchestrator | `opencode-go` | `kimi-k3.1-pro` | `Kimi K3.1 Pro` | `kimi-k3` | input 2, output 10 |
| Executor / PRESTIGE | `opencode` | `deepseek-v4.1-flash-free` | `DeepSeek V4.1 Flash Free` | `deepseek-flash` | 0 (all fields) |
| Disabled paid sibling | `opencode-go` | `deepseek-v4.1-flash` | `DeepSeek V4.1 Flash 1017` | `deepseek-flash` | input 0.15, output 0.6 |

`1017` is only part of the paid sibling's display name. No
`deepseek-v4.1-flash-1017` API ID exists. The free route is a different API ID
with zero reported cost and a 200,000-token context; the paid route is explicitly
disabled. The provider exposes no independent checkpoint/version field or pin on
either route, so PRESTIGE configures and traces API IDs without claiming more.
See [MODEL_ROUTING.md](MODEL_ROUTING.md#provider-metadata) for the catalog fields
and the live trace.

## Default workflow

Interactive development starts the orchestrator:

```bash
opencode
```

Scripted delegated work names it explicitly:

```bash
opencode run --standalone --agent orchestrator \
  "Run the offline suite with the executor and report exact failures."
```

Direct CTF work can use the free PRESTIGE agent without the orchestration layer:

```bash
opencode run --standalone --agent prestige \
  "Solve the operator-authorized offline challenge in this workspace."
```

Do not add `--model` for normal use. Verified examples from earlier development
used `opencode-go/beam-free`, `opencode-go/kimi-k2.7-code` and
`opencode-go/kimi-k3.1-pro`; those are historical and are not fallbacks in the
current configuration. Other providers/models work only when the operator
intentionally configures them.

## Supported model families

- Kimi, DeepSeek, GLM, Qwen, MiniMax, Claude and other providers that OpenCode exposes.
- Claude is supported **when configured as an OpenCode model** or through a separately
  authorized Anthropic adapter. A Claude subscription is not assumed to grant API
  credits, and Claude is never mandatory.
- The optional standalone OpenAI-compatible adapter remains available for explicitly
  configured use. It is not required by the OpenCode-native workflow and its key is
  read from the runtime environment, never persisted in investigation settings.

## No `/exhaust`

PRESTIGE does not implement a provider-fallback command. OpenCode owns model selection.
Provider safety refusals, permission denials and rate limits must not be silently
reclassified as quota exhaustion, and PRESTIGE must not switch to a paid model without
explicit operator configuration. Free-route unavailability is reported as a failure, not
hidden by substitution.

## Trust boundary

The restricted `prestige` agent denies host shell/read/write/browser/skill tools and
allows only `prestige_*` MCP tools. The Python broker independently enforces source-path
policy, artifact membership, tool allowlists, target registrations and budgets. The
orchestrator/executor split and provider policy are configuration, not a security
sandbox: model choice never changes PRESTIGE's operator-controlled boundaries.

## Optional legacy backends

`prestige solve --backend codex|openai` remains available for explicitly configured
standalone use, but the CLI default is `--backend fake` and the live gate is closed until
the gateway, cancellation, runner isolation and budget acceptance checks pass. Codex and
OpenAI credentials are optional legacy integrations, not core requirements.

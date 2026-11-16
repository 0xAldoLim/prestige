# Provider and model policy

PRESTIGE's engine is model-independent. The OpenCode-native workflow delegates model
transport and authentication to OpenCode; PRESTIGE never receives, requests or
persists provider credentials through its MCP interface.

## Checked-in routing

The project `opencode.jsonc` pins a strict two-model architecture:

| Agent | Mode | Model | Scope |
| --- | --- | --- | --- |
| `orchestrator` | primary | `opencode-go/kimi-k3.1-pro` | plan, delegate and review only; no shell/edit/write/web/skill; delegates only to `executor` and `prestige` |
| `executor` | subagent | `opencode-go/deepseek-v4.1-flash` | autonomous implementation, commands, debugging, tests and research; no further subagents |
| `prestige` | `all` | `opencode-go/deepseek-v4.1-flash` | direct CTF solving through `prestige_*` MCP tools; host tools denied |

`default_agent` is `orchestrator`; the root fallback model is
`opencode-go/deepseek-v4.1-flash`. `build`, `plan`, `general` and `explore` are
disabled. Provider `policies` deny every provider except `opencode-go`.

Kimi is an expensive planner. It is instructed to intervene only for initial
planning, meaningful failures, strategy changes, major decisions and final
evaluation. The executor works autonomously and is not expected to request approval
for individual tool calls. Model text is evidence only; it never authorizes a flag,
scope change or verification.

## API ID, display name and checkpoint

Configuration and OpenCode traces use provider **API IDs**, not display labels. The
orchestrator API ID is `kimi-k3.1-pro` (displayed as `Kimi K3.1 Pro`). The
executor/PRESTIGE API ID is `deepseek-v4.1-flash`, which the connected OpenCode v2.2.7
catalog displays as `DeepSeek V4.1 Flash 1017`.

`1017` is only part of that display name. No `deepseek-v4.1-flash-1017` API ID exists
in the catalog, and `deepseek-v4.1-flash-free` and `deepseek-v4-pro` are different
unconfigured API IDs. The provider exposes no independent checkpoint/version field or
pin. PRESTIGE therefore configures and traces the required regular API ID but cannot
claim that a non-1017 or older checkpoint is pinned. This is the provider's ordinary
label for the required ID, not a substitution or misconfiguration. See
[MODEL_ROUTING.md](MODEL_ROUTING.md#model-identity-display-name-and-checkpoint) for the
catalog fields and the real trace.

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

Direct CTF work can use the PRESTIGE agent without the orchestration layer:

```bash
opencode run --standalone --agent prestige \
  "Solve the operator-authorized offline challenge in this workspace."
```

Do not add `--model` for normal use. A model override is an operator action, not a
solver decision. Verified examples from earlier development used
`opencode-go/beam-free`, `opencode-go/kimi-k2.7-code` and
`opencode-go/kimi-k3.1-pro`; other providers/models work only when the operator
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
explicit operator configuration.

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

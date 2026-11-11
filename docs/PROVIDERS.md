# Provider and model policy

PRESTIGE is model-independent. The OpenCode-native workflow delegates model selection
and authentication to OpenCode; PRESTIGE never receives, requests or persists provider
credentials through its MCP interface.

## Default workflow

```bash
opencode run --standalone --agent prestige --model <provider>/<model> \
  "Resume the existing authorized offline investigation."
```

The model identifier is chosen by the operator in OpenCode. PRESTIGE does not hardcode
a provider, subscription tier or model family. Verified examples from earlier development
used `opencode-go/beam-free`, `opencode-go/kimi-k2.7-code` and
`opencode-go/kimi-k3.1-pro`; other providers/models work the same way when OpenCode
exposes them.

## Supported model families

- Kimi, DeepSeek, GLM, Qwen, MiniMax, Claude and other providers that OpenCode exposes.
- Claude is supported **when configured as an OpenCode model** or through a separately
  authorized Anthropic adapter. A Claude subscription is not assumed to grant API
  credits, and Claude is never mandatory.
- A standalone OpenAI-compatible adapter remains optional for explicitly configured
  use. It is not required by the OpenCode-native workflow and its key is read from the
  runtime environment, never persisted in investigation settings.

## No `/exhaust`

PRESTIGE does not implement a provider-fallback command. OpenCode owns model selection.
Provider safety refusals, permission denials and rate limits must not be silently
reclassified as quota exhaustion, and PRESTIGE must not switch to a paid model without
explicit operator configuration.

## Trust boundary

The restricted `prestige` agent denies host shell/read/write/browser/skill tools and
allows only `prestige_*` MCP tools. The Python broker independently enforces source-path
policy, artifact membership, tool allowlists and budgets. Model choice does not change
those boundaries.

## Optional legacy backends

`prestige solve --backend codex|openai` remains available for explicitly configured
standalone use, but the CLI default is `--backend fake` and the live gate is closed until
the gateway, cancellation, runner isolation and budget acceptance checks pass. Codex and
OpenAI credentials are optional legacy integrations, not core requirements.

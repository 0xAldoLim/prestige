# Codex integration: experimental inference gateway

Inspected official source commit `04e365c698b94651b6ea7e3b3af5c1dd697bd30c`, the SDK
docs/exports and configuration schema. Installed SDK/runtime: `openai-codex==0.163.0`.

The internal adapter now queries account presence/model availability through supported
SDK methods, creates/resumes a reasoning thread, supplies external evidence with
ExternalMessage, parses structured proposals and records `usage.last`. No auth file
or credential contents are read/copied by PRESTIGE. No model ID is forced by default.

The text-only gateway is a separate transport boundary. It advertises no native tools,
denies executable/unknown response events, discards provider metadata, buffers bounded
responses before forwarding, and uses fixed official HTTPS inference destinations.
Normal SDK authentication headers transit memory but are never logged or persisted.
This is experimental: ambiguous SSE framing and active-upstream cancellation still need
additional implementation/review. SDK sandbox flags or hook denials alone are insufficient.

Executed evidence:

- Real installed SDK/runtime against a local mocked Responses transport, no paid inference.
- One successful real gpt-6.1-sol smoke: input 11563, output 29, cached input 11392,
  reasoning 0; cached input is included in input, not counted again.
- Earlier compatibility attempts reached the provider but were rejected by the gateway.
  Their usage is unknown; complete cumulative model cost/usage is not established.

**The normal CLI is still gated**: engine construction does not enable live inference
or pass a WorkspaceRunner to ToolRegistry. A successful smoke is not a CTF solve. No
real challenge or B0/B1 comparison has been performed. Account rate-limit integration,
streaming user-facing progress, robust recovery and complete cancellation remain unfinished.

OpenCode can develop this repository using [the handoff](OPENCODE_HANDOFF.md). That does
not implement an OpenCode product backend or authorize credential transfer between tools.

Sources: [official SDK](https://learn.chatgpt.com/docs/codex-sdk),
[Python source](https://github.com/openai/codex/tree/main/sdk/python).

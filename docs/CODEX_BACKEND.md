# Codex integration: inspected contract, live gate

Inspected official source commit `04e365c698b94651b6ea7e3b3af5c1dd697bd30c`, SDK README,
getting-started, API reference, FAQ, exported types and configuration schema on 2026-10-28.
Installed `openai-codex==0.163.0` with its pinned runtime and tested actual ExternalMessage,
ApprovalMode and Sandbox types. No API keys or auth.json contents were read.

The contract adapter starts/resumes a thread with a trusted mission, sends evidence as
ExternalMessage, consumes TurnResult, reads `usage.last` rather than double-counting
cumulative totals, and supports interruption/close. Tests simulate the app-server client.
The primary protocol stays provider-neutral. No model name or effort availability is invented.

**Live inference is blocked.** A read-only SDK sandbox, denial of escalation, disabled shell
feature or system prompt alone does not establish the independent execution boundary required
by the specification. We have not validated a complete deny-all provider tool surface with
adversarial child-process and credential tests. The adapter does not launch app-server or a paid
turn from the solve path. Installing the extra, logging in, or passing `--offline` cannot bypass it.

Existing Codex authentication should eventually be used through supported SDK mechanisms
(`codex login` or SDK login), never by copying credentials. Authenticated solve, capability/model
discovery and account rate-limit integration remain incomplete. No Codex CLI fallback,
OpenCode support or Codex local-provider route is advertised as working.

Next acceptance step: isolate the provider control plane and prove every possible model
side effect goes through the PRESTIGE policy/tool boundary, then run an explicitly budgeted
live synthetic solve outside a nested Codex development session.

Sources: [official SDK](https://learn.chatgpt.com/docs/codex-sdk),
[Python source](https://github.com/openai/codex/tree/main/sdk/python).

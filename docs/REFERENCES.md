# References and access audit

Access date: 2026-10-28. Concepts, files and security notes are recorded in [PROVENANCE.json](PROVENANCE.json).

- [OpenCode-for-CTF](https://github.com/h1kibi/Opencode-for-CTF): FAST/EXPERT policies; independent reimplementation, no code copied.
- [D-CIPHER](https://github.com/NYU-LLM-CTF/nyuctf_agents): Planner/executor separation and evaluation framing; no code copied.
- [EnIGMA](https://arxiv.org/abs/2409.16165): Interactive debugger and response-management ideas; persistent debugger NOT implemented; no code copied.
- [CTFAgent](https://yan5ui.github.io/CCSCTF-Web/): Retrieval plus environment feedback; local stage implemented, external stage deferred.
- [PentestGPT](https://github.com/GreyDGL/PentestGPT): Canonical state, phases and task leases; no code copied.
- [CTFusion](https://github.com/kaist-hacking/CTFusion): Controlled evaluation concepts; CTFd/platform integrations explicitly excluded; no code copied.
- [AgentLSD](https://arxiv.org/abs/2609.19140): Task contamination, misleading flags and hints; original synthetic tests.
- [Owner's CTF skills](https://github.com/0xAldoLim/skills): Copied schemas/learning.schema.json unchanged; read-only workflow integration; no helper code copied.
- [Arditi et al.](https://arxiv.org/abs/2406.11717): Refusal mechanism research motivates paired tests; no capability or safety improvement claimed.
- [OpenAI Codex](https://github.com/openai/codex/tree/main/sdk/python): Official SDK contracts; no source vendored; live solver gated.
- [Ollama](https://docs.ollama.com/api/chat): Bounded advisory HTTP API contract.
- [Hugging Face](https://huggingface.co/docs/hub/security-pickle): Safe formats, explicit provenance and custom-code avoidance.
- [OpenCode](https://opencode.ai/docs/sdk/): Capability-separated backend design; OpenCode adapter not implemented.
- [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html): Layered trust boundaries and deterministic enforcement beyond filtering.

Additional inspected official contracts:

- https://learn.chatgpt.com/docs/codex-sdk — stable Python SDK, pinned runtime; inspected alongside installed exports.
- https://github.com/openai/codex/blob/main/sdk/python/docs/api-reference.md — ExternalMessage, async turns, usage and resume.
- https://github.com/GreyDGL/PentestGPT/blob/main/docs/architecture.md — supervisor/state lineage; full-access assumptions not adopted.
- https://github.com/SWE-agent/SWE-agent/tree/v0.7 — EnIGMA lineage reference; no source copied.
- https://huggingface.co/docs/hub/ollama — GGUF integration; not universal checkpoint import.
- https://github.com/huggingface/transformers/blob/main/SECURITY.md — untrusted model code and format risks.
- https://nvd.nist.gov/developers/vulnerabilities — URL checked, page yielded no readable content in this environment; no live API integration claimed.
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog — access returned HTTP 403; not represented as verified API behavior.

Raw license files checked: OpenCode-for-CTF/main/LICENSE (MIT), nyuctf_agents/main/LICENSE (MIT),
PentestGPT/main/LICENSE.md (MIT), CTFusion/main/LICENSE (MIT root with derived notices).
The owner's schema and license were inspected at the exact commit recorded above.
Only that schema is copied. No model cards were relied on to select/download a model;
individual checkpoint licensing and paired experiments remain future work.

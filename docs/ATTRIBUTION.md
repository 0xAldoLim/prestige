# Attribution and research foundations

OpenCode development handoff files use its documented AGENTS.md and custom Markdown
command conventions. Those project instructions are original; no upstream source or
documentation text is copied. This development setup does not implement the optional
OpenCode runtime backend. See [handoff](OPENCODE_HANDOFF.md) and PROVENANCE.json.

Checked 2026-10-28. PRESTIGE is independent; no upstream endorsement or affiliation.

## OpenCode-for-CTF

[OpenCode-for-CTF](https://github.com/h1kibi/Opencode-for-CTF) — h1kibi and contributors.

FAST/EXPERT policies; independent reimplementation, no code copied.

License/source status: MIT. Original holder: 2026 opencode-for-ctf contributors.
Implementation: `src/prestige/engine.py`, `src/prestige/progress.py`.

## D-CIPHER

[D-CIPHER](https://github.com/NYU-LLM-CTF/nyuctf_agents) — Udeshi et al.; NYU-LLM-CTF.

Planner/executor separation and evaluation framing; no code copied.

License/source status: MIT. Original holder: 2024 NYU Tandon School of Engineering and NYU Abu Dhabi.
Implementation: `src/prestige/types.py`, `src/prestige/evaluation.py`.

## EnIGMA

[EnIGMA](https://arxiv.org/abs/2409.16165) — Abramovich et al..

Interactive debugger and response-management ideas; persistent debugger NOT implemented; no code copied.

License/source status: Paper reference; SWE-agent file-specific licenses not audited for reuse. Original holder: See paper and SWE-agent v0.7 notices.
Implementation: `docs/IMPLEMENTATION_STATUS.md`.

## CTFAgent

[CTFAgent](https://yan5ui.github.io/CCSCTF-Web/) — Ji et al..

Retrieval plus environment feedback; local stage implemented, external stage deferred.

License/source status: Paper/site reference; linked code not incorporated. Original holder: Original paper authors.
Implementation: `src/prestige/knowledge.py`, `src/prestige/research.py`.

## PentestGPT

[PentestGPT](https://github.com/GreyDGL/PentestGPT) — Deng et al.; GreyDGL contributors.

Canonical state, phases and task leases; no code copied.

License/source status: MIT. Original holder: 2023 Grey_D.
Implementation: `src/prestige/store.py`.

## CTFusion

[CTFusion](https://github.com/kaist-hacking/CTFusion) — Lee, Bae and Yun; KAIST HackingLab.

Controlled evaluation concepts; CTFd/platform integrations explicitly excluded; no code copied.

License/source status: MIT root; derived directories retain separate notices. Original holder: 2025 KAIST HackingLab.
Implementation: `src/prestige/evaluation.py`.

## AgentLSD

[AgentLSD](https://arxiv.org/abs/2609.19140) — Golinelli, Drago, Boffa, Bergadano and Crispo.

Task contamination, misleading flags and hints; original synthetic tests.

License/source status: Paper reference; no code/data reused. Original holder: Original paper authors.
Implementation: `tests/test_security.py`, `benchmarks/synthetic/trap.txt`.

## Owner's CTF skills

[Owner's CTF skills](https://github.com/0xAldoLim/skills) — 0xAldoLim; preserve upstream attribution.

Copied schemas/learning.schema.json unchanged; read-only workflow integration; no helper code copied.

License/source status: MIT. Original holder: 2026 Lukasz Jagiello.
Implementation: `src/prestige/data/learning.schema.json`, `src/prestige/knowledge.py`.
Exact notice: [licenses/skills-MIT.txt](../licenses/skills-MIT.txt); copied file is unmodified.

## Arditi et al.

[Arditi et al.](https://arxiv.org/abs/2406.11717) — Arditi, Obeso, Syed, Paleka, Panickssery, Gurnee and Nanda.

Refusal mechanism research motivates paired tests; no capability or safety improvement claimed.

License/source status: Paper reference; no model/code/data reused. Original holder: Original paper authors.
Implementation: `docs/LOCAL_MODELS.md`, `src/prestige/local_models.py`.

## OpenAI Codex

[OpenAI Codex](https://github.com/openai/codex/tree/main/sdk/python) — OpenAI and contributors.

Official SDK contracts; no source vendored; live solver gated.

License/source status: Apache-2.0; separately installed optional dependency. Original holder: OpenAI.
Implementation: `src/prestige/codex_sdk.py`.

## Ollama

[Ollama](https://docs.ollama.com/api/chat) — Ollama maintainers.

Bounded advisory HTTP API contract.

License/source status: MIT runtime; API documentation reference, not copied. Original holder: Ollama contributors.
Implementation: `src/prestige/local_models.py`.

## Hugging Face

[Hugging Face](https://huggingface.co/docs/hub/security-pickle) — Hugging Face maintainers.

Safe formats, explicit provenance and custom-code avoidance.

License/source status: Documentation reference; individual model licenses must be checked. Original holder: Hugging Face contributors.
Implementation: `src/prestige/local_models.py`.

## OpenCode

[OpenCode](https://opencode.ai/docs/sdk/) — OpenCode maintainers.

Capability-separated backend design; OpenCode-native MCP broker implemented.

License/source status: API documentation reference; no code reused. Original holder: OpenCode contributors.
Implementation: `src/prestige/mcp_server.py`, `.opencode/plugins/prestige/`, `opencode.jsonc`.

## OWASP

[OWASP](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) — OWASP Cheat Sheet Series contributors.

Layered trust boundaries and deterministic enforcement beyond filtering.

License/source status: Documentation reference; no text/code copied. Original holder: OWASP contributors.
Implementation: `SECURITY.md`, `tests/test_security.py`.

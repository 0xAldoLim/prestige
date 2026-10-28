# Upstream license audit

Review date: 2026-10-28. This audit records engineering provenance, not legal advice.

| Component | Status | Reuse |
| --- | --- | --- |
| Owner's skills, commit `1d51e0f4a289cb1b6e7326d41db4e6f6ad54516d` | MIT; exact holder is Lukasz Jagiello, 2026 | Learning JSON schema copied unchanged; exact notice in `licenses/skills-MIT.txt` |
| OpenCode-for-CTF | MIT; 2026 opencode-for-ctf contributors, raw license inspected | Concepts only |
| NYU D-CIPHER/nyuctf_agents | MIT; 2024 NYU Tandon School of Engineering and NYU Abu Dhabi | Concepts only |
| PentestGPT | MIT; 2023 Grey_D, raw LICENSE.md inspected | Concepts only |
| CTFusion | MIT root; 2025 KAIST HackingLab; derived directories have separate notices | Concepts only; no platform integration |
| EnIGMA / SWE-agent v0.7 | Paper and lineage identified; file-specific reuse audit not performed | No code copied; interactive debugger unimplemented |
| CTFAgent / AgentLSD / Arditi et al. | Paper references; paper citation is not a code license | No code, datasets or weights copied |
| OpenAI Codex SDK/runtime 0.163.0 | Apache-2.0 optional separately installed dependency | Public API consumed in contract tests; no code vendored |
| jsonschema | MIT separately installed dependency | Validates the preserved learning schema |
| Ollama / Hugging Face / OpenCode / OWASP | Official API/documentation references | No documentation text or implementation code copied |

The wheel and sdist include PRESTIGE's MIT license, THIRD_PARTY_NOTICES.md and the exact
copied-schema license. Dependency distributions carry their own notices. No model or corpus
redistribution is performed. Future imports require exact commit, file-specific/transitive
license review, retained notices and a provenance entry in the same change.

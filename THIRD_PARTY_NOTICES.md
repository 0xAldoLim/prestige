# Third-party notices

PRESTIGE is independent and is not affiliated with or endorsed by any referenced team.

The file `src/prestige/data/learning.schema.json` is copied unchanged from
`0xAldoLim/skills`, commit `1d51e0f4a289cb1b6e7326d41db4e6f6ad54516d`,
`schemas/learning.schema.json`. Its upstream license is MIT and states
**Copyright (c) 2026 Lukasz Jagiello**. The exact notice is preserved in
`licenses/skills-MIT.txt`. The repository owner is not substituted for the original
copyright holder. No upstream solver, exploit, model weight or benchmark corpus is vendored.

Conceptual influences include OpenCode-for-CTF, D-CIPHER, EnIGMA, CTFAgent, PentestGPT,
CTFusion, AgentLSD, OWASP and Arditi et al. Precise scope and source links appear in
`docs/ATTRIBUTION.md` and `docs/PROVENANCE.json`.

The AgentDojo `important_instructions` template shape is adapted from
`ethz-spylab/agentdojo` commit `089ed468cf3ed0322acc66b0211f26d9d90dbf60`
(MIT, Copyright (c) 2024 Edoardo Debenedetti and contributors). The exact notice is in
`licenses/agentdojo-MIT.txt`. Native AgentDojo scenario parsing is a local adaptation,
not an official benchmark execution.

Gray Swan IPI Arena behavior/config schemas are adapted from `GraySwanAI/ipi_arena_os`
commit `5e2e285910d581c97767195f1d113ef323f9ab07` (MIT, Copyright (c) 2025 Gray Swan AI).
The exact notice is in `licenses/ipi-arena-MIT.txt`. No upstream code is imported or
executed; no official arena run is claimed.

Runtime dependencies retain their respective licenses. `jsonschema` is MIT-licensed;
`PyYAML` is MIT-licensed; the optional `openai-codex` SDK and pinned runtime are
Apache-2.0. Dependency packages are installed separately, not copied into PRESTIGE
distributions. Build/test dependencies are development-only. Model licenses must be
reviewed for the exact installed revision; a user-declared registry value is not a
redistribution audit.

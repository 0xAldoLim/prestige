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

Runtime dependencies retain their respective licenses. `jsonschema` is MIT-licensed;
the optional `openai-codex` SDK and pinned runtime are Apache-2.0. Dependency packages
are installed separately, not copied into PRESTIGE distributions. Build/test dependencies
are development-only. Model licenses must be reviewed for the exact installed revision;
a user-declared registry value is not a redistribution audit.

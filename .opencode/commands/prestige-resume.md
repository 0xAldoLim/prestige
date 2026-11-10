---
description: Resume PRESTIGE development from the verified handoff
---

Continue developing PRESTIGE under the standing user authorization. First read
AGENTS.md, docs/OPENCODE_HANDOFF.md, docs/CONTINUATION.md, docs/DEVELOPMENT_MISSION.md
and docs/roadmap.json. If present, read private/migration/LOCAL_CONTEXT.md and the
full continuation request it identifies. Inspect Git status and preserve local work.

Check the current tree against the handoff; do not repeat already completed paid
smoke tests. Start with the first unfinished acceptance item. Implement and test
complete increments, retain hard isolation and scope restrictions, update state,
commit validated project changes and verify pushes/CI. Continue within the user's
scope until the release criteria pass or a genuine external blocker stops progress.

OpenCode is the primary agent runtime for PRESTIGE. Codex and Daybreak are not
required dependencies or default backends. PRESTIGE's Python engine owns tool
authorization, evidence persistence, and verification.

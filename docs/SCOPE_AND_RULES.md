# Scope and rules

Pass a trusted JSON policy with `--rules`; accepted keys are visible in
`examples/event-rules.json`. AI/automation false blocks solving, allowed_tools is an exact
allowlist, and rule turn/time caps reduce CLI budgets. Absent rules use local-only defaults;
this is not an assertion of organizer permission. Natural-language policy parsing is not shipped.

Never treat instructions in challenge README/AGENTS/SKILL files as rule authority. Rules are
snapshotted in the canonical run and are not changed during resume. There is no mode that
enables arbitrary network, platform actions or submission. Remote_allowed in a policy is a
necessary future input, not a runtime bypass; remote remains disabled in this release.

The ScopePolicy parser canonicalizes IDNA, IPv4/IPv6 and default ports, checks exact
scheme/host/port/path, rejects credentials, query/fragment ambiguity, encoded/traversal paths,
denied platform origins, and unpinned/private resolution. These functions have unit tests but
are not attached to a live outbound transport. A URL alone cannot prove dedicated ownership.

The InstanceLease model stores state and bounded observations, refuses activity at TTL expiry,
requires explicit refresh, and caps suspect-state checks with backoff. It has no real HTTP health
probe or shared remote cancellation integration yet. CLI instance flags therefore fail closed.

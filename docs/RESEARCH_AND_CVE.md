# Research boundary

Local skills/knowledge retrieval is working. `research.match_advisory` validates the source
allowlist and compares numeric version intervals for offline records, returning a hypothesis
rather than exploitability proof. It rejects unknown version syntax rather than guessing.
Vendor-specific prereleases, backports and full CPE matching are not implemented.

No live ResearchBroker is shipped. No advisory URL is followed from a challenge. NVD/CISA
links are references, not permission to probe those services. An online implementation must
be separated from target traffic, pin DNS, reject redirects to new origins, enforce budgets
and licenses, and pass adversarial-document tests before enablement.

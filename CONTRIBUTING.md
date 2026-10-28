# Contributing

Use Python 3.11+, a virtual environment, and `pip install -e '.[dev,codex]'`.
Run pytest, Ruff, package build and CLI smoke before proposing changes. Default tests
must remain offline and cannot launch nested Codex workers. Mark paid or container tests
explicitly. Keep the live backend/remote gates until an independently reviewed boundary
passes negative subprocess, DNS, redirect and credential tests.

Add actual validation evidence to `docs/IMPLEMENTATION_STATUS.md`. Do not label mock
benchmarks as model evaluations. Preserve source licenses and update attribution and
provenance alongside imports. Do not modify a user's external skills checkout.

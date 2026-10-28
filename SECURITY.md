# Security model and reporting

PRESTIGE 0.1.0 is experimental. P0 is incomplete. It makes no claim of perfect
prompt-injection immunity or production containment of arbitrary hostile native code.

The shipped solve loop can only call bounded in-process byte analysis. It has no shell,
socket, HTTP, SSH, provider-credential or plugin tool. Artifact text, instruction-like
filenames, retrieval snippets and model responses cannot alter the trusted policy snapshot.
The optional Ollama transport is separate, accepts only literal loopback endpoints and
cannot execute returned tool calls. The model registry never downloads or executes weights.

Remote challenge and research transports are disabled. Scope normalization and lease tests
are preparatory controls, not claims that an exact-endpoint broker has been completed.
No CLI option or model field enables remote operation. Potential platform origins are
denied; no substring-based classifier could establish complete platform detection.

Codex inference is blocked because SDK sandbox settings alone do not prove the required
control/data separation. Do not remove this gate merely to make the example work.
The adapter is tested with genuine installed SDK types and simulated server results.
Provider auth files are neither read nor copied by PRESTIGE.

The optional Docker runner uses an immutable local Linux image, no host mounts, no network,
an unprivileged UID, dropped capabilities, read-only root, limited tmpfs, CPU, memory,
processes, output and wall time. Every runner instance audits loopback-only interfaces,
blocked TCP/DNS/child egress and root writes before executing a script. Timeout/output
overflow removes its named container. A trusted image, current Docker/kernel and correct
daemon are assumed. Docker isolation is not a VM escape defense or a guarantee against
kernel vulnerabilities. Container availability does not enable remote challenges.

Untrusted archives are never executed or extracted to chosen filesystem paths. Sources
are bounded and copied to content-addressed snapshots; traversal, links, devices, duplicate
archive names and decompression excess are denied. Pure Python parsers remain a trusted
code surface. The original source directory and private state must not be concurrently
modified by a malicious local process. Local administrator compromise is outside the model.

Candidates require a trusted independent digest plus derivation replay to count as solved.
This verifier is suitable for synthetic tests or known commitments; it is not a universal
live-challenge oracle. No scoreboard submission is performed. Replaying an encoding alone
would not establish a flag's authenticity.

State includes original artifact bytes and candidate values. Routine output is redacted,
but redaction is not a complete secret detector. Protect state with OS access controls;
it is not encrypted at rest. Never commit run databases, private traces, model weights,
credentials or real flags. Reusable knowledge uses reviewed static generalizers and the
owner's schema; arbitrary model-authored learning is not accepted automatically.

Report vulnerabilities privately through the repository owner's available GitHub security
reporting channel. If unavailable, contact the maintainer without posting exploit details,
credentials or private CTF data in a public issue. Security tests use synthetic content only.

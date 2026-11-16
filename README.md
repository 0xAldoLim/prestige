# PRESTIGE V3

**An OpenCode-native autonomous CTF solver with isolated tools, evidence and independent verification.**

PRESTIGE is for CTF players, challenge authors and security researchers who want an
agent that can use real analysis tools without handing the model unrestricted access
to the operator's host. OpenCode owns model transport and interactive sessions;
PRESTIGE owns tool execution, evidence, scope, verification and recovery.

V3 is a release candidate. It is not claimed to solve every challenge. Benchmark
results are published with their exact cohort, budget and limitations in
[Benchmark V2](docs/benchmarks/CTF_EVALUATION_V2.md) and the companion
[CTF evaluation](docs/benchmarks/CTF_EVALUATION.md). Current evidence does not show a
solve-rate advantage over a strong OpenCode + skills baseline.

## What V3 provides

- **Lightweight default agent**: create one investigation, then use isolated tools
  directly. No mandatory hypothesis or status ceremony.
- **Isolated arbitrary tool execution**: `prestige_exec` runs bounded argv inside the
  pinned Docker worker, with no host shell, no host credentials, no Docker socket and
  no network unless an operator explicitly authorizes a registered endpoint.
- **Broad installed-tool access**: shell, Python, file utilities, GDB, radare2/Ghidra
  when present in the reviewed worker image; missing tools fail with an actionable
  diagnostic instead of falling back to the host.
- **Authorized remote services**: HTTP, HTTPS, TCP and SSH through operator-registered,
  investigation-bound targets. The model cannot register, enable or widen scope.
- **Persistent sessions**: Python, GDB, radare2, shells or other commands installed in
  the worker can remain alive across model turns.
- **Skills and research**: owner CTF skills are read-only; web search supports
  DuckDuckGo, Tavily or an operator-hosted SearXNG endpoint; all retrieved text is
  untrusted reference data.
- **Evidence and verification**: content-addressed artifacts, replayable derivations,
  independent operator commitments, explicit final submissions, provenance and
  deception classification.
- **Recovery**: durable jobs, pause/resume, session cleanup, budget enforcement and
  resumable benchmark batches.

## Requirements

- Python 3.11+
- [OpenCode](https://opencode.ai/) with a configured model/provider
- Docker for isolated analysis, tools and sessions
- Optional: GDB, Ghidra, radare2, Wireshark/tshark, binwalk, exiftool, SageMath,
  pwntools, angr, Frida, QEMU, Playwright — install them in the reviewed worker image,
  not on the host for challenge execution

## Install

```bash
git clone https://github.com/0xAldoLim/prestige.git
cd prestige
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
prestige doctor
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m prestige doctor
```

The package is not published on PyPI. `prestige` and `python -m prestige` are
equivalent.

## Configure the isolated worker

PRESTIGE never executes unknown challenge binaries on the host. Configure a reviewed,
immutable local image:

```bash
prestige --home ./.prestige config set sandbox.image \
  python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39
prestige security sandbox-test \
  --image python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39
```

The default image is intentionally minimal. Build a reviewed worker image containing
the CTF tools you need (GDB/pwndbg, pwntools, radare2, Ghidra, tshark, binwalk,
exiftool, Playwright, etc.) and pin it by digest. A missing tool in the image is a
tooling failure, not permission to run it on the host.

## OpenCode integration

The project registers a restricted `prestige` agent in `opencode.jsonc`. It can call
only `prestige_*` MCP tools; host shell/read/write/browser tools are denied. The
isolated worker provides shell and language capabilities through `prestige_exec`.

```bash
python -m prestige agent
# or use the plugin registration in opencode.jsonc
opencode run --standalone --agent prestige --model opencode-go/kimi-k3.1-pro \
  "Solve the authorized challenge in this workspace."
```

If you use a custom structure, configure `PRESTIGE_HOME` and
`PRESTIGE_ALLOWED_DIRS`. Do not expose provider credentials to the worker.

## Solve a local challenge

```bash
prestige --home ./private/state solve ./challenge --mode auto --offline
prestige --home ./private/state status
```

For an operator-known answer, use a separately supplied SHA-256 commitment:

```bash
prestige commitment add <source-artifact-sha256> <expected-candidate-sha256>
prestige verify-candidate --expected-sha256 <digest> < candidate.txt
```

A flag-shaped string is not a solve. A model claim, intermediate observation or
guessed candidate is not a solve. A candidate is verified only by an operator
commitment or a legitimate challenge checker.

### Authorized interactive CTF services

An operator registers an exact target, then binds it to an investigation:

```bash
prestige target register registration.json
prestige target list
prestige target bind RUN_ID TARGET_ID
PRESTIGE_REMOTE_ENABLED=1 python -m prestige agent
```

HTTP/HTTPS/TCP/SSH scope is enforced outside the model: pinned DNS, exact host/port,
path exclusions, rate/request limits, expiry and cancellation. Redirects and metadata
addresses are rejected. Competition platforms, scoreboards and provisioning systems
must never be registered or probed.

## Tools

The worker tool registry exposes content transforms (`inspect`, `strings`, `read`,
`file`, `pdf`, base64/hex/XOR/ZIP), bounded Python, arbitrary argv through
`prestige_exec`, and durable Ghidra/radare2 jobs. Persistent sessions can run any
command installed in the worker. `prestige_exec` is not a host shell.

Use the pinned worker for all untrusted challenge programs, including malware. Keep
network access disabled for offline work. Malware analysis and exploit development
must remain inside disposable, resource-limited containers.

## Web research

Research is disabled by default. Enable it and choose a provider:

```bash
prestige --home ./.prestige config set research.enabled true
prestige --home ./.prestige config set research.search_provider duckduckgo
# or:
prestige --home ./.prestige config set research.search_provider searxng
prestige --home ./.prestige config set research.searxng_url https://search.example
# or use TAVILY_API_KEY with:
prestige --home ./.prestige config set research.search_provider tavily
prestige --home ./.prestige research sources
```

Retrieved content is cached with SHA-256 provenance and marked untrusted. It is not an
instruction source and cannot change scope, tools or verification. In blind
benchmarks, disable research or block solution/writeup access.

## CLI quick reference

```text
prestige doctor
prestige solve PATH [--mode fast|auto|expert] [--offline]
prestige status | report RUN_ID | logs RUN_ID
prestige pause RUN_ID | resume RUN_ID | stop RUN_ID
prestige agent
prestige target list|register|show|bind|unbind|enable|disable|revoke
prestige skills discover|route|search|read|pivots|apply
prestige knowledge list|search|inbox|propose|promote|reject|quarantined|release
prestige research sources|fetch|search|web-search
prestige commitment list|add|remove
prestige verify-candidate --expected-sha256 DIGEST
prestige security audit RUN_ID
```

Run `prestige --help` or `python -m prestige --help` for the full surface.

## Security and isolation

- Challenge artifacts, tool output, skills, research and model text are data, never
  authority.
- Only operator-controlled registrations, rules, images, budgets, expected digests and
  final submissions can change policy.
- The worker has no host mounts beyond the investigation input/output, no Docker
  socket, no provider credentials, dropped capabilities and resource limits.
- Verification is independent of the model; `prestige_submit_final` records a
  submission but does not verify it.
- Deception findings are evidence, not blockers; high-risk content is quarantined in
  memory rather than silently accepted.
- Do not use PRESTIGE to attack competition infrastructure, other teams, unrelated
  hosts or systems you do not own.

## Limitations

- No universal solvability or benchmark superiority is claimed.
- Only challenges with participant-visible artifacts and an independent checker or
  operator answer are eligible for verified evaluation.
- The default worker image is minimal; specialized tools must be installed in a
  reviewed image.
- Browser-automation research and some interactive services depend on optional
  installed components and are not guaranteed on every platform.
- Windows supports the core CLI and supported tests; container-backed tools require
  Docker Desktop/WSL configuration.

## Benchmarks and evidence

- V2 evaluation: `docs/benchmarks/CTF_EVALUATION_V2.md`
- Machine-readable V2: `benchmark-results/sasctf-2026-v2.json`
- Eligibility inventory: `benchmark-results/sasctf-2026-eligibility.json`
- V3 service pilot: see the V3 section in the benchmark report

The repository intentionally does not publish private answers, raw transcripts,
operator state or sensitive target configurations.

## Research acknowledgments

PRESTIGE is independent and not endorsed by the projects below. It is informed by
OpenCode-for-CTF, D-CIPHER, EnIGMA, CTFAgent, PentestGPT, CTFusion, AgentLSD,
CTF-ABACUS, Arditi et al. and the owner/upstream CTF skills. See
[attribution](docs/ATTRIBUTION.md), [provenance](docs/PROVENANCE.json) and
[third-party notices](THIRD_PARTY_NOTICES.md).

## Contributing

Read `AGENTS.md`, `docs/PRODUCT_CONTRACT.md`, `docs/ARCHITECTURE.md` and
`docs/CONTINUATION.md`. Keep security boundaries outside the model, add executable
positive/negative tests, do not commit private benchmark material, and report
negative results honestly.

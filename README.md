# PRESTIGE V3.1

**An OpenCode-native autonomous CTF solver with isolated tools, evidence and independent verification.**

PRESTIGE is for CTF players, challenge authors and security researchers who want an
agent that can use real analysis tools without handing the model unrestricted access
to the operator's host. OpenCode owns model transport and interactive sessions;
PRESTIGE owns tool execution, evidence, scope, verification and recovery.

V3.1 is a release candidate. It is not claimed to solve every challenge. Benchmark
results are published with their exact cohort, budget and limitations in the
[V3.1 stabilization report](docs/benchmarks/CTF_EVALUATION_V3_1.md),
[Benchmark V2](docs/benchmarks/CTF_EVALUATION_V2.md) and the companion
[CTF evaluation](docs/benchmarks/CTF_EVALUATION.md). Current evidence does not show a
solve-rate advantage over a strong OpenCode + skills baseline.

## What V3.1 provides

- **Strict model routing**: a delegation-only Kimi orchestrator, a DeepSeek execution
  subagent and a DeepSeek PRESTIGE CTF agent, with built-in agents disabled.
- **Lightweight default agent**: create one investigation, then use isolated tools
  directly. No mandatory hypothesis or status ceremony.
- **Isolated arbitrary tool execution**: `prestige_exec` runs bounded argv inside the
  pinned Docker worker, with no host shell, no host credentials, no Docker socket and
  no network unless an operator explicitly authorizes a registered endpoint.
- **Broad installed-tool access**: shell, Python, file utilities, GDB, radare2/Ghidra
  when present in the reviewed worker image; missing tools fail with an actionable
  diagnostic instead of falling back to the host.
- **Authorized remote services**: HTTP, HTTPS, one-shot TCP and persistent interactive
  TCP sessions through operator-registered, investigation-bound targets. Persistent
  sessions support arbitrary binary send, exact/delimiter reads, live connection reuse,
  EOF/reset detection, expiry cancellation and cleanup. SSH is supported through the
  remote SSH adapter. The model cannot register, enable or widen scope.
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
python -m pip install -e '.[mcp]'
prestige doctor
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[mcp]"
.\.venv\Scripts\python.exe -m prestige doctor
```

The package is not published on PyPI. `prestige` and `python -m prestige` are
equivalent.

## Configure the isolated worker

PRESTIGE never executes unknown challenge binaries on the host. Configure a reviewed,
immutable local image:

```bash
prestige --home ./.prestige config set sandbox.image \
  sha256:987cc389afc23e21fce00011bd094249e66c7d1a36f9d0c6e318fddfc63a65f1
prestige --home ./.prestige doctor
prestige security sandbox-test \
  --image sha256:987cc389afc23e21fce00011bd094249e66c7d1a36f9d0c6e318fddfc63a65f1
```

The default image is intentionally minimal. Build a reviewed worker image containing
the CTF tools you need and pin it by digest. Reproducible core and pwn Dockerfiles are
in [`docker/`](docker/) and documented in [worker images](docs/WORKER_IMAGES.md). The
pwn image includes GDB, pwntools, Z3, GCC, file/strings/xxd, curl, git and network
utilities. Radare2/Ghidra/Playwright are optional additions. A missing tool in the
image is a tooling failure, not permission to run it on the host.

## OpenCode integration

The project uses strict two-model routing in `opencode.jsonc`:

- **`orchestrator`** (`opencode-go/kimi-k3.1-pro`, primary) plans, delegates and
  reviews. It may read/glob/grep and call only the `executor` and `prestige`
  subagents; it has no shell, edit, write, browser, web or skill tools.
- **`executor`** (`opencode/deepseek-v4.1-flash-free`, subagent) does implementation,
  commands, debugging, tests and research autonomously and cannot spawn subagents.
- **`prestige`** (`opencode/deepseek-v4.1-flash-free`, mode `all`) is the direct CTF
  solver. It can call only `prestige_*` MCP tools; host shell/read/write/browser/skill
  tools are denied. The isolated worker provides execution through `prestige_exec`.

`default_agent` is `orchestrator`; the root fallback model and the
`compaction`/`title`/`summary` helpers use `opencode/deepseek-v4.1-flash-free`.
Provider policy denies every provider except `opencode-go` and `opencode`, and the
checked-in disable lists leave `opencode models` with exactly those two routes.
Built-in `build`, `plan`, `general` and `explore` agents are disabled. Paid
`opencode-go/deepseek-v4.1-flash` (displayed as `DeepSeek V4.1 Flash 1017`),
GPT-6 Luna, DeepSeek V4 Pro and every other fallback are disabled; a free-route
failure must be reported, never silently substituted. See
[model routing](docs/MODEL_ROUTING.md) for the validated trace, catalog metadata,
fallback limitations and the minimal-Kimi-intervention policy.

```bash
# interactive development starts the orchestrator
opencode

# scripted delegated work: Kimi plans, DeepSeek executes
opencode run --standalone --agent orchestrator \
  "Run the offline test suite with the executor and report exact failures."

# direct CTF solving through the trusted Python broker
python -m prestige agent
opencode run --standalone --agent prestige \
  "Solve the operator-authorized challenge in this workspace."
```

Do not add `--model` for normal use; the checked-in configuration pins the assigned
models. If you use a custom structure, configure `PRESTIGE_HOME` and
`PRESTIGE_ALLOWED_DIRS`. Do not expose provider credentials to the worker.

Model routing is a cost and instruction-following arrangement, not a security
sandbox. PRESTIGE's operator-controlled scope, tool authorization, verification
commitments and isolated worker remain authoritative.

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
- The Sunk_Cost adaptive pilot did not demonstrate a solve-rate advantage; its KE condition did not exercise the child executor handoff.
- Only challenges with participant-visible artifacts and an independent checker or
  operator answer are eligible for verified evaluation.
- The default worker image is minimal; specialized tools must be installed in a
  reviewed image.
- Browser-automation research and some interactive services depend on optional
  installed components and are not guaranteed on every platform.
- Windows supports the core CLI and supported tests; container-backed tools require
  Docker Desktop/WSL configuration.

## Benchmarks and evidence

- V3.1 stabilization and qualification: `docs/benchmarks/CTF_EVALUATION_V3_1.md`
- Machine-readable V3.1: `benchmark-results/sasctf-2026-v3_1.json`
- V2 evaluation: `docs/benchmarks/CTF_EVALUATION_V2.md`
- Machine-readable V2: `benchmark-results/sasctf-2026-v2.json`
- Eligibility inventory: `benchmark-results/sasctf-2026-eligibility.json`
- V3 service pilot: see the V3 section in the benchmark report
- Adaptive DD/KE/DP pilot (Sunk_Cost 0/15 verified; aborted JSculator cohort kept separate): `docs/benchmarks/ADAPTIVE_EXECUTION_PILOT.md` and `benchmark-results/adaptive-pilot.json`
- Model routing and real trace evidence: `docs/MODEL_ROUTING.md`

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

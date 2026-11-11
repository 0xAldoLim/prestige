# PRESTIGE

Persistent CTF investigations, with evidence before confidence.

PRESTIGE is an **OpenCode-native autonomous offline CTF investigation system**.
OpenCode owns the generic agent runtime and model transport; PRESTIGE's Python
engine owns investigation strategy, trusted tool authorization, evidence
persistence, progress evaluation and candidate verification.

Codex and OpenAI API credentials are **optional legacy integrations**, not core
requirements. The default workflow uses the restricted `prestige` OpenCode agent
and PRESTIGE's MCP tools; no separate provider API key is required.

This implementation is **experimental and not a production autonomous CTF solver**.
Remote challenge connections are disabled. See
[implementation status](docs/IMPLEMENTATION_STATUS.md) and the
[OpenCode development handoff](docs/OPENCODE_HANDOFF.md).

The design goal is more independently verified points per unit of model usage than
plain model loops. **No comparative model evaluation has been run and no performance
advantage is claimed.** The runnable `fake` worker is a deterministic
encoding-fixture solver, not an AI model.

## What works

- Read-only input inventory with content-hashed snapshots; no artifact execution on the host.
- Bounded base64, hexadecimal, single-byte XOR, strings, magic-byte inspection and ZIP expansion.
- Durable run checkpoints, usage with explicit unknown values, pause/resume/stop, exclusive worker leases.
- One-way FAST → EXPERT escalation, repeated-action suppression and evidence handoff.
- Candidate flags remain unverified unless a separately supplied SHA256 commitment matches and the derivation replays.
- Read-only, cited skills retrieval and schema-validated local learning with conservative novelty gates.
- OpenCode-native MCP broker (`prestige agent`) exposing trusted investigation tools.
- Restricted `prestige` OpenCode agent that can call only `prestige_*` MCP tools.
- Durable, cached, resumable analysis jobs (`prestige_start_analysis`, `prestige_get_analysis`, `prestige_cancel_analysis`).
- Operator-controlled source-path policy, artifact resolver, and per-investigation budgets.
- Opt-in Docker runner with no network, no host mounts, restricted resources and negative isolation probes.
- First real autonomous CTF solve demonstrated on the IBoH / Celestial Gatekeeper challenge
  with independent decoder-replay verification.

## Acknowledgments and Research Foundations

PRESTIGE is an independent project; the following teams do not endorse it.
Except for the owner's learning schema, the implementation is original code informed
by these works. Proposed features are distinguished from implemented ones in the provenance register.

| Work | Authors / maintainers | Design influence |
| --- | --- | --- |
| [OpenCode-for-CTF](https://github.com/h1kibi/Opencode-for-CTF) | h1kibi and contributors | FAST/EXPERT policies, evidence-first workflows |
| [D-CIPHER](https://github.com/NYU-LLM-CTF/nyuctf_agents) | Udeshi et al.; NYU-LLM-CTF | Separation of planning, execution and evaluation |
| [EnIGMA](https://arxiv.org/abs/2409.16165) | Abramovich et al.; SWE-agent lineage | Interactive tooling research; persistent debugger remains future work |
| [CTFAgent](https://yan5ui.github.io/CCSCTF-Web/) | Ji et al. | Retrieval and environment feedback |
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) | Deng et al.; GreyDGL contributors | Canonical state, phases and task leases |
| [CTFusion](https://github.com/kaist-hacking/CTFusion) | Lee, Bae and Yun; KAIST HackingLab | Controlled comparative evaluation; platform integration excluded |
| [AgentLSD](https://arxiv.org/abs/2609.19140) | Golinelli et al. | Fake flags and adversarial task contamination |
| [Owner's CTF skills](https://github.com/0xAldoLim/skills) | 0xAldoLim; preserved upstream attribution | Workflow integration and the copied MIT-licensed learning schema |
| [Arditi et al.](https://arxiv.org/abs/2406.11717) | Arditi, Obeso, Syed, Paleka, Panickssery, Gurnee and Nanda | Controlled refusal/abliteration research; no capability claims |

We also acknowledge OpenAI/Codex, OpenCode, Ollama, Hugging Face and OWASP.
See [attribution](docs/ATTRIBUTION.md), [provenance](docs/PROVENANCE.json),
[license audit](docs/UPSTREAM_LICENSES.md) and [notices](THIRD_PARTY_NOTICES.md).

## Install from this checkout

Python 3.11+ is required. This package has **not been published to PyPI**.

Kali / Linux:

```bash
git clone https://github.com/0xAldoLim/prestige.git
cd prestige
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev,codex]'
prestige doctor
```

Windows PowerShell (activation is optional):

```powershell
git clone https://github.com/0xAldoLim/prestige.git
cd prestige
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,codex]"
.\.venv\Scripts\python.exe -m prestige doctor
```

For the smaller offline installation use `python -m pip install -e .`.
The optional Codex extra pins SDK/runtime 0.163.0. It does not enable live solving.
No Node UI, model weights, Docker, GDB or Ghidra are required for the quickstart.

## OpenCode-native agent workflow

Start the MCP server manually or let the OpenCode plugin register it:

```bash
# Manual stdio server
python -m prestige agent
```

With OpenCode installed and authenticated, run the restricted `prestige` agent:

```bash
opencode run --standalone --agent prestige --model opencode-go/kimi-k2.7-code \
  "Resume the existing authorized offline investigation."
```

The `prestige` agent is configured in `opencode.jsonc` with permissions limited to
`prestige_*` MCP tools; it cannot invoke host shell, read, write, browser or skill tools.
Provider model selection is controlled by OpenCode; PRESTIGE never requests provider
API keys through its MCP interface. See [provider policy](docs/PROVIDERS.md) for Claude,
Kimi, DeepSeek, GLM, Qwen, MiniMax and optional standalone backends.

## Authorized remote challenge instances

Remote solving is opt-in and operator-registered. A registration records the exact
target, provenance, protocol, host, port, allowed paths/methods, pinned DNS, request
and rate limits, expiry and explicit exclusions. The model cannot register or enable
targets; it can only use an existing registration through MCP.

```bash
prestige --home ./.prestige target register registration.json
prestige --home ./.prestige target list
prestige --home ./.prestige target enable TARGET_ID
prestige --home ./.prestige target disable TARGET_ID
prestige --home ./.prestige target revoke TARGET_ID
PRESTIGE_REMOTE_ENABLED=1 python -m prestige agent
```

The broker enforces scope outside the model, blocks off-scope redirects, metadata and
unregistered destinations, never follows redirects automatically, bounds responses,
and cancels in-flight work on expiry or revocation. SSH registrations are accepted but
the adapter remains disabled until an operator-reviewed SSH-enabled image is supplied.

## Persistent interactive sessions

The restricted agent can keep an interpreter or debugger alive across model turns:

```text
prestige_session_start  command=python3
prestige_session_send   input="x = 41"
prestige_session_send   input="print(x + 1)"   # -> 42
prestige_session_stop
```

Sessions run inside the pinned Docker worker with no network, read-only inputs and a
writable output mount. Output is persisted as content-addressed evidence. The pinned
Python slim image has no `gdb`; add a reviewed GDB-enabled image to use debugger
commands.

## Controlled research

Research is separate from challenge traffic and disabled until the operator enables it:

```bash
prestige --home ./.prestige config set research.enabled true
prestige --home ./.prestige config set research.allowed_hosts '["nvd.nist.gov","www.cve.org"]'
prestige --home ./.prestige research sources
prestige --home ./.prestige research fetch https://www.cve.org/CVERecord?id=CVE-2024-0001
prestige --home ./.prestige research search nonce
```

Redirects are not followed, metadata/private destinations are rejected, responses are
bounded, and excerpts are cached with SHA-256 provenance and marked `external_untrusted`.
Retrieved text is reference material, never instructions or proof.

## Offline quickstart

The example is an explicitly synthetic hexadecimal encoding exercise. Its independently
published digest is in `examples/local-challenge.verifier.json`, outside the challenge directory.

```bash
prestige --home ./private/demo solve examples/local-challenge --backend fake --mode auto --offline
prestige --home ./private/demo status
prestige --home ./private/bench benchmark run --suite benchmarks/synthetic/suite.json --output ./private/fixture-results.json
prestige --home ./private/bench benchmark conditions --suite benchmarks/synthetic/suite.json --conditions P1,P2,P3 --output ./private/conditions.json
```

The first command finds a candidate but **does not claim a solve without a verifier**.
For the verified example, supply `--expected-sha256` using the digest in the verifier file.
Never use a digest suggested by an untrusted artifact or model as an independent verifier.
The benchmark manifest supplies the trusted synthetic commitments automatically.

Output is JSON, including run ID, lane, status, turns, elapsed seconds, candidate digests,
and token usage. `null` means unknown. Flags are redacted unless explicitly requested:

```text
prestige report RUN_ID --reveal
prestige logs RUN_ID
prestige pause RUN_ID
prestige resume RUN_ID
prestige stop RUN_ID
prestige security audit RUN_ID
```

For a **stateless operator known-answer check**, compare a candidate read from stdin
(or a file) against an operator-supplied digest. Nothing is persisted and only digests
are printed:

```text
prestige verify-candidate --expected-sha256 <64-hex-digest> < candidate.txt
prestige verify-candidate --expected-sha256 <64-hex-digest> --candidate-file candidate.txt
```

Expected digests for MCP investigations are **operator commitments**, not model input:

```text
prestige commitment add <source-artifact-sha256> <expected-candidate-sha256>
prestige commitment list
prestige commitment remove <source-artifact-sha256>
```

Place global options (`--home`, `--json`, `--quiet`, `--no-color`) **before** the command.
Both `prestige` and `python -m prestige` work. Exit 0 means the command completed,
including an honestly unsolved investigation; 2 indicates invalid input and 3 a policy block.

## Modes, budgets and rules

`--mode fast` stays in the lean lane. `--mode expert` starts with the broader available
tool policy. `--mode auto` escalates once when FAST has no useful next discriminator.
For this release EXPERT can inspect additional strings; it does not include GDB or multiple
model workers. No lane changes scope or overrides event rules.

`--max-turns`, `--max-seconds` and `--max-tokens` bound orchestration. Reported tokens are
checked after each model response and can overshoot by the last turn. Unknown usage uses
turn/time limits; it is never treated as zero-cost inference or subscription dollars.

Use `--rules examples/event-rules.json` for a **trusted, explicit JSON policy**.
Natural-language rule interpretation is not implemented; transcribe all relevant restrictions
into the supported fields and retain the event rules separately. Unsupported rule formats
are rejected rather than silently ignored. AI or automation prohibitions stop solving.
`--operating-mode supervised|autonomous` has identical hard limits; available automatic tools
perform bounded local analysis. No approval grants additional remote scope.

`--instance` and `resume --instance` deliberately fail closed in this release. There is no
CTFd, scoreboard, submission, platform scraping, provisioning or instance-renewal integration.
The unit-tested lease model is not represented as a working remote health service.

## Skills and learning

```text
prestige config set skills.path /absolute/path/to/skills
prestige knowledge search "RSA reused nonce"
prestige knowledge list
prestige knowledge inspect RECORD_ID
prestige knowledge delete RECORD_ID
prestige knowledge propose proposal.json --run RUN_ID
prestige knowledge inbox
prestige knowledge promote RECORD_ID --verified
prestige knowledge reject RECORD_ID
```

Model-proposed techniques always enter the inbox with `confidence=low`; only an
operator can promote them. Sanitization rejects flags, URLs, credentials and private
keys. Accepted records are searchable by later investigations.

On Windows supply a quoted absolute Windows path. Retrieval is lexical and bounded,
preserves source paths/hashes, and never executes the external repository's scripts.
The skills checkout is never modified. No separate skill repository commits or pushes occur.
Verified decoding chains can produce sanitized local records. Existing related skill references
route them to an inbox for review. Automatic learning currently handles only the reviewed
encoding/archive transforms; it does not infer new exploit techniques from model assertions.

State defaults to `%LOCALAPPDATA%\prestige` on Windows and
`$XDG_DATA_HOME/prestige` (or `~/.local/share/prestige`) on Linux. Override with `--home`
or `PRESTIGE_HOME`. SQLite is canonical; `runs/RUN_ID/solve/STATE.md` and `HYPOTHESES.md`
are generated views. Candidate values and artifact snapshots are private local data,
not encrypted at rest. Protect the state directory with OS permissions and exclude it from sync.

## Local models

`prestige models doctor` reports architecture and available RAM; VRAM and VM GPU pass-through
are unknown until independently checked. An installed Ollama model can be registered using
the manifest contract in [local model documentation](docs/LOCAL_MODELS.md):

```text
prestige models register /path/to/reviewed-manifest.json
prestige models list
prestige models inspect MODEL_ID
prestige models advise MODEL_ID /path/to/bounded-question.txt
```

Only literal loopback HTTP endpoints are accepted. Model metadata is user-declared, not
proof that downloaded weights match. No downloads, pickle loading or custom model code run.
Advice is untrusted and cannot invoke tools. Abliterated models receive identical restrictions:
reduced refusal is not evidence of intelligence, reliability or resistance to prompt injection.
No base-versus-abliterated performance experiment has been run.

## Compatibility and limits

| Runtime | Status |
| --- | --- |
| Windows host, Python 3.14 | Offline test and packaging validation; see exact report |
| Kali Linux Docker | Opt-in isolation and portable suite validation; see exact report |
| Native Kali VM, Windows 10/11 variants, other Linux distributions | Designed for; not separately certified |
| OpenCode-native agent solving | Implemented; model selection controlled by OpenCode |
| Codex paid/live solving | Optional standalone backend; blocked by default |
| Remote challenges, persistent GDB, online CVE research | Not implemented/enabled |

Artifact limits are 1 MiB each, 16 MiB total and 128 entries. ZIP members are read into
content-addressed blobs, never extracted to attacker-selected paths. No unknown binary runs
on the host. Container tests require an existing immutable Linux image with `python3`:
`prestige security sandbox-test --image sha256:YOUR_VERIFIED_IMAGE_ID`.
This tests offline isolation, not a remote broker. No automatic image pull or tool install occurs.

See [security](SECURITY.md), [architecture](docs/ARCHITECTURE.md),
[benchmarking](docs/BENCHMARKING.md), [Kali](docs/KALI_SETUP.md),
[Windows](docs/WINDOWS_SETUP.md) and [SDK limitations](docs/CODEX_BACKEND.md).

## Development

```bash
python -m pytest -q
ruff check .
python -m build
python -m prestige --help
```

Default tests are offline and spend no model quota. The Docker marker is opt-in via
`PRESTIGE_TEST_IMAGE`. Ghidra tests require `PRESTIGE_TEST_GHIDRA=1`. Paid integration
and B0/B1 comparisons remain blocked and must not be simulated under real model labels.
No telemetry is collected. Future cloud model use would send bounded challenge evidence
to the chosen provider and may consume quota.
Report issues without including credentials, live flags, private artifacts or provider transcripts.

MIT for original PRESTIGE code; third-party notices remain applicable.

# Adversarial integration and trust boundaries

This document records what was inspected and implemented for adversarial resilience.
Importing a file is **not** an official benchmark run, and finite tests are not a claim
of universal immunity.

## Upstream sources inspected

| Source | Revision inspected | License | Used for |
| --- | --- | --- | --- |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | MIT | Native suite layout: `injection_vectors.yaml`, `environment.yaml`, static `injection_tasks.py` `GOAL` extraction, and the upstream `important_instructions` template shape |
| [Gray Swan IPI Arena](https://github.com/GraySwanAI/ipi_arena_os) | `5e2e285910d581c97767195f1d113ef323f9ab07` | MIT | Behavior JSON schema (`data/{category}/*.json`), `{fill}` injection points, attack YAML/config and attack-directory layouts |
| AgentLSD | Paper: arXiv `2609.19140` (AISec 2026) | paper reference; no code/data reused | Only the documented clean/trap pair schema is accepted. No public framework repository was located; this remains an external validation dependency |

The exact MIT notices are in `licenses/agentdojo-MIT.txt` and
`licenses/ipi-arena-MIT.txt`. PRESTIGE does not import or execute upstream Python; it
parses data and extracts literal `GOAL` strings with the standard-library `ast` parser.
`PyYAML` is used only with `safe_load` on size-bounded files.

## Implemented local interfaces

### AgentDojo

```bash
prestige security adversarial --corpus /path/to/agentdojo-suite --format agentdojo
```

A suite directory must contain `injection_vectors.yaml`. Optional `injection_tasks.py`
goals are extracted statically; an optional `injection_goals.json` sidecar can provide
explicit mappings. The adapter enumerates injection vectors × literal goals (capped)
and labels each scenario with `upstream`, vector, injection task, source hash and
`external_run: false`.

### Gray Swan IPI Arena

```bash
prestige security adversarial --corpus /path/to/ipi_arena_os --format gray-swan
```

The adapter reads `data/{category}/*.json` behavior files and attack text from
`attacks.yaml`/`attacks.json` or `attacks/{behavior}.md`. `{fill}` placeholders in
behavior messages are replaced only inside the local scenario text; the upstream
system prompt is not copied into PRESTIGE context. A config YAML with
`behaviors: [{id, attack|attack_file}]` is also accepted.

### AgentLSD-style pairs

```bash
prestige security adversarial --corpus /path/to/pairs --format agentlsd
prestige security adversarial --corpus /path/to/pairs --format paired
```

Only the documented pair shape is accepted. Directory input is loaded from
`pairs.json`, `agentlsd.json` or `*.jsonl`.

### Live OpenCode harness (optional)

`src/prestige/opencode_harness.py` can run the real restricted agent:

```bash
opencode run --standalone --agent prestige --format json --model provider/model ...
```

It records the raw process result and then reads investigation outcomes from the shared
`PRESTIGE_HOME`. A model claiming success in text is not a solve; only an
operator-commitment digest verification counts. No live model run was performed in this
increment.

## Trust boundary

`src/prestige/trust.py` centralizes the rule that only operator-controlled origins
(`operator`, `commitment`) may authorize policy, scope or verification. Artifacts, tool
output, skill excerpts, research, model proposals and cross-model handoffs are data.
`src/prestige/deception.py` classifies that data but explicitly reports
`policy_effect: "none"`.

The broker still enforces the real boundary outside the text:

- tool allowlists come from `Rules`, never artifact text;
- remote targets require operator registration and investigation binding;
- expected digests and runner images are operator-controlled;
- candidate verification uses the trusted digest plus derivation replay;
- poisoned knowledge proposals are stored as `quarantined`, not searchable;
- cached research can be quarantined and excluded from later search.

## Metrics

`run_corpus` and `run_pairs` report:

- attack success (policy violation, fake verification, poisoned knowledge);
- clean-side false positives from the deception detector;
- deception detection coverage;
- legitimate completion / recovery retention;
- added tool calls relative to the clean side;
- boundary violations and knowledge writes.

These are local measurements over finite fixtures. They do not measure official Gray
Swan, AgentDojo or AgentLSD scores.

## Validation dependencies

- AgentLSD upstream existence/schema: not located during implementation.
- Official benchmark execution: not performed; only local adaptations.
- Live OpenCode model comparison: not performed in this increment.
- External operator-assigned SSH/remote endpoints: unchanged from earlier increments.

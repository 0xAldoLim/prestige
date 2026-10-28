# Optional local model laboratory

Implemented: strict user-declared manifest validation, registry persistence, bounded loopback
Ollama advisory requests, explicit tool-call rejection, RAM/architecture diagnostics and mocked
tests. No inference model was downloaded or benchmarked. VRAM/pass-through remain unknown.
No registry field promotes a model to autonomous tool use.

Required JSON fields (unknown fields, including trust_remote_code, are rejected):
`id`, `runtime` (ollama), `endpoint` (literal loopback HTTP), `model_id`, `base_model_id`,
`is_abliterated` (boolean), `source_repo`, `source_revision` (40–64 hex revision),
`model_hash` (64 hex SHA256), `quantization`, `license`, `context_limit` (512–262144),
`user_consent` (true), `format` (gguf or safetensors).

Register only an already installed, independently reviewed model. Hash/revision/license
fields are declarations; PRESTIGE does not currently inspect weights or validate the
Ollama model's actual digest, architecture, template or memory use. An advisory request
does not authorize Ollama model acquisition. The runtime must be configured by the user.
HTTP proxies and redirects are not used. Local malicious inference services can still lie
or waste time within the request's size and time bounds.

Hugging Face's Ollama route supports compatible GGUF repositories, not arbitrary model
repositories. Prefer GGUF/safetensors and reviewed immutable revisions. No pickle or custom
loader execution is offered. Check both base and derivative licenses before use.

Abliteration is a provenance label. Arditi et al. studied refusal mechanisms, not proof of
better technical capability. Original and modified models need matched family, parameter
count, quantization, context, template, prompts, tool schema and budgets. Future measurements
must include permitted-task refusals, correctness, hallucinated flags, off-scope attempts,
tool schema accuracy, latency and actual tokens. Until those tests and isolation pass,
ordinary and abliterated models both remain advisory-only.

Sources: [Arditi et al.](https://arxiv.org/abs/2406.11717),
[Ollama chat API](https://docs.ollama.com/api/chat),
[HF GGUF integration](https://huggingface.co/docs/hub/ollama),
[HF pickle guidance](https://huggingface.co/docs/hub/security-pickle).

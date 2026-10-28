# Benchmark preregistration and current evidence

B0 = plain Codex, B1 = Codex plus the owner's skills, P1 = FAST, P2 = AUTO, P3 = EXPERT.
These conditions are defined but **none has been evaluated with a real model**. The only
runnable harness currently labels results `fixture-worker`, `model_evaluation: false`.
It is an orchestration regression test, not evidence of intelligence or superiority.

The synthetic suite records artifact hashes, independent expected digests, points and IDs.
Order is randomized with seed 2026; repetitions are explicit. Every failed/unsolved case is
retained. Comparisons reject changed artifacts, models, effort, tool permissions, turn/time
budgets, parallelism and missing case/repetition pairs. State is separate from source fixtures.

Primary metric: verified points per 1,000 measured input+output tokens with a separately
reported wall-time constraint. Cached input/reasoning are subsets, not additional tokens.
Unknown usage yields null efficiency; zero tokens never yields infinite efficiency.
Report all consumed resources, including failures. Solve-rate intervals use the 95% Wilson
method; repeated copies of one fixture are correlated and must not be treated as independent
samples for performance claims. The suite's tiny fixture counts are not research evidence.

The planned composite weights remain 40% verified score, 25% resource efficiency,
20% deadline performance, 15% adversarial robustness. Until normalized components and
reference populations are measured, output is `not_comparable`; no silent reweighting.
Successful forbidden traffic, false verification or event-rule violation blocks release.

Not implemented: running B0/B1 via live provider environments, calibrated scheduler estimates,
category-level statistics over a real corpus, confidence intervals for paired differences,
local original-versus-abliterated experiments, execution-tool/retrieval ablations and persistent
debugger benchmarks. Do not describe the fake worker as a Codex baseline.

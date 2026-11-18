# V3.2 expanded-cohort readiness (pwn + crypto)

Date: 2026-11-17. Status: **dry-run ready, not executed. No expanded-cohort model
attempt was made.** The proposed cohort is 12 jobs: two tasks x two conditions x three
repetitions, 180 s each, seed `20261118`. It covers pwn and crypto only. Reverse, web,
forensics and misc candidates were inventoried but remain blocked for the reasons below.
No superiority claim is made.

This document and `benchmark-results/v3_2_expanded_readiness.json` contain no flag,
answer, answer-derived hash, checker logic, raw trace or private path. Raw views,
answers, commitments, services and checkers remain outside the repository.

## 1. Evidence boundary

- The read-only operator challenge workspace and the imported SASCTF 2026 corpus were
  inventoried without executing unknown binaries on the development host.
- The only challenge binary executed in this increment was the DEAD_DROP handout, and
  only inside an isolated container: read-only root, all capabilities dropped, no
  Docker socket, no host mounts beyond the challenge files, bounded memory/CPU/PIDs and
  no external network.
- Participant views were frozen from handout bytes only. Each view has a `VIEW.json`
  manifest whose digest excludes the manifest itself.
- Operator-private answers and commitments live outside the repository. Solver views
  contain no answer bytes or answer-derived digests.
- Services are local and isolated. No CTFd, scoreboard, organizer infrastructure or
  adjacent host was contacted.

## 2. Inventory summary

Two sources were reviewed:

1. The operator challenge workspace, containing ten IBoH 2026 archives plus operator
   solve directories, notes and a writeup. Solve material was never copied into a view.
2. The imported SASCTF 2026 corpus, containing 24 challenges. The five already used or
   blocked in V3.2 were excluded, as were Sanity, VENOM and JSculator.

### READY for a future approved cohort

| Task | Category | Source | Participant artifact | Service | Verification | Provenance |
| --- | --- | --- | --- | --- | --- | --- |
| `dead-drop` | pwn | IBoH 2026 | Original menu-driven 64-bit Linux handout binary plus a protocol README | Isolated TCP service on the private benchmark network | Equality over an operator synthetic flag injected at `/flag` | Benchmark-unseen but operator-solved; not claimed as unseen |
| `sunk-cost` | crypto | IBoH 2026 | Original self-contained mission brief with 16 high-bit blocks | Offline; none | Equality over the operator-supplied answer independently verified against all 16 blocks | Previously evaluated adaptive cohort, 0/15 verified, all 15 outer timeouts; not unseen |

Both tasks are equality-based. `dead-drop` is not derivation-verified; the local service
contains an operator synthetic flag and the checker compares the submitted value to that
commitment. `sunk-cost` uses the prior operator answer and the 16-block verification
already recorded in the adaptive pilot.

### BLOCKED candidates and exact reasons

| Candidate | Category | Reason |
| --- | --- | --- |
| `rev-fpga`, `pwn-snaking`, `pwn-snaking-revenge`, `web-naas`, `web-xod-revenge` | mixed | V3.2 overlap; already executed or excluded |
| `welcome-sanity-files` | welcome | Sanity overlap |
| `rev-venom` | reverse | VENOM overlap |
| `pwn-jsculator` | pwn | JSculator overlap |
| `You_Find_Lor` | OSINT | Targets a likely real private person; ethical/privacy exclusion |
| `Allowance_Day` | forensics | No authoritative prompt or flag format; only a phishing email |
| `Relay_Cascade` | pwn/reverse | No service descriptor, prompt or operator answer |
| `Oversimplified_Crackme` | reverse | AES-encrypted ZIP; password/prompt absent |
| `Conservation`, `Margins` | blockchain | Missing deployment, Setup or chain context |
| `BLACK_LANTERN` | kernel pwn | Requires VM/QEMU and a private answer; not safely provisioned |
| `misc-gatekeeper`, `misc-readyssornot` | misc/pwn | QEMU-based service, no private commitment |
| `net-incident-67` | network | VM/network lab, no private commitment |
| `pwn-sasenger` | pwn | Android/Cuttlefish VM, no private commitment |
| `game-backrooms`, `misc-cbt`, `misc-kolobok`, `misc-tgs`, `mlw-cyrill`, `web-paradoxy` | game/misc/web | Source-only or no participant files; no private commitment |
| `game-guba` | game | Missing multi-gigabyte external assets |
| `web-gav` | web | Compose exists, but required Go/gcc/alpine base images and module download are unavailable offline; handout also contains a `.git` tree needing review |
| `web-sentinel` | web | Compose exists, but required alpine/redis base images and apk packages are unavailable offline |
| `mlw-backfloppa` | malware | Participant artifact is only a URL to a missing multi-gigabyte archive; service needs privileged eBPF and a host Docker socket, violating the isolation model |

No mechanics were altered to force a candidate into READY.

## 3. Frozen views and checks

- `dead-drop`: protocol README and the original handout binary under `challenge/`.
- `sunk-cost`: the original mission brief as both `README.md` and `challenge/` handout.
- Each view has a `VIEW.json` manifest with per-file sizes and a tree digest over all
  files except `VIEW.json`.
- The dry run revalidated the tree digest, confirmed no answer bytes or commitment
  digests appear in either view, and recorded no contamination findings.
- The private checker parses exactly one `{"flag": "..."}` submission object, normalises
  trailing whitespace, and compares a SHA-256 commitment without printing answers.
- Checker self-test: positive, one-bit-mutated negative and empty candidate for both
  tasks; all passed.

## 4. Service and B/DP parity

`dead-drop` runs in an isolated container:

- Ubuntu 24.04 userland with glibc 2.39, matching the challenge's solved remote libc
  family.
- Read-only root, uid 65534, all capabilities dropped, no-new-privileges, bounded
  memory/CPU/PIDs and a small writable `/tmp`.
- No Docker socket and no external network. The only network is the private benchmark
  bridge.
- A static TCP wrapper serves a fresh process per connection; the service restart is
  verified by banner health and the injected flag commitment.

Parity paths verified in the dry run:

- **B:** the reviewed worker image on the private benchmark network resolved the service
  alias and read the banner.
- **DP:** an operator-registered loopback endpoint, forwarded by a host-only proxy to the
  isolated service, read the same banner.
- `sunk-cost` is offline and receives the identical participant view in both conditions.

Both conditions use the same model, skills checkout, 180 s cap, submission contract and
fresh workspace/state/reset discipline. No solver was invoked.

## 5. Frozen schedule and dry-run result

- Jobs: **12** = 2 tasks x 2 conditions x 3 repetitions.
- Seed: `20261118`; 180 s per job.
- Order: shuffled once with that seed and frozen before any attempt.
- Dry-run checks passed: schedule count/seed/tasks/conditions/seconds, view integrity,
  view contamination, checker self-test, service running, direct and DP-proxy banners,
  injected flag commitment, B sandbox path, DP loopback path, both-paths parity, model
  listing, worker image, service image, disk, skills commit and offline-task shape.
- No model process was launched; the recorded model-attempt count is zero.

## 6. Planning estimate

Measured V3.2 baseline: 19 paid model attempts used 653,940 uncached-input+output
tokens, 3,501,440 cache-read tokens and 319 tool calls. Per-attempt means were about
34,418 uncached-input+output tokens, 184,286 cache-read tokens and 16.8 tool calls.

Scaling those means to 12 jobs gives an estimate of about **413k uncached-input+output
tokens, 2.21M cache-read tokens and 202 tool calls**. A planning range of roughly
350k-450k uncached-input+output and 2.0M-2.5M cache-read tokens is more realistic given
task variation. The wall-clock cap is 2,160 s; with resets and startup overhead, plan for
about 45-55 minutes.

These are estimates, not predictions. Provider-reported cost was 0.0 on every measured
V3.2 step. Actual billing is unknown; no dollar estimate is fabricated.

## 7. Limitations and claim

- Readiness only; no expanded-cohort paid attempt and no solve.
- The cohort covers pwn and crypto only. Reverse, web, forensics and misc remain blocked.
- `dead-drop` is not unseen and not an independent solve; it uses an operator synthetic
  flag and equality checking.
- `sunk-cost` is not unseen; it carries a prior 0/15 adaptive result and an
  operator-supplied, 16-block-verified answer.
- Three repetitions per cell cannot support a superiority claim.
- A future paid cohort requires fresh operator approval. The 12-job count is proposed
  only if that approval is given.

**Claim:** dry-run readiness only. No comparative result is claimed.

## 8. Validation

- Full offline suite: **397 passed, 10 skipped**.
- `ruff check .`: clean.
- Wheel and sdist build: successful.
- `python -m prestige --help`: exit 0.
- Roadmap and both benchmark JSON files parse.
- `git diff --check`: clean.
- The full suite initially exposed a checked-in provider-policy drift: newly listed
  `opencode/gpt-6.2-astra` and `opencode/gpt-6.2-sol` models were not disabled. Both were
  added to the disabled provider list. This tightens the catalog to the intended routes
  and does not change the benchmark model.

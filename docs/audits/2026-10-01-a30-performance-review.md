# A30 stream scaling recheck (in progress)

The selected V1 profile keeps each completed attachment group in its own
bounded `Bytes` allocation. A retained first group does not retain all later
groups or following messages (`message_allocation.rs`). The pre-change parser
at `de08a972` shared the whole input allocation, so it is a useful throughput
control but does not satisfy the same retained-memory behavior.

## Same-host method

- Host: Apple M4 Pro, aarch64-darwin; current Nix development toolchain and
  one shared `CARGO_TARGET_DIR` for both builds. Runs were sequential, with
  no other benchmark run concurrently.
- Current head: `48482b06` (parser code from `cbd6c8f1`), command
  `nix develop --command cargo bench -p cesr-stream --bench stream -- stream_parse_scaling`.
- Pre-change: detached worktree at `de08a972`, same current Nix shell and
  target directory, command
  `CARGO_TARGET_DIR=/Users/joel/Code/devrandom/cesr/target nix develop /Users/joel/Code/devrandom/cesr --command cargo bench -p cesr-stream --bench stream -- stream_parse_scaling`.
- Each Criterion case used 3 seconds warmup and 100 samples. Raw command
  output: [current head](2026-10-01-a30-head-scaling.txt),
  [pre-change](2026-10-01-a30-pre-change-scaling.txt).

| Fixed two-signature groups | Pre-change median | Current median | Current versus pre-change |
| ---: | ---: | ---: | ---: |
| 1 | 75.911 ns | 64.760 ns | 14.7% faster |
| 16 | 704.55 ns | 870.66 ns | 23.6% slower |
| 64 | 2.5591 µs | 3.1992 µs | 25.0% slower |
| 256 | 10.024 µs | 13.572 µs | 35.4% slower |

The earlier same-host preflight, recorded in `TODO.md`, measured 9.9872 µs
versus 12.711 µs for 256 groups (27.3% slower) using the same parser code.
Together these runs support a material many-group throughput cost, with run
variance affecting its exact percentage. This is a fixed-size group parse and
collect workload; it does not measure message validation, signing, storage,
network delivery, or peak memory. The 1-group result improves because the V1
controller/witness parser no longer scans the same elements twice.

## Representative message parser workload

`keri-codec/benches/message.rs` measures the public V1 JSON/text message
parsers with a genuinely signed transferable inception. Key generation,
serialization and signing happen before measurement. One case parses one
signed event; a second parses the same body with 16 syntactically valid
controller-signature groups; a third parses 16 concatenated framed copies.
Repeated signatures/copies make the latter two parser workloads synthetic;
they do not represent 16 distinct KEL decisions or signature verification.

On the same Apple M4 Pro/aarch64-darwin host, `nix develop -c cargo bench -p
keri-codec --bench message -- --warm-up-time 3 --measurement-time 5
--sample-size 100` passed. Criterion reported these median estimates:

| Parser workload | Median | 95% interval reported by Criterion |
| --- | ---: | ---: |
| Signed inception, one group | 1.8063 µs | 1.8033–1.8093 µs |
| Signed inception, 16 groups | 4.7511 µs | 4.7452–4.7566 µs |
| Sixteen framed messages | 31.945 µs | 31.824–32.089 µs |

The benchmark is a current-head latency sample, not a paired pre-change
comparison or an end-to-end Kevery capacity result. Its first two inputs are
checked with `EventMessage::parse` before timing; the framed batch uses
`Message::parse` until the remainder is empty.

## Selo full accepted-KEL replay

Selo draft PR #37 at `582c980` adds an explicitly ignored integration
measurement. It builds one signed transferable V1 inception plus 1,023 signed
interactions under one AID, stores them as schema-1 Fjall accepted facts, and
calls the public `audit_kel` 11 times at each history length. The manual
release-mode command was `nix develop -c cargo test --release -p selo-kel
--test a30_replay_cost -- --ignored --exact
accepted_kel_replay_cost_by_history_length --nocapture`.

| Accepted facts | Median full replay, Apple M4 Pro/aarch64-darwin |
| ---: | ---: |
| 1 | 0.207 ms |
| 16 | 0.554 ms |
| 64 | 2.490 ms |
| 256 | 7.490 ms |
| 1,024 | 30.151 ms |

The store was open and warm, with no concurrent writer. This is a synthetic
single-controller interaction chain under Selo's currently **published** CESR
dependency graph. It does not measure the marker/outbox read, sink call,
receipt write, cold startup, recovery history, corrected unpublished CESR,
or a constrained device. `audit_kel` and the PR #37 delivery guard share the
full accepted-KEL replay loop, so these samples expose the guard's repeated
history cost, not complete effect-delivery latency. The Selo final-tree
`nix flake check -L --option max-jobs 1` passed all six compatible checks;
that ordinary gate compiled but did not execute the ignored measurement.
The owner still needs a bounded startup/cursor policy and target-device
acceptance criteria.

## PR CI at `5064d635`

The [deep-fuzz PR run](https://github.com/devrandom-labs/cesr/actions/runs/36883858957)
completed successfully: 14 libFuzzer jobs, 14 AFL++/CMPLOG jobs and the
aggregate fuzz gate reported success. The workflow configures 60 seconds per
target on pull requests; this is a smoke campaign, not a long-duration
release fuzz conclusion. The CI, CodeQL, deny and CodSpeed workflow runs for
that exact head also completed successfully.

The separate CodSpeed **Performance Analysis** check on the same head failed:
its simulation reported one regressed benchmark,
`stream_parse_scaling[16]`, from 16.3 µs at base to 18.3 µs at head
(reported efficiency −10.65%). It also reported eight improvements, 24
unchanged cases, three new message parser cases and 54 skipped cases. The
workflow's success means benchmark collection succeeded; it does not override
the failed performance analysis check. The same-host Criterion measurements
above independently show a many-group slowdown, but their absolute values
are not interchangeable with CodSpeed simulation results.

## Decision still required

The current parser has linear copied bytes and bounded retained memory; the
pre-change parser is faster on this many-group workload because its output
shares one allocation with the entire input. Restoring that ownership would
undo A05's retained-memory rule. A four-group chunk trial was slower for
1/16/64 groups and only slightly better at 256, so it was removed. The
CodSpeed simulation for PR #300 reports a separate regression and warns that
its compared runs used different runtime environments; it is not a clean
same-host attribution. The message parser cases above establish a current
latency sample but do not measure full validation, host storage or effect
delivery. A30 still needs the owner's throughput/memory acceptance decision
and a workload tied to target device limits before closing its performance
gate. No benchmark result here establishes production readiness.

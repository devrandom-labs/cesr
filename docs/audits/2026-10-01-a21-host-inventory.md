# A21 host acceptance inventory and first Selo slice

This track is still open. The repository and contract baseline is:

| Checkout | Revision | Relevant owner |
| --- | --- | --- |
| `cesr` | `de08a972b390ea640519d4dcb7343d5dc4a864b9` plus A01–A28 worktree | Pure KEL/TEL/credential/IPEX decisions |
| `selo` | `c7f394bf46c2e150dcdd38f36b7b0989d85ea68e` plus `feat/20-kel-aggregate` branch | Identity domain and application acceptance |
| `nexus` (Mnesis checkout) | `5d8096912fc3c41769a26c3a32073be2e321e851` | Aggregate/repository and atomic storage capabilities |
| `bombay` | `a7a66e3912731923015560463cd2c9e5e76fc041` | Actor runtime |
| `mnesis-bombay` | `9d567f6d4f113bf3ac5ffeb569c219efb0ecf160` plus unrelated local changes | Direct command execution and Bombay hosting |

`selo` at baseline contains only `selo-naming`; its open card #20 owns the
KEL aggregate domain, and #21 owns the event/escrow service. Its card #24
owns the custody seam. The accepted `mnesis-bombay` ADR 0001 says Mnesis is
the durable authority, Bombay actors are disposable hosts, command IDs differ
from aggregate/actor/stream identities, and external effects originate from
the committed log. Its project card #4's direct execution adapter is already
implemented. Cards #5 (aggregate Entity host), #7 (committed relay/effects),
#21/#22/#23 (projection/saga/assembly) remain open. The existing
`mnesis-bombay` worktree contains unrelated edits and is preserved.

Mnesis `AggregateRoot` separates storage `Version` (first accepted event is
1) from KERI sequence `s` (inception is 0). `AggregateState::apply` is an
infallible trusted fold over *already accepted* facts. Its `Repository::save`
appends the aggregate stream with optimistic version checking. Its lower
`AtomicAppend::atomic_append_many` capability can CAS several stream heads in
one store transaction, returning the highest committed global position;
`Repository::save` by itself does not atomically include a distinct durable
outgoing-intent or inbox stream. `mnesis-bombay` direct execution identifies
ambiguous commits and confirmed conflicts but does not substitute for the
Selo-specific multi-stream acceptance transaction. Mailbox publication is
not a durable effect receipt.

The Selo branch now pins the same published Mnesis 0.3.1 family as the
checked-out `mnesis-bombay` host. The branch adds `selo-kel`: a private Mnesis `Handle`
command parses the exact signed frame, verifies it with the published
`keri-rs` fold, binds the event prefix to the addressed AID, and emits a
constructor-restricted accepted fact. Public `KelAggregate::decide` derives
that AID from the loaded root. Rehydration uses `KeyStateSnapshot::genesis`
and trusted `advance`, checks KERI sequence/prior/prefix independently of
storage version, and enters a `Corrupt` state if accepted-fact order is
broken. The signed pinned inception/interaction fixtures prove this; a
repeated interaction at a new storage version failed the initial test and
now poisons replay. The published `keri-rs` 0.0.15 and `keri-codec` 0.9.0 have an
older public API than the A20–A28 worktree; the branch uses only their
published contracts while CESR changes await a release.

**Authentication release blocker discovered after the transaction gate:**
`scripts/keripy_a21_basic_attack.py` in Selo generated a 345-byte signed,
SAID-valid basic inception whose prefix belongs to a different key than its
controller/signature. Pinned keripy rejected it with `Mismatch prefix`. In
Selo, `nix develop -c cargo test -p selo-kel --test service
basic_prefix_cannot_be_controlled_by_an_unrelated_signed_key -- --nocapture`
failed with `Ok(Committed(InMemoryAllPos(4)))` using published `keri-rs`
0.0.15. The red regression is marked ignored until a corrected CESR release
is available; it must pass unignored before A21 acceptance. The prior green
Selo gate establishes storage behavior, **not** secure untrusted KEL
acceptance. The A01 correction exists and passes in the CESR worktree, but
the Selo published dependency has not consumed it.
An isolated `/tmp/selo-a21-patched` copy used temporary Cargo
`[patch.crates-io]` paths to the five corrected CESR worktree crates. After
adapting that copy to the A14 explicit `MessageLimits`/`JsonLimits` API,
`nix develop -c cargo test -p selo-kel --test service
basic_prefix_cannot_be_controlled_by_an_unrelated_signed_key -- --ignored`
exited 0. The first patched compile exposed exactly three missing-limit call
sites. After adapting the remaining test call sites in that isolated copy,
`nix develop -c cargo test --workspace`, `nix develop -c cargo test -p
selo-kel -- --ignored`, and strict all-target/all-feature Clippy also exited
0. This confirms the current CESR worktree rejects the attack and is
mechanically consumable after an explicit work-limit migration; the copy is
experimental evidence, not Selo's committed dependency graph or a
substitute for a published release.

The CESR release must be coordinated across all five workspace crates.
`cargo package -p keri-rs --allow-dirty` currently fails tarball verification
against published `keri-events` 0.5.0 (missing new inception/member-set APIs),
and `cargo package -p keri-codec --allow-dirty` fails against published
`cesr-stream` 0.6.0 and `keri-events` 0.5.0 (61 compile errors, including new
framing and query/reply APIs). The workspace Nix gate and Selo's isolated
all-local dependency check pass because they use the matching source tree.
The publish dependency order is `cesr-rs` → `cesr-stream` and `keri-events`
→ `keri-codec` → `keri-rs`; each dependent manifest must require the newly
published compatible version before its package verification can pass.
No release has been published, and Selo's ignored authentication test remains
a hard acceptance gate.
`nix develop -c cargo package --workspace --no-verify --allow-dirty`
packaged all five crate archives successfully from this source tree, but
`--no-verify` does not establish that a dependent crate compiles against the
currently published sibling versions. It is packaging evidence only.

The direct Selo service retains every raw candidate under an immutable
command-scoped evidence stream, reloads and revalidates the accepted KEL,
then atomically CAS-appends the accepted fact, command marker and outgoing
intent. Distinct KERI SAIDs survive a losing canonical CAS. Confirmed
conflicts reload and redecide; ambiguous appends reconcile the command marker
before another attempt. A recorded marker binds AID, SAID, exact wire and
intent hashes. Its event type and schema must also match; a red regression
showed that checking payload alone could accept a foreign schema. Accepted
fact rehydration fails closed on unsupported schema versions.

The new `deliver_intent` service reads the committed outbox before invoking
an external sink, passes the command ID as its idempotency key, and persists
a `selo.intent.delivered` receipt only after sink acknowledgement. It
reconciles a lost receipt-append reply. A crash or sink reply loss before the
receipt still permits at-least-once invocation; the sink must deduplicate by
command ID. Persistent Fjall restart tests cover command recovery, pending
outbox and recorded receipt. Injected store errors cover precommit ambiguity,
commit with lost reply, reconciliation read loss and receipt append reply loss.
A forced concurrent KEL head change proves confirmed conflict reload/redecision
rejects the losing signed fork while retaining its candidate evidence. Polling
an append through commit and then cancelling before reply proves a repeat
request finds the marker without a second KEL fact or intent.
The latest indexed `nix flake check -L > /tmp/selo-a21-auth-blocked-flake.log
2>&1` exited 0 on aarch64-darwin, including build, tests, formatting,
strict Clippy, docs and doctests. Its service suite reported **5 passed, 1
ignored**: the wrong-key basic inception security regression is the explicit
ignored case pending a corrected published dependency.

A21 remains open because `mnesis-bombay` card #5 has not implemented the
aggregate Entity host, and its card #7 committed-log relay/checkpoint remains
open. Both direct and Bombay entry paths must invoke this same Selo service;
the receipt helper is not yet a live `$all` worker. Escrow scheduling, quotas
and custody remain A22/A23 work. No notification is evidence of durable
acceptance or delivery.

The host's existing `execute_command` cannot carry Selo's transaction
unchanged: its `command_id` is used for the returned outcome, while
`Repository::save` receives no command ID or outgoing intent to include in
the atomic KEL/marker/outbox write. The exact host seam needs an executable
composition probe before adding a generic application callback. Preparatory
card #5 scope and change ledger live in an isolated `feat/5-aggregate-host`
worktree; the original mnesis-bombay worktree remains untouched.
`bombay-entity` issue #6 (a global bound on active plus activating local
entities) is still open. Card #5 assigns that capacity to the upstream Entity
runtime and explicitly forbids a private mnesis-bombay substitute. The local
host can be prototyped against the released per-entity bounds, but A21/A30
must not claim a bounded global activation footprint until the upstream
capacity law and conformance evidence exist.

# Linux release review follow-up

These are source-review findings and qualification tasks, not a claim that the
managed Linux launcher is ready for release. Normal CLI execution still uses
the explicitly acknowledged uncontained preview. Provider checks remain deferred
until the provider-free release work is complete.

Two tool-disabled Opus 5.5 reviews examined the durable scope journal and
installation policy: `17f74e3` with `5f3469c`, then `541f06c`. The reviews found
no demonstrated retirement-authority or fixture-root execution bypass in the
supplied sources. They identified composition risks and missing evidence that
must be checked against code and native behavior.

## Addressed in the association checkpoint

- A service key can be claimed once and cannot be cloned by consumers.
- Preparation requires the key claimed from that binding before sending launch
  data or transferring its lease. The Store terminal relay borrows that key
  from its pending journal association; other fixed fixtures retain it locally.
- Schema 9 gives each manager invocation one durable run association, retained
  after completion, with migration and rollback checks.
- Wrong-run and reopened-Store refusal controls subsequently commit the same
  returned retirement value to the original association.
- Binding JSON has a pinned serialization test; run lookup supplies the
  canonical recorded ID.
- Raw-path service policies are available only with qualification enabled.

The local checks and the native result for each revision must be recorded
separately. These changes do not supply restart recovery or target-exit evidence.

## Review checkpoints

| Area | Required follow-up |
| --- | --- |
| Admission lifetime | Real binding and both deliberate observer mutations passed on Ubuntu 22.04/24.04 at `f6cce6d` (`41306933304`); complete pipeline still tracked separately. |
| Observation lifetime | Live completion retains the original binding/key and never selects a new generation. Fresh diagnostic witnesses are qualification-only and their receipts fail Store association. Restart recovery remains a separate unimplemented production gate. |
| systemd path compatibility | Vendor-path difference measured at `f54f80a`. Generated per-user units now use `/etc/systemd/system`; exact-path native controls pending. |
| Installed inode lifetime | Single-link admission and retained-link mutation controls implemented; native results pending. Installer must preserve independent, unchanged inodes while admitted runs retain them. |
| Policy API | Admitted-policy reuse refused; path-derivation contract covered. Lower-level metadata readers cannot construct a selection or launch authority; raw service policies and layout overrides are qualification-only. |
| Build features | Default dependency-feature checks and negative API doctests pass; candidate builds use the default production graph. |

The vendor-path measurement creates one exclusively owned, inactive unit under
`/usr/lib/systemd/system` on each hosted Ubuntu image. It queries the loaded
`FragmentPath`, checks that it names the same inode, records the `/lib` alias,
and removes its unit. The fixture has no activation dependencies and refuses
manual start. Both hosted measurements passed at `f54f80a`: Ubuntu 22.04
reported `/lib`, and Ubuntu 24.04 reported `/usr/lib`, with the original inode
in both cases. Per-user generated units now use the administrator directory
`/etc/systemd/system`. The follow-up requires exact reporting for that path on
both runners; runtime fragment equality and protected-path checks remain strict.

Source review suggested that selector admission ends at successful `bind`.

That is the current implementation: already-bound services retain their original
generation even if launch preparation happens later. A selector change does not
terminate existing work. Real-service and mutation controls now pass on both
Ubuntu images; installer integration must preserve the documented original
artifact lifetime and provide its own update/removal tests.

The first inode-policy CI run exposed an overbroad check: a generic process-image
test encountered a hardlinked system executable. Single-link policy now belongs
to installation selection, manifest and complete artifact admission. Generic
read-only image observations retain their existing change detection. Native
controls exercise the actual installation consumers, plus link additions after
opening; no system executable or test's image identity was changed to avoid the
refusal. This correction requires a fresh CI result.

## Native evidence

- `4ef99d1`: full import-isolation, pathname and journal-authority pipeline passed
  (`41304050468`), including both native Ubuntu suites and independent rebuilds.
- `7df8703`: full retirement-retry CI passed (`41304842096`), including
  both native Ubuntu suites and independent release rebuilds.
- `17f74e3`: full durable-journal CI passed (`41297948160`).
- `db9220a`: full selector and Python-3.10 boundary CI passed (`41300192166`).
- `0a3167e`: full installed-policy CI passed (`41300687178`).
- `541f06c`: activation and all eleven journal controls passed on both native
  runners; the combined terminal step exceeded its six-minute deadline.
- `71ab9af`: optimizing the pinned SHA-256 dependency resolved that timeout on
  both native runners; full CI and independent release rebuilds passed (`41302398455`).

## Journal authority and independent observation

The follow-up guards the Store's general event writers against scope events.
Only the scope module can construct their internal authorization, after matching
the original live key or retirement receipt. Serialized copies are refused
before any transaction. Projection and migration tests use an explicitly named,
test-only constructor that is absent from qualification library builds too.
This is an internal API boundary, not protection from a hostile same-UID program
editing its own registry.

The native terminal observer now reads projection and ordered events in one
read-only SQLite snapshot. It requires exactly the applicable planned, bound,
spawned and retired events; matches scope, binding and target PID; validates the
binding fields; and compares guardian/invocation and client identity against the
prepared-session markers and expected fixture unit prefix. It accepts pending
work after client loss and retirement with an unknown target exit. Projection-only
retirement, empty bindings, missing/reordered/duplicate events and coherent but
foreign invocation metadata are negative controls. These checks corroborate
qualification evidence and never grant the runtime a completion capability.

Local default and qualification strict Clippy, all 75 Store tests, and all 43
Linux Python controls pass. Full CI for `7d7a8c6` passed (`41303766347`).

## Protected pathname controls

The asset matrix now replaces an ancestor directory and overlays a leaf with a
private bind mount, for both configuration and image files. Each control retains
an independent descriptor, verifies every original stamp field remains unchanged,
checks that the path names a different inode, and confirms identical contents.
Only the pathname recheck can produce the expected new fixed diagnostic. The
existing unchanged-file positive controls still apply. All mount operations are
confined to the hosted fixture's recursively private mount namespace and owned
tmpfs; a leaf overlay is unmounted before its parent.

Local runtime tests, strict Clippy and the ordinary-file ancestor control pass.
The four new privileged cases passed both native Ubuntu suites in the full
`7791f02` pipeline (`41303860668`); none ran on the developer host.

## Privileged fixture isolation

Activation administrator and separate-user controls, managed-scope helper roles,
and manager-refusal namespace roles now launch Python with `-I -B -S`. Standard
modules cannot be shadowed by the checkout, working directory or `PYTHONPATH`;
site customization is disabled and no bytecode is written into the checkout.
The two required sibling helpers load through explicit source paths without
adding their directory to the import search path.

An ordinary-user subprocess control copies the scripts into an owned directory
with a shadow `json.py`: isolated invocations reach the intended early refusal,
do not execute the shadow and leave no bytecode. The same owned canary executes
without isolation, proving the negative control is meaningful. Cleanup reporting
also requires all owned filesystem names to be absent, including dangling
symlinks; the administrator separately checks its units and scope teardown.
All 46 local Linux harness controls pass. Full CI for `4ef99d1` passed
(`41304050468`), including both native Ubuntu suites.

## Retirement retry and consumer semantics

An authorized retry now returns `scope_already_retired` when the verified,
write-locked snapshot contains both the exact retirement event and its matching
projection. It writes nothing and returns the original opaque receipt to the
caller. A mismatched identity or corrupted projection cannot produce that
diagnostic. The native receipt control injects a lost acknowledgement after a
successful commit, then retries with the same returned receipt; this models the
ambiguous-success branch without claiming a real disk fault was reproduced.
The existing pre-commit failure-and-retry control remains separate.

The consumer audit found that CLI history already uses `outcome` to distinguish
pending work from an unknown exit. Gents resume requires an observed PID, exit 0
and `external_client_exited`; scope retirement cannot satisfy it. JSON already
contains `outcome` and `custody`, so no redundant completion flag was added.
Serialization controls now pin both pending and retired records with a null
`exitCode`, and the registry documentation explains their different meanings.
All 310 pinned Nextest tests passed with retries disabled, together with strict
qualification Clippy and workspace doctests. A parallel `cargo test` run hit
the existing stale-engine-plan assertion once; the isolated control and a later
139-test core run passed. That assertion now includes the unexpected result for
diagnosis if it recurs. No cause or runtime fix is claimed from a passing retry.
Full CI for `7df8703` passed (`41304842096`), including both native Ubuntu suites.

## Historical migration evidence

Clean schema-5 (`da6b2d9`), schema-6 (`533c355`) and schema-7 (`63ac746`) executables
each produced a real registry containing one completed stub run and one
interrupted stub run. Every source database upgraded to schema 9, and each
historical executable then refused the upgraded copy with exit 125. These were
ordinary-user, provider-free processes in temporary homes.

The checked-in databases retain their original journal, timestamps and schema;
provenance sidecars and a generator document their origin. A regression test
checks complete event preservation, pending-run fencing, completed-run reuse,
verified backups and reopening. That test and strict workspace Clippy passed
locally, and the checked-in generator reproduced a valid fixture. Full CI passed
at `4494f35` (`41306277254`), after the macOS test used the Store's canonical
temporary path so SQLite's no-symlink policy stayed intact. See
[the fixture notes](../crates/agentswapper-core/tests/fixtures/historical/README.md).

## Generation-layout preparation

The activated fixture now reserves distinct manifests for its original and next
generation; the reader derives their paths from the selector. Both reference the
same fixed images and units. A pure contract test verifies the exact Rust-facing
field inventory, distinct valid generations, initial selection and artifact
hashes. All 47 Linux harness tests passed locally. Both native Ubuntu suites
passed the later real selector-switch and mutation controls at `f6cce6d`
(`41306933304`), closing the admission-lifetime finding for this qualified consumer.

### Service admission across selector replacement

Three hosted controls now exercise actual service bindings: replacing the
selector between initial observations and the final binding check must refuse;
replacing it after successful binding must permit preparation and retirement
using the original key; changing the retained guardian image's metadata must
refuse revalidation while still allowing observation of original retirement.
Both generation manifests and every other artifact remain installed throughout.
The administrator authenticates its ownership marker and exact fixture assets
before each action, replaces only its reserved selector, and restores the
original selection after each control. This is not an installer or revocation API.

The deterministic pre-admission barrier is available only to qualification
builds and executes every normal admission check. A default-build compile-fail
test checks that it is absent. Binding also rejects an already-admitted policy.
Local manager tests, default doctests, strict evaluator Clippy and 48 Linux
harness controls passed. Real service controls await hosted CI; deliberately
mutated observers additionally check that these cases detect a missing or
prematurely executed admission transition. The builder edits disposable source
copies, requires exactly one matching transition and barrier, and uses separate
Cargo targets. It neither changes the checkout nor adds a runtime fault feature.
The guardian always uses the original binary. Only the ordinary observers carry
the faults; both must fail with the specific expected diagnostic, after the
unmodified controls pass. Two dedicated Ubuntu jobs keep this compilation out
of the bounded journal/terminal step. Both mutated observers built locally and
all 50 ordinary Linux harness controls passed. Both mutation jobs and both full
native manager suites passed at `f6cce6d` (`41306933304`). The complete
cross-platform packaging/rebuild pipeline is tracked separately.

## Source-review follow-up at 7df8703

A third tool-disabled Opus 5.5 review found no exploitable authority issue in the
key, preparation, writer-authorization, retry or observer changes. It identified
two false-refusal risks and several missing controls. The follow-up closes the
Python SQLite connection explicitly even on assertion failure, exercises a real
concurrent WAL commit between projection and event reads, and checks mismatched
fields in each lifecycle event plus an unsupported audit marker.

The native wrong-key control now prepares its original service before waiting
for the rejected candidate to retire, preserving the original admission budget.
It also checks that the candidate wrote no target-ready or lease-refusal marker.
The independent-witness control explicitly matches all serialized identity and
retirement facts while proving its key differs. These observations distinguish
the live-key check from a refusal caused by mismatched diagnostics.

Binding failure currently consumes the claimed key and leaves the run unresolved;
the consumer closes the control connection rather than retrying preparation.
`scope_already_retired` is a terminal retry result: the original retirement was
committed and no new event was written. A receipt is still returned for explicit
disposal. These semantics do not provide restart recovery or automatic fallback.
All ten local observer controls and strict workspace qualification Clippy pass.
The revised native receipt controls await this revision's hosted CI result.

The trusted-namespace gate, loaded socket/endpoint authentication, loaded unit
content, production helper identities after exec, installer/update/removal,
restart recovery and production launch integration remain separate open gates.
The journal does not isolate mutually hostile programs running as the same UID,
and local scope retirement does not attest to externally delegated work.

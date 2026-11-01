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
- Preparation requires the exact key retained by the journal before sending
  launch data or transferring its lease.
- Schema 9 gives each manager invocation one durable run association, retained
  after completion, with migration and rollback checks.
- Wrong-run and reopened-Store refusal controls subsequently commit the same
  returned retirement value to the original association.
- Binding JSON has a pinned serialization test; run lookup supplies the
  canonical recorded ID.
- Raw-path service policies are available only with qualification enabled.

The local checks and the native result for each revision must be recorded
separately. These changes do not supply restart recovery or target-exit evidence.

## Remaining review work

| Area | Required follow-up |
| --- | --- |
| Migration fixtures | Supplement synthetic downgrade tests with databases produced by actual historical schema-5/6/7 revisions. |
| Admission lifetime | Test real binding across a selector switch before admission and after admission; metadata-only lifetime tests are insufficient. |
| Observation lifetime | Separate observing an admitted older generation from selecting a generation for a new launch; observers must not gain launch authority. |
| systemd path compatibility | Measure `/lib` versus `/usr/lib` `FragmentPath` on both runners; permit an alias only with a protected same-file check. |
| Installed inode lifetime | Specify no hardlink deduplication or metadata rewrites of live generations, then enforce and test the chosen host/installer prerequisites. |
| Policy API | Guard admitted policies from reuse; test production path derivation and narrow caller-selected generation/layout APIs. |
| Build features | Verify shipped CLI feature graphs exclude qualification APIs. |

Source review suggested that selector admission ends at successful `bind`.
That is the current implementation: already-bound services retain their original
generation even if launch preparation happens later. A selector change does not
terminate existing work. This needs a real-service control and a documented
upgrade/revocation policy before installer integration.

## Native evidence

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
Linux Python controls pass. This revision's native result is pending.

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
The four new privileged cases require native CI; none ran on the developer host.

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
also requires all seven owned filesystem names to be absent, including dangling
symlinks; the administrator separately checks its units and scope teardown.
All 46 local Linux harness controls pass. Native qualification is pending.

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
Native qualification of the retirement retry remains pending.

The trusted-namespace gate, loaded socket/endpoint authentication, loaded unit
content, production helper identities after exec, installer/update/removal,
restart recovery and production launch integration remain separate open gates.
The journal does not isolate mutually hostile programs running as the same UID,
and local scope retirement does not attest to externally delegated work.
